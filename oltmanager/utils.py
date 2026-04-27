import asyncio
import datetime
import re
import secrets
import socket
import telnetlib
import threading
import time

from django.db.models import Q
from django.utils import timezone

try:
    from ncclient import manager as nc_manager
except Exception:
    nc_manager = None


BOARD_DEFAULT_PORTS = {
    # Huawei common service/control boards
    "H805GPFD": 16,
    "H801X2CS": 2,
    "H801GICF": 8,
    "H802SCUN": 4,
}

TELNET_OPEN_ATTEMPTS = 3
TELNET_OPEN_RETRY_DELAYS = (0.7, 1.4)
TELNET_SESSION_RECOVERY_GRACE_SECONDS = 20
PROMPT_LINE_PATTERN = re.compile(r"^[^\r\n]*[>#\]]\s*$")
ANSI_ESCAPE_PATTERN = re.compile(r"\x1B\[[0-?]*[ -/]*[@-~]")
_TELNET_SESSION_LOCK = threading.Lock()
_TELNET_SESSIONS = {}
_ONU_TRAFFIC_IFINDEX_CACHE_LOCK = threading.Lock()
_ONU_TRAFFIC_IFINDEX_CACHE = {}


def _run_asyncio_sync(awaitable):
    loop = asyncio.new_event_loop()
    try:
        asyncio.set_event_loop(loop)
        return loop.run_until_complete(awaitable)
    finally:
        try:
            loop.close()
        finally:
            try:
                asyncio.set_event_loop(None)
            except Exception:
                pass


def generate_snmp_community():
    token = secrets.token_urlsafe(9).replace("-", "").replace("_", "")
    return f"crm-snmp-{token[:12]}"


def _extract_versions(sys_descr):
    model_match = re.search(r"(MA\d{4}[A-Z0-9-]*)", sys_descr or "", flags=re.IGNORECASE)
    sw_match = re.search(r"\b(R\d{3,4}[A-Z0-9.-]*)\b", sys_descr or "", flags=re.IGNORECASE)
    return (
        model_match.group(1).upper() if model_match else "",
        sw_match.group(1).upper() if sw_match else "",
    )


def _extract_model_and_sw_from_text(text):
    model = ""
    sw_version = ""

    paren_model = re.search(r"\((MA\d{4}[A-Z0-9-]*)\)", text or "", flags=re.IGNORECASE)
    if paren_model:
        model = paren_model.group(1).upper()
    else:
        model, _ = _extract_versions(text or "")

    sw_match = re.search(r"\b(R\d{3,4}[A-Z0-9.-]*)\b", text or "", flags=re.IGNORECASE)
    if sw_match:
        sw_version = sw_match.group(1).upper()

    return model, sw_version


def _format_snmp_uptime(raw_value):
    try:
        ticks = int(str(raw_value).strip())
    except (TypeError, ValueError):
        return "--"
    total_seconds = ticks // 100
    days, rem = divmod(total_seconds, 86400)
    hours, rem = divmod(rem, 3600)
    minutes, _ = divmod(rem, 60)
    return f"{days} day(s), {hours:02}:{minutes:02}"


def fetch_snmp_snapshot(olt):
    snapshot = {
        "status": "SNMP data unavailable",
        "sys_name": olt.name,
        "sys_descr": "Not fetched yet",
        "model": olt.hardware_version or "Unknown",
        "sw_version": olt.sw_version or "Unknown",
        "uptime": "--",
        "temperature": "--",
        "cpu": "--",
        "memory": "--",
    }
    try:
        from pysnmp.hlapi.asyncio import (  # type: ignore
            CommunityData,
            ContextData,
            ObjectIdentity,
            ObjectType,
            SnmpEngine,
            UdpTransportTarget,
            get_cmd,
            next_cmd,
        )
    except Exception:
        snapshot["status"] = "pysnmp not installed, showing saved data"
        return snapshot

    try:
        async def _snmp_get(mp_model):
            target = await UdpTransportTarget.create(
                (olt.ip_address, olt.snmp_port),
                timeout=1.2,
                retries=1,
            )
            return await get_cmd(
                SnmpEngine(),
                CommunityData(olt.snmp_community, mpModel=mp_model),
                target,
                ContextData(),
                ObjectType(ObjectIdentity("1.3.6.1.2.1.1.5.0")),  # sysName
                ObjectType(ObjectIdentity("1.3.6.1.2.1.1.1.0")),  # sysDescr
                ObjectType(ObjectIdentity("1.3.6.1.2.1.1.3.0")),  # sysUpTime
            )

        async def _snmp_walk(mp_model, base_oid, limit=128):
            rows = {}
            target = await UdpTransportTarget.create(
                (olt.ip_address, olt.snmp_port),
                timeout=1.2,
                retries=1,
            )
            engine = SnmpEngine()
            current_oid = base_oid
            for _ in range(limit):
                error_indication, error_status, _, var_binds = await next_cmd(
                    engine,
                    CommunityData(olt.snmp_community, mpModel=mp_model),
                    target,
                    ContextData(),
                    ObjectType(ObjectIdentity(current_oid)),
                )
                if error_indication:
                    engine.close_dispatcher()
                    raise RuntimeError(str(error_indication))
                if error_status:
                    engine.close_dispatcher()
                    raise RuntimeError(error_status.prettyPrint())
                if not var_binds:
                    break
                stop = False
                for oid, value in var_binds:
                    oid_text = str(oid)
                    if not oid_text.startswith(base_oid + "."):
                        stop = True
                        break
                    rows[oid_text.split(".")[-1]] = str(value)
                    current_oid = oid_text
                if stop:
                    break
            engine.close_dispatcher()
            return rows

        def _pick_entity_metrics(mp_model):
            try:
                names = asyncio.run(_snmp_walk(mp_model, "1.3.6.1.2.1.47.1.1.1.1.7"))
                classes = asyncio.run(_snmp_walk(mp_model, "1.3.6.1.2.1.47.1.1.1.1.5"))
                cpus = asyncio.run(_snmp_walk(mp_model, "1.3.6.1.4.1.2011.5.25.31.1.1.1.1.5"))
                mems = asyncio.run(_snmp_walk(mp_model, "1.3.6.1.4.1.2011.5.25.31.1.1.1.1.7"))
                temps = asyncio.run(_snmp_walk(mp_model, "1.3.6.1.4.1.2011.5.25.31.1.1.1.1.11"))
            except Exception:
                return {"temperature": "--", "cpu": "--", "memory": "--"}

            candidates = []
            all_indexes = set(list(temps.keys()) + list(cpus.keys()) + list(mems.keys()))
            for idx in all_indexes:
                raw_temp = temps.get(idx, "")
                try:
                    temp = int(str(raw_temp).strip()) if str(raw_temp).strip() else None
                except (TypeError, ValueError):
                    temp = None
                if temp in (2147483647, -2147483648, 0):
                    temp = None
                try:
                    cpu = int(str(cpus.get(idx, "")).strip()) if str(cpus.get(idx, "")).strip() else None
                except (TypeError, ValueError):
                    cpu = None
                try:
                    memory = int(str(mems.get(idx, "")).strip()) if str(mems.get(idx, "")).strip() else None
                except (TypeError, ValueError):
                    memory = None
                ent_class = str(classes.get(idx, "")).strip()
                ent_name = str(names.get(idx, "")).strip().lower()
                score = 0
                if ent_class in {"3", "9"}:
                    score += 4
                if any(token in ent_name for token in ("main", "control", "chassis", "shelf", "system", "board")):
                    score += 3
                if ent_name:
                    score += 1
                if temp is None and cpu is None and memory is None:
                    continue
                candidates.append((score, temp, cpu, memory))
            if not candidates:
                return {"temperature": "--", "cpu": "--", "memory": "--"}
            candidates.sort(reverse=True)
            best = candidates[0]
            return {
                "temperature": f"{best[1]}C" if best[1] is not None else "--",
                "cpu": f"{best[2]}%" if best[2] is not None else "--",
                "memory": f"{best[3]}%" if best[3] is not None else "--",
            }

        last_error = None
        for mp_model in (1, 0):  # Try v2c first, then v1.
            error_indication, error_status, _, var_binds = asyncio.run(_snmp_get(mp_model))
            if error_indication:
                last_error = str(error_indication)
                continue
            if error_status:
                last_error = f"status error: {error_status.prettyPrint()}"
                continue

            oid_map = {str(oid): str(value) for oid, value in var_binds}
            sys_name = oid_map.get("1.3.6.1.2.1.1.5.0", olt.name)
            sys_descr = oid_map.get("1.3.6.1.2.1.1.1.0", "")
            sys_uptime = oid_map.get("1.3.6.1.2.1.1.3.0", "")
            model, sw_version = _extract_versions(sys_descr)
            metrics = _pick_entity_metrics(mp_model)

            snapshot.update(
                {
                    "status": "Live SNMP data fetched",
                    "sys_name": sys_name,
                    "sys_descr": sys_descr or "No sysDescr response",
                    "model": model or snapshot["model"],
                    "sw_version": sw_version or snapshot["sw_version"],
                    "uptime": _format_snmp_uptime(sys_uptime),
                    "temperature": metrics.get("temperature", "--"),
                    "cpu": metrics.get("cpu", "--"),
                    "memory": metrics.get("memory", "--"),
                }
            )
            return snapshot

        snapshot["status"] = (
            "SNMP timeout/no response. Check community, UDP port, SNMP version, and ACL/firewall. "
            f"Last error: {last_error or 'no response'}"
        )
        return snapshot
    except Exception as exc:
        snapshot["status"] = f"SNMP fetch failed: {exc}"
        return snapshot


def probe_snmp_reachability(olt):
    result = {
        "ok": False,
        "status": "SNMP no response",
    }
    try:
        from pysnmp.hlapi.asyncio import (  # type: ignore
            CommunityData,
            ContextData,
            ObjectIdentity,
            ObjectType,
            SnmpEngine,
            UdpTransportTarget,
            get_cmd,
        )
    except Exception:
        result["status"] = "pysnmp not installed"
        return result

    async def _snmp_get(mp_model):
        target = await UdpTransportTarget.create(
            (olt.ip_address, olt.snmp_port),
            timeout=1.0,
            retries=0,
        )
        return await get_cmd(
            SnmpEngine(),
            CommunityData(olt.snmp_community, mpModel=mp_model),
            target,
            ContextData(),
            ObjectType(ObjectIdentity("1.3.6.1.2.1.1.5.0")),
        )

    last_error = ""
    for mp_model in (1, 0):
        try:
            error_indication, error_status, _, var_binds = asyncio.run(_snmp_get(mp_model))
            if error_indication:
                last_error = str(error_indication)
                continue
            if error_status:
                last_error = error_status.prettyPrint()
                continue
            if var_binds:
                result["ok"] = True
                result["status"] = "Live SNMP data fetched"
                return result
        except Exception as exc:
            last_error = str(exc)
    result["status"] = (
        "SNMP timeout/no response. Check community, UDP port, SNMP version, and ACL/firewall. "
        f"Last error: {last_error or 'no response'}"
    )[:300]
    return result


def mark_olt_onus_offline_due_to_snmp(olt, *, status_text=""):
    from .models import ConfiguredONU

    now = timezone.now()
    rows = list(
        ConfiguredONU.objects.filter(olt=olt)
        .exclude(derived_status="offline", run_state="offline")
        .only("id", "derived_status", "run_state", "status_source", "status_first_seen_at", "status_updated_at")
    )
    for row in rows:
        row.run_state = "offline"
        row.derived_status = "offline"
        row.status_source = "snmp_down"
        row.status_first_seen_at = now
        row.status_updated_at = now
    if rows:
        ConfiguredONU.objects.bulk_update(
            rows,
            ["run_state", "derived_status", "status_source", "status_first_seen_at", "status_updated_at"],
            batch_size=500,
        )

    olt.snmp_last_status = (status_text or "SNMP no response on UDP 161")[:300]
    olt.snmp_last_synced_at = now
    olt.save(update_fields=["snmp_last_status", "snmp_last_synced_at"])
    return {"checked": len(rows), "updated": len(rows)}


def fetch_snmp_interfaces(olt, limit=24):
    result = {
        "status": "SNMP interface data unavailable",
        "rows": [],
    }
    try:
        from pysnmp.hlapi.asyncio import (  # type: ignore
            CommunityData,
            ContextData,
            ObjectIdentity,
            ObjectType,
            SnmpEngine,
            UdpTransportTarget,
            next_cmd,
        )
    except Exception:
        result["status"] = "pysnmp not installed, interface data unavailable"
        return result

    oids = {
        "name": "1.3.6.1.2.1.31.1.1.1.1",
        "descr": "1.3.6.1.2.1.2.2.1.2",
        "alias": "1.3.6.1.2.1.31.1.1.1.18",
        "type": "1.3.6.1.2.1.2.2.1.3",
        "mau_type": "1.3.6.1.2.1.26.2.1.1.3",
        "hw_optical_vendor": "1.3.6.1.4.1.2011.5.25.157.1.1.1.1.1",
        "hw_eth_negotiation": "1.3.6.1.4.1.2011.5.25.157.1.1.1.1.16",
        "optical_mode": "1.3.6.1.4.1.2011.5.25.31.1.1.3.1.1",
        "optical_conn": "1.3.6.1.4.1.2011.5.25.31.1.1.3.1.43",
        "mtu": "1.3.6.1.2.1.2.2.1.4",
        "admin": "1.3.6.1.2.1.2.2.1.7",
        "oper": "1.3.6.1.2.1.2.2.1.8",
        "speed": "1.3.6.1.2.1.2.2.1.5",
        "high_speed": "1.3.6.1.2.1.31.1.1.1.15",
        "autoneg": "1.3.6.1.2.1.26.5.1.1.1",
        "duplex": "1.3.6.1.2.1.10.7.2.1.19",
        "in_octets": "1.3.6.1.2.1.31.1.1.1.6",
        "out_octets": "1.3.6.1.2.1.31.1.1.1.10",
    }

    def _status_label(value):
        mapping = {
            "1": "Up",
            "2": "Down",
            "3": "Testing",
            "4": "Unknown",
            "5": "Dormant",
            "6": "Not present",
            "7": "Lower layer down",
        }
        return mapping.get(str(value).strip(), str(value))

    def _admin_label(value):
        mapping = {
            "1": "Enabled",
            "2": "Disabled",
            "3": "Testing",
        }
        return mapping.get(str(value).strip(), str(value).strip() or "-")

    def _autoneg_label(value):
        mapping = {
            "3": "Auto",
            "4": "Manual",
        }
        return mapping.get(str(value).strip(), "-")

    def _duplex_label(value):
        mapping = {
            "1": "Unknown",
            "2": "HalfD",
            "3": "FullD",
        }
        return mapping.get(str(value).strip(), "")

    def _speed_label(speed_value, high_speed_value):
        try:
            high = int(str(high_speed_value).strip() or "0")
        except ValueError:
            high = 0
        if high > 0:
            if high >= 1000:
                return f"{high // 1000}G" if high % 1000 == 0 else f"{high}M"
            return f"{high}M"
        try:
            speed = int(str(speed_value).strip() or "0")
        except ValueError:
            speed = 0
        if speed >= 1_000_000_000:
            return f"{speed // 1_000_000_000}G"
        if speed >= 1_000_000:
            return f"{speed // 1_000_000}M"
        return "-"

    def _speed_from_mau_type(mau_type_value):
        text = str(mau_type_value or "").strip().lower()
        numeric = re.search(r"(\d+)", text)
        code = int(numeric.group(1)) if numeric else None
        if any(token in text for token in ("100g", "baseer4", "baselr4", "basesr4")):
            return "100G"
        if any(token in text for token in ("40g", "basecr4", "basesr4", "baselr4")) or code in {71, 72, 74}:
            return "40G"
        if any(token in text for token in ("10g", "baset(", "10gbase", "baselr", "basesr", "baseer")) or code in {34, 35, 36, 54, 55}:
            return "10G"
        if any(token in text for token in ("1000", "basepx", "baselx", "basesx", "basex", "baset")) or code in {30, 50}:
            return "1G"
        if any(token in text for token in ("100base", "txfd", "fx")) or code in {16}:
            return "100M"
        if "10base" in text:
            return "10M"
        return "-"

    def _classify_medium(
        name,
        descr,
        type_value,
        speed_label="",
        mau_type_value="",
        optical_mode_value="",
        optical_conn_value="",
        optical_vendor_value="",
        eth_negotiation_value="",
    ):
        text = f"{name} {descr}".lower()
        raw_type = str(type_value).strip()
        speed_text = str(speed_label or "").strip().upper()
        mau_text = str(mau_type_value or "").strip().lower()
        mau_numeric = re.search(r"(\d+)", mau_text)
        mau_code = int(mau_numeric.group(1)) if mau_numeric else None
        optical_mode_text = str(optical_mode_value or "").strip().lower()
        optical_conn_text = str(optical_conn_value or "").strip().lower()
        optical_vendor_text = str(optical_vendor_value or "").strip().lower()
        eth_negotiation_text = str(eth_negotiation_value or "").strip().lower()
        if any(token in text for token in ("meth", "me th", "management ethernet")):
            return ""
        if optical_vendor_text and optical_vendor_text not in {"0", "none", "null", "n/a", "-", "nosuchinstance", "nosuchobject"}:
            return "Optical"
        if eth_negotiation_text and eth_negotiation_text not in {"0", "none", "null", "n/a", "-", "nosuchinstance", "nosuchobject"}:
            return "Electrical"
        if "coppermode" in optical_mode_text or optical_mode_text == "7":
            return "Electrical"
        if any(token in optical_mode_text for token in ("singlemode", "multimode", "gpsmode")):
            return "Optical"
        if any(token in optical_conn_text for token in ("lc", "sc", "fc", "sfp", "optic")):
            return "Optical"
        if any(token in optical_conn_text for token in ("rj45", "electrical", "copper")):
            return "Electrical"
        if any(token in mau_text for token in ("basepx", "baselx", "basesx", "basex", "baselr", "basesr", "baseer")):
            return "Optical"
        if any(token in mau_text for token in ("1000baset", "100baset", "10baset", "10gbaset", "basecx", "basecr")):
            return "Electrical"
        if mau_code in {34, 35, 36, 50, 55, 72, 74, 77, 78}:
            return "Optical"
        if mau_code in {16, 30, 54, 71}:
            return "Electrical"
        if raw_type == "117":
            return "Optical"
        if any(token in text for token in ("sfp", "xfp", "xge", "optical", "fiber", "giu", "ten-gigabitethernet", "10ge")):
            return "Optical"
        if speed_text == "10G":
            return "Optical"
        if any(token in text for token in ("fastethernet", "gigabitethernet")):
            return "Electrical"
        if re.search(r"(?i)\bgei\b", text):
            return "Electrical"
        if raw_type == "62":
            return "Optical"
        if raw_type == "6":
            return "Electrical"
        return "-"

    def _is_ethernet_uplink(name, descr, type_value):
        text = f"{name} {descr}".lower()
        if "meth" in text:
            return False
        if any(token in text for token in ("gpon", "epon", "ont", "pon ")):
            return False
        if str(type_value).strip() in {"6", "62", "117"}:
            return True
        ethernet_tokens = (
            "eth",
            "ethernet",
            "gigabitethernet",
            "xge",
            "10ge",
            "giu",
            "up",
        )
        return any(token in text for token in ethernet_tokens)

    def _clean_description(alias, descr, port_name):
        alias_text = (alias or "").strip()
        descr_text = (descr or "").strip()
        port_text = (port_name or "").strip()
        for candidate in (alias_text, descr_text):
            lower = candidate.lower()
            if not candidate:
                continue
            if lower == port_text.lower():
                continue
            if any(token in lower for token in ("gpon", "epon", "ont", "meth")):
                continue
            return candidate
        return "-"

    async def _walk_oid(mp_model, base_oid):
        rows = {}
        target = await UdpTransportTarget.create(
            (olt.ip_address, olt.snmp_port),
            timeout=1.2,
            retries=1,
        )
        engine = SnmpEngine()
        current_oid = base_oid
        for _ in range(limit * 3):
            error_indication, error_status, _, var_binds = await next_cmd(
                engine,
                CommunityData(olt.snmp_community, mpModel=mp_model),
                target,
                ContextData(),
                ObjectType(ObjectIdentity(current_oid)),
            )
            if error_indication:
                engine.close_dispatcher()
                raise RuntimeError(str(error_indication))
            if error_status:
                engine.close_dispatcher()
                raise RuntimeError(error_status.prettyPrint())
            if not var_binds:
                break

            stop = False
            for var_bind in var_binds:
                oid, value = var_bind
                oid_text = str(oid)
                if not oid_text.startswith(base_oid + "."):
                    stop = True
                    break
                index = oid_text.split(".")[-1]
                rows[index] = str(value)
                current_oid = oid_text
            if stop or len(rows) >= limit:
                break
        engine.close_dispatcher()
        return rows

    try:
        merged = {}
        last_error = None
        for mp_model in (1, 0):
            try:
                walked = {key: asyncio.run(_walk_oid(mp_model, oid)) for key, oid in oids.items()}
            except Exception as exc:
                last_error = str(exc)
                continue

            indexes = sorted(
                {idx for data in walked.values() for idx in data.keys()},
                key=lambda item: int(item),
            )
            rows = []
            for idx in indexes[:limit]:
                port_name = (walked["name"].get(idx) or walked["descr"].get(idx) or "").strip()
                descr = (walked["descr"].get(idx) or "").strip()
                alias = (walked["alias"].get(idx) or "").strip()
                type_value = walked["type"].get(idx, "")
                if not port_name:
                    continue
                if not _is_ethernet_uplink(port_name, f"{alias} {descr}", type_value):
                    continue
                speed_label = _speed_label(walked["speed"].get(idx, "0"), walked["high_speed"].get(idx, "0"))
                if speed_label == "-":
                    speed_label = _speed_from_mau_type(walked["mau_type"].get(idx, ""))
                inferred_type = _classify_medium(
                    port_name,
                    f"{alias} {descr}",
                    type_value,
                    speed_label,
                    walked["mau_type"].get(idx, ""),
                    walked["optical_mode"].get(idx, ""),
                    walked["optical_conn"].get(idx, ""),
                    walked["hw_optical_vendor"].get(idx, ""),
                    walked["hw_eth_negotiation"].get(idx, ""),
                )
                if not inferred_type:
                    continue
                duplex_label = _duplex_label(walked["duplex"].get(idx, ""))
                status_display = _status_label(walked["oper"].get(idx, ""))
                if status_display == "Up":
                    status_display = "UP"
                elif status_display in {"Down", "Lower layer down", "Not present"}:
                    status_display = "DOWN"
                rows.append(
                    {
                        "index": idx,
                        "port": port_name,
                        "description": _clean_description(alias, descr, port_name),
                        "type": inferred_type,
                        "admin_status": _admin_label(walked["admin"].get(idx, "")),
                        "oper_status": status_display,
                        "speed": speed_label,
                        "negotiation": _autoneg_label(walked["autoneg"].get(idx, "")),
                        "mtu": walked["mtu"].get(idx, "-"),
                        "in_octets": walked["in_octets"].get(idx, "0"),
                        "out_octets": walked["out_octets"].get(idx, "0"),
                        "pvid_untag": "-",
                        "tagged_vlans": "-",
                    }
                )
            merged["rows"] = rows
            merged["status"] = f"SNMP interfaces fetched: {len(rows)}"
            return merged

        result["status"] = f"SNMP interface fetch failed: {last_error or 'no response'}"
        return result
    except Exception as exc:
        result["status"] = f"SNMP interface fetch failed: {exc}"
        return result


def fetch_snmp_onu_live_traffic(olt, slot, port, *, frame=0, ifname_limit=2048):
    result = {
        "ok": False,
        "status": "SNMP live traffic unavailable",
        "port_name": f"GPON {int(frame)}/{int(slot)}/{int(port)}",
        "if_index": "",
        "sample_time": timezone.now().isoformat(),
        "counters": {
            "in_octets": "0",
            "out_octets": "0",
            "in_packets": "0",
            "out_packets": "0",
        },
    }
    try:
        from pysnmp.hlapi.asyncio import (  # type: ignore
            CommunityData,
            ContextData,
            ObjectIdentity,
            ObjectType,
            SnmpEngine,
            UdpTransportTarget,
            get_cmd,
            next_cmd,
        )
    except Exception:
        result["status"] = "pysnmp not installed"
        return result

    cache_key = (int(olt.pk), int(frame), int(slot), int(port))
    target_ifname = f"GPON {int(frame)}/{int(slot)}/{int(port)}".upper()

    def _normalize_ifname(value):
        text = str(value or "").strip().strip('"').upper()
        return re.sub(r"\s+", " ", text)

    def _pick_first_numeric(*values):
        for value in values:
            text = str(value or "").strip()
            if text in {"18446744073709551615", "4294967295"}:
                continue
            if text.isdigit():
                return text
        return "0"

    async def _walk_ifname(mp_model):
        rows = {}
        target = await UdpTransportTarget.create(
            (olt.ip_address, olt.snmp_port),
            timeout=1.2,
            retries=1,
        )
        engine = SnmpEngine()
        base_oid = "1.3.6.1.2.1.31.1.1.1.1"
        current_oid = base_oid
        for _ in range(ifname_limit):
            error_indication, error_status, _, var_binds = await next_cmd(
                engine,
                CommunityData(olt.snmp_community, mpModel=mp_model),
                target,
                ContextData(),
                ObjectType(ObjectIdentity(current_oid)),
            )
            if error_indication:
                engine.close_dispatcher()
                raise RuntimeError(str(error_indication))
            if error_status:
                engine.close_dispatcher()
                raise RuntimeError(error_status.prettyPrint())
            if not var_binds:
                break
            stop = False
            for oid, value in var_binds:
                oid_text = str(oid)
                if not oid_text.startswith(base_oid + "."):
                    stop = True
                    break
                rows[oid_text.split(".")[-1]] = str(value)
                current_oid = oid_text
            if stop:
                break
        engine.close_dispatcher()
        return rows

    async def _get_port_counters(mp_model, if_index):
        target = await UdpTransportTarget.create(
            (olt.ip_address, olt.snmp_port),
            timeout=1.2,
            retries=1,
        )
        base = str(if_index).strip()
        return await get_cmd(
            SnmpEngine(),
            CommunityData(olt.snmp_community, mpModel=mp_model),
            target,
            ContextData(),
            ObjectType(ObjectIdentity(f"1.3.6.1.2.1.31.1.1.1.6.{base}")),   # ifHCInOctets
            ObjectType(ObjectIdentity(f"1.3.6.1.2.1.31.1.1.1.10.{base}")),  # ifHCOutOctets
            ObjectType(ObjectIdentity(f"1.3.6.1.2.1.31.1.1.1.7.{base}")),   # ifHCInUcastPkts
            ObjectType(ObjectIdentity(f"1.3.6.1.2.1.31.1.1.1.11.{base}")),  # ifHCOutUcastPkts
            ObjectType(ObjectIdentity(f"1.3.6.1.2.1.2.2.1.10.{base}")),     # ifInOctets fallback
            ObjectType(ObjectIdentity(f"1.3.6.1.2.1.2.2.1.16.{base}")),     # ifOutOctets fallback
            ObjectType(ObjectIdentity(f"1.3.6.1.2.1.2.2.1.11.{base}")),     # ifInUcastPkts fallback
            ObjectType(ObjectIdentity(f"1.3.6.1.2.1.2.2.1.17.{base}")),     # ifOutUcastPkts fallback
        )

    def _resolve_if_index():
        with _ONU_TRAFFIC_IFINDEX_CACHE_LOCK:
            cached = _ONU_TRAFFIC_IFINDEX_CACHE.get(cache_key)
            if cached:
                return cached
        last_error = ""
        for mp_model in (1, 0):
            try:
                walked = asyncio.run(_walk_ifname(mp_model))
                for idx, if_name in walked.items():
                    if _normalize_ifname(if_name) == target_ifname:
                        with _ONU_TRAFFIC_IFINDEX_CACHE_LOCK:
                            _ONU_TRAFFIC_IFINDEX_CACHE[cache_key] = str(idx)
                        return str(idx)
            except Exception as exc:
                last_error = str(exc)
        result["status"] = f"SNMP traffic ifIndex lookup failed: {last_error or 'no response'}"
        return ""

    if_index = _resolve_if_index()
    if not if_index:
        return result

    result["if_index"] = if_index
    last_error = ""
    for mp_model in (1, 0):
        try:
            error_indication, error_status, _, var_binds = asyncio.run(_get_port_counters(mp_model, if_index))
            if error_indication:
                last_error = str(error_indication)
                continue
            if error_status:
                last_error = error_status.prettyPrint()
                continue
            values = [str(var_bind[1]) for var_bind in var_binds]
            result["counters"] = {
                "in_octets": _pick_first_numeric(values[0], values[4]),
                "out_octets": _pick_first_numeric(values[1], values[5]),
                "in_packets": _pick_first_numeric(values[2], values[6]),
                "out_packets": _pick_first_numeric(values[3], values[7]),
            }
            result["ok"] = True
            result["status"] = "SNMP live traffic fetched"
            result["sample_time"] = timezone.now().isoformat()
            return result
        except Exception as exc:
            last_error = str(exc)
    result["status"] = f"SNMP live traffic fetch failed: {last_error or 'no response'}"
    return result


def _snmp_normalize_ifname(value):
    text = str(value or "").strip().strip('"').upper()
    return re.sub(r"\s+", " ", text)


def _snmp_walk_rows(olt, base_oid, *, limit=4096, mp_model=1):
    from pysnmp.hlapi.asyncio import (  # type: ignore
        CommunityData,
        ContextData,
        ObjectIdentity,
        ObjectType,
        SnmpEngine,
        UdpTransportTarget,
        next_cmd,
    )

    async def _walk():
        rows = {}
        target = await UdpTransportTarget.create(
            (olt.ip_address, olt.snmp_port),
            timeout=1.2,
            retries=1,
        )
        engine = SnmpEngine()
        current_oid = base_oid
        for _ in range(limit):
            error_indication, error_status, _, var_binds = await next_cmd(
                engine,
                CommunityData(olt.snmp_community, mpModel=mp_model),
                target,
                ContextData(),
                ObjectType(ObjectIdentity(current_oid)),
                lexicographicMode=False,
            )
            if error_indication:
                engine.close_dispatcher()
                raise RuntimeError(str(error_indication))
            if error_status:
                engine.close_dispatcher()
                raise RuntimeError(error_status.prettyPrint())
            if not var_binds:
                break
            stop = False
            for oid, value in var_binds:
                oid_text = str(oid)
                if not oid_text.startswith(base_oid + "."):
                    stop = True
                    break
                rows[oid_text] = str(value)
                current_oid = oid_text
            if stop:
                break
        engine.close_dispatcher()
        return rows

    return _run_asyncio_sync(_walk())


def _snmp_get_value(olt, oid, *, mp_model=1):
    from pysnmp.hlapi.asyncio import (  # type: ignore
        CommunityData,
        ContextData,
        ObjectIdentity,
        ObjectType,
        SnmpEngine,
        UdpTransportTarget,
        get_cmd,
    )

    async def _get():
        target = await UdpTransportTarget.create(
            (olt.ip_address, olt.snmp_port),
            timeout=1.2,
            retries=1,
        )
        return await get_cmd(
            SnmpEngine(),
            CommunityData(olt.snmp_community, mpModel=mp_model),
            target,
            ContextData(),
            ObjectType(ObjectIdentity(oid)),
        )

    return _run_asyncio_sync(_get())


def _snmp_set_value(olt, oid, value, *, value_type="Integer", mp_model=1):
    from pysnmp.hlapi.asyncio import (  # type: ignore
        CommunityData,
        ContextData,
        Integer,
        ObjectIdentity,
        ObjectType,
        OctetString,
        SnmpEngine,
        UdpTransportTarget,
        set_cmd,
    )

    type_map = {
        "Integer": Integer,
        "OctetString": OctetString,
    }
    caster = type_map.get(value_type, Integer)

    async def _set():
        target = await UdpTransportTarget.create(
            (olt.ip_address, olt.snmp_port),
            timeout=1.2,
            retries=0,
        )
        return await set_cmd(
            SnmpEngine(),
            CommunityData(olt.snmp_write_community or olt.snmp_community, mpModel=mp_model),
            target,
            ContextData(),
            ObjectType(ObjectIdentity(oid), caster(value)),
        )

    return _run_asyncio_sync(_set())


def _resolve_snmp_gpon_ifindex(olt, slot, port, *, frame=0, ifname_limit=4096):
    cache_key = (int(olt.pk), int(frame), int(slot), int(port))
    target_ifname = f"GPON {int(frame)}/{int(slot)}/{int(port)}".upper()
    with _ONU_TRAFFIC_IFINDEX_CACHE_LOCK:
        cached = _ONU_TRAFFIC_IFINDEX_CACHE.get(cache_key)
        if cached:
            return str(cached)
    last_error = ""
    for mp_model in (1, 0):
        try:
            walked = _snmp_walk_rows(olt, "1.3.6.1.2.1.31.1.1.1.1", limit=ifname_limit, mp_model=mp_model)
            for oid_text, if_name in walked.items():
                idx = oid_text.split(".")[-1]
                if _snmp_normalize_ifname(if_name) == target_ifname:
                    with _ONU_TRAFFIC_IFINDEX_CACHE_LOCK:
                        _ONU_TRAFFIC_IFINDEX_CACHE[cache_key] = str(idx)
                    return str(idx)
        except Exception as exc:
            last_error = str(exc)
    return ""


def _format_snmp_distance_value(raw_value):
    text = str(raw_value or "").strip()
    if text in {"", "-1", "2147483647", "4294967295"}:
        return ""
    try:
        value = int(text)
    except (TypeError, ValueError):
        return ""
    return str(value)


def fetch_single_onu_snmp_distance(olt, slot, port, ont_id, *, frame=0):
    result = {
        "status": "SNMP ONU distance unavailable",
        "ont_distance_m": "",
    }
    try:
        if_index = _resolve_snmp_gpon_ifindex(olt, slot, port, frame=frame)
        if not if_index:
            result["status"] = "SNMP ONU distance ifIndex lookup failed"
            return result
        last_error = ""
        base_oid = "1.3.6.1.4.1.2011.6.128.1.1.2.46.1.20"
        target_oid = f"{base_oid}.{int(if_index)}.{int(ont_id)}"
        for mp_model in (1, 0):
            try:
                error_indication, error_status, _, var_binds = _snmp_get_value(olt, target_oid, mp_model=mp_model)
                if error_indication:
                    last_error = str(error_indication)
                    continue
                if error_status:
                    last_error = error_status.prettyPrint()
                    continue
                if not var_binds:
                    continue
                result["ont_distance_m"] = _format_snmp_distance_value(var_binds[0][1])
                result["status"] = "SNMP ONU distance fetched"
                return result
            except Exception as exc:
                last_error = str(exc)
        result["status"] = f"SNMP ONU distance fetch failed: {last_error or 'no response'}"
        return result
    except Exception as exc:
        result["status"] = f"SNMP ONU distance fetch failed: {exc}"
        return result


def execute_onu_snmp_control_action(olt, slot, port, ont_id, action, *, frame=0):
    result = {
        "ok": False,
        "message": "SNMP ONU action unavailable",
        "oid": "",
        "value": "",
    }
    action_key = str(action or "").strip().lower()
    action_map = {
        "enable": {
            "oid_base": "1.3.6.1.4.1.2011.6.128.1.1.2.46.1.1",
            "value": 1,
            "label": "Enable ONU",
        },
        "disable": {
            "oid_base": "1.3.6.1.4.1.2011.6.128.1.1.2.46.1.1",
            "value": 2,
            "label": "Disable ONU",
        },
        "restart": {
            "oid_base": "1.3.6.1.4.1.2011.6.128.1.1.2.46.1.3",
            "value": 1,
            "label": "Restart ONU",
        },
        "reset": {
            "oid_base": "1.3.6.1.4.1.2011.6.128.1.1.2.46.1.2",
            "value": 1,
            "label": "Reset ONU",
        },
    }
    config = action_map.get(action_key)
    if not config:
        result["message"] = "Unsupported SNMP ONU action."
        return result
    if not str(getattr(olt, "snmp_write_community", "") or "").strip():
        result["message"] = "SNMP write community is not configured."
        return result
    try:
        if_index = _resolve_snmp_gpon_ifindex(olt, slot, port, frame=frame)
        if not if_index:
            result["message"] = "SNMP ifIndex lookup failed."
            return result
        target_oid = f"{config['oid_base']}.{int(if_index)}.{int(ont_id)}"
        result["oid"] = target_oid
        result["value"] = str(config["value"])
        last_error = ""
        for mp_model in (1, 0):
            try:
                error_indication, error_status, _, _ = _snmp_set_value(
                    olt,
                    target_oid,
                    config["value"],
                    value_type="Integer",
                    mp_model=mp_model,
                )
                if error_indication:
                    last_error = str(error_indication)
                    continue
                if error_status:
                    last_error = error_status.prettyPrint()
                    continue
                result["ok"] = True
                result["message"] = f"{config['label']} command sent."
                return result
            except Exception as exc:
                last_error = str(exc)
        result["message"] = f"{config['label']} failed: {last_error or 'no response'}"
        return result
    except Exception as exc:
        result["message"] = f"SNMP ONU action failed: {exc}"
        return result


def fetch_olt_snmp_distance_map(olt, *, ifname_limit=4096, distance_limit=16384):
    result = {
        "status": "SNMP ONU distance map unavailable",
        "items": {},
    }
    try:
        base_ifname_oid = "1.3.6.1.2.1.31.1.1.1.1"
        base_distance_oid = "1.3.6.1.4.1.2011.6.128.1.1.2.46.1.20"
        last_error = ""
        for mp_model in (1, 0):
            try:
                ifname_rows = _snmp_walk_rows(olt, base_ifname_oid, limit=ifname_limit, mp_model=mp_model)
                distance_rows = _snmp_walk_rows(olt, base_distance_oid, limit=distance_limit, mp_model=mp_model)
                break
            except Exception as exc:
                last_error = str(exc)
        else:
            result["status"] = f"SNMP ONU distance map fetch failed: {last_error or 'no response'}"
            return result

        gpon_indexes = {}
        for oid_text, if_name in (ifname_rows or {}).items():
            idx = oid_text.split(".")[-1]
            normalized = _snmp_normalize_ifname(if_name)
            match = re.search(r"GPON\s+(\d+)\s*/\s*(\d+)\s*/\s*(\d+)", normalized)
            if not match:
                continue
            frame, slot, port = [int(part) for part in match.groups()]
            gpon_indexes[str(idx)] = (frame, slot, port)
            cache_key = (int(olt.pk), frame, slot, port)
            with _ONU_TRAFFIC_IFINDEX_CACHE_LOCK:
                _ONU_TRAFFIC_IFINDEX_CACHE[cache_key] = str(idx)

        items = {}
        for oid_text, raw_value in (distance_rows or {}).items():
            suffix = oid_text[len(base_distance_oid) + 1 :]
            parts = suffix.split(".")
            if len(parts) < 2:
                continue
            if_index = str(parts[-2]).strip()
            ont_id = int(parts[-1])
            fsp = gpon_indexes.get(if_index)
            if not fsp:
                continue
            _, slot, port = fsp
            formatted = _format_snmp_distance_value(raw_value)
            if formatted:
                items[(slot, port, ont_id)] = formatted
        result["items"] = items
        result["status"] = f"SNMP ONU distance map fetched: {len(items)}"
        return result
    except Exception as exc:
        result["status"] = f"SNMP ONU distance map fetch failed: {exc}"
        return result


def _map_snmp_onu_status(control_value, run_value):
    control_text = str(control_value or "").strip()
    run_text = str(run_value or "").strip()
    if control_text == "1" or run_text == "3":
        return "online"
    if control_text == "2" or run_text == "1":
        return "offline"
    return ""


def fetch_olt_snmp_status_map(olt, *, ifname_limit=4096, status_limit=16384):
    result = {
        "status": "SNMP ONU status map unavailable",
        "items": {},
    }
    try:
        base_ifname_oid = "1.3.6.1.2.1.31.1.1.1.1"
        base_control_oid = "1.3.6.1.4.1.2011.6.128.1.1.2.46.1.15"
        base_run_oid = "1.3.6.1.4.1.2011.6.128.1.1.2.46.1.16"
        last_error = ""
        for mp_model in (1, 0):
            try:
                ifname_rows = _snmp_walk_rows(olt, base_ifname_oid, limit=ifname_limit, mp_model=mp_model)
                control_rows = _snmp_walk_rows(olt, base_control_oid, limit=status_limit, mp_model=mp_model)
                run_rows = _snmp_walk_rows(olt, base_run_oid, limit=status_limit, mp_model=mp_model)
                break
            except Exception as exc:
                last_error = str(exc)
        else:
            result["status"] = f"SNMP ONU status map fetch failed: {last_error or 'no response'}"
            return result

        gpon_indexes = {}
        for oid_text, if_name in (ifname_rows or {}).items():
            idx = oid_text.split(".")[-1]
            normalized = _snmp_normalize_ifname(if_name)
            match = re.search(r"GPON\s+(\d+)\s*/\s*(\d+)\s*/\s*(\d+)", normalized)
            if not match:
                continue
            frame, slot, port = [int(part) for part in match.groups()]
            gpon_indexes[str(idx)] = (frame, slot, port)
            cache_key = (int(olt.pk), frame, slot, port)
            with _ONU_TRAFFIC_IFINDEX_CACHE_LOCK:
                _ONU_TRAFFIC_IFINDEX_CACHE[cache_key] = str(idx)

        run_by_key = {}
        for oid_text, raw_value in (run_rows or {}).items():
            suffix = oid_text[len(base_run_oid) + 1 :]
            parts = suffix.split(".")
            if len(parts) < 2:
                continue
            run_by_key[(str(parts[-2]).strip(), int(parts[-1]))] = str(raw_value or "").strip()

        items = {}
        for oid_text, raw_value in (control_rows or {}).items():
            suffix = oid_text[len(base_control_oid) + 1 :]
            parts = suffix.split(".")
            if len(parts) < 2:
                continue
            if_index = str(parts[-2]).strip()
            ont_id = int(parts[-1])
            fsp = gpon_indexes.get(if_index)
            if not fsp:
                continue
            _, slot, port = fsp
            status_value = _map_snmp_onu_status(raw_value, run_by_key.get((if_index, ont_id)))
            if status_value:
                items[(slot, port, ont_id)] = status_value
        result["items"] = items
        result["status"] = f"SNMP ONU status map fetched: {len(items)}"
        return result
    except Exception as exc:
        result["status"] = f"SNMP ONU status map fetch failed: {exc}"
        return result


def fetch_snmp_pon_aggregate_counters(olt, ifname_limit=4096):
    result = {
        "ok": False,
        "status": "SNMP PON traffic unavailable",
        "in_octets": 0,
        "out_octets": 0,
        "in_packets": 0,
        "out_packets": 0,
        "ports": 0,
        "sample_time": timezone.now(),
    }
    try:
        from pysnmp.hlapi.asyncio import (  # type: ignore
            CommunityData,
            ContextData,
            ObjectIdentity,
            ObjectType,
            SnmpEngine,
            UdpTransportTarget,
            next_cmd,
        )
    except Exception:
        result["status"] = "pysnmp not installed"
        return result

    oids = {
        "name": "1.3.6.1.2.1.31.1.1.1.1",
        "in_hc_octets": "1.3.6.1.2.1.31.1.1.1.6",
        "out_hc_octets": "1.3.6.1.2.1.31.1.1.1.10",
        "in_hc_packets": "1.3.6.1.2.1.31.1.1.1.7",
        "out_hc_packets": "1.3.6.1.2.1.31.1.1.1.11",
        "in_octets": "1.3.6.1.2.1.2.2.1.10",
        "out_octets": "1.3.6.1.2.1.2.2.1.16",
        "in_packets": "1.3.6.1.2.1.2.2.1.11",
        "out_packets": "1.3.6.1.2.1.2.2.1.17",
    }

    def _clean_counter(value):
        text = str(value or "").strip()
        if text in {"", "18446744073709551615", "4294967295"}:
            return 0
        try:
            return int(text)
        except (TypeError, ValueError):
            return 0

    async def _walk_oid(mp_model, base_oid):
        rows = {}
        target = await UdpTransportTarget.create(
            (olt.ip_address, olt.snmp_port),
            timeout=1.2,
            retries=1,
        )
        engine = SnmpEngine()
        current_oid = base_oid
        for _ in range(ifname_limit):
            error_indication, error_status, _, var_binds = await next_cmd(
                engine,
                CommunityData(olt.snmp_community, mpModel=mp_model),
                target,
                ContextData(),
                ObjectType(ObjectIdentity(current_oid)),
            )
            if error_indication:
                engine.close_dispatcher()
                raise RuntimeError(str(error_indication))
            if error_status:
                engine.close_dispatcher()
                raise RuntimeError(error_status.prettyPrint())
            if not var_binds:
                break
            stop = False
            for oid, value in var_binds:
                oid_text = str(oid)
                if not oid_text.startswith(base_oid + "."):
                    stop = True
                    break
                rows[oid_text.split(".")[-1]] = str(value)
                current_oid = oid_text
            if stop:
                break
        engine.close_dispatcher()
        return rows

    last_error = ""
    for mp_model in (1, 0):
        try:
            walked = {key: asyncio.run(_walk_oid(mp_model, oid)) for key, oid in oids.items()}
            gpon_indexes = []
            for idx, if_name in walked["name"].items():
                normalized = str(if_name or "").strip().strip('"').upper()
                if normalized.startswith("GPON "):
                    gpon_indexes.append(idx)
            if not gpon_indexes:
                result["status"] = "No GPON interfaces found in SNMP interface table."
                return result
            result["in_octets"] = sum(_clean_counter(walked["in_hc_octets"].get(idx)) or _clean_counter(walked["in_octets"].get(idx)) for idx in gpon_indexes)
            result["out_octets"] = sum(_clean_counter(walked["out_hc_octets"].get(idx)) or _clean_counter(walked["out_octets"].get(idx)) for idx in gpon_indexes)
            result["in_packets"] = sum(_clean_counter(walked["in_hc_packets"].get(idx)) or _clean_counter(walked["in_packets"].get(idx)) for idx in gpon_indexes)
            result["out_packets"] = sum(_clean_counter(walked["out_hc_packets"].get(idx)) or _clean_counter(walked["out_packets"].get(idx)) for idx in gpon_indexes)
            result["ports"] = len(gpon_indexes)
            result["sample_time"] = timezone.now()
            result["status"] = f"SNMP PON traffic fetched: {len(gpon_indexes)} ports"
            result["ok"] = True
            return result
        except Exception as exc:
            last_error = str(exc)
    result["status"] = f"SNMP PON traffic fetch failed: {last_error or 'no response'}"
    return result


def fetch_snmp_pon_port_counters(olt, ifname_limit=4096):
    result = {
        "ok": False,
        "status": "SNMP PON port traffic unavailable",
        "rows": [],
        "sample_time": timezone.now(),
    }
    try:
        from pysnmp.hlapi.asyncio import (  # type: ignore
            CommunityData,
            ContextData,
            ObjectIdentity,
            ObjectType,
            SnmpEngine,
            UdpTransportTarget,
            next_cmd,
        )
    except Exception:
        result["status"] = "pysnmp not installed"
        return result

    oids = {
        "name": "1.3.6.1.2.1.31.1.1.1.1",
        "in_hc_octets": "1.3.6.1.2.1.31.1.1.1.6",
        "out_hc_octets": "1.3.6.1.2.1.31.1.1.1.10",
        "in_hc_packets": "1.3.6.1.2.1.31.1.1.1.7",
        "out_hc_packets": "1.3.6.1.2.1.31.1.1.1.11",
        "in_octets": "1.3.6.1.2.1.2.2.1.10",
        "out_octets": "1.3.6.1.2.1.2.2.1.16",
        "in_packets": "1.3.6.1.2.1.2.2.1.11",
        "out_packets": "1.3.6.1.2.1.2.2.1.17",
    }

    def _clean_counter(value):
        text = str(value or "").strip()
        if text in {"", "18446744073709551615", "4294967295"}:
            return 0
        try:
            return int(text)
        except (TypeError, ValueError):
            return 0

    async def _walk_oid(mp_model, base_oid):
        rows = {}
        target = await UdpTransportTarget.create((olt.ip_address, olt.snmp_port), timeout=1.2, retries=1)
        engine = SnmpEngine()
        current_oid = base_oid
        for _ in range(ifname_limit):
            error_indication, error_status, _, var_binds = await next_cmd(
                engine,
                CommunityData(olt.snmp_community, mpModel=mp_model),
                target,
                ContextData(),
                ObjectType(ObjectIdentity(current_oid)),
            )
            if error_indication:
                engine.close_dispatcher()
                raise RuntimeError(str(error_indication))
            if error_status:
                engine.close_dispatcher()
                raise RuntimeError(error_status.prettyPrint())
            if not var_binds:
                break
            stop = False
            for oid, value in var_binds:
                oid_text = str(oid)
                if not oid_text.startswith(base_oid + "."):
                    stop = True
                    break
                rows[oid_text.split(".")[-1]] = str(value)
                current_oid = oid_text
            if stop:
                break
        engine.close_dispatcher()
        return rows

    last_error = ""
    for mp_model in (1, 0):
        try:
            walked = {key: asyncio.run(_walk_oid(mp_model, oid)) for key, oid in oids.items()}
            rows = []
            for idx, if_name in walked["name"].items():
                normalized = str(if_name or "").strip().strip('"').upper()
                match = re.match(r"^GPON\s+(\d+)\/(\d+)\/(\d+)$", normalized)
                if not match:
                    continue
                frame, slot, port = [int(part) for part in match.groups()]
                rows.append({
                    "if_index": str(idx),
                    "frame": frame,
                    "slot": slot,
                    "port": port,
                    "port_name": normalized,
                    "in_octets": _clean_counter(walked["in_hc_octets"].get(idx)) or _clean_counter(walked["in_octets"].get(idx)),
                    "out_octets": _clean_counter(walked["out_hc_octets"].get(idx)) or _clean_counter(walked["out_octets"].get(idx)),
                    "in_packets": _clean_counter(walked["in_hc_packets"].get(idx)) or _clean_counter(walked["in_packets"].get(idx)),
                    "out_packets": _clean_counter(walked["out_hc_packets"].get(idx)) or _clean_counter(walked["out_packets"].get(idx)),
                })
            result["rows"] = rows
            result["sample_time"] = timezone.now()
            result["status"] = f"SNMP PON port traffic fetched: {len(rows)} ports"
            result["ok"] = True
            return result
        except Exception as exc:
            last_error = str(exc)
    result["status"] = f"SNMP PON port traffic fetch failed: {last_error or 'no response'}"
    return result


def fetch_snmp_pon_port_states(olt, limit=256):
    result = {
        "status": "SNMP PON state unavailable",
        "ports": {},
    }
    try:
        from pysnmp.hlapi.asyncio import (  # type: ignore
            CommunityData,
            ContextData,
            ObjectIdentity,
            ObjectType,
            SnmpEngine,
            UdpTransportTarget,
            next_cmd,
        )
    except Exception:
        result["status"] = "pysnmp not installed, PON state unavailable"
        return result

    oids = {
        "name": "1.3.6.1.2.1.31.1.1.1.1",
        "descr": "1.3.6.1.2.1.2.2.1.2",
        "admin": "1.3.6.1.2.1.2.2.1.7",
        "oper": "1.3.6.1.2.1.2.2.1.8",
        "type": "1.3.6.1.2.1.2.2.1.3",
        "entity_name": "1.3.6.1.2.1.47.1.1.1.1.7",
        "entity_descr": "1.3.6.1.2.1.47.1.1.1.1.2",
        "tx": "1.3.6.1.4.1.2011.5.25.31.1.1.3.1.9",
    }

    def _admin_label(value):
        mapping = {"1": "Enabled", "2": "Disabled", "3": "Testing"}
        return mapping.get(str(value).strip(), str(value).strip() or "-")

    def _oper_label(value):
        mapping = {
            "1": "Up / Autofind",
            "2": "Down / Autofind",
            "3": "Testing",
            "4": "Unknown",
            "5": "Dormant",
            "6": "Down / Not present",
            "7": "Down / Lower layer",
        }
        return mapping.get(str(value).strip(), "Unknown")

    def _parse_fsp(text):
        match = re.search(r"(\d+)\s*/\s*(\d+)\s*/\s*(\d+)", str(text or ""))
        if not match:
            return None
        return int(match.group(2)), int(match.group(3))

    def _format_entity_dbm(raw_value):
        try:
            value = int(str(raw_value).strip())
        except (TypeError, ValueError):
            return ""
        if value in (2147483647, -2147483648):
            return ""
        return f"{value / 100:.2f} dBm"

    async def _walk_oid(mp_model, base_oid):
        rows = {}
        target = await UdpTransportTarget.create((olt.ip_address, olt.snmp_port), timeout=1.2, retries=1)
        engine = SnmpEngine()
        current_oid = base_oid
        for _ in range(limit * 3):
            error_indication, error_status, _, var_binds = await next_cmd(
                engine,
                CommunityData(olt.snmp_community, mpModel=mp_model),
                target,
                ContextData(),
                ObjectType(ObjectIdentity(current_oid)),
            )
            if error_indication:
                engine.close_dispatcher()
                raise RuntimeError(str(error_indication))
            if error_status:
                engine.close_dispatcher()
                raise RuntimeError(error_status.prettyPrint())
            if not var_binds:
                break
            stop = False
            for var_bind in var_binds:
                oid, value = var_bind
                oid_text = str(oid)
                if not oid_text.startswith(base_oid + "."):
                    stop = True
                    break
                index = oid_text.split(".")[-1]
                rows[index] = str(value)
                current_oid = oid_text
            if stop or len(rows) >= limit:
                break
        engine.close_dispatcher()
        return rows

    try:
        last_error = None
        for mp_model in (1, 0):
            try:
                walked = {key: asyncio.run(_walk_oid(mp_model, oid)) for key, oid in oids.items()}
            except Exception as exc:
                last_error = str(exc)
                continue
            port_map = {}
            indexes = sorted({idx for data in walked.values() for idx in data.keys()}, key=lambda item: int(item))
            for idx in indexes[:limit]:
                name = (walked["name"].get(idx) or "").strip()
                descr = (walked["descr"].get(idx) or "").strip()
                joined = f"{name} {descr}".lower()
                if not any(token in joined for token in ("gpon", "pon")):
                    continue
                fsp = _parse_fsp(name) or _parse_fsp(descr)
                if not fsp:
                    continue
                port_map[fsp] = {
                    "admin_state": _admin_label(walked["admin"].get(idx, "")),
                    "status": _oper_label(walked["oper"].get(idx, "")),
                }

            tx_best = {}
            tx_indexes = set(walked["tx"].keys()) | set(walked["entity_name"].keys()) | set(walked["entity_descr"].keys())
            for idx in tx_indexes:
                raw_tx = walked["tx"].get(idx)
                if raw_tx in (None, ""):
                    continue
                entity_name = (walked["entity_name"].get(idx) or "").strip()
                entity_descr = (walked["entity_descr"].get(idx) or "").strip()
                text = f"{entity_name} {entity_descr}"
                lowered = text.lower()
                if not any(token in lowered for token in ("gpon", "pon", "optical", "sfp")):
                    continue
                fsp = _parse_fsp(entity_name) or _parse_fsp(entity_descr)
                if not fsp:
                    continue
                score = 0
                if "gpon" in lowered or "pon" in lowered:
                    score += 3
                if "sfp" in lowered or "optical" in lowered:
                    score += 2
                if re.search(rf"\b0\s*/\s*{fsp[0]}\s*/\s*{fsp[1]}\b", lowered):
                    score += 4
                current = tx_best.get(fsp)
                if current is None or score >= current[0]:
                    tx_best[fsp] = (score, _format_entity_dbm(raw_tx))

            for fsp, (_, formatted_tx) in tx_best.items():
                if not formatted_tx:
                    continue
                port_map.setdefault(fsp, {})
                port_map[fsp]["sfp_tx"] = formatted_tx

            result["ports"] = port_map
            result["status"] = f"SNMP PON states fetched: {len(port_map)}"
            return result
        result["status"] = f"SNMP PON state fetch failed: {last_error or 'no response'}"
        return result
    except Exception as exc:
        result["status"] = f"SNMP PON state fetch failed: {exc}"
        return result


def fetch_onu_snmp_signal(olt, slot, port, ont_id, limit=512):
    result = {
        "status": "SNMP ONU signal unavailable",
        "onu_rx": "--",
        "olt_rx": "--",
    }
    try:
        from pysnmp.hlapi.asyncio import (  # type: ignore
            CommunityData,
            ContextData,
            ObjectIdentity,
            ObjectType,
            SnmpEngine,
            UdpTransportTarget,
            next_cmd,
        )
    except Exception:
        result["status"] = "pysnmp not installed"
        return result

    oids = {
        "name": "1.3.6.1.2.1.47.1.1.1.1.7",
        "descr": "1.3.6.1.2.1.47.1.1.1.1.2",
        "rx": "1.3.6.1.4.1.2011.5.25.31.1.1.3.1.8",
    }

    async def _walk_oid(mp_model, base_oid):
        rows = {}
        target = await UdpTransportTarget.create(
            (olt.ip_address, olt.snmp_port),
            timeout=1.2,
            retries=1,
        )
        engine = SnmpEngine()
        current_oid = base_oid
        for _ in range(limit):
            error_indication, error_status, _, var_binds = await next_cmd(
                engine,
                CommunityData(olt.snmp_community, mpModel=mp_model),
                target,
                ContextData(),
                ObjectType(ObjectIdentity(current_oid)),
            )
            if error_indication:
                engine.close_dispatcher()
                raise RuntimeError(str(error_indication))
            if error_status:
                engine.close_dispatcher()
                raise RuntimeError(error_status.prettyPrint())
            if not var_binds:
                break
            stop = False
            for oid, value in var_binds:
                oid_text = str(oid)
                if not oid_text.startswith(base_oid + "."):
                    stop = True
                    break
                rows[oid_text.split(".")[-1]] = str(value)
                current_oid = oid_text
            if stop:
                break
        engine.close_dispatcher()
        return rows

    def _score_entity(text):
        lowered = str(text or "").lower()
        score = 0
        if f"0/{slot}/{port}" in lowered or f"{slot}/{port}" in lowered:
            score += 5
        if f":{ont_id}" in lowered or f" {ont_id}" in lowered:
            score += 4
        if any(token in lowered for token in ("ont", "onu")):
            score += 3
        if any(token in lowered for token in ("rx", "optical", "power")):
            score += 1
        return score

    def _format_dbm(raw_value):
        try:
            value = int(str(raw_value).strip())
        except (TypeError, ValueError):
            return "--"
        if value in (2147483647, -2147483648):
            return "--"
        return f"{value / 100:.2f} dBm"

    try:
        last_error = None
        for mp_model in (1, 0):
            try:
                walked = {key: asyncio.run(_walk_oid(mp_model, oid)) for key, oid in oids.items()}
            except Exception as exc:
                last_error = str(exc)
                continue

            best_onu = None
            best_olt = None
            best_onu_score = -1
            best_olt_score = -1

            all_indexes = set(walked["rx"].keys()) | set(walked["name"].keys()) | set(walked["descr"].keys())
            for idx in all_indexes:
                text = f"{walked['name'].get(idx, '')} {walked['descr'].get(idx, '')}"
                lowered = text.lower()
                if not walked["rx"].get(idx):
                    continue
                score = _score_entity(text)
                if score > best_onu_score and any(token in lowered for token in ("ont", "onu")):
                    best_onu_score = score
                    best_onu = idx
                if score > best_olt_score and any(token in lowered for token in ("olt", "pon", "gpon")):
                    best_olt_score = score
                    best_olt = idx

            result["onu_rx"] = _format_dbm(walked["rx"].get(best_onu)) if best_onu else "--"
            result["olt_rx"] = _format_dbm(walked["rx"].get(best_olt)) if best_olt else "--"
            result["status"] = "SNMP ONU signal fetched"
            return result

        result["status"] = f"SNMP ONU signal fetch failed: {last_error or 'no response'}"
        return result
    except Exception as exc:
        result["status"] = f"SNMP ONU signal fetch failed: {exc}"
        return result


def _normalize_interface_name(value):
    text = re.sub(r"\s+", "", str(value or "")).lower()
    text = text.replace("gigabitethernet", "ethernet")
    text = text.replace("fastethernet", "ethernet")
    text = text.replace("ten-gigabitethernet", "xge")
    return text


def _parse_frame_slot_port(port_name):
    match = re.search(r"(\d+)\s*/\s*(\d+)\s*/\s*(\d+)", str(port_name or ""))
    if not match:
        match = re.search(r"(\d+)\s*/\s*(\d+)", str(port_name or ""))
        if not match:
            return None
        return match.group(1), match.group(2), None
    return match.group(1), match.group(2), match.group(3)


def _interface_name_variants(port_name):
    raw = str(port_name or "").strip()
    compact = re.sub(r"\s+", "", raw)
    lowered = compact.lower()
    variants = [raw, compact]
    if lowered.startswith("ethernet"):
        suffix = compact[len("ethernet") :]
        variants.extend(
            [
                f"ethernet {suffix}",
                f"display port state {suffix}",
                f"display interface ethernet {suffix}",
                f"display current-configuration interface ethernet {suffix}",
            ]
        )
    elif lowered.startswith("xge"):
        suffix = compact[len("xge") :]
        variants.extend(
            [
                f"xge {suffix}",
                f"display port state {suffix}",
                f"display interface xge {suffix}",
                f"display current-configuration interface xge {suffix}",
            ]
        )
    fsp = _parse_frame_slot_port(compact)
    if fsp:
        frame, slot, port = fsp
        if port is not None:
            variants.append(f"display port state {frame}/{slot}/{port}")
        variants.extend(
            [
                f"display interface giu {frame}/{slot}",
                f"display current-configuration interface giu {frame}/{slot}",
                f"display interface mcu {frame}/{slot}",
                f"display current-configuration interface mcu {frame}/{slot}",
                f"display interface scu {frame}/{slot}",
                f"display current-configuration interface scu {frame}/{slot}",
            ]
        )
    return [item for item in variants if item]


def _is_cli_error_text(text):
    lowered = str(text or "").lower()
    error_tokens = (
        "unknown command",
        "parameter error",
        "error:",
        "incomplete command",
        "unrecognized command",
    )
    return any(token in lowered for token in error_tokens)


def _format_cli_oper_status(phy, speed, duplex):
    phy_text = (phy or "").strip().lower()
    speed_text = (speed or "").strip()
    duplex_text = (duplex or "").strip()
    if phy_text in {"down", "*down", "^down", "~down", "#down", "administrativelydown"}:
        return "Down"
    if phy_text == "up":
        if speed_text and speed_text != "-" and duplex_text and duplex_text != "-":
            return f"{speed_text}-{duplex_text}"
        return "Up"
    return phy or "-"


def _parse_uplink_brief_output(output):
    parsed = {}
    for raw in (output or "").splitlines():
        line = raw.strip()
        if not line or line.lower().startswith(("interface", "phy", "port", "---")):
            continue
        parts = re.split(r"\s{2,}", line)
        if len(parts) < 2:
            continue
        iface = parts[0].strip()
        normalized = _normalize_interface_name(iface)
        if not normalized or "ethernet" not in normalized and not normalized.startswith("xge"):
            continue
        phy = parts[1].strip() if len(parts) > 1 else "-"
        negotiation = parts[2].strip() if len(parts) > 2 else "-"
        duplex = parts[3].strip() if len(parts) > 3 else "-"
        speed = parts[4].strip() if len(parts) > 4 else "-"
        parsed[normalized] = {
            "oper_status": "UP" if str(phy).strip().lower() == "up" else ("DOWN" if str(phy).strip() else "-"),
            "negotiation": "Auto" if "auto" in negotiation.lower() or negotiation.lower() in {"enable", "enabled"} else ("Manual" if negotiation and negotiation != "-" else "-"),
            "phy": phy,
            "duplex": duplex if duplex else "-",
            "speed": speed if speed else "-",
            "raw": line,
        }
    return parsed


def _parse_uplink_description(config_output, detail_output, fallback="-"):
    text = "\n".join([str(config_output or ""), str(detail_output or "")])
    match = re.search(r"(?im)^\s*description\s+(.+)$", text)
    if match:
        value = match.group(1).strip()
        if value:
            return value
    match = re.search(r"(?im)^\s*Description\s*:\s*(.+)$", text)
    if match:
        value = match.group(1).strip()
        if value:
            return value
    return fallback


def _sanitize_uplink_description(value):
    text = str(value or "").strip()
    if not text:
        return ""
    lowered = text.lower()
    junk_tokens = (
        "ma5600",
        "huawei-",
        "ethernet",
        "version",
        "v800",
        "release",
    )
    if all(token in lowered for token in ("huawei", "ethernet")):
        return ""
    if sum(token in lowered for token in junk_tokens) >= 3:
        return ""
    return text


def _sanitize_uplink_type(value, port_name=""):
    text = str(value or "").strip()
    if text in {"Optical", "Electrical"}:
        return text
    return "-"


def _parse_uplink_type(port_name, detail_output, fallback="-"):
    text = f"{port_name}\n{detail_output or ''}".lower()
    fiber_tokens = (
        "fiber",
        "optical",
        "sfp",
        "xfp",
        "1000base-x",
        "10gbase-lr",
        "10gbase-sr",
        "transceiver",
    )
    copper_tokens = (
        "copper",
        "electrical",
        "rj45",
        "1000base-t",
        "100base-t",
        "10base-t",
    )
    if any(token in text for token in fiber_tokens):
        return "Optical"
    if any(token in text for token in copper_tokens):
        return "Electrical"
    return fallback


def _parse_uplink_detail_output(detail_output):
    text = str(detail_output or "")
    parsed = {}
    match = re.search(r"(?im)^\s*(?:current|physical)\s+state\s*:\s*([^\r\n]+)$", text)
    if match:
        state_text = match.group(1).strip().lower()
        parsed["oper_status"] = "UP" if "up" in state_text else "DOWN"
    match = re.search(r"(?im)^\s*(?:auto-?negotiation|negotiation)\s*:\s*([^\r\n]+)$", text)
    if match:
        value = match.group(1).strip().lower()
        parsed["negotiation"] = "Auto" if any(token in value for token in ("enable", "auto")) else ("Manual" if value else "-")
    match = re.search(r"(?im)^\s*(?:speed|port\s+rate)\s*:\s*([^\r\n]+)$", text)
    if match:
        speed_value = match.group(1).strip()
        mapped = re.search(r"(\d+)\s*(g|m)", speed_value, flags=re.IGNORECASE)
        if mapped:
            parsed["speed"] = f"{mapped.group(1)}{mapped.group(2).upper()}"
    match = re.search(r"(?im)^\s*(?:duplex|duplex mode)\s*:\s*([^\r\n]+)$", text)
    if match:
        duplex_value = match.group(1).strip().lower()
        if "full" in duplex_value:
            parsed["duplex"] = "FullD"
        elif "half" in duplex_value:
            parsed["duplex"] = "HalfD"
    return parsed


def _parse_board_port_state_output(output, port_name):
    text = str(output or "")
    fsp = _parse_frame_slot_port(port_name)
    if not fsp or fsp[2] is None:
        return {}
    _, _, port = fsp
    target_port = str(int(port))
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        match = re.match(
            r"^(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)$",
            line,
        )
        if not match:
            continue
        if match.group(1) != target_port:
            continue
        parsed = {}
        port_type = match.group(2)
        optic_status = match.group(3)
        mdi = match.group(5)
        speed = match.group(6)
        duplex = match.group(7)
        active_state = match.group(9)
        link_state = match.group(10)

        lowered = f"{port_type} {optic_status} {mdi} {speed} {duplex} {active_state} {link_state}".lower()
        if link_state.lower() == "online":
            parsed["oper_status"] = "UP"
        elif link_state.lower() == "offline":
            parsed["oper_status"] = "DOWN"
        elif "up" in lowered or "online" in lowered or "normal" in lowered:
            parsed["oper_status"] = "UP"
        elif "down" in lowered or "offline" in lowered or "absence" in lowered:
            parsed["oper_status"] = "DOWN"
        if mdi.lower() == "auto" or speed.lower().startswith("auto_") or duplex.lower().startswith("auto_"):
            parsed["negotiation"] = "Auto"
        elif mdi == "-" or "manual" in lowered or "disable" in lowered:
            parsed["negotiation"] = "Manual"
        speed_digits = re.search(r"(\d+)", speed)
        if speed_digits:
            speed_num = int(speed_digits.group(1))
            if speed_num >= 1000:
                parsed["speed"] = f"{speed_num // 1000}G" if speed_num % 1000 == 0 else f"{speed_num}M"
            else:
                parsed["speed"] = f"{speed_num}M"
        if "full" in duplex.lower():
            parsed["duplex"] = "FullD"
        elif "half" in duplex.lower():
            parsed["duplex"] = "HalfD"
        if port_type.upper() == "10GE":
            parsed["type"] = "Optical"
        elif port_type.upper() == "GE":
            parsed["type"] = "Electrical"
        return parsed
    return {}


def _parse_board_interface_output(output, port_name):
    text = str(output or "")
    fsp = _parse_frame_slot_port(port_name)
    if not fsp or fsp[2] is None:
        return {}
    _, _, port = fsp
    target_port = str(int(port))
    parsed = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        if not re.match(rf"^{re.escape(target_port)}\b", line):
            continue
        lowered = line.lower()
        if "down" in lowered:
            parsed["oper_status"] = "DOWN"
        elif "up" in lowered or "online" in lowered or "normal" in lowered:
            parsed["oper_status"] = "UP"
        if "auto" in lowered:
            parsed["negotiation"] = "Auto"
        elif "manual" in lowered or "disable" in lowered:
            parsed["negotiation"] = "Manual"
        if "fiber" in lowered or "optical" in lowered or "sfp" in lowered:
            parsed["type"] = "Optical"
        elif "copper" in lowered or "rj45" in lowered or "electrical" in lowered:
            parsed["type"] = "Electrical"
        speed_match = re.search(r"(\d+)\s*(g|m)", line, flags=re.IGNORECASE)
        if speed_match:
            parsed["speed"] = f"{speed_match.group(1)}{speed_match.group(2).upper()}"
        if "full" in lowered:
            parsed["duplex"] = "FullD"
        elif "half" in lowered:
            parsed["duplex"] = "HalfD"
        desc_match = re.search(r"(?i)description[:\s]+(.+)$", line)
        if desc_match:
            parsed["description"] = desc_match.group(1).strip()
        return parsed
    return {}


def _parse_board_config_output(output, port_name):
    text = str(output or "")
    fsp = _parse_frame_slot_port(port_name)
    if not fsp or fsp[2] is None:
        return {}
    _, _, port = fsp
    target_port = str(int(port))
    parsed = {}
    current_port = None
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        port_match = re.match(r"(?i)^port\s+(\d+)\b", line)
        if port_match:
            current_port = port_match.group(1)
            continue
        if current_port != target_port:
            continue
        desc_match = re.match(r"(?i)^description\s+(.+)$", line)
        if desc_match:
            parsed["description"] = desc_match.group(1).strip()
        neg_match = re.match(r"(?i)^auto-neg\s+\d+\s+(enable|disable)", line)
        if neg_match:
            parsed["negotiation"] = "Auto" if neg_match.group(1).lower() == "enable" else "Manual"
        speed_match = re.match(r"(?i)^speed\s+\d+\s+(\d+)", line)
        if speed_match:
            speed_num = int(speed_match.group(1))
            parsed["speed"] = f"{speed_num // 1000}G" if speed_num >= 1000 else f"{speed_num}M"
        duplex_match = re.match(r"(?i)^duplex\s+\d+\s+(full|half)", line)
        if duplex_match:
            parsed["duplex"] = "FullD" if duplex_match.group(1).lower() == "full" else "HalfD"
    return parsed


def _parse_port_desc_map(output):
    desc_map = {}
    text = str(output or "")
    for raw in text.splitlines():
        line = raw.rstrip()
        if not line.strip():
            continue
        match = re.match(r"^\s*(\d+)\s*/\s*(\d+)\s*/\s*(\d+)\s+\S+\s*(.*)$", line)
        if not match:
            continue
        key = f"{int(match.group(1))}/{int(match.group(2))}/{int(match.group(3))}"
        desc = (match.group(4) or "").strip()
        desc_map[key] = "" if desc == "-" else desc
    return desc_map


def _open_board_interface_context(tn, frame, slot):
    board_kind, response, config_entered = _enter_interface_context(tn, ("mcu", "giu", "scu"), frame, slot)
    return board_kind, response, config_entered


def _run_board_context_dump(tn, frame, slot):
    board_kind, enter_output, config_entered = _open_board_interface_context(tn, frame, slot)
    if not board_kind:
        if config_entered:
            _run_telnet_command(tn, "quit")
        return {
            "board_kind": "",
            "state_output": "",
            "detail_output": "",
            "config_output": "",
            "desc_output": "",
        }

    try:
        state_output = _run_telnet_command(tn, "display port state all", enter_until_prompt=True)
        desc_output = _run_telnet_command(tn, f"display port desc {frame}/{slot}", enter_until_prompt=True)
        if desc_output and "total:" not in desc_output.lower():
            retry_desc = _run_telnet_command(tn, f"display port desc {frame}/{slot}", enter_until_prompt=True)
            if retry_desc and len(retry_desc) >= len(desc_output):
                desc_output = retry_desc
        config_output = _run_telnet_command(tn, "display current-configuration", enter_until_prompt=True)
        if not config_output or _is_cli_error_text(config_output):
            config_output = _run_telnet_command(tn, "display this", enter_until_prompt=True)
        return {
            "board_kind": board_kind,
            "state_output": state_output or "",
            "detail_output": state_output or "",
            "config_output": config_output or "",
            "desc_output": desc_output or "",
            "desc_map": _parse_port_desc_map(desc_output or ""),
            "enter_output": enter_output or "",
        }
    finally:
        _run_telnet_command(tn, "quit")
        if config_entered:
            _run_telnet_command(tn, "quit")


def _fetch_cli_uplink_details(olt, rows):
    if not rows:
        return {}

    tn, status = open_telnet_authenticated_session(olt)
    if tn is None:
        return {"status": status, "rows": []}

    try:
        _prepare_telnet_cli_session(tn, use_paging=True)

        brief_output = ""
        for command in ("display interface ethernet brief", "display interface brief"):
            candidate = _run_telnet_command(tn, command, enter_until_prompt=True)
            if candidate and not _is_cli_error_text(candidate):
                brief_output = candidate
                break
        brief_map = _parse_uplink_brief_output(brief_output)

        board_cache = {}
        enriched_rows = []
        for row in rows:
            port = row.get("port", "")
            normalized = _normalize_interface_name(port)
            detail_output = ""
            config_output = ""
            state_output = ""
            desc_output = ""
            board_detail = {}
            fsp = _parse_frame_slot_port(port)
            port_fsp = fsp
            if fsp:
                frame, slot, _ = fsp
                board_key = (frame, slot)
                if board_key not in board_cache:
                    board_cache[board_key] = _run_board_context_dump(tn, frame, slot)
                board_detail = board_cache.get(board_key) or {}
                state_output = board_detail.get("state_output", "") or ""
                detail_output = board_detail.get("detail_output", "") or ""
                config_output = board_detail.get("config_output", "") or ""
                desc_output = board_detail.get("desc_output", "") or ""

            cli_brief = brief_map.get(normalized, {})
            cli_detail = _parse_uplink_detail_output(detail_output)
            cli_state = _parse_board_port_state_output(state_output, port)
            cli_board_detail = _parse_board_interface_output(detail_output, port)
            cli_board_config = _parse_board_config_output(config_output, port)
            speed = cli_board_config.get("speed") or cli_board_detail.get("speed") or cli_state.get("speed") or cli_detail.get("speed") or cli_brief.get("speed") or ""
            duplex = cli_board_config.get("duplex") or cli_board_detail.get("duplex") or cli_state.get("duplex") or cli_detail.get("duplex") or cli_brief.get("duplex") or ""
            oper_status = cli_state.get("oper_status") or cli_board_detail.get("oper_status") or cli_detail.get("oper_status") or cli_brief.get("oper_status") or row.get("oper_status") or "-"
            if oper_status == "Up":
                oper_status = "UP"
            elif oper_status in {"Down", "Lower layer down", "Not present"}:
                oper_status = "DOWN"

            cli_description = ""
            if port_fsp and port_fsp[2] is not None:
                desc_key = f"{int(port_fsp[0])}/{int(port_fsp[1])}/{int(port_fsp[2])}"
                cli_description = (board_detail.get("desc_map") or {}).get(desc_key, "")
            if not cli_description:
                cli_description = row.get("description", "")
            cli_type = row.get("type") or "-"

            enriched = dict(row)
            enriched["description"] = _sanitize_uplink_description(cli_description)
            enriched["oper_status"] = oper_status
            normalized_speed = row.get("speed") or speed or "-"
            if normalized_speed == "-" and str(cli_type).strip().lower() == "fiber":
                normalized_speed = "10G" if "10ge" in str(port).lower() or "xge" in str(port).lower() else "-"
            enriched["type"] = _sanitize_uplink_type(cli_type, port)
            enriched["speed"] = normalized_speed
            enriched["negotiation"] = cli_board_config.get("negotiation") or cli_board_detail.get("negotiation") or cli_state.get("negotiation") or cli_detail.get("negotiation") or cli_brief.get("negotiation") or "-"
            enriched_rows.append(enriched)

        return {
            "status": f"CLI uplink details fetched: {len(enriched_rows)}",
            "rows": enriched_rows,
        }
    except (socket.timeout, TimeoutError):
        return {"status": "Telnet timeout while fetching uplink details.", "rows": rows}
    except OSError as exc:
        return {"status": f"Telnet error while fetching uplink details: {exc}", "rows": rows}
    finally:
        _close_telnet_session(tn)


def fetch_uplink_snapshot(olt, limit=24):
    snmp_data = fetch_snmp_interfaces(olt, limit=limit)
    rows = snmp_data.get("rows") or []
    if not rows:
        return snmp_data

    cli_data = _fetch_cli_uplink_details(olt, rows)
    cli_rows = cli_data.get("rows") or rows
    for row in cli_rows:
        row["description"] = _sanitize_uplink_description(row.get("description", ""))
        row["mtu"] = row.get("mtu") or "-"
    status_bits = []
    if snmp_data.get("status"):
        status_bits.append(snmp_data["status"])
    if cli_data.get("status"):
        status_bits.append(cli_data["status"])
    return {
        "status": " | ".join(status_bits[:2]) or "Uplink data fetched",
        "rows": cli_rows,
    }


def _snmp_config_commands(vendor, read_community, write_community=""):
    vendor_name = (vendor or "").lower()
    read_community = str(read_community or "").strip()
    write_community = str(write_community or "").strip()
    if "huawei" in vendor_name:
        huawei_commands = []
        if read_community:
            huawei_commands.append(f"snmp-agent community read {read_community}")
        if write_community:
            huawei_commands.append(f"snmp-agent community write {write_community}")
        return [
            ["config", *huawei_commands, "quit", "save"],
            ["enable", "config", *huawei_commands, "quit", "save"],
        ]
    if "zte" in vendor_name:
        zte_commands = ["configure terminal"]
        if read_community:
            zte_commands.append(f"snmp-server community {read_community} ro")
        if write_community:
            zte_commands.append(f"snmp-server community {write_community} rw")
        return [
            [*zte_commands, "end", "write"],
        ]
    generic_commands = ["configure terminal"]
    if read_community:
        generic_commands.append(f"snmp-server community {read_community} ro")
    if write_community:
        generic_commands.append(f"snmp-server community {write_community} rw")
    return [
        [*generic_commands, "end", "write memory"],
    ]


def _authenticate_telnet(tn, username, password):
    login_prompts = [re.compile(rb"(?im)^[^\r\n]*(login|user\s*name|username|user)\s*:?\s*$")]
    password_prompts = [re.compile(rb"(?im)^[^\r\n]*password\s*:?\s*$")]
    fail_markers = [
        re.compile(rb"(?i)user\s*name\s*or\s*password\s*invalid\.?"),
        re.compile(rb"(?i)username\s*or\s*password\s*invalid\.?"),
        re.compile(rb"(?i)password\s*invalid\.?"),
        re.compile(rb"(?i)authentication\s*failed\.?"),
        re.compile(rb"(?i)access\s*denied\.?"),
    ]
    # Matches common prompts like "#", "MA5600T>", "<Huawei>", "OLT]"
    shell_prompts = [re.compile(rb"(?m)^[^\r\n]*[>#\]]\s*$")]

    def _detect_from_buffer(buffer):
        if not buffer:
            return -1
        for idx, pattern in enumerate(shell_prompts + login_prompts + password_prompts + fail_markers):
            if pattern.search(buffer):
                return idx
        return -1

    last_reason = "Telnet login failed."
    for eol in ("\r\n", "\n"):
        try:
            preface_raw = tn.read_very_eager()
            preface = preface_raw.decode("ascii", errors="ignore")
            idx = _detect_from_buffer(preface_raw)
            if idx < 0:
                tn.write(eol.encode("ascii", errors="ignore"))
                # Handle direct shell or immediate login/password prompts.
                idx, _, _ = tn.expect(shell_prompts + login_prompts + password_prompts + fail_markers, timeout=12)
            if idx == 0:
                return True, "Telnet authenticated."
            if idx == 1:
                tn.write((username.strip() + eol).encode("ascii", errors="ignore"))
                idx, _, _ = tn.expect(password_prompts + fail_markers + shell_prompts + login_prompts, timeout=12)
                if idx == 0:
                    tn.write((password + eol).encode("ascii", errors="ignore"))
                    idx, _, _ = tn.expect(shell_prompts + fail_markers + login_prompts, timeout=12)
                    if idx == 0:
                        return True, "Telnet authenticated."
                    if idx == 1:
                        last_reason = "Telnet login failed: username/password invalid."
                        continue
                    if idx == 2:
                        last_reason = "Telnet login failed: returned to login prompt."
                        continue
                    last_reason = "Telnet login failed: shell prompt not detected after password."
                    continue
                if idx == 1:
                    last_reason = "Telnet login failed: username/password invalid."
                    continue
                if idx == 2:
                    return True, "Telnet authenticated."
                if idx == 3:
                    last_reason = "Telnet login failed: returned to login prompt."
                    continue
                last_reason = "Telnet password prompt not detected."
                continue
            if idx == 2:
                # Some devices prompt password directly (cached username).
                tn.write((password + eol).encode("ascii", errors="ignore"))
                idx, _, _ = tn.expect(shell_prompts + fail_markers + login_prompts, timeout=12)
                if idx == 0:
                    return True, "Telnet authenticated."
                if idx == 1:
                    last_reason = "Telnet login failed: username/password invalid."
                    continue
                if idx == 2:
                    last_reason = "Telnet login failed: returned to login prompt."
                    continue
                last_reason = "Telnet login failed: shell prompt not detected after password."
                continue
            if idx == 3:
                last_reason = "Telnet login failed: username/password invalid."
                continue

            snippet = " ".join(preface.strip().split())[:120]
            last_reason = f"Telnet login prompt not detected. Banner snippet: {snippet or 'empty'}"
        except EOFError:
            last_reason = "Telnet connection closed during login."
        except (socket.timeout, TimeoutError):
            last_reason = "Telnet login timeout."
        except OSError as exc:
            last_reason = f"Telnet login error: {exc}"
    return False, last_reason


def _is_retryable_auth_status(status):
    text = (status or "").lower()
    retryable_tokens = (
        "timeout",
        "prompt not detected",
        "returned to login prompt",
    )
    return any(token in text for token in retryable_tokens)


def _is_retryable_socket_error(exc):
    text = str(exc or "").lower()
    retryable_tokens = (
        "timed out",
        "timeout",
        "temporarily unavailable",
        "resource busy",
        "would block",
    )
    return any(token in text for token in retryable_tokens)


def _telnet_host_key(olt=None, host="", port=None):
    if olt is not None:
        host = getattr(olt, "ip_address", "") or host
        port = getattr(olt, "port", None) if port is None else port
    return f"{host}:{port or 23}"


def _register_telnet_session(olt, tn):
    if tn is None:
        return
    host_key = _telnet_host_key(olt=olt)
    session_id = id(tn)
    now = timezone.now()
    with _TELNET_SESSION_LOCK:
        _TELNET_SESSIONS[session_id] = {
            "tn": tn,
            "host_key": host_key,
            "updated_at": now,
        }


def _touch_telnet_session(tn):
    if tn is None:
        return
    session_id = id(tn)
    with _TELNET_SESSION_LOCK:
        session = _TELNET_SESSIONS.get(session_id)
        if session is not None:
            session["updated_at"] = timezone.now()


def _unregister_telnet_session(tn):
    if tn is None:
        return
    session_id = id(tn)
    with _TELNET_SESSION_LOCK:
        _TELNET_SESSIONS.pop(session_id, None)


def _close_competing_telnet_sessions(olt, keep_tn=None, force=False):
    host_key = _telnet_host_key(olt=olt)
    now = timezone.now()
    stale_sessions = []
    with _TELNET_SESSION_LOCK:
        for session_id, session in list(_TELNET_SESSIONS.items()):
            tn = session.get("tn")
            if tn is None or session.get("host_key") != host_key:
                continue
            if keep_tn is not None and id(tn) == id(keep_tn):
                continue
            updated_at = session.get("updated_at")
            age_seconds = None
            if updated_at is not None:
                age_seconds = (now - updated_at).total_seconds()
            is_stale = False
            if age_seconds is None:
                is_stale = force
            elif age_seconds >= TELNET_SESSION_RECOVERY_GRACE_SECONDS:
                is_stale = True
            if is_stale:
                stale_sessions.append(tn)
                _TELNET_SESSIONS.pop(session_id, None)
    for session_tn in stale_sessions:
        try:
            session_tn.write(b"\r\n")
            session_tn.write(b"quit\r\n")
            session_tn.write(b"exit\r\n")
            time.sleep(0.08)
        except OSError:
            pass
        finally:
            try:
                session_tn.close()
            except OSError:
                pass


def _close_telnet_session(tn):
    if tn is None:
        return
    _unregister_telnet_session(tn)
    try:
        tn.write(b"\r\n")
        tn.write(b"quit\r\n")
        tn.write(b"exit\r\n")
        time.sleep(0.08)
    except OSError:
        pass
    finally:
        try:
            tn.close()
        except OSError:
            pass


def _snmp_status_looks_down(status_text):
    lowered = str(status_text or "").strip().lower()
    if not lowered:
        return False
    down_tokens = (
        "timeout",
        "no response",
        "timed out",
        "connection refused",
        "network is unreachable",
        "host unreachable",
        "snmp data unavailable",
    )
    return any(token in lowered for token in down_tokens)


def _recent_snmp_down_hint(olt, max_age_seconds=1200):
    synced_at = getattr(olt, "snmp_last_synced_at", None)
    if not synced_at:
        return ""
    try:
        age_seconds = (timezone.now() - synced_at).total_seconds()
    except Exception:
        return ""
    if age_seconds > max_age_seconds:
        return ""
    status_text = str(getattr(olt, "snmp_last_status", "") or "").strip()
    if _snmp_status_looks_down(status_text):
        return status_text
    return ""


def _probe_tcp_port(host, port, timeout=2.2):
    try:
        with socket.create_connection((host, int(port)), timeout=timeout):
            return True, "reachable"
    except socket.timeout:
        return False, "timeout"
    except ConnectionRefusedError:
        return False, "connection refused"
    except OSError as exc:
        text = str(exc).strip() or exc.__class__.__name__
        return False, text


def _diagnose_telnet_open_failure(olt, last_status):
    telnet_port = int(getattr(olt, "tcp_port", 23) or 23)
    tcp_ok, tcp_reason = _probe_tcp_port(olt.ip_address, telnet_port)
    snmp_down_hint = _recent_snmp_down_hint(olt)
    lowered_status = str(last_status or "").lower()

    if "username/password invalid" in lowered_status or "returned to login prompt" in lowered_status:
        if tcp_ok:
            return f"{last_status} | OLT is reachable on Telnet TCP {telnet_port}; likely credential or shell prompt issue."
        return f"{last_status} | Telnet TCP {telnet_port} is not reachable ({tcp_reason})."

    if not tcp_ok and snmp_down_hint:
        return (
            f"OLT appears down or unreachable. Telnet TCP {telnet_port} probe failed ({tcp_reason}). "
            f"Recent SNMP status: {snmp_down_hint}"
        )[:300]
    if not tcp_ok:
        return f"Telnet TCP {telnet_port} is not reachable ({tcp_reason})."
    if snmp_down_hint:
        return (
            f"{last_status} | Telnet port is reachable, but recent SNMP health was bad: {snmp_down_hint}. "
            f"Possible shell/session issue on OLT."
        )[:300]
    return f"{last_status} | Telnet port is reachable; likely shell/session/auth issue on OLT."


def open_telnet_authenticated_session(olt):
    telnet_port = int(getattr(olt, "tcp_port", 23) or 23)
    last_status = "Telnet timeout while opening session."
    recovered_sessions = False
    for attempt in range(1, TELNET_OPEN_ATTEMPTS + 1):
        tn = None
        try:
            if attempt == 1:
                _close_competing_telnet_sessions(olt)
            tn = telnetlib.Telnet(str(olt.ip_address), telnet_port, timeout=8)
            auth_ok, status = _authenticate_telnet(tn, str(olt.username or ""), str(olt.password or ""))
            if not auth_ok:
                last_status = status
                _close_telnet_session(tn)
                if attempt < TELNET_OPEN_ATTEMPTS and _is_retryable_auth_status(status):
                    if not recovered_sessions:
                        _close_competing_telnet_sessions(olt, force=True)
                        recovered_sessions = True
                    time.sleep(TELNET_OPEN_RETRY_DELAYS[min(attempt - 1, len(TELNET_OPEN_RETRY_DELAYS) - 1)])
                    continue
                return None, _diagnose_telnet_open_failure(olt, status)
            _register_telnet_session(olt, tn)
            return tn, status
        except (socket.timeout, TimeoutError):
            last_status = "Telnet timeout while opening session."
            _close_telnet_session(tn)
            if attempt < TELNET_OPEN_ATTEMPTS:
                if not recovered_sessions:
                    _close_competing_telnet_sessions(olt, force=True)
                    recovered_sessions = True
                time.sleep(TELNET_OPEN_RETRY_DELAYS[min(attempt - 1, len(TELNET_OPEN_RETRY_DELAYS) - 1)])
                continue
            return None, _diagnose_telnet_open_failure(olt, last_status)
        except OSError as exc:
            last_status = f"Telnet connection error: {exc}"
            _close_telnet_session(tn)
            if attempt < TELNET_OPEN_ATTEMPTS:
                if not recovered_sessions:
                    _close_competing_telnet_sessions(olt, force=True)
                    recovered_sessions = True
                time.sleep(TELNET_OPEN_RETRY_DELAYS[min(attempt - 1, len(TELNET_OPEN_RETRY_DELAYS) - 1)])
                continue
            return None, _diagnose_telnet_open_failure(olt, last_status)

    return None, _diagnose_telnet_open_failure(olt, last_status)


def _read_telnet_chunk(tn, wait=0.55, rounds=3):
    _touch_telnet_session(tn)
    output = ""
    empty_rounds = 0
    for _ in range(rounds):
        time.sleep(wait)
        try:
            chunk = tn.read_very_eager().decode("ascii", errors="ignore")
        except EOFError:
            break
        if chunk:
            output += chunk
            empty_rounds = 0
            lines = [line.strip() for line in output.splitlines() if line.strip()]
            if lines and PROMPT_LINE_PATTERN.match(lines[-1]):
                break
        else:
            empty_rounds += 1
            # Do not stop too early before first bytes arrive (common after Enter).
            if not output:
                if empty_rounds >= 6:
                    break
                continue
            if empty_rounds >= 3:
                break
    return output


def _collapse_repeated_prompts(text):
    if not text:
        return ""
    collapsed = []
    last_prompt = None
    saw_non_prompt_after_last_prompt = True
    for line in text.splitlines():
        stripped = line.strip()
        if PROMPT_LINE_PATTERN.match(stripped):
            if last_prompt == stripped and not saw_non_prompt_after_last_prompt:
                continue
            last_prompt = stripped
            saw_non_prompt_after_last_prompt = False
            collapsed.append(line)
            continue

        saw_non_prompt_after_last_prompt = True
        collapsed.append(line)

    return "\n".join(collapsed)


def _clean_cli_transcript_block(command, output):
    command_text = str(command or "").strip().lower()
    cleaned_lines = []
    for raw in str(output or "").splitlines():
        line = raw.strip()
        if not line:
            continue
        lowered = line.lower()
        if command_text and lowered == command_text:
            continue
        if PROMPT_LINE_PATTERN.match(line):
            continue
        cleaned_lines.append(line)
    return "\n".join(cleaned_lines).strip()


def _clean_cli_response_text(command, output):
    cleaned = _clean_cli_transcript_block(command, output)
    cleaned = re.sub(r"(?im)^\s*scroll\s+512\s*$", "", cleaned)
    cleaned = re.sub(r"(?im)^\s*enable\s*$", "", cleaned)
    cleaned = re.sub(r"(?im)^\s*config\s*$", "", cleaned)
    cleaned = re.sub(r"(?im)^\s*quit\s*$", "", cleaned)
    cleaned = re.sub(r"(?im)^\s*save\s*$", "", cleaned)
    cleaned = re.sub(r"(?im)^\s*Command:\s*$", "", cleaned)
    cleaned = re.sub(r"(?im)^\s*it\s+will\s+take\s+a\s+long\s+time.*$", "", cleaned)
    cleaned = re.sub(r"(?im)^\s*you\s+can\s+press\s+ctrl_c\s+to\s+break\s*$", "", cleaned)
    cleaned = re.sub(r"(?im)^\s*return\s*$", "", cleaned)
    cleaned = re.sub(r"(?im)^\s*\^\s*$", "", cleaned)
    cleaned = re.sub(r"(?im)^%.*$", "", cleaned)
    cleaned = re.sub(r"\n{3,}", "\n\n", cleaned).strip()
    return cleaned


def _prepare_telnet_cli_session(tn, include_enable=True, use_paging=False):
    if include_enable:
        _run_telnet_command(tn, "enable")
    if use_paging:
        # Use only the safest paging tweak and only for long-output flows.
        _run_telnet_command(tn, "scroll 512")


def _enter_config_mode(tn):
    response = _run_telnet_command(tn, "config")
    if response and _is_cli_error_text(response):
        return False, response or ""
    return True, response or ""


def _enter_interface_context(tn, interface_kinds, frame, slot):
    config_entered, config_output = _enter_config_mode(tn)
    if not config_entered:
        return "", "", False

    for board_kind in interface_kinds:
        response = _run_telnet_command(tn, f"interface {board_kind} {frame}/{slot}")
        if response and _is_cli_error_text(response):
            continue
        lines = [line.strip().lower() for line in str(response or "").splitlines() if line.strip()]
        if any(f"config-if-{board_kind}-{frame}/{slot}" in line for line in lines):
            return board_kind, response or "", True
        if not str(response or "").strip():
            return board_kind, response or "", True
        if lines and not _is_cli_error_text(response):
            return board_kind, response or "", True

    _run_telnet_command(tn, "quit")
    return "", "", False


def _run_telnet_command(tn, command, enter_until_prompt=False):
    _touch_telnet_session(tn)
    more_patterns = [
        re.compile(rb"(?i)-+\s*more\s*-+"),
        re.compile(rb"(?i)--more--"),
        re.compile(rb"(?i)\bmore\b.*press"),
        re.compile(rb"(?i)press\s+space"),
        re.compile(rb"(?i)press\s+'?q'?"),
    ]
    continue_patterns = [
        # Example: "{ <cr>|backplane<K>|frameid/slotid<S><Length 1-15> }:"
        re.compile(rb"\{\s*<cr>\|[^\r\n]*\}\s*:\s*$", re.IGNORECASE),
        # Some devices return incomplete prompt fragments like "{ <cr"
        re.compile(rb"(?i)\{\s*<cr"),
        re.compile(rb"(?i)<cr>"),
        # Generic "press Enter to continue" prompts
        re.compile(rb"(?i)press\s+enter"),
    ]
    prompt_pattern = re.compile(rb"(?m)^[^\r\n]*[>#\]]\s*$")
    needs_enter_tokens = ("<cr", "press enter")
    enter_injections = 0
    max_enter_injections = 8 if enter_until_prompt else 2
    prompt_seen = False
    prompt_only_rounds = 0
    forced_enter_presses = 0
    max_forced_enter_presses = 24 if enter_until_prompt else 8

    # Flush stale prompt/banner bytes before sending a new command.
    try:
        tn.read_very_eager()
    except (OSError, EOFError):
        pass

    try:
        tn.write((command + "\r\n").encode("ascii", errors="ignore"))
    except EOFError:
        return ""
    output = ""
    idle_rounds = 0
    pattern_list = more_patterns + continue_patterns + [prompt_pattern]
    start_ts = time.time()
    max_wait_seconds = 12 if enter_until_prompt else 8

    for _ in range(220 if enter_until_prompt else 30):
        try:
            idx, _, text = tn.expect(pattern_list, timeout=0.8 if enter_until_prompt else 0.45)
        except EOFError:
            break
        if text:
            decoded = text.decode("ascii", errors="ignore")
            output += ANSI_ESCAPE_PATTERN.sub("", decoded)
            idle_rounds = 0
            prompt_only_rounds = 0
        else:
            try:
                extra = tn.read_very_eager().decode("ascii", errors="ignore")
            except EOFError:
                break
            if extra:
                output += ANSI_ESCAPE_PATTERN.sub("", extra)
                idle_rounds = 0
                prompt_only_rounds = 0
            else:
                idle_rounds += 1

        output_tail = (output or "")[-400:].lower()
        lines = [line.strip() for line in (output or "").splitlines() if line.strip()]
        if lines and PROMPT_LINE_PATTERN.match(lines[-1]):
            prompt_seen = True

        if idx == -1:
            if any(token in output_tail for token in needs_enter_tokens):
                if enter_injections < max_enter_injections and forced_enter_presses < max_forced_enter_presses:
                    _touch_telnet_session(tn)
                    tn.write(b"\r\n")
                    enter_injections += 1
                    forced_enter_presses += 1
                    idle_rounds = 0
                    continue
            if enter_until_prompt and not prompt_seen and forced_enter_presses < max_forced_enter_presses and idle_rounds >= 1:
                _touch_telnet_session(tn)
                tn.write(b"\r\n")
                forced_enter_presses += 1
                idle_rounds = 0
                continue
            if enter_until_prompt and not prompt_seen:
                if (time.time() - start_ts) < max_wait_seconds:
                    continue
                if idle_rounds >= 4:
                    break
                continue
            if idle_rounds >= (6 if enter_until_prompt else 2):
                break
            continue
        if idx < len(more_patterns):
            # Device pager: press space to continue next page.
            _touch_telnet_session(tn)
            tn.write(b" ")
            continue
        if idx < len(more_patterns) + len(continue_patterns):
            # Some commands wait for explicit Enter selection (<cr>).
            if enter_injections < max_enter_injections and forced_enter_presses < max_forced_enter_presses:
                _touch_telnet_session(tn)
                tn.write(b"\r\n")
                enter_injections += 1
                forced_enter_presses += 1
            continue
        prompt_seen = True
        non_prompt_lines = [line for line in lines if not PROMPT_LINE_PATTERN.match(line)]
        meaningful_lines = [
            line for line in non_prompt_lines
            if line.lower() != str(command or "").strip().lower()
        ]
        if enter_until_prompt and not meaningful_lines:
            prompt_only_rounds += 1
            if prompt_only_rounds <= 3 and (time.time() - start_ts) < max_wait_seconds:
                continue
        if any(token in output_tail for token in needs_enter_tokens):
            if enter_injections < max_enter_injections and forced_enter_presses < max_forced_enter_presses:
                _touch_telnet_session(tn)
                tn.write(b"\r\n")
                enter_injections += 1
                forced_enter_presses += 1
                continue
        if enter_until_prompt and (time.time() - start_ts) < max_wait_seconds:
            break
        break

    # Remove pager artifacts from parsed output.
    output = re.sub(r"(?i)-+\s*more\s*-+", "", output)
    output = re.sub(r"(?i)--more--", "", output)
    output = re.sub(r"(?i)press\s+space\s+to\s+continue", "", output)
    output = re.sub(r"\{\s*<cr>\|[^\r\n]*\}\s*:\s*$", "", output, flags=re.IGNORECASE | re.MULTILINE)
    output = re.sub(
        r"\{\s*<cr>\|(?:[^\r\n]*\r?\n){0,2}[^\r\n]*\}\s*:\s*",
        "",
        output,
        flags=re.IGNORECASE,
    )
    output = re.sub(
        r"\|backplane<k>\|frameid/slotid<s>\s*[\r\n]*<length\s*1-15>\s*:?",
        "",
        output,
        flags=re.IGNORECASE,
    )
    output = re.sub(r"(?i)\{\s*<cr", "", output)
    output = re.sub(r"(?i)<cr>", "", output)
    output = re.sub(r"(?i)press\s+enter[^\r\n]*", "", output)
    return output


def _run_telnet_save_command(tn):
    _touch_telnet_session(tn)
    try:
        tn.read_very_eager()
    except (OSError, EOFError):
        pass

    try:
        tn.write(b"save\r\n")
    except EOFError:
        return ""

    output = ""
    answered_yes = False
    prompt_pattern = re.compile(rb"(?m)^[^\r\n]*[>#\]]\s*$")
    confirm_patterns = [
        re.compile(rb"(?i)\bcontinue\?\s*\[y/n\]"),
        re.compile(rb"(?i)\bare\s+you\s+sure.*\[y/n\]"),
        re.compile(rb"(?i)\bplease\s+input\s+y/n"),
        re.compile(rb"(?i)\bconfirm\b.*\[y/n\]"),
    ]
    patterns = confirm_patterns + [prompt_pattern]
    start_ts = time.time()

    while time.time() - start_ts < 15:
        try:
            idx, _, text = tn.expect(patterns, timeout=0.8)
        except EOFError:
            break

        if text:
            output += ANSI_ESCAPE_PATTERN.sub("", text.decode("ascii", errors="ignore"))
        else:
            try:
                extra = tn.read_very_eager().decode("ascii", errors="ignore")
            except EOFError:
                break
            output += ANSI_ESCAPE_PATTERN.sub("", extra or "")

        if idx != -1 and idx < len(confirm_patterns) and not answered_yes:
            _touch_telnet_session(tn)
            tn.write(b"y\r\n")
            answered_yes = True
            continue

        lines = [line.strip() for line in output.splitlines() if line.strip()]
        if lines and PROMPT_LINE_PATTERN.match(lines[-1]):
            break

    return output


def _run_telnet_bulk_command(tn, command, max_wait_seconds=45, idle_poke=b"\r\n"):
    _touch_telnet_session(tn)
    try:
        tn.read_very_eager()
    except (OSError, EOFError):
        pass

    try:
        tn.write((command + "\r\n").encode("ascii", errors="ignore"))
    except EOFError:
        return ""

    output = ""
    prompt_pattern = re.compile(r"(?m)^[^\r\n]*[>#\]]\s*$")
    start_ts = time.time()
    idle_rounds = 0
    saw_payload = False
    idle_pokes = 0

    while (time.time() - start_ts) < max_wait_seconds:
        time.sleep(0.35)
        try:
            chunk = tn.read_very_eager().decode("ascii", errors="ignore")
        except EOFError:
            break
        if chunk:
            cleaned = ANSI_ESCAPE_PATTERN.sub("", chunk)
            output += cleaned
            idle_rounds = 0
            lowered = cleaned.lower()
            if "more" in lowered and "press" in lowered:
                _touch_telnet_session(tn)
                tn.write(b" ")
                continue
            if "<cr>" in lowered or "press enter" in lowered:
                _touch_telnet_session(tn)
                tn.write(b"\r\n")
                continue
            meaningful_lines = [
                line.strip() for line in output.splitlines()
                if line.strip() and line.strip().lower() != command.strip().lower()
            ]
            if meaningful_lines:
                saw_payload = True
            if saw_payload and meaningful_lines and prompt_pattern.match(meaningful_lines[-1]):
                break
        else:
            idle_rounds += 1
            if idle_rounds in {2, 4, 6, 8, 10, 12}:
                try:
                    _touch_telnet_session(tn)
                    tn.write(idle_poke)
                    idle_pokes += 1
                except EOFError:
                    break
            if saw_payload and idle_rounds >= 14 and idle_pokes >= 2:
                lines = [line.strip() for line in output.splitlines() if line.strip()]
                if lines and prompt_pattern.match(lines[-1]):
                    break
            if not saw_payload and idle_rounds >= 18 and idle_pokes >= 2:
                lines = [line.strip() for line in output.splitlines() if line.strip()]
                if lines and prompt_pattern.match(lines[-1]):
                    break

    output = re.sub(r"(?i)-+\s*more\s*-+", "", output)
    output = re.sub(r"(?i)--more--", "", output)
    output = re.sub(r"(?i)press\s+space\s+to\s+continue", "", output)
    output = re.sub(r"(?i)press\s+enter[^\r\n]*", "", output)
    return output


def _run_service_port_all_command(tn, max_wait_seconds=45):
    command = "display service-port all"
    _touch_telnet_session(tn)
    try:
        tn.read_very_eager()
    except (OSError, EOFError):
        pass

    try:
        tn.write((command + "\r\n").encode("ascii", errors="ignore"))
    except EOFError:
        return ""

    output = ""
    prompt_pattern = re.compile(r"(?m)^[^\r\n]*[>#\]]\s*$")
    start_ts = time.time()
    idle_rounds = 0
    saw_table = False
    initial_steps = [b"\r\n", b"\r\n", b" "]
    initial_step_index = 0

    while (time.time() - start_ts) < max_wait_seconds:
        time.sleep(0.35)
        try:
            chunk = tn.read_very_eager().decode("ascii", errors="ignore")
        except EOFError:
            break

        if chunk:
            cleaned = ANSI_ESCAPE_PATTERN.sub("", chunk)
            output += cleaned
            idle_rounds = 0
            lowered = cleaned.lower()

            if "switch-oriented flow list" in lowered or "index vlan vlan" in lowered:
                saw_table = True

            if "more" in lowered and "press" in lowered:
                _touch_telnet_session(tn)
                tn.write(b" ")
                continue

            if "<cr>" in lowered or "press enter" in lowered or "sort-by" in lowered:
                if initial_step_index < len(initial_steps):
                    _touch_telnet_session(tn)
                    tn.write(initial_steps[initial_step_index])
                    initial_step_index += 1
                else:
                    _touch_telnet_session(tn)
                    tn.write(b" ")
                continue

            lines = [line.strip() for line in output.splitlines() if line.strip()]
            if saw_table and lines and prompt_pattern.match(lines[-1]):
                break
        else:
            idle_rounds += 1
            if initial_step_index < len(initial_steps) and idle_rounds >= 2:
                try:
                    _touch_telnet_session(tn)
                    tn.write(initial_steps[initial_step_index])
                    initial_step_index += 1
                    idle_rounds = 0
                    continue
                except EOFError:
                    break
            if saw_table and idle_rounds >= 2:
                try:
                    _touch_telnet_session(tn)
                    tn.write(b" ")
                except EOFError:
                    break
            if idle_rounds >= 10:
                lines = [line.strip() for line in output.splitlines() if line.strip()]
                if lines and prompt_pattern.match(lines[-1]):
                    break

    output = re.sub(r"(?i)-+\s*more\s*-+", "", output)
    output = re.sub(r"(?i)--more--", "", output)
    output = re.sub(r"(?i)press\s+space\s+to\s+continue", "", output)
    output = re.sub(r"(?i)press\s+enter[^\r\n]*", "", output)
    output = re.sub(r"\{\s*<cr>\|[^\r\n]*\}\s*:\s*$", "", output, flags=re.IGNORECASE | re.MULTILINE)
    output = re.sub(r"(?i)\{\s*<cr", "", output)
    output = re.sub(r"(?i)<cr>", "", output)
    return output


def _parse_board_table(output):
    cards = []
    now_text = time.strftime("%Y-%m-%d %H:%M:%S")
    for line in (output or "").splitlines():
        match = re.match(r"^\s*(\d+)\s+([A-Za-z0-9-]+)\s+([A-Za-z0-9_/-]+)", line)
        if not match:
            continue
        slot = match.group(1)
        model = match.group(2)
        state_token = match.group(3)
        state_l = (state_token or "").lower()

        if any(token in state_l for token in ("offline", "abnormal", "fault", "down")):
            status = "Offline"
        elif "normal" in state_l:
            status = "Normal"
        else:
            status = state_token

        if "active" in state_l or "master" in state_l or "main" in state_l:
            role = "Main"
        elif "standby" in state_l or "slave" in state_l:
            role = "Standby"
        else:
            role = "-"
        board_category = _classify_card_real_type(model, role)
        cards.append(
            {
                "slot": slot,
                "type": model,
                "real_type": board_category,
                "model_type": model,
                "ports": 0,
                "sw": "",
                "status": status,
                "role": role,
                "info_updated": now_text,
            }
        )
    return cards


def _count_ports(board_detail_output):
    port_count = 0
    for line in (board_detail_output or "").splitlines():
        if re.match(r"^\s*\d+\s+[A-Za-z][A-Za-z0-9/-]*\s+", line):
            port_count += 1
    return port_count


def _fill_ports_from_model_defaults(cards):
    unknown_slots = []
    for card in cards:
        default_ports = BOARD_DEFAULT_PORTS.get(card["model_type"].upper())
        if default_ports is None:
            unknown_slots.append(card["slot"])
        else:
            card["ports"] = default_ports
    return unknown_slots


def _parse_card_sw_from_text(text):
    return _parse_sw_from_display_version(text, fallback="")


def _parse_card_real_type(text, fallback):
    patterns = (
        r"^\s*Board\s+Type\s*:\s*([A-Za-z0-9._/-]+)",
        r"^\s*Real\s*Type\s*:\s*([A-Za-z0-9._/-]+)",
        r"^\s*Board\s*Name\s*:\s*([A-Za-z0-9._/-]+)",
        r"^\s*Type\s*:\s*([A-Za-z0-9._/-]+)",
    )
    for pattern in patterns:
        match = re.search(pattern, text or "", flags=re.IGNORECASE | re.MULTILINE)
        if match:
            return match.group(1).upper()
    return fallback


def _classify_card_real_type(model, role=""):
    text = (model or "").upper().strip()
    role_text = (role or "").upper().strip()
    if not text:
        if "MAIN" in role_text:
            return "Main"
        return "-"

    power_tokens = (
        "POWER",
        "PWR",
        "PISA",
        "PISB",
        "PIA",
        "PIB",
        "PW",
    )
    if any(token in text for token in power_tokens):
        return "Power"

    main_tokens = (
        "SCU",
        "MCU",
        "MPSG",
        "MPS",
        "MPU",
        "X2CS",
        "X2CA",
        "X2CB",
        "CCR",
        "SCC",
    )
    if any(token in text for token in main_tokens) or "MAIN" in role_text:
        return "Main"

    pon_tokens = (
        "GP",
        "XG",
        "EP",
        "CGID",
    )
    if any(token in text for token in pon_tokens):
        return "GPON"

    uplink_tokens = (
        "GIC",
        "ETH",
        "GE",
        "FE",
        "UP",
    )
    if any(token in text for token in uplink_tokens):
        return "Uplink"

    return text


def _merge_card_detail(card, detail_output):
    detail_text = detail_output or ""
    if not detail_text:
        return

    parsed_model_type = _parse_card_real_type(detail_text, card.get("model_type") or card.get("type") or "")
    if parsed_model_type:
        card["model_type"] = parsed_model_type
        card["real_type"] = _classify_card_real_type(parsed_model_type, card.get("role") or "")

    parsed_sw = _parse_card_sw_from_text(detail_text)
    if parsed_sw:
        card["sw"] = parsed_sw

    ports = _count_ports(detail_text)
    if ports > 0:
        card["ports"] = ports


def _is_pon_board_model(model):
    text = (model or "").upper()
    if not text:
        return False
    if "GP" in text:
        return True
    if "XG" in text:
        return True
    return False


def _parse_pon_ports_from_board_detail(slot, board_type, detail_output, default_ports):
    ports = []
    seen = set()
    lines = (detail_output or "").splitlines()
    for raw in lines:
        line = raw.strip()
        if not line:
            continue
        match = re.match(r"^(\d+)\s+([A-Za-z][A-Za-z0-9_./-]*)\s*(.*)$", line)
        if not match:
            continue
        port_no = int(match.group(1))
        port_type = match.group(2).upper()
        rest = (match.group(3) or "").strip()
        rest_l = rest.lower()
        admin_state = "Enabled"
        if any(token in rest_l for token in ("disable", "disabled", "shutdown")):
            admin_state = "Disabled"
        status_text = _derive_pon_status_from_detail(rest_l)

        ports.append(
            {
                "slot": str(slot),
                "board_type": board_type or "Unknown",
                "port": port_no,
                "type": port_type,
                "admin_state": admin_state,
                "status": status_text,
                "onus": "Online:0 Offline:0",
                "onus_online": 0,
                "onus_offline": 0,
                "sfp_tx": "",
            }
        )
        seen.add(port_no)

    if ports:
        return sorted(ports, key=lambda item: item["port"])

    count = int(default_ports or 0)
    for port_no in range(count):
        ports.append(
            {
                "slot": str(slot),
                "board_type": board_type or "Unknown",
                "port": port_no,
                "type": "GPON",
                "admin_state": "Enabled",
                "status": "Unknown",
                "onus": "Online:0 Offline:0",
                "onus_online": 0,
                "onus_offline": 0,
                "sfp_tx": "",
            }
        )
    return ports


def _derive_pon_status_from_detail(rest_l):
    text = (rest_l or "").strip()
    if not text:
        return "Unknown"

    token_positions = []
    for token in ("up", "down", "online", "offline", "normal", "autofind"):
        idx = re.search(rf"\b{re.escape(token)}\b", text)
        if idx:
            token_positions.append((idx.start(), token))
    token_positions.sort(key=lambda item: item[0])

    if token_positions:
        first = token_positions[0][1]
        if first in ("up", "online", "normal"):
            return "Up / Autofind"
        if first in ("down", "offline"):
            return "Down / Autofind"
    if "down" in text or "offline" in text:
        return "Down / Autofind"
    if "up" in text or "online" in text or "normal" in text:
        return "Up / Autofind"
    return "Unknown"


def _classify_ont_state(text):
    value = (text or "").strip().lower()
    if not value:
        return ""
    if "online" in value:
        return "online"
    offline_tokens = ("offline", "down", "initial", "failed", "deactive", "los")
    if any(token in value for token in offline_tokens):
        return "offline"
    return ""


def _parse_ont_counts_by_port(ont_output):
    counts = {}
    parsed_rows = 0
    text = ont_output or ""
    lines = text.splitlines()

    # Mode 1: table rows like:
    # "0/ 0/0    0  4857...  active  online  normal ..."
    # or "0/0/0   0  4857... active online ..."
    for raw in lines:
        line = raw.strip()
        row_match = re.match(
            r"^\s*(\d+)\s*/\s*(\d+)\s*/\s*(\d+)\s+(\d+)\s+(\S+)\s+(\S+)\s+(\S+)",
            line,
        )
        if not row_match:
            continue
        slot = int(row_match.group(2))
        port = int(row_match.group(3))
        run_state = row_match.group(7)
        state = _classify_ont_state(run_state)
        if not state:
            continue
        key = (slot, port)
        bucket = counts.setdefault(key, {"online": 0, "offline": 0, "total": 0})
        bucket[state] += 1
        bucket["total"] += 1
        parsed_rows += 1

    if parsed_rows > 0:
        return counts, parsed_rows

    # Mode 2: block output with explicit fields.
    current = None
    for raw in lines:
        line = raw.strip()
        fsp = re.search(r"(?i)\bF/S/P\s*:\s*(\d+)/(\d+)/(\d+)", line)
        if fsp:
            current = (int(fsp.group(2)), int(fsp.group(3)))
            continue
        if current is None:
            continue
        run_state = re.search(r"(?i)\bRun\s*state\s*:\s*([A-Za-z0-9_-]+)", line)
        if not run_state:
            continue
        state = _classify_ont_state(run_state.group(1))
        if not state:
            current = None
            continue
        bucket = counts.setdefault(current, {"online": 0, "offline": 0, "total": 0})
        bucket[state] += 1
        bucket["total"] += 1
        parsed_rows += 1
        current = None

    return counts, parsed_rows


def _parse_ont_inventory_rows(ont_output):
    rows = []
    text = ont_output or ""
    for raw in text.splitlines():
        line = raw.rstrip()
        prefix_match = re.match(r"^\s*(\d+)\s*/\s*(\d+)\s*/\s*(\d+)\s+(\d+)\s+(.*)$", line)
        if not prefix_match:
            continue
        frame = int(prefix_match.group(1))
        slot = int(prefix_match.group(2))
        port = int(prefix_match.group(3))
        ont_id = int(prefix_match.group(4))
        tail = prefix_match.group(5).strip()
        columns = [part.strip() for part in re.split(r"\s{2,}", tail) if part.strip()]
        if len(columns) < 6:
            compact = tail.split()
            if len(compact) < 6:
                continue
            columns = compact[:6] + ([" ".join(compact[6:])] if len(compact) > 6 else [])
        rows.append(
            {
                "frame": frame,
                "slot": slot,
                "port": port,
                "fsp": f"{frame}/{slot}/{port}",
                "ont_id": ont_id,
                "sn": columns[0],
                "control_flag": (columns[1] if len(columns) > 1 else "").lower(),
                "run_state": (columns[2] if len(columns) > 2 else "").lower(),
                "config_state": (columns[3] if len(columns) > 3 else "").lower(),
                "match_state": (columns[4] if len(columns) > 4 else "").lower(),
                "protect_side": (columns[5] if len(columns) > 5 else "").lower(),
                "description": " ".join(columns[6:]).strip() if len(columns) > 6 else "",
                "raw_line": line,
            }
        )
    return rows


def _parse_ont_description_section(ont_output):
    desc_map = {}
    in_desc_section = False
    for raw in (ont_output or "").splitlines():
        line = raw.rstrip()
        if not line.strip():
            continue
        if re.search(r"^\s*F/S/P\s+ONT-ID\s+Description\s*$", line, flags=re.IGNORECASE):
            in_desc_section = True
            continue
        if not in_desc_section:
            continue
        if re.match(r"^\s*-{5,}\s*$", line):
            continue
        if "more" in line.lower() and "press" in line.lower():
            continue
        match = re.match(
            r"^\s*(\d+)\s*/\s*(\d+)\s*/\s*(\d+)\s+(\d+)\s+(.+?)\s*$",
            line,
        )
        if not match:
            continue
        slot = int(match.group(2))
        port = int(match.group(3))
        ont_id = int(match.group(4))
        description = match.group(5).strip()
        if description.lower() == "none":
            description = ""
        desc_map[(slot, port, ont_id)] = description
    return desc_map


def _parse_ont_optical_section(optical_output):
    power_map = {}
    current_key = None

    for raw in (optical_output or "").splitlines():
        line = raw.rstrip()
        stripped = line.strip()
        if not stripped:
            continue
        if "more" in stripped.lower() and "press" in stripped.lower():
            continue

        fsp_block = re.search(r"(?i)\bF/S/P\s*:\s*(\d+)\s*/\s*(\d+)\s*/\s*(\d+)", stripped)
        if fsp_block:
            current_key = (int(fsp_block.group(2)), int(fsp_block.group(3)), None)
            continue

        ont_block = re.search(r"(?i)\bONT-ID\s*:\s*(\d+)", stripped)
        if ont_block and current_key is not None:
            current_key = (current_key[0], current_key[1], int(ont_block.group(1)))
            power_map.setdefault(current_key, {})
            continue

        if current_key is not None and current_key[2] is not None:
            onu_rx = re.search(r"(?i)\bONU.*?Rx.*?(-?\d+(?:\.\d+)?)\s*dBm", stripped)
            if onu_rx:
                power_map.setdefault(current_key, {})["onu_rx"] = f"{float(onu_rx.group(1)):.2f} dBm"
                continue
            olt_rx = re.search(r"(?i)\bOLT.*?Rx.*?(-?\d+(?:\.\d+)?)\s*dBm", stripped)
            if olt_rx:
                power_map.setdefault(current_key, {})["olt_rx"] = f"{float(olt_rx.group(1)):.2f} dBm"
                continue
            generic_pair = re.search(r"(-?\d+(?:\.\d+)?)\s*dBm\s*/\s*(-?\d+(?:\.\d+)?)\s*dBm", stripped, flags=re.IGNORECASE)
            if generic_pair:
                power_map.setdefault(current_key, {})["onu_rx"] = f"{float(generic_pair.group(1)):.2f} dBm"
                power_map.setdefault(current_key, {})["olt_rx"] = f"{float(generic_pair.group(2)):.2f} dBm"
                continue

        table_match = re.match(
            r"^\s*(\d+)\s*/\s*(\d+)\s*/\s*(\d+)\s+(\d+)\s+(-?\d+(?:\.\d+)?)\s*dBm\s*/\s*(-?\d+(?:\.\d+)?)\s*dBm",
            stripped,
            flags=re.IGNORECASE,
        )
        if table_match:
            key = (int(table_match.group(2)), int(table_match.group(3)), int(table_match.group(4)))
            power_map[key] = {
                "onu_rx": f"{float(table_match.group(5)):.2f} dBm",
                "olt_rx": f"{float(table_match.group(6)):.2f} dBm",
            }
            continue

    return power_map


def _format_optical_dbm(value):
    text = str(value or "").strip()
    if not text or text == "-":
        return "--"
    try:
        return f"{float(text):.2f} dBm"
    except (TypeError, ValueError):
        return "--"


def _signal_bucket_from_dbm_text(text):
    value = str(text or "").strip()
    if not value or value == "--":
        return ""
    match = re.search(r"(-?\d+(?:\.\d+)?)", value)
    if not match:
        return ""
    try:
        dbm = float(match.group(1))
    except (TypeError, ValueError):
        return ""
    if -27.0 <= dbm <= -8.0:
        return "good"
    if (-30.0 <= dbm < -27.0) or (-8.0 < dbm <= -6.0):
        return "warn"
    return "bad"


def _fallback_configured_onu_status(run_state):
    state = str(run_state or "").strip().lower()
    return "online" if state == "online" else "offline"


def derive_inventory_onu_status(row):
    row = row or {}
    control_flag = str(row.get("control_flag") or "").strip().lower()
    run_state = str(row.get("run_state") or "").strip().lower()

    if any(token in control_flag for token in ("deactivated", "deactive", "disabled", "disable")):
        return "admin_disabled"

    if run_state == "online":
        return "online"

    return "offline"


def map_onu_alarm_to_status(alarm_code, alarm_name, extra_text=""):
    code = str(alarm_code or "").strip().lower()
    name = str(alarm_name or "").strip().lower()
    extra = str(extra_text or "").strip().lower()
    text = " ".join(part for part in (code, name, extra) if part).strip()
    if not text:
        return ""

    if (
        "5000217" in text
        or "ont is disabled" in text
        or "admin disabled" in text
        or re.search(r"\bdis\b", f" {name} ")
    ):
        return "admin_disabled"

    power_tokens = (
        "dying-gasp",
        "dyinggasp",
        "dying gasp",
        "dying_gasp",
        "dying gasp alarm",
        "power failure",
        "powerfail",
        "power fail",
        "power off",
        "power down",
        "ont power",
        "onu power",
        "power alarm",
    )
    if any(token in text for token in power_tokens):
        return "power_failure"

    signal_tokens = (
        "loss of signal",
        "loss-of-signal",
        "loss_of_signal",
        " los ",
        " los:",
        " los-",
        "losi",
        "los alarm",
        "optical signal loss",
        "signal loss",
        "signal fail",
        "signal degrade",
        "lofi",
        "sfi",
        "sdi",
        "lof",
        "rx low",
        "rx low alarm",
        "optical power low",
        "fiber cut",
    )
    padded = f" {text} "
    if any(token in padded or token in text for token in signal_tokens):
        return "loss_of_signal"

    return ""


def get_active_onu_trap_status_map(olt):
    from .models import ONUTrapEvent

    priority = {
        "admin_disabled": 0,
        "power_failure": 1,
        "loss_of_signal": 2,
    }
    status_map = {}
    qs = (
        ONUTrapEvent.objects.filter(olt=olt, is_active=True)
        .only("slot", "port", "ont_id", "mapped_status", "alarm_code", "alarm_name")
    )
    for event in qs:
        mapped = (event.mapped_status or "").strip() or map_onu_alarm_to_status(event.alarm_code, event.alarm_name)
        if not mapped:
            continue
        key = (int(event.slot), int(event.port), int(event.ont_id))
        current = status_map.get(key)
        if current is None or priority.get(mapped, 99) < priority.get(current, 99):
            status_map[key] = mapped
    return status_map


def _parse_port_optical_table(optical_output, slot, port):
    power_map = {}
    for raw in (optical_output or "").splitlines():
        line = raw.rstrip()
        stripped = line.strip()
        if not stripped:
            continue
        if "more" in stripped.lower() and "press" in stripped.lower():
            continue
        if stripped.lower().startswith(("ont id", "rx power", "command:", "huawei", "note:")):
            continue
        if re.match(r"^\s*-{5,}\s*$", stripped):
            continue

        match = re.match(
            r"^\s*(\d+)\s+(-?\d+(?:\.\d+)?|-)\s+(-?\d+(?:\.\d+)?|-)\s+(-?\d+(?:\.\d+)?|-)\s+(-?\d+(?:\.\d+)?|-)\s+(-?\d+(?:\.\d+)?|-)\s+(-?\d+(?:\.\d+)?|-)(?:\s+(-?\d+(?:\.\d+)?|-))?\s*$",
            stripped,
        )
        if not match:
            continue

        ont_id = int(match.group(1))
        power_map[(slot, port, ont_id)] = {
            "onu_rx": _format_optical_dbm(match.group(2)),
            "tx_power": _format_optical_dbm(match.group(3)),
            "olt_rx": _format_optical_dbm(match.group(4)),
        }

    return power_map


def _pon_interface_kinds_for_board(board_type):
    text = str(board_type or "").strip().upper()
    if "XG" in text:
        return ("xgpon", "gpon", "epon")
    if "EP" in text:
        return ("epon", "gpon", "xgpon")
    return ("gpon", "xgpon", "epon")


def _parse_pon_sfp_tx_from_text(text):
    raw_text = str(text or "")
    if not raw_text.strip() or _is_cli_error_text(raw_text):
        return ""
    for raw in raw_text.splitlines():
        line = raw.strip()
        if not line:
            continue
        lowered = line.lower()
        if "tx" not in lowered and "transmit" not in lowered:
            continue
        if "power" not in lowered and "optical" not in lowered:
            continue
        match = re.search(r"(-?\d+(?:\.\d+)?)", line)
        if not match:
            continue
        try:
            return f"{float(match.group(1)):.2f} dBm"
        except (TypeError, ValueError):
            continue
    return ""


def _fetch_pon_sfp_tx_map_in_context(tn, slot_port_map):
    tx_map = {}
    if not slot_port_map:
        return tx_map

    # `display port state` is the one command that consistently exposes PON SFP TX power
    # across our Huawei OLTs without the syntax issues seen on other command families.
    command_templates = (
        "display port state {port}",
    )

    for slot in sorted(slot_port_map):
        slot_data = slot_port_map.get(slot) or {}
        board_type = slot_data.get("board_type") or ""
        ports = sorted({int(port) for port in (slot_data.get("ports") or [])})
        if not ports:
            continue
        board_kind, _, entered = _enter_interface_context(tn, _pon_interface_kinds_for_board(board_type), 0, slot)
        if not entered or not board_kind:
            continue
        try:
            for port in ports:
                for template in command_templates:
                    output = _run_telnet_command(tn, template.format(port=port), enter_until_prompt=True)
                    parsed = _parse_pon_sfp_tx_from_text(output)
                    if parsed:
                        tx_map[(int(slot), int(port))] = parsed
                        break
        finally:
            _run_telnet_command(tn, "quit")
            _run_telnet_command(tn, "quit")
    return tx_map


def _fetch_ont_optical_map_in_context(tn, slot_ports):
    optical_map = {}
    successful_ports = set()
    if not slot_ports:
        return optical_map, successful_ports

    grouped_ports = {}
    for slot, port in slot_ports:
        grouped_ports.setdefault(int(slot), set()).add(int(port))

    for slot in sorted(grouped_ports):
        board_kind, _, entered = _enter_interface_context(tn, ("gpon",), 0, slot)
        if not entered or board_kind != "gpon":
            continue
        for port in sorted(grouped_ports[slot]):
            output = ""
            parsed = {}
            for _ in range(2):
                output = _run_telnet_command(tn, f"display ont optical-info {port} all", enter_until_prompt=True)
                parsed = _parse_port_optical_table(output, slot, port)
                cleaned_output = _clean_cli_transcript_block(f"display ont optical-info {port} all", output)
                if parsed or (cleaned_output and not _is_cli_error_text(cleaned_output)):
                    successful_ports.add((int(slot), int(port)))
                if parsed:
                    optical_map.update(parsed)
                    break
        _run_telnet_command(tn, "quit")
        _run_telnet_command(tn, "quit")
    return optical_map, successful_ports


def fetch_single_ont_optical_info(olt, slot, port, ont_id):
    result = {
        "onu_rx": "--",
        "tx_power": "--",
        "olt_rx": "--",
    }
    tn, status = open_telnet_authenticated_session(olt)
    if tn is None:
        return result

    try:
        _prepare_telnet_cli_session(tn, use_paging=True)
        optical_map, _ = _fetch_ont_optical_map_in_context(tn, [(slot, port)])
        return optical_map.get((int(slot), int(port), int(ont_id)), result)
    except (socket.timeout, TimeoutError, EOFError, OSError):
        return result
    finally:
        _close_telnet_session(tn)


def fetch_ont_optical_subset(olt, onu_keys):
    result = {}
    if not onu_keys:
        return result

    slot_ports = sorted({(int(slot), int(port)) for slot, port, _ in onu_keys})
    tn, status = open_telnet_authenticated_session(olt)
    if tn is None:
        return result

    try:
        _prepare_telnet_cli_session(tn, use_paging=True)
        optical_map, _ = _fetch_ont_optical_map_in_context(tn, slot_ports)
        for key in onu_keys:
            slot, port, ont_id = int(key[0]), int(key[1]), int(key[2])
            result[(slot, port, ont_id)] = optical_map.get((slot, port, ont_id), {
                "onu_rx": "--",
                "tx_power": "--",
                "olt_rx": "--",
            })
        return result
    except (socket.timeout, TimeoutError, EOFError, OSError):
        return result
    finally:
        _close_telnet_session(tn)


def fetch_configured_onus_snapshot(olt):
    result = {
        "status": "ONU inventory unavailable",
        "rows": [],
    }
    tn, status = open_telnet_authenticated_session(olt)
    if tn is None:
        result["status"] = status
        return result

    try:
        _prepare_telnet_cli_session(tn, use_paging=True)
        try:
            tn.read_very_eager()
        except (OSError, EOFError):
            pass
        ont_output = _run_telnet_bulk_command(tn, "display ont info 0 all")
        if not _parse_ont_inventory_rows(ont_output):
            ont_output = _run_telnet_bulk_command(tn, "display ont info 0 all")
        rows = _parse_ont_inventory_rows(ont_output)
        desc_map = _parse_ont_description_section(ont_output)
        slot_ports = sorted(
            {
                (int(row.get("slot", 0) or 0), int(row.get("port", 0) or 0))
                for row in rows
            }
        )
        optical_map, _ = _fetch_ont_optical_map_in_context(tn, slot_ports)
        for row in rows:
            row["description"] = desc_map.get((row["slot"], row["port"], row["ont_id"]), "").strip()
            power = optical_map.get((row["slot"], row["port"], row["ont_id"])) or {}
            row["onu_rx"] = power.get("onu_rx", "--")
            row["tx_power"] = power.get("tx_power", "--")
            row["olt_rx"] = power.get("olt_rx", "--")
            row["signal_bucket"] = _signal_bucket_from_dbm_text(row["olt_rx"])
        result["rows"] = rows
        result["status"] = f"Configured ONUs fetched: {len(rows)} | Descriptions mapped: {len(desc_map)} | Signals mapped: {len(optical_map)}"
        return result
    except (socket.timeout, TimeoutError):
        result["status"] = "Telnet timeout while fetching configured ONUs."
        return result
    except EOFError:
        result["status"] = "Telnet connection closed while fetching configured ONUs."
        return result
    except OSError as exc:
        result["status"] = f"Telnet error while fetching configured ONUs: {exc}"
        return result
    finally:
        _close_telnet_session(tn)


def sync_configured_onus_inventory(olt):
    from django.db import transaction

    from .models import ConfiguredONU

    fetched = fetch_configured_onus_snapshot(olt)
    rows = fetched.get("rows") or []
    status = fetched.get("status") or ""
    if not rows:
        return {
            "status": status or "No configured ONUs fetched.",
            "count": 0,
        }

    deduped_rows = {}
    for row in rows:
        key = (
            int(row.get("frame", 0) or 0),
            int(row.get("slot", 0) or 0),
            int(row.get("port", 0) or 0),
            int(row.get("ont_id", 0) or 0),
        )
        existing = deduped_rows.get(key)
        if existing is None:
            deduped_rows[key] = dict(row)
            continue

        merged = dict(existing)
        for field in ("sn", "control_flag", "run_state", "config_state", "match_state", "protect_side", "raw_line"):
            new_value = (row.get(field) or "").strip()
            if new_value:
                merged[field] = new_value

        new_description = (row.get("description") or "").strip()
        if new_description and new_description.lower() not in {"none", "-"}:
            merged["description"] = new_description

        for field in ("onu_rx", "olt_rx", "tx_power"):
            new_value = (row.get(field) or "").strip()
            if new_value and new_value != "--":
                merged[field] = new_value

        deduped_rows[key] = merged

    rows = list(deduped_rows.values())
    now = timezone.now()
    trap_status_map = get_active_onu_trap_status_map(olt)
    existing_map = {
        (item.frame, item.slot, item.port, item.ont_id): item
        for item in ConfiguredONU.objects.filter(olt=olt)
    }
    to_create = []
    to_update = []
    seen_keys = set()

    for row in rows:
        key = (
            int(row.get("frame", 0) or 0),
            int(row.get("slot", 0) or 0),
            int(row.get("port", 0) or 0),
            int(row.get("ont_id", 0) or 0),
        )
        seen_keys.add(key)
        trap_key = (key[1], key[2], key[3])
        trap_status = trap_status_map.get(trap_key)
        derived_status = trap_status or derive_inventory_onu_status(row)
        status_source = "trap" if trap_key in trap_status_map else "inventory"
        signal_bucket = (row.get("signal_bucket") or "").strip()
        if not trap_status and derived_status == "offline" and signal_bucket in {"good", "warn", "bad"}:
            derived_status = "online"
            status_source = "signal_inventory"
        payload = {
            "sn": (row.get("sn") or "")[:64],
            "control_flag": (row.get("control_flag") or "")[:32],
            "run_state": (row.get("run_state") or "")[:32],
            "config_state": (row.get("config_state") or "")[:32],
            "match_state": (row.get("match_state") or "")[:32],
            "protect_side": (row.get("protect_side") or "")[:32],
            "description": (row.get("description") or "")[:255],
            "onu_rx": (row.get("onu_rx") or "")[:32],
            "olt_rx": (row.get("olt_rx") or "")[:32],
            "tx_power": (row.get("tx_power") or "")[:32],
            "signal_bucket": signal_bucket[:16],
            "derived_status": derived_status[:32],
            "status_source": status_source[:32],
            "status_first_seen_at": now,
            "status_updated_at": now,
            "raw_line": (row.get("raw_line") or "")[:2000],
            "synced_at": now,
        }

        existing = existing_map.get(key)
        if existing is None:
            to_create.append(
                ConfiguredONU(
                    olt=olt,
                    frame=key[0],
                    slot=key[1],
                    port=key[2],
                    ont_id=key[3],
                    created_at=now,
                    **payload,
                )
            )
            continue

        existing_status = (existing.derived_status or "").strip()
        existing_source = (existing.status_source or "").strip()
        existing_first_seen = existing.status_first_seen_at
        if existing_status == derived_status and existing_source == status_source and existing_first_seen:
            payload["status_first_seen_at"] = existing_first_seen

        for field, value in payload.items():
            setattr(existing, field, value)
        to_update.append(existing)

    with transaction.atomic():
        if to_create:
            ConfiguredONU.objects.bulk_create(to_create, batch_size=500)
        if to_update:
            ConfiguredONU.objects.bulk_update(
                to_update,
                [
                    "sn",
                    "control_flag",
                    "run_state",
                    "config_state",
                    "match_state",
                    "protect_side",
                    "description",
                    "onu_rx",
                    "olt_rx",
                    "tx_power",
                    "signal_bucket",
                    "derived_status",
                    "status_source",
                    "status_first_seen_at",
                    "status_updated_at",
                    "raw_line",
                    "synced_at",
                ],
                batch_size=500,
            )

    refresh_saved_pon_counts_from_inventory(olt)
    reconcile_offline_onus_with_signal(olt=olt)

    return {
        "status": f"{status} | Database synced: {len(rows)} | New: {len(to_create)}",
        "count": len(rows),
    }


def reconcile_offline_onus_with_signal(olt=None, limit=None):
    from .models import ConfiguredONU

    qs = ConfiguredONU.objects.filter(derived_status="offline").filter(
        Q(signal_bucket__in=["good", "warn", "bad"]) | Q(run_state__iexact="online")
    )
    if olt is not None:
        qs = qs.filter(olt=olt)
        trap_status_map = get_active_onu_trap_status_map(olt)
    else:
        trap_status_map = None

    records = list(qs.order_by("olt_id", "slot", "port", "ont_id")[:limit] if limit else qs.order_by("olt_id", "slot", "port", "ont_id"))
    if not records:
        return {"checked": 0, "updated": 0}

    now = timezone.now()
    updated = []
    checked = 0
    trap_cache = {}

    for record in records:
        checked += 1
        if trap_status_map is None:
            olt_map = trap_cache.get(record.olt_id)
            if olt_map is None:
                olt_map = get_active_onu_trap_status_map(record.olt)
                trap_cache[record.olt_id] = olt_map
            active_trap_status = olt_map.get((int(record.slot or 0), int(record.port or 0), int(record.ont_id or 0)))
        else:
            active_trap_status = trap_status_map.get((int(record.slot or 0), int(record.port or 0), int(record.ont_id or 0)))

        if active_trap_status:
            continue

        record.derived_status = "online"
        record.status_source = "signal_inventory"
        record.status_updated_at = now
        record.status_first_seen_at = now
        updated.append(record)

    if updated:
        ConfiguredONU.objects.bulk_update(
            updated,
            ["derived_status", "status_source", "status_updated_at", "status_first_seen_at"],
            batch_size=500,
        )

    return {"checked": checked, "updated": len(updated)}


def _apply_ont_counts_to_groups(groups, ont_counts):
    for group in groups:
        slot = int(group.get("slot", 0) or 0)
        for row in group.get("ports", []):
            port = int(row.get("port", 0) or 0)
            bucket = ont_counts.get((slot, port))
            if not bucket:
                row["onus"] = "Online:0 Offline:0"
                row["onus_online"] = 0
                row["onus_offline"] = 0
                row.setdefault("sfp_tx", "")
                continue
            row["onus_online"] = int(bucket["online"])
            row["onus_offline"] = int(bucket["offline"])
            row["onus"] = f"Online:{row['onus_online']} Offline:{row['onus_offline']}"
            row.setdefault("sfp_tx", "")


def _parse_dbm_float(value):
    text = str(value or "").strip().lower()
    if not text or text in {"-", "--", "none", "n/a"}:
        return None
    match = re.search(r"-?\d+(?:\.\d+)?", text)
    if not match:
        return None
    try:
        return float(match.group(0))
    except (TypeError, ValueError):
        return None


def _format_average_signal(value):
    if value is None:
        return ""
    return f"{value:.2f}"


def _average_signal_bucket(avg_signal):
    if avg_signal is None:
        return ""
    try:
        value = float(avg_signal)
    except (TypeError, ValueError):
        return ""
    return _signal_bucket_from_dbm_text(f"{value:.2f} dBm")


def _get_ont_counts_from_db(olt):
    from .models import ConfiguredONU

    counts = {}
    total_rows = 0
    for item in ConfiguredONU.objects.filter(olt=olt).values("slot", "port", "run_state"):
        slot = int(item.get("slot") or 0)
        port = int(item.get("port") or 0)
        run_state = str(item.get("run_state") or "").strip().lower()
        bucket = counts.setdefault((slot, port), {"online": 0, "offline": 0})
        total_rows += 1
        if run_state == "online":
            bucket["online"] += 1
        else:
            bucket["offline"] += 1
    return counts, total_rows


def _get_ont_signal_averages_from_db(olt):
    from .models import ConfiguredONU

    samples = {}
    for item in ConfiguredONU.objects.filter(olt=olt).values("slot", "port", "olt_rx"):
        slot = int(item.get("slot") or 0)
        port = int(item.get("port") or 0)
        signal = _parse_dbm_float(item.get("olt_rx"))
        if signal is None:
            continue
        samples.setdefault((slot, port), []).append(signal)
    return {
        key: (sum(values) / len(values))
        for key, values in samples.items()
        if values
    }


def _apply_average_signals_to_groups(groups, signal_averages):
    for group in groups:
        slot = int(group.get("slot", 0) or 0)
        for row in group.get("ports", []):
            port = int(row.get("port", 0) or 0)
            avg_signal = signal_averages.get((slot, port))
            row["average_signal"] = _format_average_signal(avg_signal) if avg_signal is not None else ""
            row["average_signal_bucket"] = _average_signal_bucket(avg_signal)
            row.setdefault("sfp_tx", "")


def _apply_pon_sfp_tx_to_groups(groups, tx_map):
    for group in groups:
        slot = int(group.get("slot", 0) or 0)
        for row in group.get("ports", []):
            port = int(row.get("port", 0) or 0)
            row["sfp_tx"] = tx_map.get((slot, port), row.get("sfp_tx", ""))


def save_pon_ports_snapshot(olt, groups, status):
    olt.pon_ports_cache = groups or []
    olt.pon_ports_status = (status or "")[:300]
    olt.pon_ports_refreshed_at = timezone.now()
    olt.save(update_fields=["pon_ports_cache", "pon_ports_status", "pon_ports_refreshed_at"])


def refresh_saved_pon_counts_from_inventory(olt):
    groups = list(getattr(olt, "pon_ports_cache", []) or [])
    if not groups:
        return False
    counts, _ = _get_ont_counts_from_db(olt)
    signal_averages = _get_ont_signal_averages_from_db(olt)
    if not counts and not signal_averages:
        return False
    if counts:
        _apply_ont_counts_to_groups(groups, counts)
    _apply_average_signals_to_groups(groups, signal_averages)
    _normalize_pon_status_with_ont_counts(groups)
    olt.pon_ports_cache = groups
    olt.pon_ports_refreshed_at = timezone.now()
    olt.save(update_fields=["pon_ports_cache", "pon_ports_refreshed_at"])
    return True


def save_uplink_snapshot(olt, data):
    rows = (data or {}).get("rows") or []
    status = (data or {}).get("status") or ""
    olt.uplink_cache = rows
    olt.uplink_status = status[:300]
    olt.uplink_refreshed_at = timezone.now()
    olt.save(update_fields=["uplink_cache", "uplink_status", "uplink_refreshed_at"])


def _parse_vlan_table(output):
    rows = []
    pending = None
    for raw in str(output or "").splitlines():
        line = raw.strip()
        if not line or not re.match(r"^\d+\b", line):
            if pending and line and not line.lower().startswith(("vlan", "type", "command:", "display vlan all")) and not re.match(r"^-{3,}", line):
                pending["description"] = line
                rows.append(pending)
                pending = None
            continue
        parts = re.split(r"\s+", line)
        if len(parts) < 5:
            continue
        try:
            vlan_id = int(parts[0])
        except (TypeError, ValueError):
            continue
        service_port_num = parts[4].strip() if len(parts) > 4 else "-"
        if not service_port_num:
            service_port_num = "-"
        description = ""
        if len(parts) > 6:
            description = " ".join(parts[6:]).strip()
        row = {
            "vlan_id": vlan_id,
            "service_port_num": service_port_num,
            "description": description,
        }
        if description:
            rows.append(row)
            pending = None
        else:
            if pending:
                rows.append(pending)
            pending = row
    if pending:
        rows.append(pending)
    rows.sort(key=lambda row: row["vlan_id"])
    return rows


def _parse_vlan_description_table(output):
    desc_map = {}
    for raw in str(output or "").splitlines():
        line = raw.strip()
        if not line:
            continue
        if re.search(r"\bwill take a long time\b", line, re.IGNORECASE):
            continue
        match = re.match(r"^\s*(\d+)\s+(.+?)\s*$", line)
        if not match:
            continue
        try:
            vlan_id = int(match.group(1))
        except (TypeError, ValueError):
            continue
        description = match.group(2).strip()
        lowered = description.lower()
        if lowered.startswith(("vlan", "vid", "description", "command:", "display vlan desc", "display vlan description")):
            continue
        if re.match(r"^-{3,}$", description):
            continue
        desc_map[vlan_id] = description
    return desc_map


def _parse_single_vlan_description(output):
    for raw in str(output or "").splitlines():
        line = raw.strip()
        if not line:
            continue
        lowered = line.lower()
        if lowered.startswith(("command:", "display vlan")):
            continue
        match = re.search(r"\bdescription\b\s*[:=]\s*(.+)$", line, re.IGNORECASE)
        if not match:
            continue
        description = match.group(1).strip().strip('"')
        if description and description.lower() not in {"-", "n/a", "null", "none"}:
            return description
    return ""


def _parse_single_vlan_row(output):
    text = str(output or "")
    if not text.strip() or _is_cli_error_text(text):
        return None
    vlan_match = re.search(r"\bVLAN ID:\s*(\d+)", text, re.IGNORECASE)
    if vlan_match:
        service_match = re.search(r"\bService virtual port number:\s*([0-9-]+)", text, re.IGNORECASE)
        description = _parse_single_vlan_description(text) or "-"
        try:
            vlan_id = int(vlan_match.group(1))
        except (TypeError, ValueError):
            return None
        return {
            "vlan_id": vlan_id,
            "service_port_num": (service_match.group(1).strip() if service_match else "-") or "-",
            "description": description,
        }

    table_rows = _parse_vlan_table(text)
    if table_rows:
        return table_rows[0]
    return None


def _compact_dba_output(output):
    merged = []
    current = ""
    for raw in str(output or "").splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.lower().startswith("dba-profile add "):
            if current:
                merged.append(current)
            current = line
            continue
        if current:
            # Wrapped profile rows may continue with "type", "max", numeric tail, or
            # extra keywords such as "bandwidth_compensate".
            current = f"{current} {line}"
            continue
        if current:
            merged.append(current)
            current = ""
    if current:
        merged.append(current)
    return merged


def _format_dba_speed(max_value):
    try:
        max_num = int(str(max_value or "").strip())
    except (TypeError, ValueError):
        return "-"
    mbps = max_num // 1024
    if mbps >= 1000:
        if mbps % 1000 == 0:
            return f"{mbps // 1000}G"
        return f"{mbps}Mbps"
    return f"{mbps}Mbps"


def build_dba_profile_row(profile_id, profile_name, profile_type, dba_speed):
    max_value = int(dba_speed) * 1024
    return {
        "profile_id": int(profile_id),
        "profile_name": str(profile_name).strip(),
        "profile_type": str(profile_type).strip(),
        "dba_speed": _format_dba_speed(max_value),
    }


def _build_dba_profile_command(profile_id, profile_name, profile_type, dba_speed):
    speed_value = int(dba_speed) * 1024
    profile_type = str(profile_type).strip().lower()
    base = f'dba-profile add profile-id {int(profile_id)} profile-name "{profile_name}" {profile_type}'
    if profile_type == "type1":
        return f"{base} fixed {speed_value}"
    if profile_type == "type2":
        return f"{base} assure {speed_value}"
    if profile_type == "type3":
        return f"{base} assure {speed_value} max {speed_value}"
    if profile_type == "type5":
        return f"{base} fixed {speed_value} assure {speed_value} max {speed_value}"
    return f"{base} max {speed_value}"


def _parse_dba_profile_table(output):
    rows = []
    for line in _compact_dba_output(output):
        match = re.search(
            r'dba-profile\s+add\s+profile-id\s+(\d+)\s+profile-name\s+"([^"]+)"\s+type\s*([0-9]+)\b(.*)$',
            line,
            flags=re.IGNORECASE,
        )
        if not match:
            continue
        profile_id = int(match.group(1))
        profile_name = match.group(2).strip()
        profile_type = f"type{match.group(3).strip()}"
        remainder = (match.group(4) or "").strip()
        max_match = re.search(r'\bmax\s+(\d+)\b', remainder, flags=re.IGNORECASE)
        max_value = (max_match.group(1) if max_match else "").strip()
        rows.append(
            {
                "profile_id": profile_id,
                "profile_name": profile_name,
                "profile_type": profile_type,
                "dba_speed": _format_dba_speed(max_value) if max_value else "-",
            }
        )
    rows.sort(key=lambda row: row["profile_id"])
    return rows


def fetch_vlan_snapshot(olt):
    result = {
        "status": "VLAN data unavailable",
        "rows": [],
    }
    tn, status = open_telnet_authenticated_session(olt)
    if tn is None:
        result["status"] = status
        return result

    try:
        _prepare_telnet_cli_session(tn, use_paging=True)
        output = _run_telnet_command(tn, "display vlan all", enter_until_prompt=True)
        rows = _parse_vlan_table(output)
        if not rows:
            time.sleep(0.35)
            retry_output = _run_telnet_command(tn, "display vlan all", enter_until_prompt=True)
            retry_rows = _parse_vlan_table(retry_output)
            if retry_rows:
                output = retry_output
                rows = retry_rows
        desc_map = {}
        desc_output = _run_telnet_command(tn, "display vlan description", enter_until_prompt=True)
        desc_map.update(_parse_vlan_description_table(desc_output))
        if not rows and desc_map:
            time.sleep(0.35)
            retry_output = _run_telnet_command(tn, "display vlan all", enter_until_prompt=True)
            retry_rows = _parse_vlan_table(retry_output)
            if retry_rows:
                output = retry_output
                rows = retry_rows
        if len(desc_map) < len(rows):
            for row in rows:
                vlan_id = int(row.get("vlan_id") or 0)
                if not vlan_id or desc_map.get(vlan_id):
                    continue
                single_output = _run_telnet_command(tn, f"display vlan {vlan_id}", enter_until_prompt=True)
                description = _parse_single_vlan_description(single_output)
                if description:
                    desc_map[vlan_id] = description
        for row in rows:
            row["description"] = desc_map.get(int(row.get("vlan_id") or 0), row.get("description", "")) or "-"
        result["rows"] = rows
        if rows and not desc_map:
            result["status"] = f"VLANs fetched: {len(rows)} | No VLAN descriptions found on OLT"
        else:
            result["status"] = f"VLANs fetched: {len(rows)} | Descriptions mapped: {len(desc_map)}"
        return result
    except (socket.timeout, TimeoutError):
        result["status"] = "Telnet timeout while fetching VLANs."
        return result
    except EOFError:
        result["status"] = "Telnet connection closed while fetching VLANs."
        return result
    except OSError as exc:
        result["status"] = f"Telnet error while fetching VLANs: {exc}"
        return result
    finally:
        _close_telnet_session(tn)


def save_vlan_snapshot(olt, data):
    rows = (data or {}).get("rows") or []
    status = (data or {}).get("status") or ""
    existing_rows = list(getattr(olt, "vlan_cache", []) or [])
    if not rows and existing_rows and "VLANs fetched: 0" in status:
        olt.vlan_cache = existing_rows
        olt.vlan_status = f"{status[:220]} | Retained cached VLAN snapshot: {len(existing_rows)}"
        olt.vlan_refreshed_at = timezone.now()
        olt.save(update_fields=["vlan_cache", "vlan_status", "vlan_refreshed_at"])
        return
    olt.vlan_cache = rows
    olt.vlan_status = status[:300]
    olt.vlan_refreshed_at = timezone.now()
    olt.save(update_fields=["vlan_cache", "vlan_status", "vlan_refreshed_at"])


def fetch_single_vlan(olt, vlan_id):
    result = {
        "ok": False,
        "message": "VLAN not found.",
        "row": None,
    }
    tn, status = open_telnet_authenticated_session(olt)
    if tn is None:
        result["message"] = status
        return result
    try:
        _prepare_telnet_cli_session(tn, use_paging=False)
        output = _run_telnet_command(tn, f"display vlan {int(vlan_id)}", enter_until_prompt=True)
        row = _parse_single_vlan_row(output)
        if row:
            result["ok"] = True
            result["message"] = f"VLAN {int(vlan_id)} fetched."
            result["row"] = row
            return result
        raw_text = str(output or "").strip()
        result["message"] = raw_text or f"VLAN {int(vlan_id)} not found on OLT."
        return result
    except (socket.timeout, TimeoutError):
        result["message"] = "Telnet timeout while verifying VLAN."
        return result
    except EOFError:
        result["message"] = "Telnet connection closed while verifying VLAN."
        return result
    except OSError as exc:
        result["message"] = f"Telnet error while verifying VLAN: {exc}"
        return result
    finally:
        _close_telnet_session(tn)


def fetch_ont_optical_subset_meta(olt, onu_keys):
    payload = {
        "items": {},
        "ok": False,
        "status": "",
        "successful_ports": set(),
        "requested_ports": set(),
    }
    if not onu_keys:
        payload["ok"] = True
        return payload

    slot_ports = sorted({(int(slot), int(port)) for slot, port, _ in onu_keys})
    payload["requested_ports"] = set(slot_ports)
    tn, status = open_telnet_authenticated_session(olt)
    if tn is None:
        payload["status"] = status or "Telnet session could not be opened."
        return payload

    try:
        _prepare_telnet_cli_session(tn, use_paging=True)
        optical_map, successful_ports = _fetch_ont_optical_map_in_context(tn, slot_ports)
        payload["successful_ports"] = set(successful_ports)
        payload["ok"] = bool(successful_ports)
        payload["status"] = f"Ports fetched: {len(successful_ports)}/{len(slot_ports)}"
        for key in onu_keys:
            slot, port, ont_id = int(key[0]), int(key[1]), int(key[2])
            payload["items"][(slot, port, ont_id)] = optical_map.get((slot, port, ont_id), {
                "onu_rx": "--",
                "tx_power": "--",
                "olt_rx": "--",
            })
        return payload
    except (socket.timeout, TimeoutError):
        payload["status"] = "Telnet timeout while fetching ONU optical data."
        return payload
    except EOFError:
        payload["status"] = "Telnet connection closed while fetching ONU optical data."
        return payload
    except OSError as exc:
        payload["status"] = f"Telnet error while fetching ONU optical data: {exc}"
        return payload
    finally:
        _close_telnet_session(tn)


def _parse_ont_duration_to_seconds(text):
    raw = str(text or "").strip()
    if not raw:
        return None
    match = re.search(
        r"(?i)(\d+)\s+day\(s\),\s*(\d+)\s+hour\(s\),\s*(\d+)\s+minute\(s\)(?:,\s*(\d+)\s+second\(s\))?",
        raw,
    )
    if not match:
        return None
    days = int(match.group(1))
    hours = int(match.group(2))
    minutes = int(match.group(3))
    seconds = int(match.group(4) or 0)
    return (((days * 24) + hours) * 60 + minutes) * 60 + seconds


def _parse_ont_runtime_snapshot(output):
    text = str(output or "")
    run_state_match = re.search(r"(?im)^\s*Run\s+state\s*:\s*(.+)$", text)
    config_state_match = re.search(r"(?im)^\s*Config\s+state\s*:\s*(.+)$", text)
    control_flag_match = re.search(r"(?im)^\s*Control\s+flag\s*:\s*(.+)$", text)
    last_down_cause_match = re.search(r"(?im)^\s*Last\s+down\s+cause\s*:\s*(.+)$", text)
    battery_state_match = re.search(r"(?im)^\s*ONT\s+battery\s+state\s*:\s*(.+)$", text)
    attached_vlans_match = re.search(r"(?im)^\s*Attached\s+VLANs\s*:\s*(.+)$", text)
    onu_mode_match = re.search(r"(?im)^\s*ONU\s+mode\s*:\s*(.+)$", text)
    equipment_match = re.search(r"(?im)^\s*ONT\s+equipment\s*id\s*:\s*(.+)$", text)
    distance_match = re.search(r"(?im)^\s*ONT\s+distance\(m\)\s*:\s*(.+)$", text)
    return {
        "online_duration": (re.search(r"(?im)^\s*ONT\s+online\s+duration\s*:\s*(.+)$", text) or [None, ""])[1].strip() if re.search(r"(?im)^\s*ONT\s+online\s+duration\s*:\s*(.+)$", text) else "",
        "last_up_time": (re.search(r"(?im)^\s*Last\s+up\s+time\s*:\s*(.+)$", text) or [None, ""])[1].strip() if re.search(r"(?im)^\s*Last\s+up\s+time\s*:\s*(.+)$", text) else "",
        "last_down_time": (re.search(r"(?im)^\s*Last\s+down\s+time\s*:\s*(.+)$", text) or [None, ""])[1].strip() if re.search(r"(?im)^\s*Last\s+down\s+time\s*:\s*(.+)$", text) else "",
        "ont_equipment_id": (equipment_match.group(1).strip() if equipment_match else ""),
        "run_state": (run_state_match.group(1).strip() if run_state_match else ""),
        "config_state": (config_state_match.group(1).strip() if config_state_match else ""),
        "control_flag": (control_flag_match.group(1).strip() if control_flag_match else ""),
        "last_down_cause": (last_down_cause_match.group(1).strip() if last_down_cause_match else ""),
        "battery_state": (battery_state_match.group(1).strip() if battery_state_match else ""),
        "attached_vlans": (attached_vlans_match.group(1).strip() if attached_vlans_match else ""),
        "onu_mode": (onu_mode_match.group(1).strip() if onu_mode_match else ""),
        "ont_distance_m": (distance_match.group(1).strip() if distance_match else ""),
        "output": text.strip(),
    }


def fetch_single_ont_runtime_snapshot(olt, slot, port, ont_id):
    result = {
        "online_duration": "",
        "last_up_time": "",
        "last_down_time": "",
        "ont_equipment_id": "",
        "run_state": "",
        "config_state": "",
        "control_flag": "",
        "last_down_cause": "",
        "battery_state": "",
        "attached_vlans": "",
        "onu_mode": "",
        "ont_distance_m": "",
        "output": "",
    }
    tn, status = open_telnet_authenticated_session(olt)
    if tn is None:
        return result

    try:
        _prepare_telnet_cli_session(tn, use_paging=True)
        output = _run_telnet_command(
            tn,
            f"display ont info 0 {int(slot)} {int(port)} {int(ont_id)}",
            enter_until_prompt=True,
        )
        parsed = _parse_ont_runtime_snapshot(output)
        return parsed or result
    except (socket.timeout, TimeoutError, EOFError, OSError):
        return result
    finally:
        try:
            _run_telnet_command(tn, "quit")
            _run_telnet_command(tn, "quit")
        except Exception:
            pass
        _close_telnet_session(tn)


def _parse_ont_capability_snapshot(output):
    text = str(output or "")

    def _pick(pattern):
        match = re.search(pattern, text, flags=re.IGNORECASE | re.MULTILINE)
        return match.group(1).strip() if match else ""

    return {
        "equipment_id": _pick(r"^\s*Equipment\s+ID\s*:\s*(.+)$"),
        "uplink_pon_ports": _pick(r"^\s*Number\s+of\s+uplink\s+PON\s+ports\s*:\s*(.+)$"),
        "pots_ports": _pick(r"^\s*Number\s+of\s+POTS\s+ports\s*:\s*(.+)$"),
        "eth_ports": _pick(r"^\s*Number\s+of\s+ETH\s+ports\s*:\s*(.+)$"),
        "catv_uni_ports": _pick(r"^\s*Number\s+of\s+CATV\s+UNI\s+ports\s*:\s*(.+)$"),
        "output": text.strip(),
    }


def fetch_single_ont_capability_snapshot(olt, slot, port, ont_id):
    result = {
        "equipment_id": "",
        "uplink_pon_ports": "",
        "pots_ports": "",
        "eth_ports": "",
        "catv_uni_ports": "",
        "output": "",
    }
    tn, status = open_telnet_authenticated_session(olt)
    if tn is None:
        return result

    try:
        _prepare_telnet_cli_session(tn, use_paging=True)
        commands = (
            f"display ont capability 0/{int(slot)} {int(port)} {int(ont_id)}",
            f"display ont capability 0 {int(slot)} {int(port)} {int(ont_id)}",
        )
        best = result
        for command in commands:
            output = _run_telnet_command(
                tn,
                command,
                enter_until_prompt=True,
            )
            parsed = _parse_ont_capability_snapshot(output)
            if any(str(parsed.get(key) or "").strip() for key in ("equipment_id", "uplink_pon_ports", "pots_ports", "eth_ports", "catv_uni_ports")):
                return parsed
            if str(output or "").strip():
                best = dict(parsed or result)
                best["output"] = str(output or "").strip()
        return best
    except (socket.timeout, TimeoutError, EOFError, OSError):
        return result
    finally:
        try:
            _run_telnet_command(tn, "quit")
            _run_telnet_command(tn, "quit")
        except Exception:
            pass
        _close_telnet_session(tn)


def fetch_single_ont_detail_bundle(olt, slot, port, ont_id, include_optical=False, include_capability=True):
    runtime_result = {
        "online_duration": "",
        "last_up_time": "",
        "last_down_time": "",
        "ont_equipment_id": "",
        "run_state": "",
        "config_state": "",
        "control_flag": "",
        "last_down_cause": "",
        "battery_state": "",
        "attached_vlans": "",
        "onu_mode": "",
        "ont_distance_m": "",
        "output": "",
    }
    capability_result = {
        "equipment_id": "",
        "uplink_pon_ports": "",
        "pots_ports": "",
        "eth_ports": "",
        "catv_uni_ports": "",
        "output": "",
    }
    optical_result = {
        "onu_rx": "",
        "olt_rx": "",
        "tx_power": "",
    }
    tn, status = open_telnet_authenticated_session(olt)
    if tn is None:
        return {
            "runtime_snapshot": runtime_result,
            "capability_snapshot": capability_result,
            "live_signal": optical_result,
        }

    try:
        _prepare_telnet_cli_session(tn, use_paging=True)

        runtime_output = _run_telnet_command(
            tn,
            f"display ont info 0 {int(slot)} {int(port)} {int(ont_id)}",
            enter_until_prompt=True,
        )
        parsed_runtime = _parse_ont_runtime_snapshot(runtime_output)
        if parsed_runtime:
            runtime_result = parsed_runtime

        if include_capability:
            capability_commands = (
                f"display ont capability 0/{int(slot)} {int(port)} {int(ont_id)}",
                f"display ont capability 0 {int(slot)} {int(port)} {int(ont_id)}",
            )
            best_capability = capability_result
            for command in capability_commands:
                capability_output = _run_telnet_command(
                    tn,
                    command,
                    enter_until_prompt=True,
                )
                parsed_capability = _parse_ont_capability_snapshot(capability_output)
                if any(str(parsed_capability.get(key) or "").strip() for key in ("equipment_id", "uplink_pon_ports", "pots_ports", "eth_ports", "catv_uni_ports")):
                    capability_result = parsed_capability
                    break
                if str(capability_output or "").strip():
                    best_capability = dict(parsed_capability or capability_result)
                    best_capability["output"] = str(capability_output or "").strip()
            else:
                capability_result = best_capability

        if include_optical:
            optical_result = fetch_single_ont_optical_info(olt, slot, port, ont_id) or optical_result

        return {
            "runtime_snapshot": runtime_result,
            "capability_snapshot": capability_result,
            "live_signal": optical_result,
        }
    except (socket.timeout, TimeoutError, EOFError, OSError):
        return {
            "runtime_snapshot": runtime_result,
            "capability_snapshot": capability_result,
            "live_signal": optical_result,
        }
    finally:
        try:
            _run_telnet_command(tn, "quit")
            _run_telnet_command(tn, "quit")
        except Exception:
            pass
        _close_telnet_session(tn)


def sync_onu_capabilities_for_olt(olt, limit=None, start_pk=None):
    from django.utils import timezone
    from .models import ConfiguredONU

    qs = ConfiguredONU.objects.filter(olt=olt).order_by("id")
    wrapped = False
    if start_pk:
        records = list(qs.filter(id__gt=int(start_pk))[:limit] if limit else qs.filter(id__gt=int(start_pk)))
        if not records:
            records = list(qs[:limit] if limit else qs)
            wrapped = True
    else:
        records = list(qs[:limit] if limit else qs)

    if not records:
        return {"olt": olt.name, "checked": 0, "updated": 0, "status": "No ONU capability records to check.", "last_pk": start_pk or 0, "wrapped": wrapped}

    tn, status = open_telnet_authenticated_session(olt)
    if tn is None:
        return {"olt": olt.name, "checked": 0, "updated": 0, "status": status, "last_pk": start_pk or 0, "wrapped": wrapped}

    checked = 0
    updated = 0
    bulk = []
    now = timezone.now()
    try:
        _prepare_telnet_cli_session(tn, use_paging=True)
        for record in records:
            checked += 1
            capability_commands = (
                f"display ont capability 0/{int(record.slot)} {int(record.port)} {int(record.ont_id)}",
                f"display ont capability 0 {int(record.slot)} {int(record.port)} {int(record.ont_id)}",
            )
            snapshot = {}
            for command in capability_commands:
                output = _run_telnet_command(tn, command, enter_until_prompt=True)
                parsed = _parse_ont_capability_snapshot(output)
                if any(str(parsed.get(key) or "").strip() for key in ("equipment_id", "uplink_pon_ports", "pots_ports", "eth_ports", "catv_uni_ports")):
                    snapshot = parsed
                    break
                if not snapshot and str(output or "").strip():
                    snapshot = parsed

            onu_type_value = (snapshot.get("equipment_id") or "").strip()[:128]
            uplink_value = (snapshot.get("uplink_pon_ports") or "").strip()[:32]
            pots_value = (snapshot.get("pots_ports") or "").strip()[:32]
            eth_value = (snapshot.get("eth_ports") or "").strip()[:32]
            catv_value = (snapshot.get("catv_uni_ports") or "").strip()[:32]

            changed = False
            if onu_type_value != (record.onu_type_cache or ""):
                record.onu_type_cache = onu_type_value
                changed = True
            if uplink_value != (record.uplink_pon_ports_cache or ""):
                record.uplink_pon_ports_cache = uplink_value
                changed = True
            if pots_value != (record.pots_ports_cache or ""):
                record.pots_ports_cache = pots_value
                changed = True
            if eth_value != (record.eth_ports_cache or ""):
                record.eth_ports_cache = eth_value
                changed = True
            if catv_value != (record.catv_uni_ports_cache or ""):
                record.catv_uni_ports_cache = catv_value
                changed = True
            if changed or not record.capability_synced_at:
                record.capability_synced_at = now
                bulk.append(record)
                updated += 1 if changed else 0

        if bulk:
            ConfiguredONU.objects.bulk_update(
                bulk,
                [
                    "onu_type_cache",
                    "uplink_pon_ports_cache",
                    "pots_ports_cache",
                    "eth_ports_cache",
                    "catv_uni_ports_cache",
                    "capability_synced_at",
                ],
                batch_size=200,
            )
        return {
            "olt": olt.name,
            "checked": checked,
            "updated": updated,
            "status": f"Checked {checked}, updated {updated}",
            "last_pk": records[-1].id if records else (start_pk or 0),
            "wrapped": wrapped,
        }
    except (socket.timeout, TimeoutError):
        return {
            "olt": olt.name,
            "checked": checked,
            "updated": updated,
            "status": "Telnet timeout during capability sync.",
            "last_pk": records[-1].id if records else (start_pk or 0),
            "wrapped": wrapped,
        }
    except (EOFError, OSError) as exc:
        return {
            "olt": olt.name,
            "checked": checked,
            "updated": updated,
            "status": f"Telnet error during capability sync: {exc}",
            "last_pk": records[-1].id if records else (start_pk or 0),
            "wrapped": wrapped,
        }
    finally:
        _close_telnet_session(tn)


def _sync_record_detail_fields_via_telnet(tn, record, now=None):
    now = now or timezone.now()

    runtime_output = _run_telnet_command(
        tn,
        f"display ont info 0 {int(record.slot)} {int(record.port)} {int(record.ont_id)}",
        enter_until_prompt=True,
    )
    runtime_snapshot = _parse_ont_runtime_snapshot(runtime_output) or {}

    capability_snapshot = {}
    capability_commands = (
        f"display ont capability 0/{int(record.slot)} {int(record.port)} {int(record.ont_id)}",
        f"display ont capability 0 {int(record.slot)} {int(record.port)} {int(record.ont_id)}",
    )
    for command in capability_commands:
        output = _run_telnet_command(tn, command, enter_until_prompt=True)
        parsed = _parse_ont_capability_snapshot(output) or {}
        if any(str(parsed.get(key) or "").strip() for key in ("equipment_id", "uplink_pon_ports", "pots_ports", "eth_ports", "catv_uni_ports")):
            capability_snapshot = parsed
            break
        if not capability_snapshot and str(output or "").strip():
            capability_snapshot = parsed

    changed = False
    mapped_values = {
        "onu_type_cache": (capability_snapshot.get("equipment_id") or runtime_snapshot.get("ont_equipment_id") or "").strip()[:128],
        "uplink_pon_ports_cache": (capability_snapshot.get("uplink_pon_ports") or "").strip()[:32],
        "pots_ports_cache": (capability_snapshot.get("pots_ports") or "").strip()[:32],
        "eth_ports_cache": (capability_snapshot.get("eth_ports") or "").strip()[:32],
        "catv_uni_ports_cache": (capability_snapshot.get("catv_uni_ports") or "").strip()[:32],
        "ont_distance_m": (runtime_snapshot.get("ont_distance_m") or "").strip()[:32],
    }

    for field_name, value in mapped_values.items():
        if value != (getattr(record, field_name, "") or ""):
            setattr(record, field_name, value)
            changed = True

    if changed or not record.capability_synced_at:
        record.capability_synced_at = now

    return {
        "record": record,
        "changed": changed,
        "runtime_snapshot": runtime_snapshot,
        "capability_snapshot": capability_snapshot,
    }


def sync_single_onu_detail_fields(olt, slot, port, ont_id, *, record=None):
    from .models import ConfiguredONU

    record = record or ConfiguredONU.objects.filter(
        olt=olt,
        slot=slot,
        port=port,
        ont_id=ont_id,
    ).first()
    if record is None:
        return {"ok": False, "updated": False, "status": "ONU record not found."}

    tn, status = open_telnet_authenticated_session(olt)
    if tn is None:
        return {"ok": False, "updated": False, "status": status or "Telnet session could not be opened."}

    try:
        _prepare_telnet_cli_session(tn, use_paging=True)
        result = _sync_record_detail_fields_via_telnet(tn, record, now=timezone.now())
        snmp_distance = fetch_single_onu_snmp_distance(olt, slot, port, ont_id).get("ont_distance_m", "").strip()[:32]
        if snmp_distance != (record.ont_distance_m or ""):
            record.ont_distance_m = snmp_distance
            result["changed"] = True
        record.save(
            update_fields=[
                "onu_type_cache",
                "uplink_pon_ports_cache",
                "pots_ports_cache",
                "eth_ports_cache",
                "catv_uni_ports_cache",
                "ont_distance_m",
                "capability_synced_at",
            ]
        )
        return {
            "ok": True,
            "updated": bool(result["changed"]),
            "status": "ONU detail fields synced.",
        }
    except (socket.timeout, TimeoutError):
        return {"ok": False, "updated": False, "status": "Telnet timeout during ONU detail sync."}
    except (EOFError, OSError) as exc:
        return {"ok": False, "updated": False, "status": f"Telnet error during ONU detail sync: {exc}"}
    finally:
        _close_telnet_session(tn)


def sync_onu_detail_fields_for_olt(olt, limit=None, start_pk=None):
    from .models import ConfiguredONU

    qs = ConfiguredONU.objects.filter(olt=olt).order_by("id")
    wrapped = False
    if start_pk:
        records = list(qs.filter(id__gt=int(start_pk))[:limit] if limit else qs.filter(id__gt=int(start_pk)))
        if not records:
            records = list(qs[:limit] if limit else qs)
            wrapped = True
    else:
        records = list(qs[:limit] if limit else qs)

    if not records:
        return {"olt": olt.name, "checked": 0, "updated": 0, "status": "No ONU detail records to check.", "last_pk": start_pk or 0, "wrapped": wrapped}

    tn, status = open_telnet_authenticated_session(olt)
    if tn is None:
        return {"olt": olt.name, "checked": 0, "updated": 0, "status": status, "last_pk": start_pk or 0, "wrapped": wrapped}

    checked = 0
    updated = 0
    bulk = []
    now = timezone.now()
    distance_map = (fetch_olt_snmp_distance_map(olt).get("items") or {})
    try:
        _prepare_telnet_cli_session(tn, use_paging=True)
        for record in records:
            checked += 1
            result = _sync_record_detail_fields_via_telnet(tn, record, now=now)
            snmp_distance = (distance_map.get((int(record.slot), int(record.port), int(record.ont_id))) or "").strip()[:32]
            if snmp_distance != (record.ont_distance_m or ""):
                record.ont_distance_m = snmp_distance
                result["changed"] = True
            if result["changed"]:
                updated += 1
            bulk.append(record)

        if bulk:
            ConfiguredONU.objects.bulk_update(
                bulk,
                [
                    "onu_type_cache",
                    "uplink_pon_ports_cache",
                    "pots_ports_cache",
                    "eth_ports_cache",
                    "catv_uni_ports_cache",
                    "ont_distance_m",
                    "capability_synced_at",
                ],
                batch_size=200,
            )
        return {
            "olt": olt.name,
            "checked": checked,
            "updated": updated,
            "status": f"Checked {checked}, updated {updated}",
            "last_pk": records[-1].id if records else (start_pk or 0),
            "wrapped": wrapped,
        }
    except (socket.timeout, TimeoutError):
        return {
            "olt": olt.name,
            "checked": checked,
            "updated": updated,
            "status": "Telnet timeout during ONU detail sync.",
            "last_pk": records[-1].id if records else (start_pk or 0),
            "wrapped": wrapped,
        }
    except (EOFError, OSError) as exc:
        return {
            "olt": olt.name,
            "checked": checked,
            "updated": updated,
            "status": f"Telnet error during ONU detail sync: {exc}",
            "last_pk": records[-1].id if records else (start_pk or 0),
            "wrapped": wrapped,
        }
    finally:
        _close_telnet_session(tn)


def fetch_single_ont_running_config(olt, slot, port, ont_id):
    result = {
        "ok": False,
        "command": f"display current-configuration ont 0/{int(slot)}/{int(port)} {int(ont_id)}",
        "output": "",
        "message": "",
    }
    tn, status = open_telnet_authenticated_session(olt)
    if tn is None:
        result["message"] = status or "Telnet session could not be opened."
        return result

    try:
        _prepare_telnet_cli_session(tn, use_paging=True)
        primary_command = f"display current-configuration ont 0/{int(slot)}/{int(port)} {int(ont_id)}"
        service_port_command = f"display current-configuration | include 0/{int(slot)}/{int(port)} ont {int(ont_id)} gem"

        def _clean_running_config_output(command_text, output_text):
            cleaned_text = _clean_cli_transcript_block(command_text, output_text)
            cleaned_text = re.sub(r"(?im)^\s*enable\s*$", "", cleaned_text)
            cleaned_text = re.sub(r"(?im)^\s*Command:\s*$", "", cleaned_text)
            cleaned_text = re.sub(r"(?im)^\s*scroll\s+512\s*$", "", cleaned_text)
            cleaned_text = re.sub(r"(?im)^[^\r\n]*display\s+current-configuration[^\r\n]*$", "", cleaned_text)
            cleaned_text = re.sub(r"(?im)^[^\r\n]*\{\s*<cr>\|[^\r\n]*\}\s*:\s*$", "", cleaned_text)
            cleaned_text = re.sub(r"(?im)^\s*it\s+will\s+take\s+a\s+long\s+time.*$", "", cleaned_text)
            cleaned_text = re.sub(r"(?im)^\s*you\s+can\s+press\s+ctrl_c\s+to\s+break\s*$", "", cleaned_text)
            cleaned_text = re.sub(r"(?im)^\s*return\s*$", "", cleaned_text)
            cleaned_text = re.sub(r"(?im)^\s*\^\s*$", "", cleaned_text)
            cleaned_text = re.sub(r"(?im)^%.*$", "", cleaned_text)
            cleaned_text = re.sub(r"(?im)^[A-Z0-9._-]+(?:\([^)]+\))?[#>]\s*$", "", cleaned_text)
            cleaned_text = re.sub(r"(?im)^\s*(?:-{2,}|={2,})\s*$", "", cleaned_text)
            cleaned_text = "\n".join(line.rstrip() for line in cleaned_text.splitlines())
            cleaned_text = re.sub(r"\n{3,}", "\n\n", cleaned_text).strip()
            return cleaned_text

        def _extract_primary_lines(output_text):
            filtered = []
            for raw_line in str(output_text or "").splitlines():
                line = raw_line.rstrip()
                stripped = line.strip()
                lowered = stripped.lower()
                if not stripped:
                    continue
                if lowered.startswith("interface gpon "):
                    filtered.append(stripped)
                    continue
                if lowered.startswith("ont add "):
                    filtered.append(stripped)
                    continue
                if lowered.startswith("ont-srvprofile-id "):
                    filtered.append(stripped)
                    continue
            deduped = []
            for line in filtered:
                if line not in deduped:
                    deduped.append(line)
            return deduped

        def _extract_service_port_lines(output_text):
            filtered = []
            ont_token = f"ont {int(ont_id)}"
            slot_port_token = f"0/{int(slot)}/{int(port)}"
            for raw_line in str(output_text or "").splitlines():
                stripped = raw_line.strip()
                lowered = stripped.lower()
                if not stripped:
                    continue
                if not lowered.startswith("service-port "):
                    continue
                if slot_port_token in stripped and ont_token in lowered:
                    filtered.append(stripped)
            deduped = []
            for line in filtered:
                if line not in deduped:
                    deduped.append(line)
            return deduped

        primary_output = _run_telnet_bulk_command(tn, primary_command, max_wait_seconds=55)
        service_port_output = _run_telnet_bulk_command(tn, service_port_command, max_wait_seconds=55)
        primary_lines = _extract_primary_lines(_clean_running_config_output(primary_command, primary_output))
        service_port_lines = _extract_service_port_lines(_clean_running_config_output(service_port_command, service_port_output))

        final_sections = []
        if primary_lines:
            final_sections.append("\n".join(primary_lines))
        if service_port_lines:
            final_sections.append("\n".join(service_port_lines))
        final_output = "\n\n".join(section for section in final_sections if section).strip()

        if final_output:
            result["ok"] = True
            result["command"] = f"{primary_command}\n{service_port_command}"
            result["output"] = final_output[:16000]
            result["message"] = "Live running configuration fetched."
            return result

        result["command"] = f"{primary_command}\n{service_port_command}"
        result["message"] = "No running configuration output returned."
        return result
    except (socket.timeout, TimeoutError):
        result["message"] = "Running configuration command timed out."
        return result
    except (EOFError, OSError) as exc:
        result["message"] = f"Running configuration fetch failed: {exc}"
        return result
    finally:
        try:
            _run_telnet_command(tn, "quit")
            _run_telnet_command(tn, "quit")
        except Exception:
            pass
        _close_telnet_session(tn)


def _parse_attached_vlans_from_service_port_output(output_text):
    vlan_ids = []
    for raw_line in str(output_text or "").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        lower_line = line.lower()
        if "service-port" not in lower_line:
            continue
        for match in re.finditer(r"(?i)\bvlan\s+(\d+)\b", line):
            vlan_id = match.group(1)
            if vlan_id not in vlan_ids:
                vlan_ids.append(vlan_id)
    return ",".join(vlan_ids)


def _parse_service_port_all_vlan_map(output_text):
    vlan_map = {}
    for raw_line in str(output_text or "").splitlines():
        line = " ".join(raw_line.strip().split())
        if not line:
            continue
        if not re.match(r"^\d+\s+\d+\b", line):
            continue
        tokens = line.split()
        if len(tokens) < 8:
            continue
        try:
            vlan_id = str(int(tokens[1]))
        except (TypeError, ValueError):
            continue

        port_type_idx = next((idx for idx, token in enumerate(tokens) if token.lower() in {"gpon", "epon"}), -1)
        if port_type_idx < 0 or (port_type_idx + 2) >= len(tokens):
            continue

        frame = slot = port = ont_id = None
        fsp_inline = re.match(r"^(\d+)\s*/\s*(\d+)\s*/\s*(\d+)$", tokens[port_type_idx + 1])
        if fsp_inline:
            frame = int(fsp_inline.group(1))
            slot = int(fsp_inline.group(2))
            try:
                ont_id = int(tokens[port_type_idx + 2])
            except (TypeError, ValueError):
                ont_id = None
            port = int(fsp_inline.group(3))
        else:
            fsp_split = re.match(r"^(\d+)\s*/\s*(\d+)$", tokens[port_type_idx + 1])
            port_split = re.match(r"^/\s*(\d+)$", tokens[port_type_idx + 2])
            if fsp_split and port_split and (port_type_idx + 3) < len(tokens):
                frame = int(fsp_split.group(1))
                slot = int(fsp_split.group(2))
                port = int(port_split.group(1))
                try:
                    ont_id = int(tokens[port_type_idx + 3])
                except (TypeError, ValueError):
                    ont_id = None

        if None in {frame, slot, port, ont_id}:
            continue

        key = (frame, slot, port, ont_id)
        bucket = vlan_map.setdefault(key, [])
        if vlan_id not in bucket:
            bucket.append(vlan_id)

    return {key: ",".join(vlans[:32])[:255] for key, vlans in vlan_map.items()}


def _fetch_service_port_all_vlan_map(tn):
    command = "display service-port all"
    output = _run_service_port_all_command(tn, max_wait_seconds=45)
    return {
        "command": command,
        "output": output,
        "vlan_map": _parse_service_port_all_vlan_map(output),
    }


def _sync_record_attached_vlans_via_telnet(tn, record, now=None):
    now = now or timezone.now()
    command = f"display current-configuration | include 0/{int(record.slot)}/{int(record.port)} ont {int(record.ont_id)} gem"
    output = _run_telnet_bulk_command(tn, command, max_wait_seconds=35)
    vlan_value = _parse_attached_vlans_from_service_port_output(output)[:255]
    changed = vlan_value != (record.attached_vlans_cache or "")
    record.attached_vlans_cache = vlan_value
    record.attached_vlans_synced_at = now
    return {
        "record": record,
        "changed": changed,
        "vlan_value": vlan_value,
        "command": command,
        "output": output,
    }


def sync_single_onu_attached_vlans(olt, slot, port, ont_id, *, record=None):
    from .models import ConfiguredONU

    record = record or ConfiguredONU.objects.filter(
        olt=olt,
        slot=slot,
        port=port,
        ont_id=ont_id,
    ).first()
    if record is None:
        return {"ok": False, "updated": False, "status": "ONU record not found.", "vlan_value": ""}

    tn, status = open_telnet_authenticated_session(olt)
    if tn is None:
        return {
            "ok": False,
            "updated": False,
            "status": status or "Telnet session could not be opened.",
            "vlan_value": (record.attached_vlans_cache or ""),
        }

    try:
        _prepare_telnet_cli_session(tn, use_paging=True)
        now = timezone.now()
        service_port_all = _fetch_service_port_all_vlan_map(tn)
        vlan_map = service_port_all.get("vlan_map") or {}
        vlan_value = (vlan_map.get((int(record.frame or 0), int(record.slot), int(record.port), int(record.ont_id))) or "")[:255]
        changed = vlan_value != (record.attached_vlans_cache or "")
        record.attached_vlans_cache = vlan_value
        record.attached_vlans_synced_at = now
        record.save(update_fields=["attached_vlans_cache", "attached_vlans_synced_at"])
        return {
            "ok": True,
            "updated": bool(changed),
            "status": "ONU attached VLANs synced.",
            "vlan_value": vlan_value,
        }
    except (socket.timeout, TimeoutError):
        return {
            "ok": False,
            "updated": False,
            "status": "Telnet timeout during VLAN sync.",
            "vlan_value": (record.attached_vlans_cache or ""),
        }
    except (EOFError, OSError) as exc:
        return {
            "ok": False,
            "updated": False,
            "status": f"Telnet error during VLAN sync: {exc}",
            "vlan_value": (record.attached_vlans_cache or ""),
        }
    finally:
        _close_telnet_session(tn)


def sync_onu_attached_vlans_for_olt(olt, limit=None, start_pk=None):
    from django.utils import timezone
    from .models import ConfiguredONU

    qs = ConfiguredONU.objects.filter(olt=olt).order_by("id")
    wrapped = False
    if start_pk:
        records = list(qs.filter(id__gt=int(start_pk))[:limit] if limit else qs.filter(id__gt=int(start_pk)))
        if not records:
            records = list(qs[:limit] if limit else qs)
            wrapped = True
    else:
        records = list(qs[:limit] if limit else qs)

    if not records:
        return {"olt": olt.name, "checked": 0, "updated": 0, "status": "No ONU VLAN records to check.", "last_pk": start_pk or 0, "wrapped": wrapped}

    tn, status = open_telnet_authenticated_session(olt)
    if tn is None:
        return {"olt": olt.name, "checked": 0, "updated": 0, "status": status, "last_pk": start_pk or 0, "wrapped": wrapped}

    checked = 0
    updated = 0
    bulk = []
    now = timezone.now()
    try:
        _prepare_telnet_cli_session(tn, use_paging=True)
        service_port_all = _fetch_service_port_all_vlan_map(tn)
        vlan_map = service_port_all.get("vlan_map") or {}
        for record in records:
            checked += 1
            vlan_value = (vlan_map.get((int(record.frame or 0), int(record.slot), int(record.port), int(record.ont_id))) or "")[:255]
            changed = vlan_value != (record.attached_vlans_cache or "")
            record.attached_vlans_cache = vlan_value
            record.attached_vlans_synced_at = now
            if changed:
                updated += 1
            bulk.append(record)

        if bulk:
            ConfiguredONU.objects.bulk_update(
                bulk,
                [
                    "attached_vlans_cache",
                    "attached_vlans_synced_at",
                ],
                batch_size=200,
            )
        return {
            "olt": olt.name,
            "checked": checked,
            "updated": updated,
            "status": f"Service-port all checked {checked}, updated {updated}, rows {len(vlan_map)}",
            "last_pk": records[-1].id if records else (start_pk or 0),
            "wrapped": True,
        }
    except (socket.timeout, TimeoutError):
        return {
            "olt": olt.name,
            "checked": checked,
            "updated": updated,
            "status": "Telnet timeout during VLAN sync.",
            "last_pk": records[-1].id if records else (start_pk or 0),
            "wrapped": wrapped,
        }
    except (EOFError, OSError) as exc:
        return {
            "olt": olt.name,
            "checked": checked,
            "updated": updated,
            "status": f"Telnet error during VLAN sync: {exc}",
            "last_pk": records[-1].id if records else (start_pk or 0),
            "wrapped": wrapped,
        }
    finally:
        _close_telnet_session(tn)


def fetch_single_ont_live_status(olt, slot, port, ont_id):
    result = {
        "ok": False,
        "command": f"display ont info 0 {int(slot)} {int(port)} {int(ont_id)}",
        "output": "",
        "message": "",
    }
    tn, status = open_telnet_authenticated_session(olt)
    if tn is None:
        result["message"] = status or "Telnet session could not be opened."
        return result

    try:
        _prepare_telnet_cli_session(tn, use_paging=True)
        command = f"display ont info 0 {int(slot)} {int(port)} {int(ont_id)}"
        output = _run_telnet_bulk_command(tn, command, max_wait_seconds=35)
        cleaned = _clean_cli_transcript_block(command, output)
        cleaned = re.sub(r"(?im)^\s*Command:\s*$", "", cleaned)
        cleaned = re.sub(r"(?im)^\s*scroll\s+512\s*$", "", cleaned)
        cleaned = re.sub(r"(?im)^[^\r\n]*display\s+ont\s+info[^\r\n]*$", "", cleaned)
        cleaned = re.sub(r"(?im)^[^\r\n]*\{\s*<cr>\|[^\r\n]*\}\s*:\s*$", "", cleaned)
        cleaned = re.sub(r"(?im)^\s*it\s+will\s+take\s+a\s+long\s+time.*$", "", cleaned)
        cleaned = re.sub(r"(?im)^\s*you\s+can\s+press\s+ctrl_c\s+to\s+break\s*$", "", cleaned)
        cleaned = re.sub(r"(?im)^\s*return\s*$", "", cleaned)
        cleaned = re.sub(r"(?im)^\s*\^\s*$", "", cleaned)
        cleaned = re.sub(r"(?im)^%.*$", "", cleaned)
        cleaned = re.sub(r"(?is)\n?\s*Note:\s*F--Frame.*$", "", cleaned)
        cleaned = re.sub(r"\n{3,}", "\n\n", cleaned).strip()
        if cleaned:
            result["ok"] = True
            result["output"] = cleaned[:20000]
            result["message"] = "Live ONU status fetched."
            return result
        result["message"] = "No live ONU status returned."
        return result
    except (socket.timeout, TimeoutError):
        result["message"] = "Live ONU status command timed out."
        return result
    except (EOFError, OSError) as exc:
        result["message"] = f"Live ONU status fetch failed: {exc}"
        return result
    finally:
        try:
            _run_telnet_command(tn, "quit")
            _run_telnet_command(tn, "quit")
        except Exception:
            pass
        _close_telnet_session(tn)


def fetch_single_ont_mac_addresses(olt, slot, port, ont_id):
    result = {
        "ok": False,
        "command": f"display mac-address port 0/{int(slot)}/{int(port)} ont {int(ont_id)}",
        "output": "",
        "message": "",
    }
    tn, status = open_telnet_authenticated_session(olt)
    if tn is None:
        result["message"] = status or "Telnet session could not be opened."
        return result

    try:
        _prepare_telnet_cli_session(tn, use_paging=True)
        command = f"display mac-address port 0/{int(slot)}/{int(port)} ont {int(ont_id)}"
        output = _run_telnet_bulk_command(tn, command, max_wait_seconds=25)
        cleaned = _clean_cli_transcript_block(command, output)
        cleaned = re.sub(r"(?im)^\s*Command:\s*$", "", cleaned)
        cleaned = re.sub(r"(?im)^\s*scroll\s+512\s*$", "", cleaned)
        cleaned = re.sub(r"(?im)^[^\r\n]*display\s+mac-address[^\r\n]*$", "", cleaned)
        cleaned = re.sub(r"(?im)^[^\r\n]*\{\s*<cr>\|[^\r\n]*\}\s*:\s*$", "", cleaned)
        cleaned = re.sub(r"(?im)^\s*it\s+will\s+take\s+a\s+long\s+time.*$", "", cleaned)
        cleaned = re.sub(r"(?im)^\s*you\s+can\s+press\s+ctrl_c\s+to\s+break\s*$", "", cleaned)
        cleaned = re.sub(r"(?im)^\s*return\s*$", "", cleaned)
        cleaned = re.sub(r"(?im)^\s*\^\s*$", "", cleaned)
        cleaned = re.sub(r"(?im)^%.*$", "", cleaned)
        cleaned = re.sub(r"\n{3,}", "\n\n", cleaned).strip()
        if cleaned:
            result["ok"] = True
            result["output"] = cleaned[:12000]
            result["message"] = "Live MAC addresses fetched."
            return result
        result["message"] = "No MAC addresses returned for this ONU."
        return result
    except (socket.timeout, TimeoutError):
        result["message"] = "MAC address command timed out."
        return result
    except (EOFError, OSError) as exc:
        result["message"] = f"MAC address fetch failed: {exc}"
        return result
    finally:
        try:
            _run_telnet_command(tn, "quit")
            _run_telnet_command(tn, "quit")
        except Exception:
            pass
        _close_telnet_session(tn)


def derive_runtime_onu_status(runtime_snapshot, fallback_status="", fallback_run_state=""):
    snapshot = runtime_snapshot or {}
    run_state = str(snapshot.get("run_state") or fallback_run_state or "").strip().lower()
    control_flag = str(snapshot.get("control_flag") or "").strip().lower()
    last_down_cause = str(snapshot.get("last_down_cause") or "").strip().lower().replace("-", "_")

    if any(token in control_flag for token in ("deactive", "disabled")):
        return "admin_disabled"
    if run_state == "online":
        return "online"

    if any(token in last_down_cause for token in ("dying_gasp", "dying gasp", "power", "power_failure")):
        return "power_failure"
    if any(token in last_down_cause for token in ("los", "loss_of_signal", "loss of signal", "losi", "lof", "lofi", "sfi", "sdi")):
        return "loss_of_signal"

    fallback = str(fallback_status or "").strip().lower()
    if fallback in {"online", "offline", "admin_disabled", "power_failure", "loss_of_signal"}:
        return fallback
    return "online" if run_state == "online" else "offline"


def sync_runtime_statuses_for_olt(olt, only_non_online=True, limit=None, start_pk=None):
    from django.utils import timezone
    from .models import ConfiguredONU

    qs = ConfiguredONU.objects.filter(olt=olt)
    if only_non_online:
        qs = qs.exclude(derived_status="online")
    qs = qs.order_by("id")
    wrapped = False
    if start_pk:
        records = list(qs.filter(id__gt=int(start_pk))[:limit] if limit else qs.filter(id__gt=int(start_pk)))
        if not records:
            records = list(qs[:limit] if limit else qs)
            wrapped = True
    else:
        records = list(qs[:limit] if limit else qs)
    if not records:
        return {"olt": olt.name, "checked": 0, "updated": 0, "status": "No ONU records to check.", "last_pk": start_pk or 0, "wrapped": wrapped}

    updated = 0
    checked = 0
    bulk = []
    status_changed = 0
    now = timezone.now()
    try:
        trap_status_map = get_active_onu_trap_status_map(olt)
        snmp_status_map = (fetch_olt_snmp_status_map(olt).get("items") or {})
        for record in records:
            checked += 1
            changed = False
            snmp_status = str(snmp_status_map.get((int(record.slot), int(record.port), int(record.ont_id))) or "").strip().lower()
            runtime_run_state = "online" if snmp_status == "online" else "offline" if snmp_status == "offline" else ""
            if runtime_run_state and runtime_run_state != (record.run_state or "").strip().lower():
                record.run_state = runtime_run_state
                changed = True

            trap_status = trap_status_map.get((int(record.slot), int(record.port), int(record.ont_id)))
            runtime_status = trap_status or snmp_status or str(record.derived_status or "").strip().lower()
            runtime_source = "trap" if trap_status else "snmp_runtime"
            current_status = str(record.derived_status or "").strip().lower()
            current_source = str(record.status_source or "").strip()
            if runtime_status and runtime_status != current_status:
                record.derived_status = runtime_status
                record.status_source = runtime_source
                record.status_updated_at = now
                record.status_first_seen_at = now
                changed = True
                status_changed += 1
            elif runtime_status and runtime_source != current_source:
                record.status_source = runtime_source
                record.status_updated_at = now
                if not record.status_first_seen_at:
                    record.status_first_seen_at = now
                changed = True
            elif runtime_status and not record.status_first_seen_at:
                record.status_first_seen_at = now
                record.status_updated_at = now
                changed = True

            if changed:
                updated += 1
                bulk.append(record)

        if bulk:
            ConfiguredONU.objects.bulk_update(
                bulk,
                [
                    "run_state",
                    "control_flag",
                    "derived_status",
                    "status_source",
                    "status_first_seen_at",
                    "status_updated_at",
                ],
                batch_size=200,
            )
        return {
            "olt": olt.name,
            "checked": checked,
            "updated": updated,
            "status": f"Checked {checked}, updated {updated}, status changed {status_changed}",
            "last_pk": records[-1].id if records else (start_pk or 0),
            "wrapped": wrapped,
        }
    except Exception as exc:
        return {
            "olt": olt.name,
            "checked": checked,
            "updated": updated,
            "status": f"SNMP error during runtime sync: {exc}",
            "last_pk": records[-1].id if records else (start_pk or 0),
            "wrapped": wrapped,
        }


def sync_runtime_statuses_for_non_online_onus(limit_per_olt=None):
    from .models import OLT

    results = []
    for olt in OLT.objects.order_by("id"):
        results.append(sync_runtime_statuses_for_olt(olt, only_non_online=True, limit=limit_per_olt))
    return results


def _parse_ont_autofind_blocks(output):
    rows = []
    text = str(output or "")
    if not text.strip():
        return rows

    global_pon_type = "-"
    summary_match = re.search(r"the\s+number\s+of\s+([a-z0-9_-]+)\s+autofind\s+ont", text, flags=re.IGNORECASE)
    if summary_match:
        global_pon_type = summary_match.group(1).strip().upper()

    current = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        if re.match(r"^-{5,}$", line):
            if current.get("f/s/p") and current.get("sn_display"):
                fsp_match = re.match(r"^\s*(\d+)\s*/\s*(\d+)\s*/\s*(\d+)\s*$", str(current.get("f/s/p") or ""))
                if fsp_match:
                    frame = int(fsp_match.group(1))
                    slot = int(fsp_match.group(2))
                    port = int(fsp_match.group(3))
                    rows.append({
                        "number": current.get("number") or str(len(rows) + 1),
                        "frame": frame,
                        "slot": slot,
                        "port": port,
                        "board": str(slot),
                        "pon_type": _normalize_autofind_pon_type(current.get("pon_type") or global_pon_type or "-"),
                        "sn": current.get("sn_display") or "-",
                        "type": current.get("ont equipmentid") or current.get("ont equipment id") or "-",
                        "autofind_time": current.get("ont autofind time") or current.get("autofind_time") or "-",
                    })
            current = {}
            continue
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        key = key.strip().lower()
        value = value.strip()
        current[key] = value
        if key == "ont sn":
            bracket_match = re.search(r"\(([^)]+)\)", value)
            if bracket_match:
                sn_display = bracket_match.group(1).strip().replace("-", "")
                current["sn_display"] = sn_display
                current["pon_type"] = _normalize_autofind_pon_type(global_pon_type or "-")
            else:
                current["sn_display"] = value.strip().replace("-", "")
                current["pon_type"] = _normalize_autofind_pon_type(global_pon_type or "-")

    if current.get("f/s/p") and current.get("sn_display"):
        fsp_match = re.match(r"^\s*(\d+)\s*/\s*(\d+)\s*/\s*(\d+)\s*$", str(current.get("f/s/p") or ""))
        if fsp_match:
            frame = int(fsp_match.group(1))
            slot = int(fsp_match.group(2))
            port = int(fsp_match.group(3))
            rows.append({
                "number": current.get("number") or str(len(rows) + 1),
                "frame": frame,
                "slot": slot,
                "port": port,
                "board": str(slot),
                "pon_type": _normalize_autofind_pon_type(current.get("pon_type") or global_pon_type or "-"),
                "sn": current.get("sn_display") or "-",
                "type": current.get("ont equipmentid") or current.get("ont equipment id") or "-",
                "autofind_time": current.get("ont autofind time") or current.get("autofind_time") or "-",
            })
    return rows


def _normalize_autofind_pon_type(value):
    text = str(value or "").strip().upper()
    if "EPON" in text:
        return "EPON"
    if "GPON" in text:
        return "GPON"
    return "-"


def _serial_match_tokens(value):
    text = re.sub(r"[^A-Z0-9]+", "", str(value or "").upper())
    if not text:
        return set()
    tokens = {text}
    if re.fullmatch(r"[0-9A-F]{16}", text):
        prefix_hex = text[:8]
        suffix = text[8:]
        try:
            prefix = bytes.fromhex(prefix_hex).decode("ascii", errors="strict")
        except (TypeError, ValueError, UnicodeDecodeError):
            prefix = ""
        if prefix and all(32 <= ord(ch) <= 126 for ch in prefix):
            tokens.add(f"{prefix.upper()}{suffix}")
    if len(text) == 12 and re.fullmatch(r"[A-Z0-9]{4}[0-9A-F]{8}", text):
        try:
            prefix_hex = text[:4].encode("ascii").hex().upper()
            tokens.add(f"{prefix_hex}{text[4:]}")
        except UnicodeEncodeError:
            pass
    return {token for token in tokens if token}


def fetch_ont_autofind_snapshot(olt):
    result = {
        "status": "Autofind data unavailable",
        "rows": [],
        "output": "",
    }
    tn, status = open_telnet_authenticated_session(olt)
    if tn is None:
        result["status"] = status
        return result
    try:
        _prepare_telnet_cli_session(tn, use_paging=True)
        time.sleep(0.2)
        try:
            tn.read_very_eager()
        except (OSError, EOFError):
            pass
        output = _run_telnet_command(tn, "display ont autofind all", enter_until_prompt=True)
        if not re.search(r"(?i)\bont\s+sn\b|\bautofind\s+ont\b", str(output or "")):
            time.sleep(0.2)
            try:
                tn.read_very_eager()
            except (OSError, EOFError):
                pass
            output = _run_telnet_command(tn, "display ont autofind all", enter_until_prompt=True)
        result["output"] = str(output or "").strip()
        rows = _parse_ont_autofind_blocks(output)
        result["rows"] = rows
        result["status"] = f"Autofind ONUs fetched: {len(rows)}"
        return result
    except (socket.timeout, TimeoutError):
        result["status"] = "Telnet timeout while fetching autofind ONUs."
        return result
    except EOFError:
        result["status"] = "Telnet connection closed while fetching autofind ONUs."
        return result
    except OSError as exc:
        result["status"] = f"Telnet error while fetching autofind ONUs: {exc}"
        return result
    finally:
        _close_telnet_session(tn)


def sync_olt_autofind_count(olt):
    from .models import ConfiguredONU

    snapshot = fetch_ont_autofind_snapshot(olt)
    rows = snapshot.get("rows") or []
    status_text = str(snapshot.get("status") or "").strip()
    lowered_status = status_text.lower()
    success = status_text.startswith("Autofind ONUs fetched:")
    failed = any(
        token in lowered_status
        for token in ("timeout", "unavailable", "connection closed", "login failed", "error")
    )

    existing_serials = set()
    for item in ConfiguredONU.objects.exclude(sn="").values_list("sn", flat=True):
        existing_serials.update(_serial_match_tokens(item))
    resync_count = 0
    new_count = 0
    for row in rows:
        serial_tokens = _serial_match_tokens(row.get("sn"))
        if not serial_tokens:
            continue
        if existing_serials.intersection(serial_tokens):
            resync_count += 1
        else:
            new_count += 1

    if success:
        olt.autofind_onu_count = len(rows)
        olt.autofind_new_count = new_count
        olt.autofind_resync_count = resync_count
        olt.autofind_status = status_text[:300]
        olt.autofind_refreshed_at = timezone.now()
        olt.save(update_fields=["autofind_onu_count", "autofind_new_count", "autofind_resync_count", "autofind_status", "autofind_refreshed_at"])
    elif failed:
        retained = int(getattr(olt, "autofind_onu_count", 0) or 0)
        olt.autofind_status = (
            f"{status_text or 'Autofind refresh failed.'} | Retained cached count: {retained}"
        )[:300]
        olt.autofind_refreshed_at = timezone.now()
        olt.save(update_fields=["autofind_status", "autofind_refreshed_at"])
    else:
        olt.autofind_onu_count = len(rows)
        olt.autofind_new_count = new_count
        olt.autofind_resync_count = resync_count
        olt.autofind_status = status_text[:300]
        olt.autofind_refreshed_at = timezone.now()
        olt.save(update_fields=["autofind_onu_count", "autofind_new_count", "autofind_resync_count", "autofind_status", "autofind_refreshed_at"])
    return {
        "count": olt.autofind_onu_count,
        "new_count": olt.autofind_new_count,
        "resync_count": olt.autofind_resync_count,
        "status": olt.autofind_status,
        "refreshed_at": olt.autofind_refreshed_at,
    }


def fetch_vlan_range(olt, start_vlan, end_vlan):
    result = {
        "ok": False,
        "message": "VLAN range not found.",
        "rows": [],
        "output": "",
    }
    tn, status = open_telnet_authenticated_session(olt)
    if tn is None:
        result["message"] = status
        return result
    try:
        _prepare_telnet_cli_session(tn, use_paging=False)
        command = f"display vlan {int(start_vlan)}-{int(end_vlan)}"
        output = _run_telnet_command(tn, command, enter_until_prompt=True)
        rows = _parse_vlan_table(output)
        result["ok"] = bool(rows)
        result["rows"] = rows
        result["output"] = str(output or "")
        result["message"] = f"Fetched VLAN range {int(start_vlan)}-{int(end_vlan)}."
        return result
    except (socket.timeout, TimeoutError):
        result["message"] = "Telnet timeout while verifying VLAN range."
        return result
    except EOFError:
        result["message"] = "Telnet connection closed while verifying VLAN range."
        return result
    except OSError as exc:
        result["message"] = f"Telnet error while verifying VLAN range: {exc}"
        return result
    finally:
        _close_telnet_session(tn)


def add_vlan_range(olt, start_vlan, end_vlan, uplink_port=""):
    result = {
        "ok": False,
        "message": "VLAN range create failed.",
        "transcript": "",
    }
    try:
        start_vlan = int(start_vlan)
        end_vlan = int(end_vlan)
    except (TypeError, ValueError):
        result["message"] = "Invalid VLAN range."
        return result
    if start_vlan > end_vlan:
        result["message"] = "Invalid VLAN range."
        return result
    transcript_parts = []
    failures = []
    for vlan_id in range(start_vlan, end_vlan + 1):
        item_result = add_vlan(olt, vlan_id, description="", uplink_port=uplink_port)
        transcript = str(item_result.get("transcript") or "").strip()
        if transcript:
            transcript_parts.append(transcript)
        if not item_result.get("ok"):
            failures.append(f"{vlan_id}: {item_result.get('message') or 'failed'}")
    result["transcript"] = "\n\n".join([part for part in transcript_parts if part])
    if failures:
        result["message"] = f"VLAN range create failed on {len(failures)} VLAN(s)."
        return result
    result["ok"] = True
    result["message"] = "VLAN range created via SNMP."
    return result


def _snmp_octets_to_bytes(value):
    if hasattr(value, "asOctets"):
        try:
            return bytes(value.asOctets())
        except Exception:
            pass
    text = str(value or "")
    return text.encode("latin1", errors="ignore")


def _snmp_set_bitmap_port(bitmap_bytes, port_number, *, enabled=True):
    try:
        port_number = int(port_number)
    except (TypeError, ValueError):
        return bytes(bitmap_bytes or b"")
    if port_number < 1:
        return bytes(bitmap_bytes or b"")
    byte_index = (port_number - 1) // 8
    bit_index = 7 - ((port_number - 1) % 8)
    data = bytearray(bitmap_bytes or b"")
    if len(data) <= byte_index:
        data.extend(b"\x00" * ((byte_index + 1) - len(data)))
    if enabled:
        data[byte_index] |= (1 << bit_index)
    else:
        data[byte_index] &= ~(1 << bit_index)
    return bytes(data)


def _resolve_snmp_bridge_port_for_ifindex(olt, if_index):
    if_index_text = str(if_index or "").strip()
    if not if_index_text:
        return ""
    base_oid = "1.3.6.1.2.1.17.1.4.1.2"
    last_error = ""
    for mp_model in (1, 0):
        try:
            rows = _snmp_walk_rows(olt, base_oid, limit=512, mp_model=mp_model)
            for oid_text, value in (rows or {}).items():
                if str(value or "").strip() == if_index_text:
                    return oid_text.split(".")[-1]
        except Exception as exc:
            last_error = str(exc)
    return ""


def _bind_vlan_to_uplink_port_snmp(olt, vlan_id, uplink_port):
    result = {"ok": False, "message": "SNMP uplink VLAN bind failed.", "transcript": ""}
    if_index_text = str(uplink_port or "").strip()
    if not if_index_text:
        result["ok"] = True
        result["message"] = "No uplink bind requested."
        return result
    if not str(getattr(olt, "snmp_write_community", "") or "").strip():
        result["message"] = "SNMP write community is not configured."
        return result
    bridge_port = _resolve_snmp_bridge_port_for_ifindex(olt, if_index_text)
    if not bridge_port:
        result["message"] = "SNMP bridge port lookup failed."
        return result
    egress_oid = f"1.3.6.1.2.1.17.7.1.4.3.1.2.{int(vlan_id)}"
    untagged_oid = f"1.3.6.1.2.1.17.7.1.4.3.1.4.{int(vlan_id)}"
    transcript_parts = []
    last_error = ""
    for mp_model in (1, 0):
        try:
            current_egress = b""
            current_untagged = b""
            err_ind, err_stat, _, var_binds = _snmp_get_value(olt, egress_oid, mp_model=mp_model)
            if not err_ind and not err_stat and var_binds:
                current_egress = _snmp_octets_to_bytes(var_binds[0][1])
            err_ind, err_stat, _, var_binds = _snmp_get_value(olt, untagged_oid, mp_model=mp_model)
            if not err_ind and not err_stat and var_binds:
                current_untagged = _snmp_octets_to_bytes(var_binds[0][1])
            new_egress = _snmp_set_bitmap_port(current_egress, bridge_port, enabled=True)
            new_untagged = _snmp_set_bitmap_port(current_untagged, bridge_port, enabled=False)
            err_ind, err_stat, _, _ = _snmp_set_value(olt, egress_oid, new_egress, value_type="OctetString", mp_model=mp_model)
            if err_ind or err_stat:
                last_error = str(err_ind or err_stat.prettyPrint())
                continue
            transcript_parts.append(f"SET {egress_oid}")
            err_ind, err_stat, _, _ = _snmp_set_value(olt, untagged_oid, new_untagged, value_type="OctetString", mp_model=mp_model)
            if err_ind or err_stat:
                last_error = str(err_ind or err_stat.prettyPrint())
                continue
            transcript_parts.append(f"SET {untagged_oid}")
            result["ok"] = True
            result["message"] = "Uplink VLAN bind applied via SNMP."
            result["transcript"] = "\n".join(transcript_parts)
            return result
        except Exception as exc:
            last_error = str(exc)
    result["message"] = f"SNMP uplink VLAN bind failed: {last_error or 'no response'}"
    result["transcript"] = "\n".join(transcript_parts)
    return result


def add_vlan(olt, vlan_id, description="", uplink_port=""):
    result = {
        "ok": False,
        "message": "VLAN create failed.",
        "transcript": "",
    }
    try:
        vlan_id = int(vlan_id)
    except (TypeError, ValueError):
        result["message"] = "Invalid VLAN ID."
        return result
    if vlan_id < 1 or vlan_id > 4093:
        result["message"] = "VLAN ID must be between 1 and 4093."
        return result
    transcript_parts = []
    description = str(description or "").strip()[:32]
    type_oid = f"1.3.6.1.4.1.2011.5.6.1.1.1.4.{vlan_id}"
    row_oid = f"1.3.6.1.4.1.2011.5.6.1.1.1.13.{vlan_id}"
    name_oid = f"1.3.6.1.4.1.2011.5.6.1.1.1.2.{vlan_id}"
    last_error = ""
    for mp_model in (1, 0):
        try:
            err_ind, err_stat, _, _ = _snmp_set_value(olt, type_oid, 2, value_type="Integer", mp_model=mp_model)
            if err_ind or err_stat:
                last_error = str(err_ind or err_stat.prettyPrint())
                continue
            transcript_parts.append(f"SET {type_oid} = 2")
            if description:
                err_ind, err_stat, _, _ = _snmp_set_value(olt, name_oid, description, value_type="OctetString", mp_model=mp_model)
                if err_ind or err_stat:
                    last_error = str(err_ind or err_stat.prettyPrint())
                    continue
                transcript_parts.append(f"SET {name_oid} = {description}")
            err_ind, err_stat, _, _ = _snmp_set_value(olt, row_oid, 4, value_type="Integer", mp_model=mp_model)
            if err_ind or err_stat:
                last_error = str(err_ind or err_stat.prettyPrint())
                continue
            transcript_parts.append(f"SET {row_oid} = 4")
            if str(uplink_port or "").strip():
                bind_result = _bind_vlan_to_uplink_port_snmp(olt, vlan_id, uplink_port)
                bind_transcript = str(bind_result.get("transcript") or "").strip()
                if bind_transcript:
                    transcript_parts.append(bind_transcript)
                if not bind_result.get("ok"):
                    last_error = str(bind_result.get("message") or "uplink bind failed")
                    continue
            result["ok"] = True
            result["message"] = "VLAN created via SNMP."
            result["transcript"] = "\n".join(transcript_parts)
            return result
        except Exception as exc:
            last_error = str(exc)
    result["message"] = f"SNMP VLAN create failed: {last_error or 'no response'}"
    result["transcript"] = "\n".join(transcript_parts)
    return result


def delete_vlan_snmp(olt, vlan_id):
    result = {
        "ok": False,
        "message": "VLAN delete failed.",
        "transcript": "",
    }
    try:
        vlan_id = int(vlan_id)
    except (TypeError, ValueError):
        result["message"] = "Invalid VLAN ID."
        return result

    if vlan_id < 1 or vlan_id > 4094:
        result["message"] = "VLAN ID must be between 1 and 4094."
        return result

    row_oids = [
        f"1.3.6.1.4.1.2011.5.6.1.1.1.13.{vlan_id}",
        f"1.3.6.1.2.1.17.7.1.4.3.1.5.{vlan_id}",
    ]
    clear_oids = [
        f"1.3.6.1.2.1.17.7.1.4.3.1.2.{vlan_id}",
        f"1.3.6.1.2.1.17.7.1.4.3.1.3.{vlan_id}",
        f"1.3.6.1.2.1.17.7.1.4.3.1.4.{vlan_id}",
    ]
    transcript_parts = []
    last_error = ""
    for mp_model in (1, 0):
        try:
            for clear_oid in clear_oids:
                err_ind, err_stat, _, _ = _snmp_set_value(olt, clear_oid, b"", value_type="OctetString", mp_model=mp_model)
                if not err_ind and not err_stat:
                    transcript_parts.append(f"SET {clear_oid} = <empty>")
            for row_oid in row_oids:
                err_ind, err_stat, _, _ = _snmp_set_value(olt, row_oid, 6, value_type="Integer", mp_model=mp_model)
                if err_ind or err_stat:
                    last_error = str(err_ind or err_stat.prettyPrint())
                    continue
                transcript_parts.append(f"SET {row_oid} = 6")
                result["ok"] = True
                result["message"] = "VLAN deleted via SNMP."
                result["transcript"] = "\n".join(transcript_parts)
                return result
        except Exception as exc:
            last_error = str(exc)
    result["message"] = f"SNMP VLAN delete failed: {last_error or 'no response'}"
    result["transcript"] = "\n".join(transcript_parts)
    return result


def delete_vlan_netconf(olt, vlan_id):
    return delete_vlan_snmp(olt, vlan_id)


def fetch_dba_profile_snapshot(olt):
    result = {
        "status": "DBA profiles unavailable",
        "rows": [],
    }
    tn, status = open_telnet_authenticated_session(olt)
    if tn is None:
        result["status"] = status
        return result

    try:
        _prepare_telnet_cli_session(tn, use_paging=True)
        commands = (
            "display current-configuration | include dba-profile | type",
            "display current-configuration | include dba-profile",
            "display current-configuration | include profile-name",
        )
        best_rows = []
        for command in commands:
            output = _run_telnet_command(tn, command, enter_until_prompt=True)
            rows = _parse_dba_profile_table(output)
            if len(rows) > len(best_rows):
                best_rows = rows
        result["rows"] = best_rows
        result["status"] = f"DBA profiles fetched: {len(best_rows)}"
        return result
    except (socket.timeout, TimeoutError):
        result["status"] = "Telnet timeout while fetching DBA profiles."
        return result
    except EOFError:
        result["status"] = "Telnet connection closed while fetching DBA profiles."
        return result
    except OSError as exc:
        result["status"] = f"Telnet error while fetching DBA profiles: {exc}"
        return result
    finally:
        _close_telnet_session(tn)


def save_dba_profile_snapshot(olt, data):
    rows = (data or {}).get("rows") or []
    status = (data or {}).get("status") or ""
    olt.dba_profile_cache = rows
    olt.dba_profile_status = status[:300]
    olt.dba_profile_refreshed_at = timezone.now()
    olt.save(update_fields=["dba_profile_cache", "dba_profile_status", "dba_profile_refreshed_at"])


def add_dba_profile(olt, profile_id, profile_name, profile_type, dba_speed):
    result = {
        "ok": False,
        "message": "DBA profile add failed.",
        "transcript": "",
    }
    tn, status = open_telnet_authenticated_session(olt)
    if tn is None:
        result["message"] = status
        result["transcript"] = f"LOGIN FAILED\n{status}"
        return result

    try:
        transcript_parts = []
        _prepare_telnet_cli_session(tn, use_paging=True)
        transcript_parts.append("enable")
        transcript_parts.append("config")
        config_entered, config_output = _enter_config_mode(tn)
        if not config_entered:
            result["message"] = "Unable to enter configuration mode."
            result["transcript"] = "\n\n".join([part for part in transcript_parts + [str(config_output or "").strip()] if part])
            return result

        command = _build_dba_profile_command(profile_id, profile_name, profile_type, dba_speed)
        transcript_parts.append(command)
        output = _run_telnet_command(tn, command, enter_until_prompt=True)
        raw_output = str(output or "").strip()
        cleaned_output = _clean_cli_transcript_block(command, raw_output)
        if cleaned_output:
            transcript_parts.append(cleaned_output)
        lowered = raw_output.lower()

        if _is_cli_error_text(raw_output) or "already exist" in lowered or "already exists" in lowered or "duplicate" in lowered:
            result["message"] = raw_output or "OLT rejected the DBA profile command."
            result["transcript"] = "\n\n".join([part for part in transcript_parts if part])
            return result

        success_tokens = (
            "succeed",
            "succeeded",
            "success",
            "adding 1 dba profile",
        )
        if any(token in lowered for token in success_tokens) or "#" in raw_output:
            transcript_parts.append("quit")
            quit_output = _run_telnet_command(tn, "quit", enter_until_prompt=True)
            cleaned_quit = _clean_cli_transcript_block("quit", quit_output)
            if cleaned_quit:
                transcript_parts.append(cleaned_quit)
            transcript_parts.append("save")
            save_output = _run_telnet_command(tn, "save", enter_until_prompt=True)
            cleaned_save = _clean_cli_transcript_block("save", save_output)
            if cleaned_save:
                transcript_parts.append(cleaned_save)
            result["ok"] = True
            result["message"] = "DBA profile added."
            result["transcript"] = "\n\n".join([part for part in transcript_parts if part])
            return result

        result["message"] = raw_output or "Command executed, but the profile was not confirmed on the OLT."
        result["transcript"] = "\n\n".join([part for part in transcript_parts if part])
        return result
    except (TypeError, ValueError):
        result["message"] = "Invalid DBA speed value."
        return result
    except (socket.timeout, TimeoutError):
        result["message"] = "Telnet timeout while adding DBA profile."
        return result
    except EOFError:
        result["message"] = "Telnet connection closed while adding DBA profile."
        return result
    except OSError as exc:
        result["message"] = f"Telnet error while adding DBA profile: {exc}"
        return result
    finally:
        _close_telnet_session(tn)


def fetch_dba_profile_configuration(olt, profile_id, profile_name=""):
    result = {
        "ok": False,
        "message": "Profile configuration unavailable.",
        "transcript": "",
        "output": "",
    }
    tn, status = open_telnet_authenticated_session(olt)
    if tn is None:
        result["message"] = status
        result["transcript"] = f"LOGIN FAILED\n{status}"
        return result

    try:
        transcript_parts = []
        _prepare_telnet_cli_session(tn, use_paging=True)
        transcript_parts.append("enable")

        commands = [
            f"display current-configuration | include dba-profile add profile-id {int(profile_id)}",
        ]
        profile_name = str(profile_name or "").strip()
        if profile_name:
            commands.append(
                f'display current-configuration | include profile-name "{profile_name}"'
            )
        commands.append("display current-configuration | include dba-profile")

        best_output = ""
        best_command = ""
        for command in commands:
            transcript_parts.append(command)
            output = _run_telnet_command(tn, command, enter_until_prompt=True)
            raw_output = str(output or "").strip()
            cleaned_output = _clean_cli_transcript_block(command, raw_output)
            if cleaned_output:
                transcript_parts.append(cleaned_output)
            if cleaned_output and (
                f"profile-id {int(profile_id)}" in cleaned_output.lower()
                or (profile_name and profile_name.lower() in cleaned_output.lower())
            ):
                best_output = cleaned_output
                best_command = command
                break
            if cleaned_output and not best_output:
                best_output = cleaned_output
                best_command = command

        if best_output:
            result["ok"] = True
            result["message"] = f"Configuration fetched for profile {int(profile_id)}."
            result["output"] = best_output
            result["transcript"] = "\n\n".join([part for part in transcript_parts if part])
            return result

        result["message"] = f"No live configuration found for profile {int(profile_id)}."
        if best_command:
            result["transcript"] = "\n\n".join([part for part in transcript_parts if part])
        return result
    except (socket.timeout, TimeoutError):
        result["message"] = "Telnet timeout while fetching profile configuration."
        return result
    except EOFError:
        result["message"] = "Telnet connection closed while fetching profile configuration."
        return result
    except OSError as exc:
        result["message"] = f"Telnet error while fetching profile configuration: {exc}"
        return result
    finally:
        _close_telnet_session(tn)


def fetch_single_dba_profile(olt, profile_id, profile_name=""):
    result = {
        "ok": False,
        "message": "Profile not found.",
        "row": None,
        "output": "",
    }
    config_result = fetch_dba_profile_configuration(olt, profile_id, profile_name)
    output = str(config_result.get("output") or "").strip()
    if not output:
        result["message"] = config_result.get("message") or result["message"]
        return result
    rows = _parse_dba_profile_table(output)
    target_id = int(profile_id)
    target_name = str(profile_name or "").strip().lower()
    for row in rows:
        row_id = int(row.get("profile_id", -1) or -1)
        row_name = str(row.get("profile_name") or "").strip().lower()
        if row_id == target_id and (not target_name or row_name == target_name):
            result["ok"] = True
            result["message"] = f"Profile {target_id} fetched."
            result["row"] = row
            result["output"] = output
            return result
    if rows:
        result["message"] = f"Profile {target_id} not matched in OLT output."
        result["output"] = output
        return result
    result["message"] = config_result.get("message") or result["message"]
    return result


def _apply_snmp_pon_states_to_groups(groups, snmp_ports):
    for group in groups:
        slot = int(group.get("slot", 0) or 0)
        for row in group.get("ports", []):
            port = int(row.get("port", 0) or 0)
            snmp_row = (snmp_ports or {}).get((slot, port))
            if not snmp_row:
                continue
            admin_state = snmp_row.get("admin_state")
            status = snmp_row.get("status")
            sfp_tx = snmp_row.get("sfp_tx")
            if admin_state:
                row["admin_state"] = admin_state
            if status and str(status).lower() != "unknown":
                row["status"] = status
            if sfp_tx:
                row["sfp_tx"] = sfp_tx


def _normalize_pon_status_with_ont_counts(groups):
    for group in groups:
        for row in group.get("ports", []):
            online = int(row.get("onus_online", 0) or 0)
            offline = int(row.get("onus_offline", 0) or 0)
            admin_state = str(row.get("admin_state", "")).lower()
            if "disabled" in admin_state:
                row["status"] = "Down / Admin down"
                continue
            if online > 0:
                row["status"] = "Up / Autofind"
                continue
            if offline > 0:
                row["status"] = "Down / Autofind"
                continue
            current = str(row.get("status", "")).lower()
            if not current or current == "unknown":
                row["status"] = "Down / Autofind"


def fetch_pon_ports_snapshot(olt):
    snmp_pon = fetch_snmp_pon_port_states(olt)
    tn, status = open_telnet_authenticated_session(olt)
    if tn is None:
        return [], status

    try:
        _prepare_telnet_cli_session(tn, use_paging=True)

        cached_cards = list(getattr(olt, "olt_cards_cache", []) or [])
        cached_groups = list(getattr(olt, "pon_ports_cache", []) or [])
        groups = []
        if cached_groups:
            for group in cached_groups:
                ports = []
                for row in (group.get("ports") or []):
                    item = dict(row)
                    item.setdefault("slot", str(group.get("slot", "")))
                    item.setdefault("board_type", group.get("board_type") or "")
                    item.setdefault("type", "GPON")
                    item.setdefault("admin_state", "Enabled")
                    item.setdefault("status", "Unknown")
                    item.setdefault("onus", "Online:0 Offline:0")
                    item.setdefault("onus_online", 0)
                    item.setdefault("onus_offline", 0)
                    item.setdefault("sfp_tx", "")
                    ports.append(item)
                if ports:
                    groups.append(
                        {
                            "slot": str(group.get("slot", "")),
                            "board_type": group.get("board_type") or "",
                            "ports": ports,
                        }
                    )
        else:
            cards = [dict(card) for card in cached_cards]
            board_output = ""
            if not cards:
                board_output = _run_telnet_command(tn, "display board 0", enter_until_prompt=True)
                cards = _parse_board_table(board_output)
            if not cards:
                cards = [dict(card) for card in cached_cards if _is_pon_board_model(card.get("real_type") or card.get("model_type") or card.get("type") or "")]
                if not cards:
                    return [], "No board cards found from 'display board 0'."

            _fill_ports_from_model_defaults(cards)
            for card in cards:
                board_type = card.get("real_type") or card.get("model_type") or card.get("type") or ""
                if not _is_pon_board_model(board_type):
                    continue
                slot = card.get("slot")
                detail = _run_telnet_command(tn, f"display board 0/{slot}", enter_until_prompt=True)
                parsed = _parse_pon_ports_from_board_detail(slot, board_type, detail, card.get("ports", 0))
                if not parsed:
                    continue
                groups.append(
                    {
                        "slot": str(slot),
                        "board_type": board_type,
                        "ports": parsed,
                    }
                )

        if not groups:
            return [], "No PON boards/ports detected."

        _apply_snmp_pon_states_to_groups(groups, snmp_pon.get("ports") or {})
        slot_port_map = {
            int(group.get("slot", 0) or 0): {
                "board_type": group.get("board_type") or "",
                "ports": [int(row.get("port", 0) or 0) for row in group.get("ports", [])],
            }
            for group in groups
        }
        cli_sfp_tx = _fetch_pon_sfp_tx_map_in_context(tn, slot_port_map)
        if cli_sfp_tx:
            _apply_pon_sfp_tx_to_groups(groups, cli_sfp_tx)

        ont_counts, ont_rows = _get_ont_counts_from_db(olt)
        if not ont_counts:
            ont_output = _run_telnet_command(tn, "display ont info 0 all", enter_until_prompt=True)
            ont_counts, ont_rows = _parse_ont_counts_by_port(ont_output)
        if ont_counts:
            _apply_ont_counts_to_groups(groups, ont_counts)
            ont_status = f" | ONTs loaded: {ont_rows}"
        else:
            ont_status = " | ONT parse skipped"
        _apply_average_signals_to_groups(groups, _get_ont_signal_averages_from_db(olt))
        _normalize_pon_status_with_ont_counts(groups)

        groups = sorted(groups, key=lambda item: int(item["slot"]))
        total_ports = sum(len(group["ports"]) for group in groups)
        snmp_status = snmp_pon.get("status") or ""
        status_parts = []
        if snmp_status:
            status_parts.append(snmp_status)
        if cli_sfp_tx:
            status_parts.append(f"SFP Tx mapped: {len(cli_sfp_tx)}")
        suffix = f" | {' | '.join(status_parts)}" if status_parts else ""
        source_note = " | ports cache" if cached_groups else (" | cards cache" if cached_cards else "")
        return groups, f"PON ports fetched: {total_ports}{ont_status}{source_note}{suffix}"
    except (socket.timeout, TimeoutError):
        return [], "Telnet timeout while fetching PON ports."
    except EOFError:
        return [], "Telnet connection closed while fetching PON ports."
    except OSError as exc:
        return [], f"Telnet error while fetching PON ports: {exc}"
    finally:
        _close_telnet_session(tn)


DASHBOARD_STATUS_SAMPLE_SECONDS = 600
PON_TRAFFIC_SAMPLE_SECONDS = 120


def _current_dashboard_sample_boundary(now=None):
    now = now or timezone.now()
    epoch = int(now.timestamp())
    bucket_epoch = (epoch // DASHBOARD_STATUS_SAMPLE_SECONDS) * DASHBOARD_STATUS_SAMPLE_SECONDS
    return datetime.datetime.fromtimestamp(bucket_epoch, tz=datetime.timezone.utc)


def _current_pon_traffic_sample_boundary(now=None):
    now = now or timezone.now()
    epoch = int(now.timestamp())
    bucket_epoch = (epoch // PON_TRAFFIC_SAMPLE_SECONDS) * PON_TRAFFIC_SAMPLE_SECONDS
    return datetime.datetime.fromtimestamp(bucket_epoch, tz=datetime.timezone.utc)


def record_pon_traffic_samples(force=False):
    from .models import OLT, PONTrafficSample

    now = timezone.now()
    boundary = _current_pon_traffic_sample_boundary(now)
    latest = PONTrafficSample.objects.filter(olt__isnull=True).order_by("-sampled_at").first()
    if latest and not force and latest.sampled_at >= boundary:
        return latest

    per_olt_samples = []
    total_in_octets = 0
    total_out_octets = 0
    total_in_packets = 0
    total_out_packets = 0
    for olt in OLT.objects.only("id", "name", "ip_address", "snmp_port", "snmp_community").all():
        snapshot = fetch_snmp_pon_aggregate_counters(olt)
        if not snapshot.get("ok"):
            continue
        in_octets = int(snapshot.get("in_octets") or 0)
        out_octets = int(snapshot.get("out_octets") or 0)
        in_packets = int(snapshot.get("in_packets") or 0)
        out_packets = int(snapshot.get("out_packets") or 0)
        total_in_octets += in_octets
        total_out_octets += out_octets
        total_in_packets += in_packets
        total_out_packets += out_packets
        per_olt_samples.append(
            PONTrafficSample(
                olt=olt,
                in_octets=in_octets,
                out_octets=out_octets,
                in_packets=in_packets,
                out_packets=out_packets,
            )
        )
    aggregate_sample = PONTrafficSample(
        olt=None,
        in_octets=total_in_octets,
        out_octets=total_out_octets,
        in_packets=total_in_packets,
        out_packets=total_out_packets,
    )
    samples = [aggregate_sample, *per_olt_samples]
    if not samples:
        return None
    PONTrafficSample.objects.bulk_create(samples, batch_size=200)
    return aggregate_sample


def record_pon_traffic_sample_for_olt(olt, force=False):
    from .models import PONTrafficSample

    now = timezone.now()
    boundary = _current_pon_traffic_sample_boundary(now)
    latest = PONTrafficSample.objects.filter(olt=olt).order_by("-sampled_at").first()
    if latest and not force and latest.sampled_at >= boundary:
        return latest

    snapshot = fetch_snmp_pon_aggregate_counters(olt)
    if not snapshot.get("ok"):
        return None

    return PONTrafficSample.objects.create(
        olt=olt,
        in_octets=int(snapshot.get("in_octets") or 0),
        out_octets=int(snapshot.get("out_octets") or 0),
        in_packets=int(snapshot.get("in_packets") or 0),
        out_packets=int(snapshot.get("out_packets") or 0),
    )


def record_pon_port_traffic_samples(force=False):
    from .models import OLT, PONPortTrafficSample

    now = timezone.now()
    boundary = _current_pon_traffic_sample_boundary(now)
    if not force:
        latest = PONPortTrafficSample.objects.order_by("-sampled_at").first()
        if latest and latest.sampled_at >= boundary:
            return latest

    samples = []
    for olt in OLT.objects.only("id", "ip_address", "snmp_port", "snmp_community").all():
        snapshot = fetch_snmp_pon_port_counters(olt)
        if not snapshot.get("ok"):
            continue
        for row in snapshot.get("rows") or []:
            samples.append(
                PONPortTrafficSample(
                    olt=olt,
                    slot=int(row.get("slot") or 0),
                    port=int(row.get("port") or 0),
                    in_octets=int(row.get("in_octets") or 0),
                    out_octets=int(row.get("out_octets") or 0),
                    in_packets=int(row.get("in_packets") or 0),
                    out_packets=int(row.get("out_packets") or 0),
                )
            )
    if not samples:
        return None
    PONPortTrafficSample.objects.bulk_create(samples, batch_size=500)
    return samples[0]


def record_pon_port_traffic_sample_for_olt(olt, force=False, min_interval_seconds=15):
    from .models import PONPortTrafficSample

    latest = PONPortTrafficSample.objects.filter(olt=olt).order_by("-sampled_at").first()
    if latest and not force:
        if latest.sampled_at >= (timezone.now() - datetime.timedelta(seconds=int(min_interval_seconds or 15))):
            return latest

    snapshot = fetch_snmp_pon_port_counters(olt)
    if not snapshot.get("ok"):
        return None

    rows = list(snapshot.get("rows") or [])
    if not rows:
        return None

    sample_time = timezone.now()
    samples = [
        PONPortTrafficSample(
            olt=olt,
            slot=int(row.get("slot") or 0),
            port=int(row.get("port") or 0),
            in_octets=int(row.get("in_octets") or 0),
            out_octets=int(row.get("out_octets") or 0),
            in_packets=int(row.get("in_packets") or 0),
            out_packets=int(row.get("out_packets") or 0),
            sampled_at=sample_time,
        )
        for row in rows
    ]
    PONPortTrafficSample.objects.bulk_create(samples, batch_size=500)
    return samples[0]


def record_uplink_port_traffic_samples(force=False):
    from .models import OLT, UplinkPortTrafficSample

    now = timezone.now()
    boundary = _current_pon_traffic_sample_boundary(now)
    if not force:
        latest = UplinkPortTrafficSample.objects.order_by("-sampled_at").first()
        if latest and latest.sampled_at >= boundary:
            return latest

    samples = []
    for olt in OLT.objects.only("id", "ip_address", "snmp_port", "snmp_community").all():
        snapshot = fetch_snmp_interfaces(olt, limit=64)
        rows = list((snapshot or {}).get("rows") or [])
        for row in rows:
            port_name = str(row.get("port") or "").strip()
            if not port_name:
                continue
            samples.append(
                UplinkPortTrafficSample(
                    olt=olt,
                    port_name=port_name,
                    in_octets=int(str(row.get("in_octets") or "0").strip() or 0),
                    out_octets=int(str(row.get("out_octets") or "0").strip() or 0),
                )
            )
    if not samples:
        return None
    UplinkPortTrafficSample.objects.bulk_create(samples, batch_size=500)
    return samples[0]


def record_uplink_port_traffic_sample_for_olt(olt, force=False, min_interval_seconds=15):
    from .models import UplinkPortTrafficSample

    latest = UplinkPortTrafficSample.objects.filter(olt=olt).order_by("-sampled_at").first()
    if latest and not force:
        if latest.sampled_at >= (timezone.now() - datetime.timedelta(seconds=int(min_interval_seconds or 15))):
            return latest

    snapshot = fetch_snmp_interfaces(olt, limit=64)
    rows = list((snapshot or {}).get("rows") or [])
    if not rows:
        return None

    sample_time = timezone.now()
    samples = []
    for row in rows:
        port_name = str(row.get("port") or "").strip()
        if not port_name:
            continue
        samples.append(
            UplinkPortTrafficSample(
                olt=olt,
                port_name=port_name,
                in_octets=int(str(row.get("in_octets") or "0").strip() or 0),
                out_octets=int(str(row.get("out_octets") or "0").strip() or 0),
                sampled_at=sample_time,
            )
        )
    if not samples:
        return None
    UplinkPortTrafficSample.objects.bulk_create(samples, batch_size=500)
    return samples[0]


def _dashboard_status_counts_from_queryset(qs):
    from django.db.models import Count, Q
    counts = qs.aggregate(
        total_onus=Count('id'),
        online_onus=Count('id', filter=Q(derived_status='online')),
        admin_disabled=Count('id', filter=Q(derived_status='admin_disabled')),
        power_failure=Count('id', filter=Q(derived_status='power_failure')),
        loss_of_signal=Count('id', filter=Q(derived_status='loss_of_signal')),
    )
    signal_warn = 0
    signal_bad = 0
    for olt_rx in qs.values_list('olt_rx', flat=True).iterator(chunk_size=2000):
        bucket = _signal_bucket_from_dbm_text(olt_rx)
        if bucket == 'warn':
            signal_warn += 1
        elif bucket == 'bad':
            signal_bad += 1
    counts['signal_warn'] = signal_warn
    counts['signal_bad'] = signal_bad
    return counts


def record_dashboard_status_samples(force=False):
    from .models import ConfiguredONU, DashboardStatusSample, OLT

    boundary = _current_dashboard_sample_boundary()
    latest = DashboardStatusSample.objects.order_by('-sampled_at').first()
    if latest and not force and latest.sampled_at >= boundary:
        return False
    if force:
        DashboardStatusSample.objects.filter(sampled_at__gte=boundary).delete()

    global_counts = _dashboard_status_counts_from_queryset(ConfiguredONU.objects.all())
    global_total = int(global_counts.get('total_onus') or 0)
    global_online = int(global_counts.get('online_onus') or 0)
    samples = [
        DashboardStatusSample(
            olt=None,
            sampled_at=boundary,
            total_onus=global_total,
            online_onus=global_online,
            offline_onus=max(0, global_total - global_online),
            wait_for_authorize_total=sum(OLT.objects.values_list('autofind_onu_count', flat=True)),
            wait_for_authorize_new_total=sum(OLT.objects.values_list('autofind_new_count', flat=True)),
            wait_for_authorize_resync_total=sum(OLT.objects.values_list('autofind_resync_count', flat=True)),
            admin_disabled=int(global_counts.get('admin_disabled') or 0),
            power_failure=int(global_counts.get('power_failure') or 0),
            loss_of_signal=int(global_counts.get('loss_of_signal') or 0),
            signal_warn=int(global_counts.get('signal_warn') or 0),
            signal_bad=int(global_counts.get('signal_bad') or 0),
        )
    ]

    olts = list(OLT.objects.only('id', 'autofind_onu_count', 'autofind_new_count', 'autofind_resync_count'))
    for olt in olts:
        olt_id = olt.id
        counts = _dashboard_status_counts_from_queryset(ConfiguredONU.objects.filter(olt_id=olt_id))
        total = int(counts.get('total_onus') or 0)
        online = int(counts.get('online_onus') or 0)
        samples.append(
            DashboardStatusSample(
                olt_id=olt_id,
                sampled_at=boundary,
                total_onus=total,
                online_onus=online,
                offline_onus=max(0, total - online),
                wait_for_authorize_total=int(getattr(olt, 'autofind_onu_count', 0) or 0),
                wait_for_authorize_new_total=int(getattr(olt, 'autofind_new_count', 0) or 0),
                wait_for_authorize_resync_total=int(getattr(olt, 'autofind_resync_count', 0) or 0),
                admin_disabled=int(counts.get('admin_disabled') or 0),
                power_failure=int(counts.get('power_failure') or 0),
                loss_of_signal=int(counts.get('loss_of_signal') or 0),
                signal_warn=int(counts.get('signal_warn') or 0),
                signal_bad=int(counts.get('signal_bad') or 0),
            )
        )

    DashboardStatusSample.objects.bulk_create(samples, batch_size=200)
    return True


def ensure_dashboard_status_samples_for_scope(olt_id=None):
    from .models import DashboardStatusSample

    latest_qs = DashboardStatusSample.objects.filter(olt_id=olt_id) if olt_id else DashboardStatusSample.objects.filter(olt__isnull=True)
    latest = latest_qs.order_by('-sampled_at').first()
    boundary = _current_dashboard_sample_boundary()
    if latest and latest.sampled_at >= boundary:
        return latest
    record_dashboard_status_samples(force=True)
    return latest_qs.order_by('-sampled_at').first()


def fetch_olt_cards(olt):
    tn, status = open_telnet_authenticated_session(olt)
    if tn is None:
        return [], status

    try:
        _prepare_telnet_cli_session(tn)

        board_output = _run_telnet_command(tn, "display board 0")
        cards = _parse_board_table(board_output)
        if not cards:
            return [], "No board cards found from 'display board 0'."

        _fill_ports_from_model_defaults(cards)

        card_by_slot = {c["slot"]: c for c in cards}
        for slot in card_by_slot.keys():
            detail_output = _run_telnet_command(tn, f"display board 0/{slot}")
            _merge_card_detail(card_by_slot[slot], detail_output)

        commands_used = "enable -> display board 0 -> display board 0/<slot>"
        return cards, f"Fetched {len(cards)} cards using {commands_used}"
    except (socket.timeout, TimeoutError):
        return [], "Telnet timeout while fetching OLT cards."
    except OSError as exc:
        return [], f"Telnet error while fetching OLT cards: {exc}"
    finally:
        try:
            tn.close()
        except OSError:
            pass


def fetch_telnet_banner_snapshot(olt):
    snapshot = {
        "status": "Telnet banner not available",
        "sys_name": olt.name,
        "sys_descr": "",
        "model": olt.hardware_version or "Unknown",
        "sw_version": olt.sw_version or "Unknown",
    }
    tn, status = open_telnet_authenticated_session(olt)
    if tn is None:
        snapshot["status"] = status
        return snapshot

    try:
        # After successful login, most OLTs print banner and last-login info.
        time.sleep(0.4)
        tn.write(b"\r\n")
        time.sleep(0.4)
        raw = tn.read_very_eager().decode("ascii", errors="ignore")
        model, sw_version = _extract_model_and_sw_from_text(raw)
        snapshot.update(
            {
                "status": "Telnet banner parsed",
                "sys_descr": raw.strip()[:1200] or "No banner text captured",
                "model": model or snapshot["model"],
                "sw_version": sw_version or snapshot["sw_version"],
            }
        )
        return snapshot
    except (socket.timeout, TimeoutError):
        snapshot["status"] = "Telnet banner read timeout."
        return snapshot
    except OSError as exc:
        snapshot["status"] = f"Telnet banner read error: {exc}"
        return snapshot
    finally:
        try:
            tn.close()
        except OSError:
            pass


def _parse_uptime_from_display_version(output):
    match = re.search(
        r"Uptime\s+is\s+(\d+)\s+day\(s\),\s+(\d+)\s+hour\(s\),\s+(\d+)\s+minute\(s\)(?:,\s+(\d+)\s+second\(s\))?",
        output or "",
        flags=re.IGNORECASE,
    )
    if not match:
        # Some vendors print "Up time : 3 day(s), 14 hour(s), 16 minute(s)"
        match = re.search(
            r"Up\s*time\s*:?\s*(\d+)\s+day\(s\),\s*(\d+)\s+hour\(s\),\s*(\d+)\s+minute\(s\)",
            output or "",
            flags=re.IGNORECASE,
        )
        if not match:
            return "--"
    days = int(match.group(1))
    hours = int(match.group(2))
    minutes = int(match.group(3))
    return f"{days} day(s), {hours:02}:{minutes:02}"


def _parse_sw_from_display_version(output, fallback="Unknown"):
    text = output or ""
    patterns = (
        r"^\s*VERSION\s*:\s*([A-Za-z0-9._-]+)",
        r"^\s*SW\s*Version\s*:\s*([A-Za-z0-9._-]+)",
        r"^\s*Software\s+Version\s*:\s*([A-Za-z0-9._-]+)",
        r"\b(MA\d{4,}[A-Za-z0-9._-]*R\d{3,4}[A-Za-z0-9._-]*)\b",
    )
    for pattern in patterns:
        match = re.search(pattern, text, flags=re.IGNORECASE | re.MULTILINE)
        if match:
            return match.group(1).upper()
    return fallback


def fetch_telnet_version_snapshot(olt):
    snapshot = {
        "status": "Display version not available",
        "sys_name": olt.name,
        "sys_descr": "",
        "model": olt.hardware_version or "Unknown",
        "sw_version": olt.sw_version or "Unknown",
        "uptime": "--",
    }
    tn, status = open_telnet_authenticated_session(olt)
    if tn is None:
        snapshot["status"] = status
        return snapshot

    try:
        _prepare_telnet_cli_session(tn)

        output = _run_telnet_command(tn, "display version", enter_until_prompt=True) or ""
        output_u = (output or "").upper()
        if ("VERSION" not in output_u) and ("UPTIME IS" not in output_u):
            # Retry once: some devices return only prompt/warning on first pass.
            retry_output = _run_telnet_command(tn, "display version", enter_until_prompt=True) or ""
            output = retry_output if retry_output else output
        output_u = (output or "").upper()
        # One controlled post-read when device asks for <cr>, no repeated Enter spam.
        if (("VERSION" not in output_u) and ("UPTIME IS" not in output_u)) and ("<cr" in (output or "").lower()):
            tn.write(b"\r\n")
            time.sleep(0.25)
            output = f"{output}\n{_read_telnet_chunk(tn, wait=0.35, rounds=5)}".strip()

        sw_match = re.search(r"^\s*VERSION\s*:\s*([A-Za-z0-9._-]+)", output or "", flags=re.IGNORECASE | re.MULTILINE)
        product_match = re.search(r"^\s*PRODUCT\s*:\s*([A-Za-z0-9._-]+)", output or "", flags=re.IGNORECASE | re.MULTILINE)

        parsed_status = "display version parsed"
        parsed_sw = _parse_sw_from_display_version(output, fallback=snapshot["sw_version"])
        parsed_uptime = _parse_uptime_from_display_version(output)
        if (not sw_match) and (parsed_sw == snapshot["sw_version"]) and (parsed_uptime == "--"):
            parsed_status = "display version incomplete (no VERSION/uptime line)"

        snapshot.update(
            {
                "status": parsed_status,
                "sys_descr": (output or "").strip()[:2400],
                "model": (product_match.group(1).upper() if product_match else snapshot["model"]),
                "sw_version": parsed_sw,
                "uptime": parsed_uptime,
            }
        )
        return snapshot
    except (socket.timeout, TimeoutError):
        snapshot["status"] = "display version timeout."
        return snapshot
    except OSError as exc:
        snapshot["status"] = f"display version read error: {exc}"
        return snapshot
    finally:
        _close_telnet_session(tn)


def execute_olt_cli_command(olt, command):
    command_text = (command or "").strip()
    if not command_text:
        return False, "Command is empty."

    tn, status = open_telnet_authenticated_session(olt)
    if tn is None:
        return False, status

    try:
        _run_telnet_command(tn, "enable")
        output = _run_telnet_command(tn, command_text)
        cleaned = (output or "").strip()
        if not cleaned:
            return True, "Command executed. No output returned."
        return True, cleaned[:8000]
    except (socket.timeout, TimeoutError):
        return False, "CLI command timeout."
    except OSError as exc:
        return False, f"CLI command error: {exc}"
    finally:
        _close_telnet_session(tn)


def run_telnet_session_command(tn, command):
    return _run_telnet_command(tn, command)


def close_telnet_session(tn):
    _close_telnet_session(tn)


def send_telnet_input(tn, data):
    if tn is None:
        return
    _touch_telnet_session(tn)
    payload = data if isinstance(data, bytes) else str(data).encode("ascii", errors="ignore")
    tn.write(payload)


def read_telnet_output(tn, wait=0.2, rounds=5):
    if tn is None:
        return ""
    _touch_telnet_session(tn)
    return _collapse_repeated_prompts(_read_telnet_chunk(tn, wait=wait, rounds=rounds))


def push_snmp_config_over_telnet(olt, read_community, write_community=""):
    tn, auth_status = open_telnet_authenticated_session(olt)
    if tn is None:
        return False, auth_status

    try:
        _prepare_telnet_cli_session(tn, include_enable=False, use_paging=False)
        last_error = ""
        for command_set in _snmp_config_commands(olt.vendor, read_community, write_community):
            set_ok = True
            first_error = ""
            for command in command_set:
                if str(command).strip().lower() == "save":
                    raw_output = _run_telnet_save_command(tn)
                else:
                    raw_output = _run_telnet_command(tn, command, enter_until_prompt=True)
                cleaned_output = _clean_cli_transcript_block(command, raw_output)
                if _is_cli_error_text(cleaned_output):
                    set_ok = False
                    first_error = (
                        f"Telnet push rejected command '{command}'. "
                        f"Device output: {cleaned_output[:160] or raw_output[:160]}"
                    )
                    break
            if set_ok:
                return True, "SNMP community pushed successfully over Telnet."
            if first_error:
                # Try next command style for this vendor before failing.
                last_error = first_error
        return False, last_error or "Telnet push failed."
    except (socket.timeout, TimeoutError):
        return False, "Telnet timeout while pushing SNMP config."
    except OSError as exc:
        return False, f"Telnet push error: {exc}"
    finally:
        if tn is not None:
            try:
                _close_telnet_session(tn)
            except OSError:
                pass


