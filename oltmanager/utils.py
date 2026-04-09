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


def _snmp_config_commands(vendor, community):
    vendor_name = (vendor or "").lower()
    if "huawei" in vendor_name:
        return [
            ["system-view", "snmp-agent", "snmp-agent sys-info version all", f"snmp-agent community read {community}", "quit", "save", "y"],
            ["enable", "config", "snmp-agent", "snmp-agent sys-info version all", f"snmp-agent community read {community}", "exit", "write"],
            ["enable", "snmp-agent", "snmp-agent sys-info version all", f"snmp-agent community read {community}", "save", "y"],
        ]
    if "zte" in vendor_name:
        return [
            ["configure terminal", f"snmp-server community {community} ro", "end", "write"],
        ]
    return [
        ["configure terminal", f"snmp-server community {community} ro", "end", "write memory"],
    ]


def _authenticate_telnet(tn, username, password):
    login_prompts = [re.compile(rb"(?i)(login|user\s*name|username|user)\s*:?\s*$")]
    password_prompts = [re.compile(rb"(?i)password\s*:?\s*$")]
    fail_markers = [re.compile(rb"(?i)(invalid|failed|denied|incorrect)")]
    # Matches common prompts like "#", "MA5600T>", "<Huawei>", "OLT]"
    shell_prompts = [re.compile(rb"(?m)^[^\r\n]*[>#\]]\s*$")]

    last_reason = "Telnet login failed."
    for eol in ("\r\n", "\n"):
        try:
            preface = tn.read_very_eager().decode("ascii", errors="ignore")
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


def open_telnet_authenticated_session(olt):
    last_status = "Telnet timeout while opening session."
    recovered_sessions = False
    for attempt in range(1, TELNET_OPEN_ATTEMPTS + 1):
        tn = None
        try:
            if attempt == 1:
                _close_competing_telnet_sessions(olt)
            tn = telnetlib.Telnet(olt.ip_address, olt.port, timeout=8)
            ok, status = _authenticate_telnet(tn, olt.username, olt.password)
            if ok:
                _register_telnet_session(olt, tn)
                return tn, status

            last_status = status
            _close_telnet_session(tn)
            if attempt < TELNET_OPEN_ATTEMPTS:
                if not recovered_sessions:
                    _close_competing_telnet_sessions(olt, force=True)
                    recovered_sessions = True
                time.sleep(TELNET_OPEN_RETRY_DELAYS[min(attempt - 1, len(TELNET_OPEN_RETRY_DELAYS) - 1)])
                continue
            return None, status
        except (socket.timeout, TimeoutError):
            last_status = "Telnet timeout while opening session."
            _close_telnet_session(tn)
            if attempt < TELNET_OPEN_ATTEMPTS:
                if not recovered_sessions:
                    _close_competing_telnet_sessions(olt, force=True)
                    recovered_sessions = True
                time.sleep(TELNET_OPEN_RETRY_DELAYS[min(attempt - 1, len(TELNET_OPEN_RETRY_DELAYS) - 1)])
                continue
            return None, last_status
        except OSError as exc:
            last_status = f"Telnet connection error: {exc}"
            _close_telnet_session(tn)
            if attempt < TELNET_OPEN_ATTEMPTS:
                if not recovered_sessions:
                    _close_competing_telnet_sessions(olt, force=True)
                    recovered_sessions = True
                time.sleep(TELNET_OPEN_RETRY_DELAYS[min(attempt - 1, len(TELNET_OPEN_RETRY_DELAYS) - 1)])
                continue
            return None, last_status

    return None, last_status


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


def _run_telnet_bulk_command(tn, command, max_wait_seconds=45):
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
            if saw_payload and idle_rounds >= 5:
                break
            if not saw_payload and idle_rounds >= 8:
                break

    output = re.sub(r"(?i)-+\s*more\s*-+", "", output)
    output = re.sub(r"(?i)--more--", "", output)
    output = re.sub(r"(?i)press\s+space\s+to\s+continue", "", output)
    output = re.sub(r"(?i)press\s+enter[^\r\n]*", "", output)
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
        cards.append(
            {
                "slot": slot,
                "type": model,
                "real_type": model,
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


def _merge_card_detail(card, detail_output):
    detail_text = detail_output or ""
    if not detail_text:
        return

    parsed_real_type = _parse_card_real_type(detail_text, card.get("real_type") or card.get("type") or "")
    if parsed_real_type:
        card["real_type"] = parsed_real_type
        card["model_type"] = parsed_real_type

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
    if not slot_ports:
        return optical_map

    grouped_ports = {}
    for slot, port in slot_ports:
        grouped_ports.setdefault(int(slot), set()).add(int(port))

    for slot in sorted(grouped_ports):
        board_kind, _, entered = _enter_interface_context(tn, ("gpon",), 0, slot)
        if not entered or board_kind != "gpon":
            continue
        for port in sorted(grouped_ports[slot]):
            output = _run_telnet_command(tn, f"display ont optical-info {port} all", enter_until_prompt=True)
            optical_map.update(_parse_port_optical_table(output, slot, port))
        _run_telnet_command(tn, "quit")
        _run_telnet_command(tn, "quit")
    return optical_map


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
        optical_map = _fetch_ont_optical_map_in_context(tn, [(slot, port)])
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
        optical_map = _fetch_ont_optical_map_in_context(tn, slot_ports)
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
        optical_map = _fetch_ont_optical_map_in_context(tn, slot_ports)
        for row in rows:
            row["description"] = desc_map.get((row["slot"], row["port"], row["ont_id"]), "").strip()
            power = optical_map.get((row["slot"], row["port"], row["ont_id"])) or {}
            row["onu_rx"] = power.get("onu_rx", "--")
            row["tx_power"] = power.get("tx_power", "--")
            row["olt_rx"] = power.get("olt_rx", "--")
            row["signal_bucket"] = _signal_bucket_from_dbm_text(row["onu_rx"])
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
    magnitude = abs(float(avg_signal))
    if magnitude <= 26:
        return "good"
    if magnitude <= 30:
        return "warn"
    return "bad"


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
    for item in ConfiguredONU.objects.filter(olt=olt).values("slot", "port", "onu_rx"):
        slot = int(item.get("slot") or 0)
        port = int(item.get("port") or 0)
        signal = _parse_dbm_float(item.get("onu_rx"))
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
    if not vlan_match:
        return None
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
        desc_map = {}
        desc_output = _run_telnet_command(tn, "display vlan description", enter_until_prompt=True)
        desc_map.update(_parse_vlan_description_table(desc_output))
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
    equipment_match = re.search(r"(?im)^\s*ONT\s+equipmentid\s*:\s*(.+)$", text)
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

    tn, status = open_telnet_authenticated_session(olt)
    if tn is None:
        return {"olt": olt.name, "checked": 0, "updated": 0, "status": status, "last_pk": start_pk or 0, "wrapped": wrapped}

    updated = 0
    checked = 0
    bulk = []
    now = timezone.now()
    try:
        _prepare_telnet_cli_session(tn, use_paging=True)
        for record in records:
            checked += 1
            output = _run_telnet_command(
                tn,
                f"display ont info 0 {int(record.slot)} {int(record.port)} {int(record.ont_id)}",
                enter_until_prompt=True,
            )
            snapshot = _parse_ont_runtime_snapshot(output)

            changed = False
            runtime_run_state = str(snapshot.get("run_state") or "").strip()
            runtime_control_flag = str(snapshot.get("control_flag") or "").strip()
            if runtime_run_state and runtime_run_state != (record.run_state or "").strip():
                record.run_state = runtime_run_state
                changed = True
            if runtime_control_flag and runtime_control_flag != (record.control_flag or "").strip():
                record.control_flag = runtime_control_flag
                changed = True

            if changed:
                updated += 1
                bulk.append(record)

        if bulk:
            ConfiguredONU.objects.bulk_update(
                bulk,
                ["run_state", "control_flag"],
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
            "status": "Telnet timeout during runtime sync.",
            "last_pk": records[-1].id if records else (start_pk or 0),
            "wrapped": wrapped,
        }
    except (EOFError, OSError) as exc:
        return {
            "olt": olt.name,
            "checked": checked,
            "updated": updated,
            "status": f"Telnet error during runtime sync: {exc}",
            "last_pk": records[-1].id if records else (start_pk or 0),
            "wrapped": wrapped,
        }
    finally:
        _close_telnet_session(tn)


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
    snapshot = fetch_ont_autofind_snapshot(olt)
    rows = snapshot.get("rows") or []
    olt.autofind_onu_count = len(rows)
    olt.autofind_status = str(snapshot.get("status") or "")[:300]
    olt.autofind_refreshed_at = timezone.now()
    olt.save(update_fields=["autofind_onu_count", "autofind_status", "autofind_refreshed_at"])
    return {
        "count": olt.autofind_onu_count,
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


def add_vlan_range(olt, start_vlan, end_vlan):
    result = {
        "ok": False,
        "message": "VLAN range create failed.",
        "transcript": "",
    }
    tn, status = open_telnet_authenticated_session(olt)
    if tn is None:
        result["message"] = status
        result["transcript"] = f"LOGIN FAILED\n{status}"
        return result

    try:
        transcript_parts = []
        _prepare_telnet_cli_session(tn, use_paging=False)
        transcript_parts.append("enable")
        transcript_parts.append("config")
        config_entered, config_output = _enter_config_mode(tn)
        if not config_entered:
            result["message"] = "Unable to enter configuration mode."
            result["transcript"] = "\n\n".join([part for part in transcript_parts + [str(config_output or "").strip()] if part])
            return result

        range_command = f"vlan {int(start_vlan)}-{int(end_vlan)}"
        transcript_parts.append(range_command)
        try:
            tn.read_very_eager()
        except (OSError, EOFError):
            pass
        tn.write((range_command + "\r\n").encode("ascii", errors="ignore"))
        output = ""
        prompt_pattern = re.compile(rb"(?m)^[^\r\n]*[>#\]]\s*$")
        yes_no_patterns = [
            re.compile(rb"(?i)\b\(yes/no\)\b"),
            re.compile(rb"(?i)\by/n\b"),
            re.compile(rb"(?i)\bcontinue\b"),
        ]
        patterns = yes_no_patterns + [prompt_pattern]
        answered_yes = False
        start_ts = time.time()
        while time.time() - start_ts < 15:
            idx, _, text = tn.expect(patterns, timeout=0.8)
            if text:
                output += ANSI_ESCAPE_PATTERN.sub("", text.decode("ascii", errors="ignore"))
            else:
                try:
                    extra = tn.read_very_eager().decode("ascii", errors="ignore")
                except EOFError:
                    break
                output += ANSI_ESCAPE_PATTERN.sub("", extra or "")
            if idx in (0, 1, 2) and not answered_yes:
                _touch_telnet_session(tn)
                tn.write(b"y\r\n")
                answered_yes = True
                continue
            lines = [line.strip() for line in output.splitlines() if line.strip()]
            if lines and PROMPT_LINE_PATTERN.match(lines[-1]):
                break

        cleaned_output = _clean_cli_transcript_block(range_command, output)
        if cleaned_output:
            transcript_parts.append(cleaned_output)
        lowered = str(output or "").lower()
        if _is_cli_error_text(output):
            result["message"] = str(output or "").strip() or "OLT rejected VLAN range command."
            result["transcript"] = "\n\n".join([part for part in transcript_parts if part])
            return result

        processed_match = re.search(r"processed\s+is\s+(\d+)", output, re.IGNORECASE)
        added_match = re.search(r"added\s+vlans?\s+is\s+(\d+)", output, re.IGNORECASE)
        processed = int(processed_match.group(1)) if processed_match else 0
        added = int(added_match.group(1)) if added_match else 0
        expected = (int(end_vlan) - int(start_vlan)) + 1
        if processed == expected and added == expected:
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
            result["message"] = "VLAN range created."
            result["transcript"] = "\n\n".join([part for part in transcript_parts if part])
            return result

        result["message"] = str(output or "").strip() or "VLAN range was not confirmed by the OLT."
        result["transcript"] = "\n\n".join([part for part in transcript_parts if part])
        return result
    except (socket.timeout, TimeoutError):
        result["message"] = "Telnet timeout while creating VLAN range."
        return result
    except EOFError:
        result["message"] = "Telnet connection closed while creating VLAN range."
        return result
    except OSError as exc:
        result["message"] = f"Telnet error while creating VLAN range: {exc}"
        return result
    finally:
        _close_telnet_session(tn)


def add_vlan(olt, vlan_id, description=""):
    result = {
        "ok": False,
        "message": "VLAN create failed.",
        "transcript": "",
    }
    tn, status = open_telnet_authenticated_session(olt)
    if tn is None:
        result["message"] = status
        result["transcript"] = f"LOGIN FAILED\n{status}"
        return result

    try:
        transcript_parts = []
        _prepare_telnet_cli_session(tn, use_paging=False)
        transcript_parts.append("enable")
        transcript_parts.append("config")
        config_entered, config_output = _enter_config_mode(tn)
        if not config_entered:
            result["message"] = "Unable to enter configuration mode."
            result["transcript"] = "\n\n".join([part for part in transcript_parts + [str(config_output or "").strip()] if part])
            return result

        vlan_command = f"vlan {int(vlan_id)} smart"
        transcript_parts.append(vlan_command)
        vlan_output = _run_telnet_command(tn, vlan_command, enter_until_prompt=True)
        cleaned_vlan_output = _clean_cli_transcript_block(vlan_command, vlan_output)
        if cleaned_vlan_output:
            transcript_parts.append(cleaned_vlan_output)
        lowered_vlan = str(vlan_output or "").lower()
        if _is_cli_error_text(vlan_output) or "already exist" in lowered_vlan or "already exists" in lowered_vlan or "duplicate" in lowered_vlan:
            result["message"] = str(vlan_output or "").strip() or "OLT rejected VLAN create command."
            result["transcript"] = "\n\n".join([part for part in transcript_parts if part])
            return result

        description = str(description or "").strip()
        if description:
            desc_command = f"vlan desc {int(vlan_id)} description {description}"
            transcript_parts.append(desc_command)
            desc_output = _run_telnet_command(tn, desc_command, enter_until_prompt=True)
            cleaned_desc_output = _clean_cli_transcript_block(desc_command, desc_output)
            if cleaned_desc_output:
                transcript_parts.append(cleaned_desc_output)
            if _is_cli_error_text(desc_output):
                result["message"] = str(desc_output or "").strip() or "VLAN created, but description command failed."
                result["transcript"] = "\n\n".join([part for part in transcript_parts if part])
                return result

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
        result["message"] = "VLAN created."
        result["transcript"] = "\n\n".join([part for part in transcript_parts if part])
        return result
    except (socket.timeout, TimeoutError):
        result["message"] = "Telnet timeout while creating VLAN."
        return result
    except EOFError:
        result["message"] = "Telnet connection closed while creating VLAN."
        return result
    except OSError as exc:
        result["message"] = f"Telnet error while creating VLAN: {exc}"
        return result
    finally:
        _close_telnet_session(tn)


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
        groups = []
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
        source_note = " | cards cache" if cached_cards else ""
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


def _current_dashboard_sample_boundary(now=None):
    now = now or timezone.now()
    epoch = int(now.timestamp())
    bucket_epoch = (epoch // DASHBOARD_STATUS_SAMPLE_SECONDS) * DASHBOARD_STATUS_SAMPLE_SECONDS
    return datetime.datetime.fromtimestamp(bucket_epoch, tz=datetime.timezone.utc)


def _dashboard_status_counts_from_queryset(qs):
    from django.db.models import Count, Q

    return qs.aggregate(
        total_onus=Count('id'),
        online_onus=Count('id', filter=Q(run_state__iexact='online')),
        admin_disabled=Count('id', filter=Q(derived_status='admin_disabled')),
        power_failure=Count('id', filter=Q(derived_status='power_failure')),
        loss_of_signal=Count('id', filter=Q(derived_status='loss_of_signal')),
        signal_warn=Count('id', filter=Q(signal_bucket='warn')),
        signal_bad=Count('id', filter=Q(signal_bucket='bad')),
    )


def record_dashboard_status_samples(force=False):
    from .models import ConfiguredONU, DashboardStatusSample, OLT

    boundary = _current_dashboard_sample_boundary()
    latest = DashboardStatusSample.objects.order_by('-sampled_at').first()
    if latest and latest.sampled_at >= boundary:
        return False
    if latest and not force and latest.sampled_at >= boundary:
        return False

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
            admin_disabled=int(global_counts.get('admin_disabled') or 0),
            power_failure=int(global_counts.get('power_failure') or 0),
            loss_of_signal=int(global_counts.get('loss_of_signal') or 0),
            signal_warn=int(global_counts.get('signal_warn') or 0),
            signal_bad=int(global_counts.get('signal_bad') or 0),
        )
    ]

    olt_ids = list(OLT.objects.values_list('id', flat=True))
    for olt_id in olt_ids:
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
    if latest:
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


def push_snmp_config_over_telnet(olt, community):
    tn, auth_status = open_telnet_authenticated_session(olt)
    if tn is None:
        return False, auth_status

    try:
        error_markers = (
            "error",
            "invalid",
            "incomplete",
            "unrecognized",
            "failure",
            "denied",
        )
        last_error = ""
        for command_set in _snmp_config_commands(olt.vendor, community):
            set_ok = True
            first_error = ""
            for command in command_set:
                tn.write((command + "\n").encode("ascii", errors="ignore"))
                time.sleep(0.45)
                chunk = tn.read_very_eager().decode("ascii", errors="ignore").lower()
                if any(marker in chunk for marker in error_markers):
                    set_ok = False
                    first_error = f"Telnet push rejected command '{command}'. Device output: {chunk[:160]}"
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


