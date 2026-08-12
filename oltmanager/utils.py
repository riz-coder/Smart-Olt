import asyncio
import datetime
import json
import os
import platform
import re
import secrets
import socket
import subprocess
import telnetlib
import threading
import time

from django.conf import settings
from django.db import OperationalError
from django.db.models import Q
from django.utils import timezone

try:
    from ncclient import manager as nc_manager
except Exception:
    nc_manager = None


BOARD_DEFAULT_PORTS = {
    # Huawei GPON service boards
    "H805GPFD": 16,
    "H807GPFD": 16,
    "H801GPFD": 16,
    "H801GPBH": 8,
    "H801GPHF": 8,
    "H807GPHF": 8,
    "H802GPBD": 16,
    "H806GPFD": 16,
    "H831GPBH": 8,
    "H901CGID": 8,
    # Huawei EPON service boards
    "H802EPFD": 16,
    "H807EPFC": 16,
    "H801EPFC": 16,
    "H802EPFC": 16,
    # Huawei XGS-PON / XG-PON service boards
    "H801XGSB": 8,
    "H801XGHD": 4,
    "H801XGHE": 4,
    # Huawei control / main boards
    "H801X2CS": 2,
    "H801GICF": 8,
    "H802SCUN": 4,
    "H801MPSC": 0,
    "H802MPSC": 0,
}

TELNET_OPEN_ATTEMPTS = 3
TELNET_OPEN_RETRY_DELAYS = (0.7, 1.4)
DB_SIGNED_BIGINT_MAX = 9223372036854775807
DB_SIGNED_BIGINT_MIN = -9223372036854775808
TELNET_SESSION_RECOVERY_GRACE_SECONDS = 20
OLT_SAVE_DEBOUNCE_SECONDS = 180
PROMPT_LINE_PATTERN = re.compile(r"^[^\r\n]*[>#\]]\s*$")
ANSI_ESCAPE_PATTERN = re.compile(r"\x1B\[[0-?]*[ -/]*[@-~]")
_TELNET_SESSION_LOCK = threading.Lock()
_TELNET_SESSIONS = {}
_OLT_SAVE_QUEUE_LOCK = threading.Lock()
_OLT_SAVE_TIMERS = {}
_ONU_TRAFFIC_IFINDEX_CACHE_LOCK = threading.Lock()
_ONU_TRAFFIC_IFINDEX_CACHE = {}
_DASHBOARD_STATUS_SAMPLE_LOCK = threading.Lock()
_DASHBOARD_STATUS_SAMPLE_LAST_FORCE_TS = 0.0
_ONU_SNMP_RUNTIME_STATUS_LOCK = threading.Lock()
_ONU_SNMP_RUNTIME_STATUS_DEBOUNCE = {}


def _telnet_auth_output_detected(text):
    lowered = str(text or "").lower()
    markers = (
        "user name or password invalid",
        "username or password invalid",
        "configuration console exit",
        "please retry to log on",
        ">>user name:",
        ">>user password:",
    )
    return any(marker in lowered for marker in markers)


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


def fetch_snmp_snapshot(olt, *, include_entity_metrics=True, operation_timeout=4.0):
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

        def _run_snmp_operation(awaitable):
            if operation_timeout and operation_timeout > 0:
                return asyncio.run(asyncio.wait_for(awaitable, timeout=float(operation_timeout)))
            return asyncio.run(awaitable)

        def _pick_entity_metrics(mp_model):
            if not include_entity_metrics:
                return {"temperature": "--", "cpu": "--", "memory": "--"}
            try:
                names = _run_snmp_operation(_snmp_walk(mp_model, "1.3.6.1.2.1.47.1.1.1.1.7"))
                classes = _run_snmp_operation(_snmp_walk(mp_model, "1.3.6.1.2.1.47.1.1.1.1.5"))
                cpus = _run_snmp_operation(_snmp_walk(mp_model, "1.3.6.1.4.1.2011.5.25.31.1.1.1.1.5"))
                mems = _run_snmp_operation(_snmp_walk(mp_model, "1.3.6.1.4.1.2011.5.25.31.1.1.1.1.7"))
                temps = _run_snmp_operation(_snmp_walk(mp_model, "1.3.6.1.4.1.2011.5.25.31.1.1.1.1.11"))
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
            error_indication, error_status, _, var_binds = _run_snmp_operation(_snmp_get(mp_model))
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


def _snmp_ber_length(size):
    size = int(size)
    if size < 128:
        return bytes([size])
    raw = size.to_bytes((size.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def _snmp_ber_tlv(tag, payload):
    payload = bytes(payload)
    return bytes([tag]) + _snmp_ber_length(len(payload)) + payload


def _snmp_ber_integer(value):
    value = int(value)
    if value == 0:
        raw = b"\x00"
    else:
        raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
        if raw[0] & 0x80:
            raw = b"\x00" + raw
    return _snmp_ber_tlv(0x02, raw)


def _snmp_ber_octet_string(value):
    return _snmp_ber_tlv(0x04, str(value or "").encode("utf-8", errors="ignore"))


def _snmp_ber_oid(oid):
    parts = [int(part) for part in str(oid).strip(".").split(".") if part]
    if len(parts) < 2:
        raise ValueError("Invalid OID")
    encoded = bytearray([parts[0] * 40 + parts[1]])
    for part in parts[2:]:
        stack = [part & 0x7F]
        part >>= 7
        while part:
            stack.append(0x80 | (part & 0x7F))
            part >>= 7
        encoded.extend(reversed(stack))
    return _snmp_ber_tlv(0x06, encoded)


def _snmp_lightweight_get_probe(host, port, community, *, version=1, timeout=1.0):
    request_id = secrets.randbelow(0x7FFFFFFF) or 1
    varbind = _snmp_ber_tlv(0x30, _snmp_ber_oid("1.3.6.1.2.1.1.5.0") + _snmp_ber_tlv(0x05, b""))
    varbind_list = _snmp_ber_tlv(0x30, varbind)
    pdu = _snmp_ber_tlv(
        0xA0,
        _snmp_ber_integer(request_id)
        + _snmp_ber_integer(0)
        + _snmp_ber_integer(0)
        + varbind_list,
    )
    packet = _snmp_ber_tlv(
        0x30,
        _snmp_ber_integer(version)
        + _snmp_ber_octet_string(community)
        + pdu,
    )
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(float(timeout or 1.0))
        sock.sendto(packet, (str(host), int(port or 161)))
        data, _ = sock.recvfrom(2048)
    return bool(data)


def probe_snmp_reachability(olt):
    result = {
        "ok": False,
        "status": "SNMP no response",
    }
    last_error = ""
    for version in (1, 0):  # SNMP v2c first, then v1.
        try:
            if _snmp_lightweight_get_probe(
                olt.ip_address,
                olt.snmp_port,
                olt.snmp_community,
                version=version,
                timeout=1.0,
            ):
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


def probe_icmp_reachability(olt):
    ip_address = str(getattr(olt, "ip_address", "") or "").strip()
    if not ip_address:
        return {"ok": False, "status": "ICMP ping failed: no IP address"}
    try:
        is_windows = platform.system().lower().startswith("win")
        command = ["ping", "-n", "1", "-w", "1000", ip_address] if is_windows else ["ping", "-c", "1", "-W", "1", ip_address]
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=3,
            check=False,
        )
        if completed.returncode == 0:
            return {"ok": True, "status": "ICMP is fine"}
        output = f"{completed.stdout or ''}\n{completed.stderr or ''}".strip()
        return {"ok": False, "status": (output or "ICMP ping failed")[:300]}
    except Exception as exc:
        return {"ok": False, "status": f"ICMP ping failed: {exc}"[:300]}


def mark_olt_onus_offline_due_to_snmp(olt, *, status_text=""):
    from .models import ConfiguredONU, ONUStatusSample

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

    olt.snmp_last_status = (status_text or "OLT is down")[:300]
    olt.snmp_last_synced_at = now
    olt.save(update_fields=["snmp_last_status", "snmp_last_synced_at"])

    try:
        from .alerts import raise_alert
        raise_alert(
            alert_type="olt_down",
            key=f"olt_down:{olt.id}",
            severity="critical",
            title=f"OLT Down: {olt.name}",
            message=f"{olt.name} ({olt.ip_address}) is {status_text or 'unreachable'}. Affected ONUs: {len(rows)}.",
            olt=olt,
            details={"status": status_text, "affected_onus": len(rows)},
        )
    except Exception:
        pass
    return {"checked": len(rows), "updated": len(rows)}


def mark_olt_onus_online_after_snmp_recovery(olt, *, status_text="Live SNMP data fetched"):
    now = timezone.now()

    # First mark the OLT reachable so reconcile is allowed to run.
    olt.snmp_last_status = str(status_text or "Live SNMP data fetched")[:300]
    olt.snmp_last_synced_at = now
    olt.save(update_fields=["snmp_last_status", "snmp_last_synced_at"])

    # Accurate recovery: read each ONU's *real* online/offline from a single SNMP
    # status walk instead of blindly marking everything online (which previously
    # produced both false-online and stuck-offline ONUs).
    try:
        outcome = reconcile_onu_status_via_snmp(olt)
    except Exception:
        outcome = {"checked": 0, "updated": 0}

    try:
        from .alerts import resolve_alert
        resolve_alert(
            f"olt_down:{olt.id}",
            send_recovery=True,
            recovery_type="olt_recovered",
            title=f"OLT Recovered: {olt.name}",
            message=f"{olt.name} ({olt.ip_address}) is back online.",
            olt=olt,
        )
    except Exception:
        pass
    return {"checked": int(outcome.get("checked") or 0), "updated": int(outcome.get("updated") or 0)}


def reconcile_onu_status_via_snmp(olt, *, only_snmp_down=True, limit=None):
    """Bulk-correct ONU online/offline from a single SNMP status walk.

    This is the robust, self-healing recovery path: when an OLT is reachable it
    reads the *real* per-ONU status in one shot and fixes any ONU that was left
    stuck in the ``snmp_down`` state from an earlier outage — independent of any
    in-memory flag, so it survives a server restart.

    ``only_snmp_down=True`` limits the work to the stuck ONUs (cheap, common case).
    """
    from django.utils import timezone
    from .models import ConfiguredONU

    result = {"checked": 0, "updated": 0, "status": ""}

    # Never run while the OLT itself looks unreachable.
    if _snmp_status_looks_down(getattr(olt, "snmp_last_status", "")):
        result["status"] = "OLT not reachable — skipped."
        return result

    base_qs = ConfiguredONU.objects.filter(olt=olt)
    if only_snmp_down:
        base_qs = base_qs.filter(status_source="snmp_down")
    # Quick exit when there is nothing stuck to fix.
    if only_snmp_down and not base_qs.exists():
        result["status"] = "Nothing to reconcile."
        return result

    status_map = fetch_olt_snmp_status_map(olt)
    items = status_map.get("items") or {}
    if not items:
        result["status"] = status_map.get("status") or "No SNMP status data."
        return result
    snmp_complete = bool(items) and not bool(status_map.get("truncated"))

    records = list(base_qs.order_by("id")[:limit] if limit else base_qs)
    now = timezone.now()
    updated = []
    for rec in records:
        key = (int(rec.slot), int(rec.port), int(rec.ont_id))
        real = items.get(key)
        if not real:
            if not snmp_complete:
                continue
            real = "offline"
        changed = False
        if real == "online":
            if rec.derived_status != "online" or rec.run_state != "online":
                rec.derived_status = "online"
                rec.run_state = "online"
                changed = True
        else:  # offline
            if rec.derived_status != "offline" or rec.run_state != "offline":
                rec.derived_status = "offline"
                rec.run_state = "offline"
                changed = True
        # We now have real data — move it off the "snmp_down" outage marker so it
        # is no longer treated as stuck.
        if rec.status_source == "snmp_down":
            rec.status_source = "snmp_status"
            changed = True
        if changed:
            rec.status_updated_at = now
            updated.append(rec)

    if updated:
        ConfiguredONU.objects.bulk_update(
            updated,
            ["derived_status", "run_state", "status_source", "status_updated_at"],
            batch_size=500,
        )
    result["checked"] = len(records)
    result["updated"] = len(updated)
    result["status"] = f"Reconciled {len(updated)}/{len(records)} ONU(s) from SNMP."
    return result


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


def fetch_single_onu_snmp_traffic_counters(olt, slot, port, ont_id, *, frame=0):
    result = {
        "ok": False,
        "status": "SNMP ONU traffic unavailable",
        "if_index": "",
        "up_bytes": 0,
        "down_bytes": 0,
        "up_packets": 0,
        "down_packets": 0,
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

    def _counter_value(value):
        text = str(value or "").strip()
        if not text.isdigit() or text in {"18446744073709551615", "4294967295"}:
            return 0
        return int(text)

    try:
        if_index = _resolve_snmp_gpon_ifindex(olt, slot, port, frame=frame)
        if not if_index:
            result["status"] = "SNMP traffic ifIndex lookup failed"
            return result
        result["if_index"] = str(if_index)
        suffix = f"{int(if_index)}.{int(ont_id)}"
        oids = [
            f"1.3.6.1.4.1.2011.6.128.1.1.4.23.1.3.{suffix}",  # upstream bytes
            f"1.3.6.1.4.1.2011.6.128.1.1.4.23.1.4.{suffix}",  # downstream bytes
            f"1.3.6.1.4.1.2011.6.128.1.1.4.23.1.1.{suffix}",  # upstream packets
            f"1.3.6.1.4.1.2011.6.128.1.1.4.23.1.2.{suffix}",  # downstream packets
        ]

        async def _get(mp_model):
            target = await UdpTransportTarget.create(
                (olt.ip_address, olt.snmp_port),
                timeout=1.2,
                retries=1,
            )
            engine = SnmpEngine()
            try:
                return await get_cmd(
                    engine,
                    CommunityData(olt.snmp_community, mpModel=mp_model),
                    target,
                    ContextData(),
                    *[ObjectType(ObjectIdentity(oid)) for oid in oids],
                )
            finally:
                engine.close_dispatcher()

        last_error = ""
        for mp_model in (1, 0):
            try:
                error_indication, error_status, _, var_binds = asyncio.run(_get(mp_model))
                if error_indication:
                    last_error = str(error_indication)
                    continue
                if error_status:
                    last_error = error_status.prettyPrint()
                    continue
                values = [str(var_bind[1]) for var_bind in var_binds]
                if any("No Such" in value for value in values):
                    last_error = "No ONU traffic counters at this OID"
                    continue
                result.update(
                    {
                        "ok": True,
                        "status": "SNMP ONU traffic fetched",
                        "up_bytes": _counter_value(values[0]),
                        "down_bytes": _counter_value(values[1]),
                        "up_packets": _counter_value(values[2]),
                        "down_packets": _counter_value(values[3]),
                    }
                )
                return result
            except Exception as exc:
                last_error = str(exc)
        result["status"] = f"SNMP ONU traffic fetch failed: {last_error or 'no response'}"
        return result
    except Exception as exc:
        result["status"] = f"SNMP ONU traffic fetch failed: {exc}"
        return result


def _snmp_normalize_ifname(value):
    text = str(value or "").strip().strip('"').upper()
    text = re.sub(r"[_-]+", " ", text)
    text = re.sub(r"\s+", " ", text)
    return text


def _parse_snmp_gpon_fsp_from_ifname(value):
    normalized = _snmp_normalize_ifname(value)
    patterns = (
        r"\b(?:GPON|XGPON|EPON)\s*(\d+)\s*/\s*(\d+)\s*/\s*(\d+)\b",
        r"\b(?:GPON|XGPON|EPON)\s+(\d+)\s+(\d+)\s+(\d+)\b",
        r"^\s*(\d+)\s*/\s*(\d+)\s*/\s*(\d+)\s*$",
    )
    for pattern in patterns:
        match = re.search(pattern, normalized)
        if match:
            return tuple(int(part) for part in match.groups())
    return None


def _snmp_walk_rows(olt, base_oid, *, limit=4096, mp_model=1):
    from pysnmp.hlapi.asyncio import (  # type: ignore
        bulk_cmd,
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
        # Use GETBULK instead of one GETNEXT per row. Large OLTs have thousands
        # of ONUs; walking them row-by-row makes dashboard status sync take
        # minutes and leaves online/offline counts stale.
        max_repetitions = 48
        max_rounds = max(1, (int(limit or 1) // max_repetitions) + 2)
        for _ in range(max_rounds):
            error_indication, error_status, _, var_binds = await bulk_cmd(
                engine,
                CommunityData(olt.snmp_community, mpModel=mp_model),
                target,
                ContextData(),
                0,
                max_repetitions,
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
                if len(rows) >= int(limit or 0):
                    stop = True
                    break
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
        engine = SnmpEngine()
        try:
            return await get_cmd(
                engine,
                CommunityData(olt.snmp_community, mpModel=mp_model),
                target,
                ContextData(),
                ObjectType(ObjectIdentity(oid)),
            )
        finally:
            engine.close_dispatcher()

    return _run_asyncio_sync(_get())


def _snmp_get_many_values(olt, oid_list, *, mp_model=1):
    from pysnmp.hlapi.asyncio import (  # type: ignore
        CommunityData,
        ContextData,
        ObjectIdentity,
        ObjectType,
        SnmpEngine,
        UdpTransportTarget,
        get_cmd,
    )

    oid_list = [str(oid) for oid in (oid_list or []) if str(oid or "").strip()]
    if not oid_list:
        return {}

    async def _get_many():
        target = await UdpTransportTarget.create(
            (olt.ip_address, olt.snmp_port),
            timeout=1.2,
            retries=1,
        )
        engine = SnmpEngine()
        try:
            error_indication, error_status, _, var_binds = await get_cmd(
                engine,
                CommunityData(olt.snmp_community, mpModel=mp_model),
                target,
                ContextData(),
                *[ObjectType(ObjectIdentity(oid)) for oid in oid_list],
            )
            if error_indication or error_status:
                return {}
            return {
                str(oid): value
                for oid, value in (var_binds or [])
                if _snmp_varbind_has_value(((oid, value),))
            }
        finally:
            engine.close_dispatcher()

    return _run_asyncio_sync(_get_many())


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
        engine = SnmpEngine()
        try:
            return await set_cmd(
                engine,
                CommunityData(olt.snmp_write_community or olt.snmp_community, mpModel=mp_model),
                target,
                ContextData(),
                ObjectType(ObjectIdentity(oid), caster(value)),
            )
        finally:
            engine.close_dispatcher()

    return _run_asyncio_sync(_set())


def _snmp_set_multi(olt, oid_value_type_list, *, mp_model=1):
    """Send a single SNMP SET request with multiple varbinds.
    oid_value_type_list: list of (oid_str, value, "Integer"|"OctetString") tuples.
    Returns (error_indication, error_status, error_index, var_binds).
    """
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

    type_map = {"Integer": Integer, "OctetString": OctetString}

    async def _set():
        target = await UdpTransportTarget.create(
            (olt.ip_address, olt.snmp_port),
            timeout=3.0,
            retries=1,
        )
        engine = SnmpEngine()
        try:
            obj_types = [
                ObjectType(ObjectIdentity(oid), type_map.get(vtype, Integer)(value))
                for oid, value, vtype in oid_value_type_list
            ]
            return await set_cmd(
                engine,
                CommunityData(olt.snmp_write_community or olt.snmp_community, mpModel=mp_model),
                target,
                ContextData(),
                *obj_types,
            )
        finally:
            engine.close_dispatcher()

    return _run_asyncio_sync(_set())


def _snmp_varbind_has_value(var_binds):
    if not var_binds:
        return False
    try:
        value = var_binds[0][1]
    except Exception:
        return False
    type_name = value.__class__.__name__.lower()
    if "nosuch" in type_name:
        return False
    pretty = str(getattr(value, "prettyPrint", lambda: str(value))() or "").strip().lower()
    if pretty.startswith("no such "):
        return False
    return True


def _snmp_error_text(error_indication, error_status):
    if error_indication:
        return str(error_indication)
    if error_status:
        try:
            return error_status.prettyPrint()
        except Exception:
            return str(error_status)
    return ""


def _resolve_snmp_gpon_ifindex(olt, slot, port, *, frame=0, ifname_limit=4096):
    cache_key = (int(olt.pk), int(frame), int(slot), int(port))
    target_fsp = (int(frame), int(slot), int(port))
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
                if _parse_snmp_gpon_fsp_from_ifname(if_name) == target_fsp:
                    with _ONU_TRAFFIC_IFINDEX_CACHE_LOCK:
                        _ONU_TRAFFIC_IFINDEX_CACHE[cache_key] = str(idx)
                    return str(idx)
        except Exception as exc:
            last_error = str(exc)
    return ""


def _snmp_onu_key_maps(olt, *, ifname_limit=None):
    ifname_limit, _ = _configured_onu_snmp_walk_limits(olt, ifname_limit=ifname_limit, status_limit=None)
    ifname_rows = None
    last_error = ""
    for mp_model in (1, 0):
        try:
            ifname_rows = _snmp_walk_rows(olt, "1.3.6.1.2.1.31.1.1.1.1", limit=ifname_limit, mp_model=mp_model)
            break
        except Exception as exc:
            last_error = str(exc)
    if ifname_rows is None:
        raise RuntimeError(last_error or "ifName walk failed")
    gpon_indexes = {}
    for oid_text, if_name in (ifname_rows or {}).items():
        idx = oid_text.split(".")[-1]
        fsp = _parse_snmp_gpon_fsp_from_ifname(if_name)
        if not fsp:
            continue
        frame, slot, port = fsp
        gpon_indexes[str(idx)] = (frame, slot, port)
        cache_key = (int(olt.pk), frame, slot, port)
        with _ONU_TRAFFIC_IFINDEX_CACHE_LOCK:
            _ONU_TRAFFIC_IFINDEX_CACHE[cache_key] = str(idx)
    return gpon_indexes


def _format_snmp_text_value(raw_value):
    text = str(raw_value or "").strip()
    if not text or text.lower() in {"no such object", "no such instance", "unknown"}:
        return ""
    if text.startswith("0x"):
        try:
            raw = bytes.fromhex(text[2:].replace(" ", ""))
            return raw.decode("ascii", errors="ignore").strip("\x00 \r\n\t")[:128]
        except Exception:
            return text[:128]
    return text.strip('"')[:128]


def _snmp_rows_for_first_working_model(olt, base_oid, *, limit=16384):
    last_error = ""
    for mp_model in (1, 0):
        try:
            return _snmp_walk_rows(olt, base_oid, limit=limit, mp_model=mp_model), ""
        except Exception as exc:
            last_error = str(exc)
    return {}, last_error or "no response"


def _snmp_onu_rows_to_key_map(rows, base_oid, gpon_indexes, formatter):
    items = {}
    for oid_text, raw_value in (rows or {}).items():
        suffix = str(oid_text or "")[len(base_oid) + 1:]
        parts = suffix.split(".")
        if len(parts) < 2:
            continue
        if_index = str(parts[-2]).strip()
        try:
            ont_id = int(parts[-1])
        except (TypeError, ValueError):
            continue
        fsp = gpon_indexes.get(if_index)
        if not fsp:
            continue
        _, slot, port = fsp
        value = formatter(raw_value)
        if value:
            items[(slot, port, ont_id)] = value
    return items


def _snmp_status_rows_to_key_map(run_rows, config_rows, base_run_oid, base_config_oid, pon_indexes, *, allow_direct_index=False):
    items = {}

    config_by_suffix = {}
    for oid_text, raw_value in (config_rows or {}).items():
        suffix = str(oid_text or "")[len(base_config_oid) + 1:]
        if suffix:
            config_by_suffix[suffix] = str(raw_value or "").strip()

    def _put(key, raw_run, config_suffix):
        status_value = _map_snmp_onu_status(raw_run, config_by_suffix.get(config_suffix))
        if status_value:
            items[key] = status_value

    if allow_direct_index:
        for oid_text, raw_value in (run_rows or {}).items():
            suffix = str(oid_text or "")[len(base_run_oid) + 1:]
            parts = suffix.split(".")
            if len(parts) < 4:
                continue
            try:
                slot = int(parts[-3])
                port = int(parts[-2])
                ont_id = int(parts[-1])
            except (TypeError, ValueError):
                continue
            _put((slot, port, ont_id), raw_value, suffix)

    for oid_text, raw_value in (run_rows or {}).items():
        suffix = str(oid_text or "")[len(base_run_oid) + 1:]
        parts = suffix.split(".")
        if len(parts) < 2:
            continue
        if_index = str(parts[-2]).strip()
        try:
            ont_id = int(parts[-1])
        except (TypeError, ValueError):
            continue
        fsp = pon_indexes.get(if_index)
        if not fsp:
            continue
        _, slot, port = fsp
        _put((slot, port, ont_id), raw_value, suffix)

    return items


def _snmp_epon_rows_to_key_map(rows, base_oid, gpon_indexes, formatter):
    """Parse EPON DDM OID rows.

    Tries two indexing schemes in order:
      1. frame.slot.port.onu_id  (hwEponDeviceOntOpticsDdmInfoTable .104.x — 4-part index)
      2. ifIndex.onu_id          (same as GPON — falls back if scheme 1 finds nothing)
    Returns {(slot, port, onu_id): formatted_value}.
    """
    items = {}

    # Scheme 1: frame.slot.port.onu_id (4-part direct index)
    for oid_text, raw_value in (rows or {}).items():
        suffix = str(oid_text or "")[len(base_oid) + 1:]
        parts = suffix.split(".")
        if len(parts) < 4:
            continue
        try:
            slot = int(parts[-3])
            port = int(parts[-2])
            onu_id = int(parts[-1])
        except (TypeError, ValueError):
            continue
        value = formatter(raw_value)
        if value and value != "--":
            items[(slot, port, onu_id)] = value

    if items:
        return items

    # Scheme 2: ifIndex.onu_id (same as GPON)
    for oid_text, raw_value in (rows or {}).items():
        suffix = str(oid_text or "")[len(base_oid) + 1:]
        parts = suffix.split(".")
        if len(parts) < 2:
            continue
        if_index = str(parts[-2]).strip()
        try:
            onu_id = int(parts[-1])
        except (TypeError, ValueError):
            continue
        fsp = gpon_indexes.get(if_index)
        if not fsp:
            continue
        _, slot, port = fsp
        value = formatter(raw_value)
        if value and value != "--":
            items[(slot, port, onu_id)] = value

    return items


def _snmp_epon_port_rows_to_key_map(rows, base_oid, slot, port, formatter):
    """Parse EPON DDM rows from a port-scoped subtree walk."""
    items = {}
    for oid_text, raw_value in (rows or {}).items():
        suffix = str(oid_text or "")[len(base_oid) + 1:]
        parts = [part for part in suffix.split(".") if part != ""]
        if not parts:
            continue
        try:
            onu_id = int(parts[-1])
        except (TypeError, ValueError):
            continue
        value = formatter(raw_value)
        if value and value != "--":
            items[(int(slot), int(port), onu_id)] = value
    return items


def _snmp_epon_port_signal_map(olt, pon_indexes, *, signal_limit=32768):
    """Fetch EPON optical signals with chunked exact SNMP GETs.

    Full EPON .104 table walks can timeout on Huawei EPON boards. Exact OID
    chunks keep the request bounded and still update EPON ONUs in bulk.
    """
    from .models import ConfiguredONU

    epon_records = []
    max_onus = max(1, int(signal_limit or 32768))
    for row in ConfiguredONU.objects.filter(olt=olt, derived_status="online").values("slot", "port", "ont_id").order_by("slot", "port", "ont_id"):
        try:
            slot = int(row.get("slot") or 0)
            port = int(row.get("port") or 0)
            ont_id = int(row.get("ont_id") or 0)
        except (TypeError, ValueError):
            continue
        if str(_slot_pon_tech(olt, slot) or "").upper() != "EPON":
            continue
        epon_records.append((slot, port, ont_id))
        if len(epon_records) >= max_onus:
            break

    if not epon_records:
        return {}, 0

    ifindex_by_port = {
        (int(slot), int(port)): str(if_index)
        for if_index, (_frame, slot, port) in (pon_indexes or {}).items()
    }

    oid_specs = {
        "olt_rx": ("1.3.6.1.4.1.2011.6.128.1.1.2.104.1.1", _format_snmp_olt_rx_power),
        "tx_power": ("1.3.6.1.4.1.2011.6.128.1.1.2.104.1.4", _format_snmp_onu_rx_power),
        "onu_rx": ("1.3.6.1.4.1.2011.6.128.1.1.2.104.1.5", _format_snmp_onu_rx_power),
    }
    oid_lookup = {}
    fallback_lookup = {}
    for slot, port, ont_id in epon_records:
        if_index = ifindex_by_port.get((slot, port)) or _resolve_snmp_gpon_ifindex(olt, slot, port)
        for field, (base_oid, formatter) in oid_specs.items():
            if if_index:
                oid_lookup[f"{base_oid}.{if_index}.{ont_id}"] = (field, (slot, port, ont_id), formatter)
            fallback_lookup[f"{base_oid}.0.{slot}.{port}.{ont_id}"] = (field, (slot, port, ont_id), formatter)

    items = {}
    found_keys = set()

    def _apply_values(values, lookup):
        rows_seen = 0
        for oid, raw_value in (values or {}).items():
            meta = lookup.get(str(oid))
            if not meta:
                continue
            field, key, formatter = meta
            value = formatter(raw_value)
            if not value or value == "--":
                continue
            row = items.setdefault(key, {"onu_rx": "--", "olt_rx": "--", "tx_power": "--"})
            row[field] = value
            found_keys.add((field, key))
            rows_seen += 1
        return rows_seen

    def _fetch_lookup(lookup):
        rows_seen = 0
        chunk_size = int(getattr(settings, "OLT_EPON_SIGNAL_GET_CHUNK_SIZE", 24) or 24)
        oid_items = list(lookup.keys())
        for start in range(0, len(oid_items), chunk_size):
            chunk = oid_items[start:start + chunk_size]
            values = {}
            for mp_model in (1, 0):
                values = _snmp_get_many_values(olt, chunk, mp_model=mp_model)
                if values:
                    break
            rows_seen += _apply_values(values, lookup)
        return rows_seen

    rows_seen = _fetch_lookup(oid_lookup)

    missing_fallback = {
        oid: meta
        for oid, meta in fallback_lookup.items()
        if (meta[0], meta[1]) not in found_keys
    }
    if missing_fallback:
        rows_seen += _fetch_lookup(missing_fallback)

    return items, rows_seen


def _format_snmp_onu_rx_power(raw_value):
    try:
        value = int(str(raw_value).strip())
    except (TypeError, ValueError):
        return "--"
    if value in (2147483647, -2147483648):
        return "--"
    return f"{value / 100:.2f} dBm"


def _format_snmp_olt_rx_power(raw_value):
    try:
        value = int(str(raw_value).strip())
    except (TypeError, ValueError):
        return "--"
    if value in (2147483647, -2147483648):
        return "--"
    return f"{(value - 10000) / 100:.2f} dBm"


def fetch_olt_snmp_onu_signal_map(olt, *, ifname_limit=4096, signal_limit=32768):
    """Fetch optical Rx/Tx signal for all ONUs via SNMP bulk walk.

    Tries GPON/XG DDM OIDs (.51.x) in bulk. EPON uses .104.x with
    per-port subtree walks, not one giant table walk.

    GPON OIDs  (index: ifIndex.onu_id):
      hwGponOnuOpticalDdmInfoONURxPower  1.3.6.1.4.1.2011.6.128.1.1.2.51.1.4   (plain ÷100)
      hwGponOnuOpticalDdmInfoOLTRxPower  1.3.6.1.4.1.2011.6.128.1.1.2.51.1.6   (offset (v-10000)÷100)

    EPON OIDs  hwEponDeviceOntOpticsDdmInfoTable  (index: frame.slot.port.onu_id):
      hwEponOntOpticalDdmOltRxOntPower   1.3.6.1.4.1.2011.6.128.1.1.2.104.1.1  (plain ÷100)
      hwEponOntOpticalDdmTxPower         1.3.6.1.4.1.2011.6.128.1.1.2.104.1.4  (plain ÷100)
      hwEponOntOpticalDdmRxPower         1.3.6.1.4.1.2011.6.128.1.1.2.104.1.5  (plain ÷100)
    """
    result = {"ok": False, "status": "SNMP ONU signal map unavailable", "items": {}}
    try:
        # Build ifIndex → (frame, slot, port) for ALL PON ports (GPON + EPON + XGS-PON)
        pon_indexes = _snmp_onu_key_maps(olt, ifname_limit=ifname_limit)

        items = {}

        # ── GPON: ONU Rx (.51.1.4) and OLT Rx (.51.1.6) ─────────────────────
        gpon_onu_rx_oid = "1.3.6.1.4.1.2011.6.128.1.1.2.51.1.4"
        gpon_olt_rx_oid = "1.3.6.1.4.1.2011.6.128.1.1.2.51.1.6"
        gpon_onu_rx_rows, _ = _snmp_rows_for_first_working_model(olt, gpon_onu_rx_oid, limit=signal_limit)
        gpon_olt_rx_rows, _ = _snmp_rows_for_first_working_model(olt, gpon_olt_rx_oid, limit=signal_limit)
        gpon_onu_rx_map = _snmp_onu_rows_to_key_map(gpon_onu_rx_rows, gpon_onu_rx_oid, pon_indexes, _format_snmp_onu_rx_power)
        gpon_olt_rx_map = _snmp_onu_rows_to_key_map(gpon_olt_rx_rows, gpon_olt_rx_oid, pon_indexes, _format_snmp_olt_rx_power)
        for key in set(gpon_onu_rx_map.keys()) | set(gpon_olt_rx_map.keys()):
            items[key] = {
                "onu_rx": gpon_onu_rx_map.get(key) or "--",
                "olt_rx": gpon_olt_rx_map.get(key) or "--",
                "tx_power": "--",
            }

        epon_items, epon_count = _snmp_epon_port_signal_map(olt, pon_indexes, signal_limit=signal_limit)
        items.update(epon_items)

        if not items:
            result["status"] = "SNMP ONU signal map: no GPON/XG or EPON signal data"
            return result

        result["ok"] = True
        result["items"] = items
        gpon_count = len(gpon_onu_rx_map) + len(gpon_olt_rx_map)
        result["status"] = f"SNMP ONU signals fetched: {len(items)} (GPON/XG rows: {gpon_count}; EPON rows: {epon_count})"
        return result
    except Exception as exc:
        result["status"] = f"SNMP ONU signal map fetch failed: {exc}"
        return result


def fetch_single_onu_snmp_signal(olt, slot, port, ont_id):
    """Fetch optical signal for a single ONU via SNMP GET.

    Uses EPON OIDs first for EPON slots; otherwise GPON/XG OIDs first.
    GPON: ONU Rx .51.1.4 / OLT Rx .51.1.6 (offset (v-10000)/100)
    EPON: OLT Rx .104.1.1 / ONU Tx .104.1.4 / ONU Rx .104.1.5  (all plain v/100)
          Index scheme: frame.slot.port.onu_id (primary) or ifIndex.onu_id (fallback)
    """
    result = {"status": "SNMP ONU signal unavailable", "onu_rx": "--", "olt_rx": "--", "tx_power": "--"}
    if_index = _resolve_snmp_gpon_ifindex(olt, slot, port)
    if not if_index:
        result["status"] = "SNMP ONU signal ifIndex lookup failed"
        return result
    last_error = ""
    tech = str(_slot_pon_tech(olt, slot) or "").upper()
    is_epon = tech == "EPON"

    if not is_epon:
        oid_gpon_onu_rx = f"1.3.6.1.4.1.2011.6.128.1.1.2.51.1.4.{if_index}.{int(ont_id)}"
        oid_gpon_olt_rx = f"1.3.6.1.4.1.2011.6.128.1.1.2.51.1.6.{if_index}.{int(ont_id)}"
        for mp_model in (1, 0):
            try:
                err_onu, stat_onu, _, vb_onu = _snmp_get_value(olt, oid_gpon_onu_rx, mp_model=mp_model)
                err_olt, stat_olt, _, vb_olt = _snmp_get_value(olt, oid_gpon_olt_rx, mp_model=mp_model)
                if err_onu or stat_onu or err_olt or stat_olt:
                    last_error = str(err_onu or stat_onu or err_olt or stat_olt)
                    continue
                onu_rx = _format_snmp_onu_rx_power(vb_onu[0][1]) if _snmp_varbind_has_value(vb_onu) else "--"
                olt_rx = _format_snmp_olt_rx_power(vb_olt[0][1]) if _snmp_varbind_has_value(vb_olt) else "--"
                if onu_rx != "--" or olt_rx != "--":
                    result.update({"status": "SNMP ONU signal fetched (GPON)", "onu_rx": onu_rx, "olt_rx": olt_rx})
                    return result
            except Exception as exc:
                last_error = str(exc)

    # GPON OIDs returned nothing — try EPON DDM OIDs (hwEponDeviceOntOpticsDdmInfoTable .104.x)
    # Try both index schemes: frame.slot.port.onu_id AND ifIndex.onu_id
    _epon_index_candidates = [
        f"0.{int(slot)}.{int(port)}.{int(ont_id)}",   # frame.slot.port.onu_id (most common for .104)
        f"{if_index}.{int(ont_id)}",                    # ifIndex.onu_id (fallback)
    ]
    for _idx in _epon_index_candidates:
        oid_epon_olt_rx = f"1.3.6.1.4.1.2011.6.128.1.1.2.104.1.1.{_idx}"
        oid_epon_onu_tx = f"1.3.6.1.4.1.2011.6.128.1.1.2.104.1.4.{_idx}"
        oid_epon_onu_rx = f"1.3.6.1.4.1.2011.6.128.1.1.2.104.1.5.{_idx}"
        for mp_model in (1, 0):
            try:
                _, _, _, vb_olt_rx = _snmp_get_value(olt, oid_epon_olt_rx, mp_model=mp_model)
                err_rx, stat_rx, _, vb_rx = _snmp_get_value(olt, oid_epon_onu_rx, mp_model=mp_model)
                _, _, _, vb_tx = _snmp_get_value(olt, oid_epon_onu_tx, mp_model=mp_model)
                if err_rx or stat_rx:
                    last_error = str(err_rx or stat_rx)
                    continue
                onu_rx = _format_snmp_onu_rx_power(vb_rx[0][1]) if _snmp_varbind_has_value(vb_rx) else "--"
                # OLT-Rx (.104.1.1) is offset-encoded like GPON, not plain ÷100.
                olt_rx = _format_snmp_olt_rx_power(vb_olt_rx[0][1]) if _snmp_varbind_has_value(vb_olt_rx) else "--"
                tx_power = _format_snmp_onu_rx_power(vb_tx[0][1]) if _snmp_varbind_has_value(vb_tx) else "--"
                if onu_rx != "--" or olt_rx != "--" or tx_power != "--":
                    result.update({
                        "status": "SNMP ONU signal fetched (EPON)",
                        "onu_rx": onu_rx,
                        "olt_rx": olt_rx,
                        "tx_power": tx_power,
                    })
                    return result
            except Exception as exc:
                last_error = str(exc)

    result["status"] = f"SNMP ONU signal fetch failed: {last_error or 'no response'}"
    return result


def fetch_single_onu_snmp_status(olt, slot, port, ont_id):
    result = {"status": "SNMP ONU status unavailable", "value": ""}
    if_index = _resolve_snmp_gpon_ifindex(olt, slot, port)
    if not if_index:
        result["status"] = "SNMP ONU status ifIndex lookup failed"
        return result
    control_oid = f"1.3.6.1.4.1.2011.6.128.1.1.2.46.1.15.{if_index}.{int(ont_id)}"
    run_oid = f"1.3.6.1.4.1.2011.6.128.1.1.2.46.1.16.{if_index}.{int(ont_id)}"
    last_error = ""
    for mp_model in (1, 0):
        try:
            err_control, stat_control, _, vb_control = _snmp_get_value(olt, control_oid, mp_model=mp_model)
            err_run, stat_run, _, vb_run = _snmp_get_value(olt, run_oid, mp_model=mp_model)
            if err_control or stat_control or err_run or stat_run:
                last_error = str(err_control or stat_control or err_run or stat_run)
                continue
            control_value = vb_control[0][1] if _snmp_varbind_has_value(vb_control) else ""
            run_value = vb_run[0][1] if _snmp_varbind_has_value(vb_run) else ""
            status_value = _map_snmp_onu_status(control_value, run_value)
            if status_value:
                return {"status": "SNMP ONU status fetched", "value": status_value}
        except Exception as exc:
            last_error = str(exc)

    tech = str(_slot_pon_tech(olt, slot) or "").upper()
    if tech == "EPON":
        for index_suffix in (
            f"0.{int(slot)}.{int(port)}.{int(ont_id)}",
            f"{if_index}.{int(ont_id)}",
        ):
            epon_run_oid = f"1.3.6.1.4.1.2011.6.128.1.1.2.56.1.15.{index_suffix}"
            epon_config_oid = f"1.3.6.1.4.1.2011.6.128.1.1.2.56.1.16.{index_suffix}"
            for mp_model in (1, 0):
                try:
                    err_run, stat_run, _, vb_run = _snmp_get_value(olt, epon_run_oid, mp_model=mp_model)
                    err_config, stat_config, _, vb_config = _snmp_get_value(olt, epon_config_oid, mp_model=mp_model)
                    if err_run or stat_run:
                        last_error = str(err_run or stat_run)
                        continue
                    run_value = vb_run[0][1] if _snmp_varbind_has_value(vb_run) else ""
                    config_value = "" if (err_config or stat_config) else (vb_config[0][1] if _snmp_varbind_has_value(vb_config) else "")
                    status_value = _map_snmp_onu_status(run_value, config_value)
                    if status_value:
                        return {"status": "SNMP ONU status fetched (EPON)", "value": status_value}
                except Exception as exc:
                    last_error = str(exc)
    result["status"] = f"SNMP ONU status fetch failed: {last_error or 'no response'}"
    return result


def fetch_olt_snmp_onu_type_distance_maps(olt, *, ifname_limit=4096, type_limit=16384, distance_limit=16384):
    result = {
        "status": "SNMP ONU type/distance unavailable",
        "type_items": {},
        "distance_items": {},
    }
    try:
        gpon_indexes = _snmp_onu_key_maps(olt, ifname_limit=ifname_limit)
        type_items = {}
        type_errors = []
        for base_type_oid in (
            "1.3.6.1.4.1.2011.6.128.1.1.2.45.1.4",
            "1.3.6.1.4.1.2011.6.128.1.1.2.45.1.5",
        ):
            type_rows, type_error = _snmp_rows_for_first_working_model(olt, base_type_oid, limit=type_limit)
            if type_error:
                type_errors.append(type_error)
            type_items = _snmp_onu_rows_to_key_map(type_rows, base_type_oid, gpon_indexes, _format_snmp_text_value)
            if type_items:
                break

        distance_oid = "1.3.6.1.4.1.2011.6.128.1.1.2.46.1.20"
        distance_rows, distance_error = _snmp_rows_for_first_working_model(olt, distance_oid, limit=distance_limit)
        distance_items = _snmp_onu_rows_to_key_map(distance_rows, distance_oid, gpon_indexes, _format_snmp_distance_value)

        result["type_items"] = type_items
        result["distance_items"] = distance_items
        result["status"] = (
            f"SNMP ONU type/distance fetched: type {len(type_items)}, distance {len(distance_items)}"
        )
        if not type_items and type_errors:
            result["status"] = f"{result['status']} | type: {type_errors[-1]}"
        if not distance_items and distance_error:
            result["status"] = f"{result['status']} | distance: {distance_error}"
        return result
    except Exception as exc:
        result["status"] = f"SNMP ONU type/distance fetch failed: {exc}"
        return result
def fetch_olt_snmp_onu_type_map(olt, *, ifname_limit=4096, type_limit=16384):
    result = {"status": "SNMP ONU type map unavailable", "items": {}}
    base_type_oids = (
        "1.3.6.1.4.1.2011.6.128.1.1.2.45.1.4",
        "1.3.6.1.4.1.2011.6.128.1.1.2.45.1.5",
    )
    try:
        gpon_indexes = _snmp_onu_key_maps(olt, ifname_limit=ifname_limit)
        last_error = ""
        for base_type_oid in base_type_oids:
            for mp_model in (1, 0):
                try:
                    type_rows = _snmp_walk_rows(olt, base_type_oid, limit=type_limit, mp_model=mp_model)
                except Exception as exc:
                    last_error = str(exc)
                    continue
                items = {}
                for oid_text, raw_value in (type_rows or {}).items():
                    suffix = oid_text[len(base_type_oid) + 1:]
                    parts = suffix.split(".")
                    if len(parts) < 2:
                        continue
                    if_index = str(parts[-2]).strip()
                    try:
                        ont_id = int(parts[-1])
                    except (TypeError, ValueError):
                        continue
                    fsp = gpon_indexes.get(if_index)
                    if not fsp:
                        continue
                    _, slot, port = fsp
                    value = _format_snmp_text_value(raw_value)
                    if value:
                        items[(slot, port, ont_id)] = value
                if items:
                    result["items"] = items
                    result["status"] = f"SNMP ONU type map fetched: {len(items)}"
                    return result
        result["status"] = f"SNMP ONU type map fetch failed: {last_error or 'no rows'}"
        return result
    except Exception as exc:
        result["status"] = f"SNMP ONU type map fetch failed: {exc}"
        return result
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


def fetch_single_onu_snmp_type(olt, slot, port, ont_id, *, frame=0):
    result = {
        "status": "SNMP ONU type unavailable",
        "onu_type": "",
    }
    try:
        if_index = _resolve_snmp_gpon_ifindex(olt, slot, port, frame=frame)
        if not if_index:
            result["status"] = "SNMP ONU type ifIndex lookup failed"
            return result
        last_error = ""
        for base_oid in (
            "1.3.6.1.4.1.2011.6.128.1.1.2.45.1.4",
            "1.3.6.1.4.1.2011.6.128.1.1.2.45.1.5",
        ):
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
                    value = _format_snmp_text_value(var_binds[0][1])
                    if value:
                        result["onu_type"] = value
                        result["status"] = "SNMP ONU type fetched"
                        return result
                except Exception as exc:
                    last_error = str(exc)
        result["status"] = f"SNMP ONU type fetch failed: {last_error or 'no response'}"
        return result
    except Exception as exc:
        result["status"] = f"SNMP ONU type fetch failed: {exc}"
        return result


def fetch_authorized_onu_snmp_identity(olt, slot, port, ont_id, *, frame=0, attempts=3, delay_seconds=0.9):
    result = {
        "onu_type": "",
        "ont_distance_m": "",
        "type_status": "",
        "distance_status": "",
    }
    for attempt in range(1, max(1, int(attempts or 1)) + 1):
        type_payload = fetch_single_onu_snmp_type(olt, slot, port, ont_id, frame=frame)
        distance_payload = fetch_single_onu_snmp_distance(olt, slot, port, ont_id, frame=frame)
        result["type_status"] = str(type_payload.get("status") or "")
        result["distance_status"] = str(distance_payload.get("status") or "")

        onu_type = str(type_payload.get("onu_type") or "").strip()
        if onu_type:
            result["onu_type"] = onu_type

        distance_value = str(distance_payload.get("ont_distance_m") or "").strip()
        if distance_value:
            result["ont_distance_m"] = distance_value

        if result["onu_type"] and result["ont_distance_m"]:
            return result

        if attempt < int(attempts or 1):
            time.sleep(float(delay_seconds or 0.9))
    return result


def execute_onu_snmp_control_action(olt, slot, port, ont_id, action, *, frame=0):
    result = {
        "ok": False,
        "message": "SNMP ONU action unavailable",
        "oid": "",
        "value": "",
    }
    action_key = str(action or "").strip().lower()
    # ONT control lives in the device ONT-control table, one column per action:
    #   col 1 = admin switch (1 = enable / 2 = disable)
    #   col 2 = reset
    #   col 3 = restart
    # GPON / XG(S)-PON ONTs use hwGponDeviceOntControlTable (.46); EPON ONTs use the
    # mirrored hwEponDeviceOntControlTable (.56) — the same +10 device-table offset
    # Huawei uses for the ONT config table (.43 GPON / .53 EPON, see the delete path).
    action_map = {
        "enable": {"col": 1, "value": 1, "label": "Enable ONU"},
        "disable": {"col": 1, "value": 2, "label": "Disable ONU"},
        "restart": {"col": 3, "value": 1, "label": "Restart ONU"},
        "reset": {"col": 2, "value": 1, "label": "Reset ONU"},
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

        # Control-table base(s) to try, in order. For EPON try the EPON table first,
        # then fall back to the GPON table; for GPON the reverse. A SET to a column
        # that does not exist on this firmware returns a harmless no-op error, so
        # trying both safely covers firmwares that expose only one unified table.
        tech = str(_slot_pon_tech(olt, slot) or "").upper()
        gpon_base = "1.3.6.1.4.1.2011.6.128.1.1.2.46.1"
        epon_base = "1.3.6.1.4.1.2011.6.128.1.1.2.56.1"
        table_bases = [epon_base, gpon_base] if tech == "EPON" else [gpon_base, epon_base]

        result["value"] = str(config["value"])
        last_error = ""
        for base in table_bases:
            target_oid = f"{base}.{int(config['col'])}.{int(if_index)}.{int(ont_id)}"
            result["oid"] = target_oid
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


def execute_onu_eth_port_cli_admin_state(olt, slot, port, ont_id, eth_port, admin_state, *, frame=0):
    """Enable or shut down a specific ONU ethernet port via CLI.

    Command pattern:
      interface <gpon|epon|xgpon> <frame>/<slot>
      ont port attribute <port> <ont_id> eth <eth_port> operational-state <on|off>
    """
    result = {"ok": False, "message": "", "transcript": ""}
    transcript = []

    state_key = str(admin_state or "").strip().lower()
    if state_key in ("enabled", "enable", "activate", "on", "1"):
        state = "on"
        label = "Enabled"
    elif state_key in ("disabled", "disable", "shutdown", "deactivate", "off", "2"):
        state = "off"
        label = "Port shutdown"
    else:
        result["message"] = f"Unknown admin state '{admin_state}'."
        return result

    tn, status = open_telnet_authenticated_session(olt)
    if tn is None:
        result["message"] = status or "Telnet session could not be opened."
        return result

    try:
        _prepare_telnet_cli_session(tn, use_paging=False)
        entered_config, config_output = _enter_config_mode(tn)
        _append_authorize_transcript(transcript, "config", config_output)
        if not entered_config:
            result["message"] = _clean_cli_response_text("config", config_output) or "Unable to enter configuration mode."
            return result

        board_tech = _slot_pon_tech(olt, int(slot))
        interface_kinds = _pon_interface_kinds_for_board(board_tech)
        board_kind, interface_output, entered_iface = _enter_interface_context(
            tn, interface_kinds, int(frame or 0), int(slot)
        )
        _append_authorize_transcript(
            transcript,
            f"interface {board_kind or interface_kinds[0]} {int(frame or 0)}/{int(slot)}",
            interface_output,
        )
        if not entered_iface:
            result["message"] = (
                _clean_cli_response_text("interface", interface_output)
                or f"Unable to enter {board_tech} interface {int(frame or 0)}/{int(slot)}."
            )
            return result

        command = (
            f"ont port attribute {int(port)} {int(ont_id)} "
            f"eth {int(eth_port)} operational-state {state}"
        )
        output = _run_telnet_command(tn, command)
        _append_authorize_transcript(transcript, command, output)
        cleaned = _clean_cli_response_text(command, output)
        repeated_warning = "make configuration repeatedly" in cleaned.lower()
        if _cli_command_has_hard_failure(output) and not repeated_warning:
            result["message"] = cleaned or "Ethernet port state command failed."
            return result

        quit_output = _run_telnet_command(tn, "quit")
        _append_authorize_transcript(transcript, "quit", quit_output)
        save_output = _schedule_olt_save_from_command(olt, "ethernet port admin state change")
        _append_authorize_transcript(transcript, "save", save_output)
        result["ok"] = True
        result["message"] = f"eth {int(eth_port)} {label} via CLI."
        return result
    except Exception as exc:
        result["message"] = f"Ethernet port state command failed: {exc}"
        return result
    finally:
        result["transcript"] = "\n\n".join(part for part in transcript if part).strip()
        try:
            _run_telnet_command(tn, "quit")
            _run_telnet_command(tn, "quit")
        except Exception:
            pass
        _close_telnet_session(tn)


def execute_onu_cli_delete_action(olt, slot, port, ont_id, *, frame=0, service_port_ids=None):
    result = {
        "ok": False,
        "message": "CLI ONU delete failed.",
        "transcript": "",
    }
    transcript = []
    tn, status = open_telnet_authenticated_session(olt)
    if tn is None:
        result["message"] = status or "Telnet session could not be opened."
        return result

    def _delete_failure_text(text):
        lowered = str(text or "").lower()
        return any(token in lowered for token in (
            "failure:",
            "failed",
            "error:",
            "unknown command",
            "parameter error",
            "incomplete command",
            "unrecognized command",
            "wrong parameter",
            "% invalid",
        ))

    def _deleted_text(text):
        lowered = str(text or "").lower()
        return any(token in lowered for token in (
            "ont does not exist",
            "onu does not exist",
            "the ont does not exist",
            "the onu does not exist",
        ))

    def _verify_onu_deleted():
        service_port_verify_command = f"display current-configuration | include {int(frame or 0)}/{int(slot or 0)}/{int(port or 0)} ont {int(ont_id or 0)}"
        service_port_verify_output = _run_telnet_command(
            tn, service_port_verify_command, enter_until_prompt=True, max_wait_seconds=30, step_timeout=0.45
        )
        _append_authorize_transcript(transcript, service_port_verify_command, service_port_verify_output)
        service_port_cleaned = _clean_cli_response_text(service_port_verify_command, service_port_verify_output).lower()
        service_port_exists = re.search(
            rf"\bservice-port\s+\d+\b.*\b(?:gpon|epon)\s+{int(frame or 0)}/{int(slot or 0)}/{int(port or 0)}\s+ont\s+{int(ont_id or 0)}\b",
            service_port_cleaned,
            flags=re.IGNORECASE | re.DOTALL,
        )
        ont_verify_command = f"display this | include ont add {int(port or 0)} {int(ont_id or 0)}"
        ont_verify_output = _run_telnet_command(
            tn, ont_verify_command, enter_until_prompt=True, max_wait_seconds=18, step_timeout=0.45
        )
        _append_authorize_transcript(transcript, ont_verify_command, ont_verify_output)
        ont_cleaned = _clean_cli_response_text(ont_verify_command, ont_verify_output).lower()
        ont_exists = re.search(rf"\b(?:ont|onu)\s+add\s+{int(port or 0)}\s+{int(ont_id or 0)}\b", ont_cleaned)
        return not service_port_exists and not ont_exists

    try:
        _prepare_telnet_cli_session(tn, use_paging=True)
        # Seed with any service-ports we already know from the DB cache.
        delete_service_ports = []
        for raw_value in (service_port_ids or []):
            value = str(raw_value or "").strip()
            if value.isdigit() and int(value) not in delete_service_ports:
                delete_service_ports.append(int(value))

        # Discovery step (user-requested exact flow): ask the OLT which
        # service-port(s) belong to THIS ONU before touching anything, e.g.
        #   display current-configuration | include 0/0/12 ont 15
        # The OLT prints "It will take a long time ..." and then the matching
        # "service-port <id> vlan ... gpon 0/0/12 ont 15 ..." line(s). We wait
        # for the prompt to return and union the discovered ids with the cache
        # so a stale/empty cache never leaves a dangling service-port behind.
        fsp = f"{int(frame or 0)}/{int(slot or 0)}/{int(port or 0)}"
        discover_command = (
            f"display current-configuration | include {fsp} ont {int(ont_id or 0)}"
        )
        discover_output = _run_telnet_command(
            tn, discover_command, enter_until_prompt=True, max_wait_seconds=45
        )
        _append_authorize_transcript(transcript, discover_command, discover_output)
        for match in re.finditer(r"(?im)\bservice-port\s+(\d+)\b", str(discover_output or "")):
            sp_id = int(match.group(1))
            if sp_id not in delete_service_ports:
                delete_service_ports.append(sp_id)

        entered_config, config_output = _enter_config_mode(tn)
        _append_authorize_transcript(transcript, "config", config_output)
        if not entered_config:
            result["message"] = "Unable to enter configuration mode."
            return result

        for service_port_id in delete_service_ports:
            command = f"undo service-port {service_port_id}"
            output = _run_telnet_command(
                tn, command, enter_until_prompt=True, confirm_response="y", max_wait_seconds=18, step_timeout=0.45
            )
            _append_authorize_transcript(transcript, command, output)
            lowered = str(output or "").strip().lower()
            missing_service_port = any(token in lowered for token in (
                "service virtual port does not exist",
                "service-port does not exist",
                "service port does not exist",
                "does not exist",
                "not exist",
            ))
            if _delete_failure_text(output) and not missing_service_port:
                retry_output = _run_telnet_command(
                    tn, command, enter_until_prompt=True, confirm_response="y", max_wait_seconds=18, step_timeout=0.45
                )
                _append_authorize_transcript(transcript, command, retry_output)
                retry_lowered = str(retry_output or "").strip().lower()
                retry_missing = any(token in retry_lowered for token in (
                    "service virtual port does not exist",
                    "service-port does not exist",
                    "service port does not exist",
                    "does not exist",
                    "not exist",
                ))
                if _delete_failure_text(retry_output) and not retry_missing:
                    # Continue to ONT delete anyway; a stale service-port cache must not
                    # leave the ONU configured when the user asked for delete.
                    result["message"] = _clean_cli_response_text(command, retry_output) or f"Service-port {service_port_id} delete warning."

        # Enter the PON interface matching THIS board's technology (EPON / GPON /
        # XGS-PON). A hardcoded "interface gpon" silently fails on an EPON board,
        # which is exactly why EPON ONU delete never worked — the delete must run
        # under the board's own technology, detected from the slot's port type.
        board_tech = _slot_pon_tech(olt, int(slot or 0))
        interface_kinds = _pon_interface_kinds_for_board(board_tech)
        board_kind, interface_output, entered_iface = _enter_interface_context(
            tn, interface_kinds, int(frame or 0), int(slot or 0)
        )
        _append_authorize_transcript(
            transcript,
            f"interface {board_kind or interface_kinds[0]} {int(frame or 0)}/{int(slot or 0)}",
            interface_output,
        )
        if not entered_iface:
            result["message"] = f"Unable to enter {board_tech} interface 0/{int(slot or 0)}."
            result["transcript"] = "\n\n".join(transcript)[:16000]
            return result

        is_epon = "epon" in str(board_kind or "").lower()
        delete_command = f"ont delete {int(port or 0)} {int(ont_id or 0)}"
        delete_output = _run_telnet_command(
            tn, delete_command, enter_until_prompt=True, confirm_response="y", max_wait_seconds=22, step_timeout=0.45
        )
        _append_authorize_transcript(transcript, delete_command, delete_output)
        # A few EPON firmwares use the "onu" verb instead of "ont"; retry once.
        if is_epon and _delete_failure_text(delete_output) and any(
            t in str(delete_output or "").lower()
            for t in ("unknown command", "incomplete command", "% invalid", "parameter error", "command not found", "wrong parameter")
        ):
            delete_command = f"onu delete {int(port or 0)} {int(ont_id or 0)}"
            delete_output = _run_telnet_command(
                tn, delete_command, enter_until_prompt=True, confirm_response="y", max_wait_seconds=22, step_timeout=0.45
            )
            _append_authorize_transcript(transcript, delete_command, delete_output)

        lowered_delete = str(delete_output or "").strip().lower()
        if _deleted_text(delete_output):
            quit_interface_output = _run_telnet_command(tn, "quit", enter_until_prompt=True)
            _append_authorize_transcript(transcript, "quit", quit_interface_output)
            quit_config_output = _run_telnet_command(tn, "quit", enter_until_prompt=True)
            _append_authorize_transcript(transcript, "quit", quit_config_output)
            result["ok"] = True
            result["already_deleted"] = True
            result["message"] = "This ONU is already deleted."
            result["transcript"] = "\n\n".join(transcript)[:16000]
            return result

        success_match = re.search(r"(?i)success\s*:\s*(\d+)", str(delete_output or ""))
        needs_retry = (
            _delete_failure_text(delete_output)
            or (success_match and int(success_match.group(1)) < 1)
            or ("number of onts that can be deleted" in lowered_delete and not success_match)
        )
        if needs_retry:
            retry_output = _run_telnet_command(
                tn, delete_command, enter_until_prompt=True, confirm_response="y", max_wait_seconds=22, step_timeout=0.45
            )
            _append_authorize_transcript(transcript, delete_command, retry_output)
            delete_output = retry_output

        if not _deleted_text(delete_output) and not _verify_onu_deleted():
            retry_output = _run_telnet_command(
                tn, delete_command, enter_until_prompt=True, confirm_response="y", max_wait_seconds=22, step_timeout=0.45
            )
            _append_authorize_transcript(transcript, delete_command, retry_output)
            if not _deleted_text(retry_output) and not _verify_onu_deleted():
                detail = _clean_cli_response_text(delete_command, retry_output or delete_output)
                result["message"] = f"{delete_command} failed: {detail or 'ONU still exists after delete attempt.'}"
                result["transcript"] = "\n\n".join(transcript)[:16000]
                return result

        # Verified end state: ONU config is gone. No save; return immediately so
        # the UI jumps straight to Autofind.
        quit_interface_output = _run_telnet_command(tn, "quit", enter_until_prompt=True)
        _append_authorize_transcript(transcript, "quit", quit_interface_output)
        quit_config_output = _run_telnet_command(tn, "quit", enter_until_prompt=True)
        _append_authorize_transcript(transcript, "quit", quit_config_output)

        result["ok"] = True
        result["message"] = "ONU deleted successfully."
        result["transcript"] = "\n\n".join(transcript)[:16000]
        return result
    except (socket.timeout, TimeoutError):
        result["message"] = "Telnet timeout while deleting ONU."
        result["transcript"] = "\n\n".join(transcript)[:16000]
        return result
    except (EOFError, OSError) as exc:
        result["message"] = f"Telnet error while deleting ONU: {exc}"
        result["transcript"] = "\n\n".join(transcript)[:16000]
        return result
    finally:
        try:
            _close_telnet_session(tn)
        except Exception:
            pass


def find_onu_location_by_sn_cli(olt, sn):
    """Find an existing ONU location on one OLT by serial number via CLI."""
    result = {"ok": False, "frame": None, "slot": None, "port": None, "ont_id": None, "message": ""}
    sn_auth = _preferred_sn_auth_serial(sn)
    if not sn_auth:
        result["message"] = "Serial is missing."
        return result

    tn, status = open_telnet_authenticated_session(olt)
    if tn is None:
        result["message"] = status or "Telnet session could not be opened."
        return result
    try:
        _prepare_telnet_cli_session(tn, use_paging=True)
        commands = [
            f"display ont info by-sn {sn_auth}",
            f'display ont info by-sn "{sn_auth}"',
        ]
        last_output = ""
        for command in commands:
            output = _run_telnet_command(tn, command, enter_until_prompt=True, max_wait_seconds=30)
            last_output = str(output or "")
            cleaned = _clean_cli_response_text(command, output)
            fsp_match = re.search(
                r"(?i)(?:F\s*/\s*S\s*/\s*P|Frame\s*/\s*Slot\s*/\s*Port)\s*[:=]?\s*(\d+)\s*/\s*(\d+)\s*/\s*(\d+)",
                cleaned,
            )
            ont_match = re.search(r"(?i)\b(?:ONT[-\s]*ID|ONU[-\s]*ID)\s*[:=]\s*(\d+)\b", cleaned)
            if fsp_match and ont_match:
                result.update({
                    "ok": True,
                    "frame": int(fsp_match.group(1)),
                    "slot": int(fsp_match.group(2)),
                    "port": int(fsp_match.group(3)),
                    "ont_id": int(ont_match.group(1)),
                    "message": "ONU location found by serial.",
                })
                return result

            table_match = re.search(
                r"(?im)^\s*(\d+)\s*/\s*(\d+)\s*/\s*(\d+)\s+(\d+)\s+",
                cleaned,
            )
            if table_match:
                result.update({
                    "ok": True,
                    "frame": int(table_match.group(1)),
                    "slot": int(table_match.group(2)),
                    "port": int(table_match.group(3)),
                    "ont_id": int(table_match.group(4)),
                    "message": "ONU location found by serial.",
                })
                return result
        result["message"] = _clean_cli_response_text("display ont info by-sn", last_output) or "ONU serial was not found on this OLT."
        return result
    except (socket.timeout, TimeoutError):
        result["message"] = "Telnet timeout while locating existing ONU by serial."
        return result
    except (EOFError, OSError) as exc:
        result["message"] = f"Telnet error while locating existing ONU by serial: {exc}"
        return result
    finally:
        try:
            _close_telnet_session(tn)
        except Exception:
            pass


def _map_snmp_onu_status(run_value, config_value=None):
    run_text = str(run_value or "").strip()
    # Huawei XPON MIB:
    #   .46.1.15 = hwGponDeviceOntControlRunStatus
    #   .46.1.16 = hwGponDeviceOntControlConfigStatus
    # RunStatus is the reliable online/offline source. ConfigStatus is not used
    # for dashboard counts because value "1" there means config state, not down.
    if run_text == "1":
        return "online"
    if run_text == "2":
        return "offline"
    return ""


def _configured_onu_snmp_walk_limits(olt, *, ifname_limit=None, status_limit=None):
    """Pick SNMP walk limits large enough for high-density OLTs.

    Huawei status rows are keyed by interface index, so a 4k ifName walk can
    truncate OLTs with 4k+ ONUs and leave stale online/offline state behind.
    """
    try:
        from .models import ConfiguredONU

        onu_count = ConfiguredONU.objects.filter(olt=olt).count()
    except Exception:
        onu_count = 0
    ifname_limit = int(ifname_limit or max(8192, (onu_count * 3) + 1024))
    status_limit = int(status_limit or max(16384, onu_count + 2048))
    return min(ifname_limit, 65535), min(status_limit, 65535)


def fetch_olt_snmp_status_map(olt, *, ifname_limit=None, status_limit=None):
    result = {
        "status": "SNMP ONU status map unavailable",
        "items": {},
        "truncated": False,
    }
    try:
        base_ifname_oid = "1.3.6.1.2.1.31.1.1.1.1"
        base_run_oid = "1.3.6.1.4.1.2011.6.128.1.1.2.46.1.15"
        base_config_oid = "1.3.6.1.4.1.2011.6.128.1.1.2.46.1.16"
        ifname_limit, status_limit = _configured_onu_snmp_walk_limits(
            olt,
            ifname_limit=ifname_limit,
            status_limit=status_limit,
        )
        last_error = ""
        for mp_model in (1, 0):
            try:
                ifname_rows = _snmp_walk_rows(olt, base_ifname_oid, limit=ifname_limit, mp_model=mp_model)
                try:
                    run_rows = _snmp_walk_rows(olt, base_run_oid, limit=status_limit, mp_model=mp_model)
                except Exception:
                    run_rows = {}
                try:
                    config_rows = _snmp_walk_rows(olt, base_config_oid, limit=status_limit, mp_model=mp_model)
                except Exception:
                    config_rows = {}
                break
            except Exception as exc:
                last_error = str(exc)
        else:
            result["status"] = f"SNMP ONU status map fetch failed: {last_error or 'no response'}"
            return result

        gpon_indexes = {}
        for oid_text, if_name in (ifname_rows or {}).items():
            idx = oid_text.split(".")[-1]
            fsp = _parse_snmp_gpon_fsp_from_ifname(if_name)
            if not fsp:
                continue
            frame, slot, port = fsp
            gpon_indexes[str(idx)] = (frame, slot, port)
            cache_key = (int(olt.pk), frame, slot, port)
            with _ONU_TRAFFIC_IFINDEX_CACHE_LOCK:
                _ONU_TRAFFIC_IFINDEX_CACHE[cache_key] = str(idx)

        gpon_items = _snmp_status_rows_to_key_map(run_rows, config_rows, base_run_oid, base_config_oid, gpon_indexes)
        items = dict(gpon_items)
        truncated = (
            len(ifname_rows or {}) >= ifname_limit
            or len(run_rows or {}) >= status_limit
        )
        result["items"] = items
        result["truncated"] = truncated
        suffix = " (walk limit reached)" if truncated else ""
        result["status"] = f"SNMP ONU status map fetched: {len(items)} (GPON/XG){suffix}"
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
        return _format_sfp_tx_dbm(raw_value)

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


def _fetch_pon_sfp_tx_via_snmp(olt, limit=512):
    """Fetch SFP Tx power for all PON ports via SNMP.

    Uses hwGponOltOpticsDdmInfoTxPower (GPON) and hwEponOltOpticsDdmInfoTxPower (EPON),
    both indexed by ifIndex.  Also tries hwEntityOpticalTxPower as a last resort.

    Returns {(slot, port): "XX.XX dBm"}.  Empty dict on failure.
    """
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
        return {}

    oids = {
        # ifName — to map ifIndex → (slot, port)
        "ifname":     "1.3.6.1.2.1.31.1.1.1.1",
        # hwGponOltOpticsDdmInfoTxPower — GPON board SFP Tx, indexed by ifIndex, unit 0.01 dBm
        "gpon_tx":    "1.3.6.1.4.1.2011.6.128.1.1.2.23.1.4",
        # hwEponOltOpticsDdmInfoTxPower — EPON board SFP Tx, indexed by ifIndex, unit 0.01 dBm
        "epon_tx":    "1.3.6.1.4.1.2011.6.128.1.1.2.33.1.4",
        # hwEntityOpticalTxPower — generic entity optical Tx, indexed by entPhysical index
        "entity_tx":  "1.3.6.1.4.1.2011.5.25.31.1.1.3.1.9",
        # entPhysicalName — to resolve entity indexes to F/S/P strings
        "entity_name": "1.3.6.1.2.1.47.1.1.1.1.7",
        "entity_descr": "1.3.6.1.2.1.47.1.1.1.1.2",
    }

    def _parse_fsp(text):
        match = re.search(r"(\d+)\s*/\s*(\d+)\s*/\s*(\d+)", str(text or ""))
        if not match:
            return None
        return int(match.group(2)), int(match.group(3))

    async def _walk_oid(mp_model, base_oid):
        rows = {}
        target = await UdpTransportTarget.create(
            (olt.ip_address, olt.snmp_port), timeout=1.5, retries=1
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
            if error_indication or error_status:
                engine.close_dispatcher()
                break
            if not var_binds:
                break
            stop = False
            for oid, value in var_binds:
                oid_text = str(oid)
                if not oid_text.startswith(base_oid + "."):
                    stop = True
                    break
                suffix = oid_text[len(base_oid) + 1:]
                rows[suffix] = str(value)
                current_oid = oid_text
            if stop:
                break
        engine.close_dispatcher()
        return rows

    for mp_model in (1, 0):
        try:
            walked = {k: asyncio.run(_walk_oid(mp_model, oid)) for k, oid in oids.items()}
        except Exception:
            continue

        # Build ifIndex → (slot, port) for PON interfaces
        idx_to_fsp = {}
        for idx, name in walked["ifname"].items():
            lowered = name.lower()
            if not any(t in lowered for t in ("gpon", "epon", "xpon", "pon")):
                continue
            fsp = _parse_fsp(name)
            if fsp:
                idx_to_fsp[idx] = fsp

        tx_map = {}

        # GPON/EPON-specific OIDs (most reliable — indexed directly by ifIndex)
        for tx_key in ("gpon_tx", "epon_tx"):
            for idx, raw_tx in walked[tx_key].items():
                fsp = idx_to_fsp.get(idx)
                if not fsp:
                    continue
                formatted = _format_sfp_tx_dbm(raw_tx)
                if formatted and fsp not in tx_map:
                    tx_map[fsp] = formatted

        # Entity optical fallback — useful when GPON/EPON DDM OIDs are absent
        if not tx_map:
            for idx, raw_tx in walked["entity_tx"].items():
                if not raw_tx:
                    continue
                entity_name = (walked["entity_name"].get(idx) or "").strip()
                entity_descr = (walked["entity_descr"].get(idx) or "").strip()
                text = f"{entity_name} {entity_descr}".lower()
                if not any(t in text for t in ("gpon", "pon", "sfp", "optical")):
                    continue
                fsp = _parse_fsp(entity_name) or _parse_fsp(entity_descr)
                if not fsp:
                    continue
                formatted = _format_sfp_tx_dbm(raw_tx)
                if formatted and fsp not in tx_map:
                    tx_map[fsp] = formatted

        if tx_map:
            return tx_map

    return {}


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


def _fetch_link_aggregation_map(olt, tn=None):
    """Map each uplink port to its link-aggregation (LAG / port-channel) group.

    Returns {"f/s/p": {master, description, work_mode, members[], is_master}}.
    Uses ``display link-aggregation all`` (master ports) then
    ``display link-aggregation <master>`` (members + description) per group.
    Pass an open ``tn`` to reuse a session; otherwise one is opened/closed here.
    """
    result = {}
    own_session = tn is None
    if own_session:
        tn, status = open_telnet_authenticated_session(olt)
        if tn is None:
            return result
    try:
        if own_session:
            _prepare_telnet_cli_session(tn, use_paging=True)
        all_output = _run_telnet_bulk_command(tn, "display link-aggregation all", max_wait_seconds=12)
        if not all_output or "does not exist" in all_output.lower():
            return result
        masters = []
        for line in all_output.splitlines():
            m = re.match(r"^\s*(\d+)\s*/\s*(\d+)\s*/\s*(\d+)\s+\S+\s+\d+\s+\S+", line)
            if m:
                masters.append(f"{int(m.group(1))}/{int(m.group(2))}/{int(m.group(3))}")
        for master in masters:
            detail = _run_telnet_bulk_command(tn, f"display link-aggregation {master}", max_wait_seconds=12)
            desc = ""
            work_mode = ""
            dm = re.search(r"(?i)link\s+aggregation\s+description\s*:\s*(.+)", detail or "")
            if dm:
                desc = " ".join(dm.group(1).split()).strip()
            wm = re.search(r"(?i)^\s*work\s+mode\s*:\s*(.+)$", detail or "", re.MULTILINE)
            if wm:
                work_mode = " ".join(wm.group(1).split()).strip()
            members = []
            for raw in (detail or "").replace("\t", " ").splitlines():
                pm = re.match(r"^\s*(\d+)\s*/\s*(\d+)\s+([\d,\s]+)$", raw)
                if not pm:
                    continue
                frame_v, slot_v = int(pm.group(1)), int(pm.group(2))
                for p in pm.group(3).split(","):
                    p = p.strip()
                    if p.isdigit():
                        members.append(f"{frame_v}/{slot_v}/{int(p)}")
            if not members:
                members = [master]
            for mp in members:
                result[mp] = {
                    "master": master,
                    "description": desc,
                    "work_mode": work_mode,
                    "members": members,
                    "is_master": (mp == master),
                }
        return result
    except (socket.timeout, TimeoutError, EOFError, OSError):
        return result
    finally:
        if own_session:
            _close_telnet_session(tn)


def fetch_uplink_snapshot(olt, limit=24):
    snmp_data = fetch_snmp_interfaces(olt, limit=limit)
    rows = snmp_data.get("rows") or []
    if not rows:
        return snmp_data

    cli_data = _fetch_cli_uplink_details(olt, rows)
    cli_rows = cli_data.get("rows") or rows
    agg_map = _fetch_link_aggregation_map(olt)
    for row in cli_rows:
        row["description"] = _sanitize_uplink_description(row.get("description", ""))
        row["mtu"] = row.get("mtu") or "-"
        fsp_match = re.search(r"(\d+)\s*/\s*(\d+)\s*/\s*(\d+)", str(row.get("port") or row.get("name") or ""))
        fsp = f"{int(fsp_match.group(1))}/{int(fsp_match.group(2))}/{int(fsp_match.group(3))}" if fsp_match else ""
        row["aggregate"] = agg_map.get(fsp) or {}
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
    _close_competing_telnet_sessions(olt)
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
    cleaned = re.sub(r"(?i)\b(ont|onu)\s+delete\s*(\d+)\s+(\d+)\b", r"\1 delete \2 \3", cleaned)
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
    if tn is None:
        return
    if include_enable:
        _run_telnet_command(tn, "enable")
    if use_paging:
        # Use only the safest paging tweak and only for long-output flows.
        _run_telnet_command(tn, "scroll 512")


def _enter_config_mode(tn):
    if tn is None:
        return False, "Telnet session not open."
    try:
        tn.write(b"\r\n")
        time.sleep(0.08)
        prompt_probe = tn.read_very_eager().decode("utf-8", errors="ignore")
        if "(config)" in str(prompt_probe).lower() or "(config-" in str(prompt_probe).lower():
            return True, prompt_probe or ""
    except Exception:
        pass
    response = _run_telnet_command(
        tn,
        "config",
        enter_until_prompt=True,
        max_wait_seconds=5,
        step_timeout=0.25,
        max_loops=32,
    )
    if "(config)" in str(response or "").lower() or "(config-" in str(response or "").lower():
        return True, response or ""
    if response and _is_cli_error_text(response):
        return False, response or ""
    # Some Huawei builds do not echo a clean `(config)#` prompt through telnet
    # after `config`, but they are already in config mode if no CLI error came
    # back. Do not block service-port updates on prompt formatting.
    return True, response or ""


def _enter_global_config_mode(tn, transcript=None):
    """Leave sub-modes, then enter global config mode for global commands.

    Only issues ``quit`` when the prompt actually shows a config sub-mode. At the
    top-level (enable) prompt ``quit`` triggers a logout confirmation, so we never
    send it on an empty/uncertain read — that is what produced the stray
    "Are you sure to log out?" lines in the transcript.
    """
    last_output = ""

    def _probe_prompt():
        text = ""
        for _ in range(3):
            try:
                tn.write(b"\r\n")
                time.sleep(0.12)
                chunk = tn.read_very_eager().decode("utf-8", errors="ignore")
            except Exception:
                chunk = ""
            if str(chunk or "").strip():
                text = chunk
                break
        return text

    for _ in range(4):
        probe = _probe_prompt()
        last_output = probe or last_output
        lower_probe = str(probe or "").lower()

        # A stray logout confirmation is sitting on the line — decline it and
        # treat ourselves as back at the top-level prompt.
        if "log out" in lower_probe or "(y/n)" in lower_probe:
            try:
                _run_telnet_command(tn, "n", enter_until_prompt=True, max_wait_seconds=3, step_timeout=0.25, max_loops=22)
            except Exception:
                pass
            break

        # Inside a config sub-mode (config-if-*, config-gpon-*, etc.) — step out.
        if "(config-" in lower_probe:
            quit_output = _run_telnet_command(tn, "quit", enter_until_prompt=True, max_wait_seconds=4, step_timeout=0.25, max_loops=28)
            last_output = quit_output or last_output
            if transcript is not None and str(quit_output or "").strip():
                _append_authorize_transcript(transcript, "quit", quit_output)
            continue

        # Already in global config mode.
        if "(config)" in lower_probe:
            return True, last_output

        # Top-level prompt (#, >, ]) or an empty/uncertain read — ready to enter
        # config without quitting (quitting here would log us out).
        break

    entered, output = _enter_config_mode(tn)
    if transcript is not None and str(output or "").strip():
        _append_authorize_transcript(transcript, "config", output)
    return entered, output


def _enter_interface_context(tn, interface_kinds, frame, slot):
    if tn is None:
        return "", "Telnet session not open.", False
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


def _run_telnet_command(
    tn,
    command,
    enter_until_prompt=False,
    *,
    max_wait_seconds=None,
    step_timeout=None,
    max_loops=None,
    confirm_response=None,
):
    if tn is None:
        return "Telnet session not open."
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
    # Huawei delete commands (ont delete / undo service-port) prompt for a y/n
    # confirmation, e.g. "Are you sure to delete the ONT(s)? (y/n)[n]:". If we
    # answer with a blank Enter it takes the default [n] = NO and the delete is
    # silently cancelled. When a caller passes confirm_response (e.g. "y") we
    # detect that prompt and reply with it so the command completes in one pass.
    confirm_tokens = ("(y/n)", "[y/n]", "y/n)[n]", "y/n)[y]", "are you sure", "confirm? [")
    confirm_sent = 0
    max_confirm_sent = 4
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
    max_wait_seconds = float(max_wait_seconds if max_wait_seconds is not None else (12 if enter_until_prompt else 8))
    step_timeout = float(step_timeout if step_timeout is not None else (0.8 if enter_until_prompt else 0.45))
    max_loops = int(max_loops if max_loops is not None else (220 if enter_until_prompt else 30))

    for _ in range(max_loops):
        try:
            idx, _, text = tn.expect(pattern_list, timeout=step_timeout)
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
            if confirm_response and confirm_sent < max_confirm_sent and any(
                token in output_tail for token in confirm_tokens
            ):
                _touch_telnet_session(tn)
                tn.write((str(confirm_response) + "\r\n").encode("ascii", errors="ignore"))
                confirm_sent += 1
                idle_rounds = 0
                continue
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
        if confirm_response and confirm_sent < max_confirm_sent and any(
            token in output_tail for token in confirm_tokens
        ):
            _touch_telnet_session(tn)
            tn.write((str(confirm_response) + "\r\n").encode("ascii", errors="ignore"))
            confirm_sent += 1
            prompt_seen = False
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


def _db_safe_int(value, default=0):
    try:
        number = int(str(value).strip())
    except (TypeError, ValueError, AttributeError):
        return int(default or 0)
    if number > DB_SIGNED_BIGINT_MAX:
        return DB_SIGNED_BIGINT_MAX
    if number < DB_SIGNED_BIGINT_MIN:
        return DB_SIGNED_BIGINT_MIN
    return number


def _cli_system_busy(text):
    lowered = str(text or "").lower()
    return (
        "system is busy" in lowered
        or "system busy" in lowered
        or "please retry after a while" in lowered
        or "resource busy" in lowered
    )


def _run_telnet_authorize_command(
    tn,
    command,
    enter_until_prompt=True,
    *,
    busy_retries=10,
    max_wait_seconds=None,
    step_timeout=None,
    max_loops=None,
):
    output = ""
    for attempt in range(1, int(busy_retries or 0) + 2):
        output = _run_telnet_command(
            tn,
            command,
            enter_until_prompt=enter_until_prompt,
            max_wait_seconds=max_wait_seconds if max_wait_seconds is not None else (6.0 if enter_until_prompt else 4.0),
            step_timeout=step_timeout if step_timeout is not None else (0.28 if enter_until_prompt else 0.2),
            max_loops=max_loops if max_loops is not None else (42 if enter_until_prompt else 22),
        )
        if not _cli_system_busy(output):
            return output
        if attempt <= int(busy_retries or 0):
            time.sleep(2.0)
            try:
                _touch_telnet_session(tn)
                tn.write(b"\r\n")
                time.sleep(0.25)
                tn.read_very_eager()
            except (OSError, EOFError):
                pass
    return output


def _is_retryable_authorize_exception(exc):
    text = str(exc or "").lower()
    retryable_tokens = (
        "10053",
        "10054",
        "aborted by the software in your host machine",
        "connection aborted",
        "forcibly closed",
        "connection reset",
        "broken pipe",
        "timed out",
        "timeout",
        "connection closed",
    )
    return any(token in text for token in retryable_tokens)


def _run_telnet_settled_command(tn, command, max_wait_seconds=6):
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
    start_ts = time.time()
    while (time.time() - start_ts) < max_wait_seconds:
        time.sleep(0.25)
        try:
            chunk = tn.read_very_eager().decode("ascii", errors="ignore")
        except EOFError:
            break
        if not chunk:
            continue
        cleaned = ANSI_ESCAPE_PATTERN.sub("", chunk)
        output += cleaned
        lowered = cleaned.lower()
        if "more" in lowered and "press" in lowered:
            try:
                _touch_telnet_session(tn)
                tn.write(b" ")
            except EOFError:
                break
            continue
        lines = [line.strip() for line in output.splitlines() if line.strip()]
        if str(command or "").strip().lower() in output.lower() and lines and PROMPT_LINE_PATTERN.match(lines[-1]):
            break

    output = re.sub(r"(?i)-+\s*more\s*-+", "", output)
    output = re.sub(r"(?i)--more--", "", output)
    output = re.sub(r"(?i)press\s+space\s+to\s+continue", "", output)
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


def _record_olt_save_history(olt_id, action, details):
    try:
        from .models import OLT, OLTLoginHistory

        olt = OLT.objects.filter(pk=int(olt_id)).filter(olt_background_enabled_q()).first()
        if not olt:
            return
        OLTLoginHistory.objects.create(
            olt=olt,
            user=None,
            username="system",
            action=str(action or "save")[:50],
            details=str(details or "")[:300],
        )
    except Exception:
        pass


def _run_scheduled_olt_save(olt_id, reason):
    from django.db import close_old_connections
    from .models import OLT

    with _OLT_SAVE_QUEUE_LOCK:
        _OLT_SAVE_TIMERS.pop(int(olt_id), None)
    close_old_connections()
    tn = None
    try:
        olt = OLT.objects.filter(pk=int(olt_id)).first()
        if not olt:
            return
        _record_olt_save_history(olt_id, "save_running", f"Scheduled save started: {reason}")
        tn, auth_status = open_telnet_authenticated_session(olt)
        if tn is None:
            _record_olt_save_history(olt_id, "save_failed", auth_status)
            return
        _prepare_telnet_cli_session(tn, include_enable=False, use_paging=False)
        output = _run_telnet_save_command(tn)
        if _is_cli_error_text(output):
            _record_olt_save_history(olt_id, "save_failed", _clean_cli_response_text("save", output) or "Save failed.")
            return
        _record_olt_save_history(olt_id, "save_completed", f"Configuration saved. {reason}")
    except Exception as exc:
        _record_olt_save_history(olt_id, "save_failed", f"Scheduled save failed: {exc}")
    finally:
        _close_telnet_session(tn)
        close_old_connections()


def schedule_olt_save(olt, reason="configuration changed", delay_seconds=None):
    if not olt:
        return "Save skipped: OLT not found."
    olt_id = int(getattr(olt, "pk", 0) or 0)
    if not olt_id:
        return "Save skipped: OLT not saved."
    delay = int(delay_seconds if delay_seconds is not None else OLT_SAVE_DEBOUNCE_SECONDS)
    with _OLT_SAVE_QUEUE_LOCK:
        old_timer = _OLT_SAVE_TIMERS.get(olt_id)
        if old_timer:
            try:
                old_timer.cancel()
            except Exception:
                pass
        timer = threading.Timer(delay, _run_scheduled_olt_save, args=(olt_id, str(reason or "configuration changed")))
        timer.daemon = True
        _OLT_SAVE_TIMERS[olt_id] = timer
        timer.start()
    _record_olt_save_history(olt_id, "save_scheduled", f"Save scheduled in {delay}s: {reason}")
    return f"Save scheduled in {delay}s."


def _schedule_olt_save_from_command(olt, reason="configuration changed"):
    return schedule_olt_save(olt, reason=reason)


def execute_olt_save_now(olt):
    """Run the Huawei ``save`` command immediately (manual Save button).

    Returns ``(ok: bool, message: str)``.
    """
    from django.db import close_old_connections

    tn = None
    try:
        tn, auth_status = open_telnet_authenticated_session(olt)
        if tn is None:
            return False, auth_status or "Telnet connection failed."
        _prepare_telnet_cli_session(tn, include_enable=False, use_paging=False)
        output = _run_telnet_save_command(tn)
        if _is_cli_error_text(output):
            msg = _clean_cli_response_text("save", output) or "Save failed on OLT."
            _record_olt_save_history(getattr(olt, "pk", 0), "save_failed", f"Manual save failed: {msg}")
            return False, msg
        _record_olt_save_history(getattr(olt, "pk", 0), "save_completed", "Manual save from OLT settings.")
        return True, "Configuration saved to OLT flash."
    except Exception as exc:
        _record_olt_save_history(getattr(olt, "pk", 0), "save_failed", f"Manual save error: {exc}")
        return False, f"Save failed: {exc}"
    finally:
        _close_telnet_session(tn)
        close_old_connections()


def fetch_olt_full_running_config(olt):
    """Fetch the entire OLT running config via ``display current-configuration``.

    Used by the manual Backup button. Returns ``(ok: bool, text: str, message: str)``.
    """
    from django.db import close_old_connections

    tn = None
    try:
        tn, auth_status = open_telnet_authenticated_session(olt)
        if tn is None:
            return False, "", auth_status or "Telnet connection failed."
        # enable mode + disable paging so the full config streams without --More--.
        _prepare_telnet_cli_session(tn, include_enable=True, use_paging=True)
        raw = _run_telnet_bulk_command(tn, "display current-configuration", max_wait_seconds=240)
        text = _clean_full_config_dump("display current-configuration", raw)
        if not text.strip() or _is_cli_error_text(text):
            return False, "", "Could not read configuration from OLT (empty or error response)."
        return True, text, "OK"
    except Exception as exc:
        return False, "", f"Backup failed: {exc}"
    finally:
        _close_telnet_session(tn)
        close_old_connections()


def _clean_full_config_dump(command, raw):
    """Tidy a full ``display current-configuration`` dump for download.

    Removes the echoed command and paging artefacts, and strips the device CLI
    prompt only from the start/end. Huawei config section separators (a bare
    ``#`` on its own line) are PRESERVED so the backup stays faithful.
    """
    text = str(raw or "")
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    cmd = str(command or "").strip().lower()

    def _looks_like_prompt(line):
        s = line.strip()
        # Bare separators (#, >, ]) are real config structure, not a prompt.
        if s in ("#", ">", "]", ""):
            return False
        # A hostname prompt is a single token ending in > / # / ] (e.g. <HUAWEI>,
        # OLT-27>, huawei(config)#) — config commands contain spaces.
        if " " in s:
            return False
        return bool(re.match(r"^[^\r\n]+[>#\]]$", s))

    lines = []
    for raw_line in text.split("\n"):
        line = raw_line.rstrip()
        low = line.strip().lower()
        if not low:
            lines.append("")
            continue
        if low == cmd:
            continue
        if low.startswith(("it will take a long time", "you can press ctrl_c", "press ctrl_c")):
            continue
        if "--more--" in low or low.startswith("{ <cr") or low == "<cr>":
            continue
        lines.append(line)

    # Strip leading/trailing CLI prompt lines (keep section separators intact).
    while lines and _looks_like_prompt(lines[0]):
        lines.pop(0)
    while lines and (_looks_like_prompt(lines[-1]) or not lines[-1].strip()):
        lines.pop()

    cleaned = "\n".join(lines).strip("\n")
    cleaned = re.sub(r"\n{3,}", "\n\n", cleaned)
    return cleaned + "\n"


def _run_telnet_bulk_command(tn, command, max_wait_seconds=45, idle_poke=b"\r\n", poll_seconds=0.2):
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
    initial_steps = [b"\r\n", b"\r\n", b" "]
    initial_step_index = 0

    poll_seconds = max(0.08, float(poll_seconds or 0.2))
    while (time.time() - start_ts) < max_wait_seconds:
        time.sleep(poll_seconds)
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
            if "<cr>" in lowered or "press enter" in lowered or "sort-by" in lowered:
                if initial_step_index < len(initial_steps):
                    _touch_telnet_session(tn)
                    tn.write(initial_steps[initial_step_index])
                    initial_step_index += 1
                else:
                    _touch_telnet_session(tn)
                    tn.write(b" ")
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
            if initial_step_index < len(initial_steps) and idle_rounds >= 2:
                try:
                    _touch_telnet_session(tn)
                    tn.write(initial_steps[initial_step_index])
                    initial_step_index += 1
                    idle_rounds = 0
                    continue
                except EOFError:
                    break
            if idle_rounds in {2, 4, 6, 8, 10, 12}:
                try:
                    _touch_telnet_session(tn)
                    tn.write(b" " if saw_payload else idle_poke)
                    idle_pokes += 1
                except EOFError:
                    break
            if saw_payload and idle_rounds >= 10 and idle_pokes >= 2:
                lines = [line.strip() for line in output.splitlines() if line.strip()]
                if lines and prompt_pattern.match(lines[-1]):
                    break
            if not saw_payload and idle_rounds >= 12 and idle_pokes >= 2:
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

    # XGS-PON must be checked before XG-PON because "XGS" contains "XG"
    if "XGS" in text:
        return "XGS-PON"
    if "XG" in text:
        return "XG-PON"
    if "CGID" in text:
        return "GPON"
    if "EP" in text:
        return "EPON"
    if "GP" in text:
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
    """Return True if the model/real_type string identifies a PON service board (GPON, EPON, XGS-PON, XG-PON)."""
    text = (model or "").upper().strip()
    if not text:
        return False
    # Exact classified-type names
    if text in ("GPON", "EPON", "XGS-PON", "XG-PON"):
        return True
    # Huawei GPON board model-name substrings (GP appears in GPFD, GPBH, GPHF, etc.)
    if "GP" in text:
        return True
    # Huawei XGS-PON / XG-PON board model-name substrings
    if "XG" in text:
        return True
    if "CGID" in text:
        return True
    # Huawei EPON board model-name substrings (EPFD, EPFC)
    if "EPON" in text or "EPFD" in text or "EPFC" in text:
        return True
    return False


_PON_TYPE_KEYWORDS = frozenset({
    "GPON", "EPON", "XGSPON", "XGS-PON", "XG-PON", "XGPON", "PON",
})
_ADMIN_STATE_KEYWORDS = frozenset({
    "ACTIVATE", "DEACTIVATE", "ACTIVATED", "DEACTIVATED",
    "ENABLED", "DISABLED", "ENABLE", "DISABLE", "SHUTDOWN",
})


def _pon_tech_from_board_type(board_type):
    """Derive the PON technology label (GPON/EPON/XGS-PON) from a board type / real-type string."""
    text = (board_type or "").upper().strip()
    if "XGS" in text:
        return "XGS-PON"
    if "XG" in text:
        return "XG-PON"
    if "CGID" in text:
        return "GPON"
    if "EPON" in text or "EPFD" in text or "EPFC" in text:
        return "EPON"
    return "GPON"


def _slot_pon_tech(olt, slot):
    """Return the PON technology ('GPON', 'EPON', 'XGS-PON', 'XG-PON') for a given slot number."""
    target = str(slot)
    for group in list(getattr(olt, "pon_ports_cache", []) or []):
        if str((group or {}).get("slot", "")) == target:
            for port in (group or {}).get("ports") or []:
                pt = str((port or {}).get("type") or "").upper()
                if pt:
                    return _pon_tech_from_board_type(pt)
    for card in list(getattr(olt, "olt_cards_cache", []) or []):
        if str((card or {}).get("slot") or "") == target:
            real_type = str((card or {}).get("real_type") or (card or {}).get("type") or "")
            return _pon_tech_from_board_type(real_type)
    return "GPON"


def _parse_pon_ports_from_board_detail(slot, board_type, detail_output, default_ports):
    """Parse PON port rows from 'display board 0/<slot>' output.

    Handles multiple Huawei output formats:
      Format A – column 2 is AdminStatus: '0  activate   up/autofind  5  5  5'
      Format B – column 2 is PortType:    '0  GPON  Enabled  Up'
    """
    default_port_type = _pon_tech_from_board_type(board_type)
    ports = []
    seen = set()
    lines = (detail_output or "").splitlines()
    in_port_section = False

    for raw in lines:
        line = raw.strip()
        if not line:
            continue

        # Detect the start of the port table section (optional but improves accuracy)
        low = line.lower()
        if re.search(r"\bport\b.*\badmin", low) or re.search(r"\bport\b.*\blink\b", low) or re.search(r"\bport\b.*\bstate\b", low):
            in_port_section = True
            continue
        if re.match(r"^-{3,}", line):
            continue

        match = re.match(r"^(\d+)\s+([A-Za-z][A-Za-z0-9_./-]*)\s*(.*)?$", line)
        if not match:
            continue

        port_no = int(match.group(1))
        if port_no in seen:
            continue

        col2 = match.group(2)
        rest = (match.group(3) or "").strip()
        col2_up = col2.upper()

        # Determine if col2 is a PON type name or an admin status keyword
        if col2_up in _PON_TYPE_KEYWORDS:
            # Format B: Port  Type  AdminState  LinkState
            port_type = col2_up
            rest_for_state = rest
        elif col2_up in _ADMIN_STATE_KEYWORDS:
            # Format A: Port  AdminStatus  LinkState  ...
            port_type = default_port_type
            rest_for_state = col2 + " " + rest
        else:
            # Unknown column — use default type and treat rest as combined state text
            port_type = default_port_type
            rest_for_state = col2 + " " + rest

        rest_l = rest_for_state.lower()
        admin_state = "Disabled" if any(
            token in rest_l for token in ("deactivate", "deactivated", "disable", "disabled", "shutdown")
        ) else "Enabled"
        status_text = _derive_pon_status_from_detail(rest_l)

        seen.add(port_no)
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

    if ports:
        return sorted(ports, key=lambda item: item["port"])

    # Fallback: generate stub ports so the slot is still represented in the UI
    count = int(default_ports or 0)
    for port_no in range(count):
        ports.append(
            {
                "slot": str(slot),
                "board_type": board_type or "Unknown",
                "port": port_no,
                "type": default_port_type,
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
        if stripped.lower().startswith(("ont id", "onu id", "onu-id", "ont-id", "rx power", "command:", "huawei", "note:")):
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


def _parse_single_ont_optical_info(optical_output):
    text = str(optical_output or "")

    def _pick(patterns):
        for pattern in patterns:
            match = re.search(pattern, text, flags=re.IGNORECASE | re.MULTILINE)
            if match:
                return _format_optical_dbm(match.group(1))
        return "--"

    return {
        "onu_rx": _pick((
            r"^\s*Rx\s+optical\s+power\s*\(dBm\)\s*:\s*(-?\d+(?:\.\d+)?|-)",
            r"^\s*ONU\s+Rx\s+optical\s+power\s*\(dBm\)\s*:\s*(-?\d+(?:\.\d+)?|-)",
            r"^\s*Receive\s+optical\s+power\s*\(dBm\)\s*:\s*(-?\d+(?:\.\d+)?|-)",
            r"^\s*ONU\s+receive\s+optical\s+power\s*\(dBm\)\s*:\s*(-?\d+(?:\.\d+)?|-)",
            r"(?i)\bRx\b.*?(-?\d+(?:\.\d+)?)\s*dBm",
        )),
        "tx_power": _pick((
            r"^\s*Tx\s+optical\s+power\s*\(dBm\)\s*:\s*(-?\d+(?:\.\d+)?|-)",
            r"^\s*Transmit\s+optical\s+power\s*\(dBm\)\s*:\s*(-?\d+(?:\.\d+)?|-)",
            r"^\s*ONU\s+Tx\s+optical\s+power\s*\(dBm\)\s*:\s*(-?\d+(?:\.\d+)?|-)",
            r"^\s*ONU\s+transmit\s+optical\s+power\s*\(dBm\)\s*:\s*(-?\d+(?:\.\d+)?|-)",
            r"(?i)\bTx\b.*?(-?\d+(?:\.\d+)?)\s*dBm",
        )),
        "olt_rx": _pick((
            r"^\s*OLT\s+Rx\s+ONT\s+optical\s+power\s*\(dBm\)\s*:\s*(-?\d+(?:\.\d+)?|-)",
            r"^\s*OLT\s+Rx\s+optical\s+power\s*\(dBm\)\s*:\s*(-?\d+(?:\.\d+)?|-)",
            r"^\s*OLT\s+receive\s+optical\s+power\s*\(dBm\)\s*:\s*(-?\d+(?:\.\d+)?|-)",
        )),
    }


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
        patterns = (
            r"(?i)\b(?:tx|transmit)(?:\s+optical)?(?:\s+power)?(?:\s*\(dbm\))?\s*[:=]?\s*(-?\d+(?:\.\d+)?)",
            r"(?i)\b(?:tx|transmit).*?\bpower(?:\s*\(dbm\))?\s*[:=]?\s*(-?\d+(?:\.\d+)?)",
            r"(?i)\b(?:tx|transmit).*?(-?\d+(?:\.\d+)?)\s*dBm\b",
        )
        for pattern in patterns:
            match = re.search(pattern, line)
            if not match:
                continue
            formatted = _format_sfp_tx_dbm(match.group(1))
            if formatted:
                return formatted
    return ""


def _parse_pon_sfp_tx_map_from_state_all(text, ports):
    tx_map = {}
    wanted_ports = {int(port) for port in (ports or [])}
    if not wanted_ports:
        return tx_map

    current_port = None
    tx_column_index = None
    saw_tx_header = False
    for raw_line in str(text or "").splitlines():
        line = str(raw_line or "").strip()
        if not line:
            continue
        lowered = line.lower()
        if "tx" in lowered and ("power" in lowered or "dbm" in lowered):
            saw_tx_header = True
            header_tokens = re.split(r"\s{2,}|\t+", line)
            for idx, token in enumerate(header_tokens):
                token_l = token.lower()
                if "tx" in token_l and ("power" in token_l or "dbm" in token_l):
                    tx_column_index = idx
                    break
            continue

        port_match = None
        for pattern in (
            r"(?i)\bport\s*[: ]+\s*(\d+)\b",
            r"(?i)\binterface\s*[: ]+\s*(\d+)\b",
            r"(?i)^\s*(\d+)\s*/\s*(\d+)\s*/\s*(\d+)\b",
            r"(?i)^\s*(\d+)\s*/\s*(\d+)\b",
            r"(?i)^\s*(\d+)\s+(?:up|down|online|offline|enable|enabled|disable|disabled)\b",
        ):
            match = re.search(pattern, line)
            if match:
                port_match = match
                break

        if port_match:
            groups = port_match.groups()
            try:
                current_port = int(groups[-1])
            except (TypeError, ValueError):
                current_port = None

        parsed_tx = _parse_pon_sfp_tx_from_text(line)
        if parsed_tx and current_port in wanted_ports and current_port not in tx_map:
            tx_map[current_port] = parsed_tx
            continue

        if saw_tx_header and current_port in wanted_ports and current_port not in tx_map:
            row_tokens = re.split(r"\s{2,}|\t+", line)
            candidate = ""
            if tx_column_index is not None and tx_column_index < len(row_tokens):
                candidate = row_tokens[tx_column_index]
            if not candidate:
                numeric_values = re.findall(r"(?<!/)-?\d+(?:\.\d+)?", line)
                if numeric_values:
                    candidate = numeric_values[-1]
            formatted = _format_sfp_tx_dbm(candidate)
            if formatted:
                tx_map[current_port] = formatted

    return tx_map


def _format_sfp_tx_dbm(raw_value):
    text = str(raw_value or "").strip()
    if not text or text in {"-", "--"}:
        return ""
    match = re.search(r"-?\d+(?:\.\d+)?", text)
    if not match:
        return ""
    try:
        value = float(match.group(0))
    except (TypeError, ValueError):
        return ""
    if value in (2147483647, -2147483648):
        return ""
    if abs(value) > 3000 and abs(value) <= 30000:
        value = value / 1000
    elif abs(value) > 100 and abs(value) <= 3000:
        value = value / 100
    if value < -40 or value > 25:
        return ""
    return f"{value:.2f} dBm"


def _fetch_pon_sfp_tx_map_in_context(tn, slot_port_map, *, per_port_fallback=True):
    tx_map = {}
    if not slot_port_map:
        return tx_map

    # First try one board-wide dump so all ports on that PON board can be parsed in one
    # shot. If a board/model still misses some values, only then fall back to per-port
    # commands for the remaining ports.
    command_templates = (
        "display port state {port}",
        "display port ddm-info {port}",
        "display port ddm-info port {port}",
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
            state_all_output = _run_telnet_command(tn, "display port state all", enter_until_prompt=True)
            state_all_map = _parse_pon_sfp_tx_map_from_state_all(state_all_output, ports)
            for port, value in state_all_map.items():
                if value:
                    tx_map[(int(slot), int(port))] = value

            if per_port_fallback:
                missing_ports = [port for port in ports if (int(slot), int(port)) not in tx_map]
                for port in missing_ports:
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


def _fetch_ont_optical_map_in_context(tn, slot_ports, onu_keys=None, olt=None):
    """Fetch optical Rx/Tx power for ONUs via Telnet CLI.

    Supports GPON (interface gpon / display ont optical-info),
    EPON (interface epon / display onu optical-info), and XGS-PON.
    Pass the OLT model object so board technology is detected per slot.
    """
    optical_map = {}
    successful_ports = set()
    if not slot_ports:
        return optical_map, successful_ports

    grouped_ports = {}
    for slot, port in slot_ports:
        grouped_ports.setdefault(int(slot), set()).add(int(port))
    ont_ids_by_port = {}
    for key in onu_keys or []:
        try:
            key_slot, key_port, key_ont_id = int(key[0]), int(key[1]), int(key[2])
        except (TypeError, ValueError, IndexError):
            continue
        ont_ids_by_port.setdefault((key_slot, key_port), set()).add(key_ont_id)

    for slot in sorted(grouped_ports):
        # Determine the correct interface kind and CLI command prefix for this slot
        if olt is not None:
            board_tech = _slot_pon_tech(olt, slot)
            interface_kinds = _pon_interface_kinds_for_board(board_tech)
        else:
            board_tech = "GPON"
            interface_kinds = ("gpon", "xgpon", "epon")

        board_kind, _, entered = _enter_interface_context(tn, interface_kinds, 0, slot)
        if not entered:
            continue

        # EPON uses "onu" terminology; GPON/XGS-PON use "ont"
        is_epon = "epon" in (board_kind or "").lower()
        node_word = "onu" if is_epon else "ont"

        try:
            time.sleep(0.25)
            tn.read_very_eager()
        except (OSError, EOFError):
            pass

        for port in sorted(grouped_ports[slot]):
            cmd_all = f"display {node_word} optical-info {port} all"
            output = ""
            parsed = {}
            for _ in range(2):
                output = _run_telnet_command(tn, cmd_all, enter_until_prompt=True)
                parsed = _parse_port_optical_table(output, slot, port)
                cleaned_output = _clean_cli_transcript_block(cmd_all, output)
                if parsed or (cleaned_output and not _is_cli_error_text(cleaned_output)):
                    successful_ports.add((int(slot), int(port)))
                if parsed:
                    optical_map.update(parsed)
                    break

            if not parsed and ont_ids_by_port.get((int(slot), int(port))):
                for ont_id in sorted(ont_ids_by_port[(int(slot), int(port))]):
                    cmd_single = f"display {node_word} optical-info {port} {ont_id}"
                    out_single = _run_telnet_settled_command(tn, cmd_single)
                    parsed_single = _parse_single_ont_optical_info(out_single)
                    if any(value != "--" for value in parsed_single.values()):
                        optical_map[(int(slot), int(port), int(ont_id))] = parsed_single
                        successful_ports.add((int(slot), int(port)))

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
        optical_map, _ = _fetch_ont_optical_map_in_context(tn, [(slot, port)], [(slot, port, ont_id)], olt=olt)
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
        optical_map, _ = _fetch_ont_optical_map_in_context(tn, slot_ports, onu_keys, olt=olt)
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

    def _cached_gpon_slots():
        slots = set()
        # Primary source: already-fetched PON port groups
        for group in list(getattr(olt, "pon_ports_cache", []) or []):
            try:
                if (group or {}).get("ports"):
                    slots.add(int((group or {}).get("slot") or 0))
            except (TypeError, ValueError):
                continue
        # Fallback: scan card cache for any PON service board (GPON, EPON, XGS-PON, XG-PON)
        for card in list(getattr(olt, "olt_cards_cache", []) or []):
            # real_type is the reliable classified field; fall back to model_type / type
            real_type = str(
                (card or {}).get("real_type")
                or (card or {}).get("model_type")
                or (card or {}).get("type")
                or ""
            ).upper()
            if not _is_pon_board_model(real_type):
                continue
            try:
                slots.add(int((card or {}).get("slot") or 0))
            except (TypeError, ValueError):
                continue
        return sorted(slots)

    def _expected_counts_from_pon_cache():
        expected_by_slot = {}
        for group in list(getattr(olt, "pon_ports_cache", []) or []):
            try:
                slot = int((group or {}).get("slot") or 0)
            except (TypeError, ValueError):
                continue
            for port_row in (group or {}).get("ports") or []:
                try:
                    online = int((port_row or {}).get("onus_online") or 0)
                    offline = int((port_row or {}).get("onus_offline") or 0)
                except (TypeError, ValueError):
                    continue
                expected_by_slot[slot] = expected_by_slot.get(slot, 0) + online + offline
        return expected_by_slot

    try:
        _prepare_telnet_cli_session(tn, use_paging=True)
        try:
            tn.read_very_eager()
        except (OSError, EOFError):
            pass
        slots = _cached_gpon_slots()
        expected_by_slot = _expected_counts_from_pon_cache()
        rows = []
        desc_map = {}
        slot_status = []
        for slot in slots:
            expected_slot_total = int(expected_by_slot.get(int(slot), 0) or 0)
            board_tech = _slot_pon_tech(olt, slot)

            # GPON/XGS-PON: prefer the direct ONT-info command; board detail as fallback.
            # EPON: board detail is used (ONU table format differs, handled by parser).
            if board_tech in ("GPON", "XGS-PON", "XG-PON"):
                commands_to_try = [
                    f"display ont info 0/{slot} all",
                    f"display board 0/{slot}",
                ]
            else:
                commands_to_try = [
                    f"display board 0/{slot}",
                    f"display ont info 0/{slot} all",
                ]

            best_rows = []
            best_desc = {}
            for command in commands_to_try:
                for _ in range(2):
                    output = _run_telnet_bulk_command(tn, command, max_wait_seconds=90)
                    parsed_rows = _parse_ont_inventory_rows(output)
                    parsed_desc = _parse_ont_description_section(output)
                    if len(parsed_rows) > len(best_rows):
                        best_rows = parsed_rows
                        best_desc = parsed_desc
                    if expected_slot_total and len(best_rows) >= expected_slot_total:
                        break
                if expected_slot_total and len(best_rows) >= expected_slot_total:
                    break
                if best_rows and not expected_slot_total:
                    break
            rows.extend(best_rows)
            desc_map.update(best_desc)
            expected_note = f"/{expected_by_slot.get(int(slot), 0)}" if expected_by_slot.get(int(slot), 0) else ""
            slot_status.append(f"0/{slot}: {len(best_rows)}{expected_note}")
        expected_total = sum(expected_by_slot.values())
        # Allow a tolerance of up to 5 ONUs or 5% (whichever is larger) to handle
        # minor Telnet pagination gaps without cancelling the entire sync cycle.
        # A truly incomplete fetch (e.g. timeout mid-command) will still be caught
        # because it returns far fewer rows than expected.
        if expected_total:
            tolerance = max(5, int(expected_total * 0.05))
            if len(rows) < (expected_total - tolerance):
                result["rows"] = []
                result["incomplete"] = True
                result["expected_count"] = expected_total
                result["actual_count"] = len(rows)
                result["status"] = (
                    f"Incomplete configured ONU inventory: fetched {len(rows)} of expected {expected_total}. "
                    f"Slots: {', '.join(slot_status) if slot_status else 'none'}"
                )
                return result
        slot_ports = sorted(
            {
                (int(row.get("slot", 0) or 0), int(row.get("port", 0) or 0))
                for row in rows
            }
        )
        optical_map, _ = _fetch_ont_optical_map_in_context(tn, slot_ports, olt=olt)
        for row in rows:
            row["description"] = desc_map.get((row["slot"], row["port"], row["ont_id"]), "").strip()
            power = optical_map.get((row["slot"], row["port"], row["ont_id"])) or {}
            row["onu_rx"] = power.get("onu_rx", "--")
            row["tx_power"] = power.get("tx_power", "--")
            row["olt_rx"] = power.get("olt_rx", "--")
            signal_source = row["olt_rx"] if row["olt_rx"] != "--" else row["onu_rx"]
            row["signal_bucket"] = _signal_bucket_from_dbm_text(signal_source)
        result["rows"] = rows
        result["status"] = (
            f"Configured ONUs fetched from board detail: {len(rows)} | "
            f"Slots: {', '.join(slot_status) if slot_status else 'none'} | "
            f"Descriptions mapped: {len(desc_map)} | Signals mapped: {len(optical_map)}"
        )
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


def fetch_configured_onu_status_rows(olt, slots):
    """Fetch configured ONU status rows for selected slots without optical reads."""
    result = {"status": "ONU status inventory unavailable", "rows": []}
    slots = sorted({int(slot) for slot in (slots or [])})
    if not slots:
        result["status"] = "No slots requested."
        return result

    tn, status = open_telnet_authenticated_session(olt)
    if tn is None:
        result["status"] = status
        return result

    try:
        _prepare_telnet_cli_session(tn, use_paging=True)
        rows = []
        slot_status = []
        for slot in slots:
            board_tech = _slot_pon_tech(olt, slot)
            if board_tech in ("GPON", "XGS-PON", "XG-PON"):
                commands_to_try = (f"display ont info 0/{slot} all", f"display board 0/{slot}")
            else:
                commands_to_try = (f"display board 0/{slot}", f"display ont info 0/{slot} all")

            best_rows = []
            for command in commands_to_try:
                output = _run_telnet_bulk_command(tn, command, max_wait_seconds=60)
                parsed_rows = _parse_ont_inventory_rows(output)
                if len(parsed_rows) > len(best_rows):
                    best_rows = parsed_rows
                if best_rows:
                    break
            rows.extend(best_rows)
            slot_status.append(f"0/{slot}: {len(best_rows)}")

        result["rows"] = rows
        result["status"] = f"Configured ONU status rows fetched: {len(rows)} | Slots: {', '.join(slot_status)}"
        return result
    except (socket.timeout, TimeoutError):
        result["status"] = "Telnet timeout while fetching configured ONU status rows."
        return result
    except EOFError:
        result["status"] = "Telnet connection closed while fetching configured ONU status rows."
        return result
    except OSError as exc:
        result["status"] = f"Telnet error while fetching configured ONU status rows: {exc}"
        return result
    finally:
        _close_telnet_session(tn)


def detect_new_onus_from_snmp(olt):
    """Compare SNMP-visible ONU keys with DB. Returns new (slot, port, ont_id) tuples not yet in DB.

    Used by the SNMP monitor loop to detect ONUs provisioned externally (CLI, NETCONF, etc.)
    so an immediate inventory sync can be triggered without waiting for the 10-min cycle.
    """
    from .models import ConfiguredONU

    status_map = fetch_olt_snmp_status_map(olt)
    snmp_items = status_map.get("items") or {}
    if not snmp_items:
        return {"new_keys": [], "snmp_count": 0, "status": status_map.get("status") or "No SNMP data"}

    snmp_keys = set(snmp_items.keys())
    db_keys = set(
        map(
            tuple,
            ConfiguredONU.objects.filter(olt=olt).values_list("slot", "port", "ont_id"),
        )
    )
    new_keys = snmp_keys - db_keys
    return {
        "new_keys": list(new_keys),
        "snmp_count": len(snmp_keys),
        "db_count": len(db_keys),
        "status": f"SNMP: {len(snmp_keys)} ONUs | DB: {len(db_keys)} | New: {len(new_keys)}",
    }


def sync_configured_onus_inventory(olt):
    from django.db import transaction

    from .models import ConfiguredONU

    fetched = fetch_configured_onus_snapshot(olt)
    rows = fetched.get("rows") or []
    status = fetched.get("status") or ""
    if fetched.get("incomplete"):
        return {
            "status": status or "Configured ONU inventory incomplete.",
            "count": 0,
            "incomplete": True,
            "expected_count": fetched.get("expected_count") or 0,
            "actual_count": fetched.get("actual_count") or 0,
        }
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
            payload["onu_mode_cache"] = "routing"
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

        if not getattr(existing, "configured_via_app", False):
            payload["onu_mode_cache"] = "routing"

        if not (payload.get("description") or "").strip() and (existing.description or "").strip():
            payload["description"] = existing.description[:255]

        # Preserve existing good signal data when the fresh optical fetch returned
        # nothing ("--" or empty) — this prevents inventory sync from erasing SNMP-
        # filled signals every cycle when Telnet optical fetch times out.
        for _sig in ("onu_rx", "olt_rx", "tx_power"):
            new_val = (payload.get(_sig) or "").strip()
            if not new_val or new_val == "--":
                existing_val = (getattr(existing, _sig, "") or "").strip()
                if existing_val and existing_val != "--":
                    payload[_sig] = existing_val
        if not (payload.get("signal_bucket") or "").strip():
            existing_bucket = (getattr(existing, "signal_bucket", "") or "").strip()
            if existing_bucket in ("good", "warn", "bad"):
                payload["signal_bucket"] = existing_bucket

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
                    "onu_mode_cache",
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
    for item in ConfiguredONU.objects.filter(olt=olt).values("slot", "port", "run_state", "derived_status"):
        slot = int(item.get("slot") or 0)
        port = int(item.get("port") or 0)
        derived_status = str(item.get("derived_status") or "").strip().lower()
        run_state = str(item.get("run_state") or "").strip().lower()
        bucket = counts.setdefault((slot, port), {"online": 0, "offline": 0})
        total_rows += 1
        if derived_status == "online" or (not derived_status and run_state == "online"):
            bucket["online"] += 1
        else:
            bucket["offline"] += 1
    return counts, total_rows


def _get_ont_signal_averages_from_db(olt):
    from .models import ConfiguredONU

    samples = {}
    # Prefer OLT-Rx (upstream signal the OLT measures) but fall back to ONU-Rx.
    # On EPON the OLT-Rx OID (.104.1.1) is unreliable/empty on many devices while
    # ONU-Rx (.104.1.5) is solid, so without this fallback the EPON PON ports show
    # a blank "Average Signal" even though every ONU has a valid reading.
    for item in ConfiguredONU.objects.filter(olt=olt).values("slot", "port", "olt_rx", "onu_rx"):
        slot = int(item.get("slot") or 0)
        port = int(item.get("port") or 0)
        signal = _parse_dbm_float(item.get("olt_rx"))
        if signal is None:
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
            row["sfp_tx"] = _format_sfp_tx_dbm(tx_map.get((slot, port), row.get("sfp_tx", ""))) or ""


def _normalize_pon_sfp_tx_in_groups(groups):
    for group in groups or []:
        for row in group.get("ports", []) or []:
            row["sfp_tx"] = _format_sfp_tx_dbm(row.get("sfp_tx", "")) or ""


def save_pon_ports_snapshot(olt, groups, status):
    previous_tx = {}
    for group in list(getattr(olt, "pon_ports_cache", []) or []):
        try:
            slot = int((group or {}).get("slot") or 0)
        except (TypeError, ValueError):
            continue
        for row in (group or {}).get("ports") or []:
            try:
                port = int((row or {}).get("port") or 0)
            except (TypeError, ValueError):
                continue
            previous_tx[(slot, port)] = str((row or {}).get("sfp_tx") or "").strip()
    for group in groups or []:
        try:
            slot = int((group or {}).get("slot") or 0)
        except (TypeError, ValueError):
            continue
        for row in (group or {}).get("ports") or []:
            try:
                port = int((row or {}).get("port") or 0)
            except (TypeError, ValueError):
                continue
            row["sfp_tx"] = previous_tx.get((slot, port), str((row or {}).get("sfp_tx") or "").strip())
    _normalize_pon_sfp_tx_in_groups(groups)
    olt.pon_ports_cache = groups or []
    olt.pon_ports_status = (status or "")[:300]
    olt.pon_ports_refreshed_at = timezone.now()
    olt.save(update_fields=["pon_ports_cache", "pon_ports_status", "pon_ports_refreshed_at"])


def refresh_pon_sfp_tx_snapshot(olt):
    groups = list(getattr(olt, "pon_ports_cache", []) or [])
    result = {
        "ok": False,
        "groups": groups,
        "status": "No PON ports in database.",
        "updated": 0,
    }
    if not groups:
        return result

    slot_port_map = {}
    for group in groups:
        try:
            slot = int((group or {}).get("slot") or 0)
        except (TypeError, ValueError):
            continue
        ports = []
        for row in (group or {}).get("ports") or []:
            try:
                ports.append(int((row or {}).get("port") or 0))
            except (TypeError, ValueError):
                continue
        if ports:
            slot_port_map[slot] = {
                "board_type": (group or {}).get("board_type") or "",
                "ports": ports,
            }

    total_ports = sum(len(data.get("ports") or []) for data in slot_port_map.values())
    before = {
        (int((group or {}).get("slot") or 0), int((row or {}).get("port") or 0)): str((row or {}).get("sfp_tx") or "").strip()
        for group in groups
        for row in ((group or {}).get("ports") or [])
    }

    # --- Try SNMP first (faster, no Telnet login required) ---
    tx_map = _fetch_pon_sfp_tx_via_snmp(olt)
    method = "SNMP"

    # --- Fall back to Telnet when SNMP yields nothing ---
    if not tx_map:
        method = "Telnet"
        tn, tn_status = open_telnet_authenticated_session(olt)
        if tn is None:
            result["status"] = tn_status or "SNMP returned no data and Telnet session could not be opened."
            return result
        try:
            _prepare_telnet_cli_session(tn, use_paging=True)
            tx_map = _fetch_pon_sfp_tx_map_in_context(tn, slot_port_map, per_port_fallback=False)
        except (socket.timeout, TimeoutError):
            result["status"] = "Telnet timeout while refreshing SFP Tx."
            return result
        except (EOFError, OSError) as exc:
            result["status"] = f"Telnet error while refreshing SFP Tx: {exc}"
            return result
        finally:
            _close_telnet_session(tn)

    _apply_pon_sfp_tx_to_groups(groups, tx_map)
    updated = 0
    for group in groups:
        slot = int((group or {}).get("slot") or 0)
        for row in (group or {}).get("ports") or []:
            port = int((row or {}).get("port") or 0)
            if str(row.get("sfp_tx") or "").strip() != before.get((slot, port), ""):
                updated += 1
    olt.pon_ports_cache = groups
    missing_ports = max(0, total_ports - len(tx_map))
    if missing_ports:
        olt.pon_ports_status = f"SFP Tx refreshed via {method}: {len(tx_map)}/{total_ports} port(s) mapped, {missing_ports} missing."
    else:
        olt.pon_ports_status = f"SFP Tx refreshed via {method}: {len(tx_map)}/{total_ports} port(s) mapped."
    olt.pon_ports_refreshed_at = timezone.now()
    olt.save(update_fields=["pon_ports_cache", "pon_ports_status", "pon_ports_refreshed_at"])
    result.update({
        "ok": True,
        "groups": groups,
        "status": olt.pon_ports_status,
        "updated": updated,
    })
    return result


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
    _normalize_pon_sfp_tx_in_groups(groups)
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


def _parse_dba_profile_entries(output_text):
    entries = []
    for line in _compact_dba_output(output_text):
        normalized = " ".join(str(line or "").strip().split())
        if not normalized:
            continue
        id_match = re.search(r'(?i)\bprofile-id\s+(\d+)', normalized)
        if not id_match:
            continue
        name_match = re.search(r'(?i)\bprofile-name\s+"([^"]+)"', normalized)
        max_match = re.search(r'(?i)\bmax\s+(\d+)', normalized)
        entries.append(
            {
                "id": int(id_match.group(1)),
                "name": (name_match.group(1).strip() if name_match else ""),
                "max": (int(max_match.group(1)) if max_match else None),
            }
        )
    for raw_line in str(output_text or "").splitlines():
        normalized = " ".join(str(raw_line or "").strip().split())
        if not normalized:
            continue
        table_match = re.match(
            r"^(\d+)\s+\d+\s+\S+\s+\d+\s+\d+\s+(\d+)\s+\d+\s*$",
            normalized,
            flags=re.IGNORECASE,
        )
        if not table_match:
            continue
        entries.append(
            {
                "id": int(table_match.group(1)),
                "name": "",
                "max": int(table_match.group(2)),
            }
        )
    deduped = []
    seen = set()
    for item in entries:
        key = (int(item["id"]), str(item.get("name") or "").strip().upper(), item.get("max"))
        if key in seen:
            continue
        seen.add(key)
        deduped.append(item)
    return deduped


def _compact_traffic_profile_output(output):
    merged = []
    current = ""
    for raw in str(output or "").splitlines():
        line = raw.strip()
        if not line:
            continue
        lowered = line.lower()
        if lowered.startswith(("command:", "display current-configuration", "it will take a long time", "you can press ctrl_c", "huawei-", "hua-", "<")):
            continue
        if lowered.startswith("traffic table ip index "):
            if current:
                merged.append(current)
            current = line
            continue
        if current:
            current = f"{current} {line}"
    if current:
        merged.append(current)
    return merged


def _parse_speed_profile_templates_from_file():
    profile_path = settings.BASE_DIR / "Speed_Profiles.txt"
    if not profile_path.exists():
        return []

    grouped = {}
    in_custom_section = False
    for raw_line in profile_path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if line.startswith(CUSTOM_PROFILE_MARKER):
            in_custom_section = True
            continue
        match = re.search(r'traffic\s+table\s+ip\s+index\s+(\d+)\s+name\s+"([^"]+)"\s+cir\s+(\d+)\b', line, flags=re.IGNORECASE)
        if not match:
            continue
        index_value = int(match.group(1))
        full_name = match.group(2).strip()
        cir_value = int(match.group(3))
        direction_match = re.search(r'(?i)(?:-|_)(UP|DOWN)$', full_name)
        direction = (direction_match.group(1).lower() if direction_match else "")
        base_name = re.sub(r'(?i)(?:-|_)(UP|DOWN)$', '', full_name).strip() or full_name
        key = base_name.upper()
        entry = grouped.setdefault(
            key,
            {
                "key": key,
                "index_number": index_value,
                "name": base_name,
                "speed_mbps_value": round(cir_value / 1024, 2),
                "speed_display": f"{cir_value} kbps",
                "download_name": "",
                "upload_name": "",
                "download_command": "",
                "upload_command": "",
                "is_custom": in_custom_section,
            },
        )
        if in_custom_section:
            entry["is_custom"] = True
        if direction == "down":
            entry["download_name"] = full_name
            entry["download_command"] = line
        elif direction == "up":
            entry["upload_name"] = full_name
            entry["upload_command"] = line
        else:
            entry["download_command"] = entry["download_command"] or line

    rows = [item for item in grouped.values() if item.get("download_command") or item.get("upload_command")]
    rows.sort(key=lambda item: (item.get("speed_mbps_value", 0), item.get("name", "")))
    return rows


def sync_speed_profiles_from_file():
    from .models import SpeedProfile

    rows = _parse_speed_profile_templates_from_file()
    seen_keys = set()
    for row in rows:
        key = str(row.get("key") or "").strip().upper()
        if not key:
            continue
        seen_keys.add(key)
        SpeedProfile.objects.update_or_create(
            key=key,
            defaults={
                "name": row.get("name") or key,
                "index_number": row.get("index_number") or 0,
                "speed_mbps_value": row.get("speed_mbps_value") or 0,
                "speed_display": row.get("speed_display") or "",
                "download_name": row.get("download_name") or "",
                "upload_name": row.get("upload_name") or "",
                "download_command": row.get("download_command") or "",
                "upload_command": row.get("upload_command") or "",
                "is_active": True,
                "is_custom": bool(row.get("is_custom")),
            },
        )
    if seen_keys:
        SpeedProfile.objects.exclude(key__in=seen_keys).update(is_active=False)
    return rows


# Burst (cbs/pbs) is capped here — anything above this is clamped, matching the
# reference SOLT-1000M profile whose burst lands exactly on this value.
SPEED_PROFILE_BURST_MAX = 10240000
# Empirically derived from the existing SOLT profiles: cbs(bytes) per Mbps.
SPEED_PROFILE_CBS_PER_MBPS = 33434.6
# Everything below this marker line in Speed_Profiles.txt is a user-created
# profile (kept visually separate from the built-in defaults).
CUSTOM_PROFILE_MARKER = "#### Custom Speed Profiles (created in app) ####"


def speed_profile_onu_usage_counts():
    """Return {profile_key: number_of_ONUs_using_it}.

    Matching is by profile name (the ONU caches store e.g. "SOLT-51M-DOWN"),
    which is reliable across OLTs even when the on-device traffic-table index
    differs from our file index. One ONU is counted once per profile even if it
    uses the same profile on several service-ports.
    """
    from collections import defaultdict
    from .models import ConfiguredONU

    usage = defaultdict(set)
    for onu_id, dl_name, ul_name in ConfiguredONU.objects.values_list(
        "id", "download_profile_name_cache", "upload_profile_name_cache"
    ):
        bases = set()
        for cache in (dl_name, ul_name):
            for raw in str(cache or "").split(","):
                token = raw.strip().upper()
                if not token:
                    continue
                base = re.sub(r"(?i)[-_](UP|DOWN)$", "", token).strip()
                if base:
                    bases.add(base)
        for base in bases:
            usage[base].add(onu_id)
    return {key: len(ids) for key, ids in usage.items()}


def create_speed_profile_in_file(name_input, *, want_download=True, want_upload=True):
    """Create a new SOLT speed profile and append it to Speed_Profiles.txt.

    ``name_input`` is the speed magnitude the user typed — e.g. "3M", "55M" (the
    trailing M is optional). The stored profile follows the existing pattern
    ``SOLT-<n>M-DOWN`` / ``SOLT-<n>M-UP``. Everything else is auto-derived:

        cir = pir = round(n * 1024)                         (kbps)
        cbs = pbs = min(round(n * 33434.6), 10240000)       (bytes, capped)

    DOWN takes the next free even index, UP the next free odd index. If a profile
    with the same name already exists, it returns an error instead of creating it.
    """
    from .models import SpeedProfile

    result = {"ok": False, "message": "", "created": []}

    raw = str(name_input or "").strip().upper().replace("MBPS", "M")
    num_match = re.search(r"(\d+(?:\.\d+)?)", raw)
    if not num_match:
        result["message"] = "Enter a speed like 3M, 5M or 55M."
        return result
    speed_value = float(num_match.group(1))
    if speed_value <= 0:
        result["message"] = "Speed must be greater than 0."
        return result
    if not want_download and not want_upload:
        result["message"] = "Select Download and/or Upload."
        return result

    speed_token = str(int(speed_value)) if speed_value == int(speed_value) else ("%g" % speed_value)
    base_name = f"SOLT-{speed_token}M"
    key = base_name.upper()

    if SpeedProfile.objects.filter(key=key, is_active=True).exists():
        result["message"] = f"{base_name} already exists."
        return result

    profile_path = settings.BASE_DIR / "Speed_Profiles.txt"
    existing_text = ""
    used_indices = set()
    used_names = set()
    if profile_path.exists():
        existing_text = profile_path.read_text(encoding="utf-8", errors="ignore")
        for m in re.finditer(r'traffic\s+table\s+ip\s+index\s+(\d+)\s+name\s+"([^"]+)"', existing_text, flags=re.IGNORECASE):
            used_indices.add(int(m.group(1)))
            used_names.add(m.group(2).strip().upper())

    if f"{key}-DOWN" in used_names or f"{key}-UP" in used_names:
        result["message"] = f"{base_name} already exists."
        return result

    cir = int(round(speed_value * 1024))
    cbs = min(int(round(speed_value * SPEED_PROFILE_CBS_PER_MBPS)), SPEED_PROFILE_BURST_MAX)

    def _next_free(start):
        n = start
        while n in used_indices:
            n += 2
        return n

    def _build_line(index_value, full_name):
        return (
            f'traffic table ip index {index_value} name "{full_name}" '
            f'cir {cir} cbs {cbs} pir {cir} pbs {cbs} '
            f'color-mode color-blind priority 0 priority-policy local-setting'
        )

    lines_to_add = []
    created = []
    down_index = None
    if want_download:
        down_index = _next_free(200)  # next free even
        used_indices.add(down_index)
        lines_to_add.append(_build_line(down_index, f"{base_name}-DOWN"))
        created.append(f"{base_name}-DOWN")
    if want_upload:
        if down_index is not None and (down_index + 1) not in used_indices:
            up_index = down_index + 1
        else:
            up_index = _next_free(201)  # next free odd
        used_indices.add(up_index)
        lines_to_add.append(_build_line(up_index, f"{base_name}-UP"))
        created.append(f"{base_name}-UP")

    block = "\n".join(lines_to_add)
    new_text = existing_text.rstrip("\n")
    if CUSTOM_PROFILE_MARKER in existing_text:
        # Custom section already started — just append below it.
        new_text = f"{new_text}\n\n{block}\n"
    elif new_text:
        # First user-created profile — start the custom section with the marker.
        new_text = f"{new_text}\n\n{CUSTOM_PROFILE_MARKER}\n\n{block}\n"
    else:
        new_text = f"{CUSTOM_PROFILE_MARKER}\n\n{block}\n"
    profile_path.write_text(new_text, encoding="utf-8")

    # Refresh the DB from the file so the profile is immediately usable.
    sync_speed_profiles_from_file()

    result.update({
        "ok": True,
        "message": f"Created {', '.join(created)} ({cir} kbps).",
        "created": created,
        "cir": cir,
        "cbs": cbs,
    })
    return result


def delete_speed_profile_from_file(key):
    """Delete a user-created speed profile (both DOWN and UP lines) from the file.

    Built-in/default profiles cannot be deleted — only those marked is_custom.
    """
    from .models import SpeedProfile

    result = {"ok": False, "message": ""}
    key = str(key or "").strip().upper()
    if not key:
        result["message"] = "Profile key missing."
        return result

    profile = SpeedProfile.objects.filter(key=key).first()
    if not profile:
        result["message"] = "Profile not found."
        return result
    if not profile.is_custom:
        result["message"] = "Default profiles cannot be deleted."
        return result

    in_use = speed_profile_onu_usage_counts().get(key, 0)
    if in_use:
        result["message"] = (
            f"This profile is used by {in_use} ONU(s). "
            f"Remove it from those ONUs first, then delete the speed profile."
        )
        return result

    profile_path = settings.BASE_DIR / "Speed_Profiles.txt"
    if not profile_path.exists():
        result["message"] = "Speed profile file not found."
        return result

    target_names = {f"{key}-DOWN", f"{key}-UP", key}
    kept = []
    removed = 0
    for raw_line in profile_path.read_text(encoding="utf-8", errors="ignore").splitlines():
        match = re.search(r'traffic\s+table\s+ip\s+index\s+\d+\s+name\s+"([^"]+)"', raw_line, flags=re.IGNORECASE)
        if match and match.group(1).strip().upper() in target_names:
            removed += 1
            continue
        kept.append(raw_line)

    if not removed:
        result["message"] = f"{key} not found in the profile file."
        return result

    # Drop the custom marker if no custom profiles remain below it.
    text_after_marker = ""
    joined = "\n".join(kept)
    if CUSTOM_PROFILE_MARKER in joined:
        text_after_marker = joined.split(CUSTOM_PROFILE_MARKER, 1)[1]
        if not re.search(r'traffic\s+table\s+ip\s+index', text_after_marker, flags=re.IGNORECASE):
            joined = joined.split(CUSTOM_PROFILE_MARKER, 1)[0]

    # Collapse runs of blank lines so removed rows do not leave large gaps.
    cleaned = re.sub(r"\n{3,}", "\n\n", joined).rstrip("\n") + "\n"
    profile_path.write_text(cleaned, encoding="utf-8")

    sync_speed_profiles_from_file()
    # Remove the now-inactive row so the key is fully freed.
    SpeedProfile.objects.filter(key=key).delete()

    result.update({"ok": True, "message": f"Deleted {key}."})
    return result


def load_speed_profile_templates():
    from .models import SpeedProfile

    sync_speed_profiles_from_file()
    rows = []
    for profile in SpeedProfile.objects.filter(is_active=True).order_by("index_number", "name"):
        rows.append(
            {
                "key": profile.key,
                "index_number": profile.index_number,
                "name": profile.name,
                "speed_mbps_value": float(profile.speed_mbps_value or 0),
                "speed_display": profile.speed_display,
                "download_name": profile.download_name,
                "upload_name": profile.upload_name,
                "download_command": profile.download_command,
                "upload_command": profile.upload_command,
            }
        )
    return rows


def _inject_traffic_table_index(command_text, index_value):
    return re.sub(
        r"(?i)\btraffic\s+table\s+ip\s+index\s+name\b",
        f"traffic table ip index {int(index_value)} name",
        str(command_text or "").strip(),
        count=1,
    )


def _cap_traffic_table_burst_values(command_text, max_value=10240000):
    def _cap_match(match):
        keyword = match.group(1)
        try:
            value = int(match.group(2))
        except (TypeError, ValueError):
            return match.group(0)
        return f"{keyword} {min(value, int(max_value))}"

    return re.sub(
        r"(?i)\b(cbs|pbs)\s+(\d+)\b",
        _cap_match,
        str(command_text or "").strip(),
    )


def _parse_used_traffic_table_indices(output_text):
    used = set()
    for line in _compact_traffic_profile_output(output_text):
        match = re.search(r'(?i)\btraffic\s+table\s+ip\s+index\s+(\d+)\s+name\s+"([^"]+)"', line)
        if not match:
            continue
        used.add(int(match.group(1)))
    return used


def _parse_used_traffic_table_names(output_text):
    used = set()
    for line in _compact_traffic_profile_output(output_text):
        match = re.search(r'(?i)\btraffic\s+table\s+ip\s+index\s+\d+\s+name\s+"([^"]+)"', line)
        if match:
            used.add(match.group(1).strip().upper())
    return used


def _next_available_traffic_table_indices(used_indices, count=1, min_index=0, max_index=255):
    picked = []
    used = set(int(value) for value in (used_indices or set()))
    for candidate in range(int(min_index), int(max_index) + 1):
        if candidate in used:
            continue
        picked.append(candidate)
        used.add(candidate)
        if len(picked) >= int(count):
            return picked
    return []


def _load_selected_speed_profile_templates(download_profile_index, upload_profile_index):
    from .models import SpeedProfile

    def _extract_traffic_table_index(command_text):
        match = re.search(r'(?i)\btraffic\s+table\s+ip\s+index\s+(\d+)\b', str(command_text or "").strip())
        return int(match.group(1)) if match else None

    def _extract_traffic_table_name(command_text):
        match = re.search(r'(?i)\btraffic\s+table\s+ip\s+index\s+\d+\s+name\s+"([^"]+)"', str(command_text or "").strip())
        return str(match.group(1)).strip() if match else ""

    def _resolve_selected_index(selected_index_text):
        if not selected_index_text:
            return None
        try:
            selected_index_value = int(selected_index_text)
        except (TypeError, ValueError):
            return None

        for profile in SpeedProfile.objects.filter(is_active=True):
            candidates = [
                (
                    str(profile.download_command or "").strip(),
                    str(profile.download_name or "").strip(),
                    str(profile.name or "").strip(),
                ),
                (
                    str(profile.upload_command or "").strip(),
                    str(profile.upload_name or "").strip(),
                    str(profile.name or "").strip(),
                ),
            ]
            for command_text, explicit_name, fallback_name in candidates:
                if not command_text:
                    continue
                command_index = _extract_traffic_table_index(command_text)
                if command_index != selected_index_value:
                    continue
                resolved_name = explicit_name or _extract_traffic_table_name(command_text) or fallback_name
                return {
                    "index": int(selected_index_value),
                    "name": str(resolved_name).strip(),
                    "command": command_text,
                }
        return None

    selected_download = str(download_profile_index or "").strip()
    selected_upload = str(upload_profile_index or "").strip()
    return {
        "download": _resolve_selected_index(selected_download),
        "upload": _resolve_selected_index(selected_upload),
    }


def _ensure_selected_traffic_tables(
    tn,
    *,
    download_profile_index,
    upload_profile_index,
    transcript,
    verify_only=False,
):
    result = {"ok": False, "message": "Traffic table verify failed."}
    selected = _load_selected_speed_profile_templates(download_profile_index, upload_profile_index)
    missing = []
    if not selected.get("download") or not selected["download"].get("command"):
        missing.append(f"download index {download_profile_index}")
    if not selected.get("upload") or not selected["upload"].get("command"):
        missing.append(f"upload index {upload_profile_index}")
    if missing:
        result["message"] = f"Selected speed profile config missing in DB for {', '.join(missing)}."
        return result

    effective_indices = {}
    config_ready = False

    for direction in ("download", "upload"):
        item = selected[direction]
        if not item:
            continue
        template_index = int(item["index"])
        expected_name = str(item.get("name") or "").strip()
        expected_command = _cap_traffic_table_burst_values(str(item.get("command") or "").strip())

        # 1. Resolve the ACTUAL on-device index by NAME. The OLT may already have
        #    this traffic table at a different index than the template's — in that
        #    case the service-port MUST reference the real index, not the template
        #    one, otherwise it fails with "The traffic table does not exist".
        name_command = f"display traffic table ip name {expected_name}"
        name_output = _run_telnet_bulk_command(tn, name_command, max_wait_seconds=14)
        _append_authorize_transcript(transcript, name_command, name_output)
        found_index = _traffic_table_index_from_name_output(name_output)
        if found_index is not None and expected_name.upper() in str(name_output or "").upper():
            effective_indices[direction] = int(found_index)
            continue

        if verify_only:
            effective_indices[direction] = template_index
            continue

        # 2. Not present on the device — create it.
        if not config_ready:
            entered_config, config_output = _enter_global_config_mode(tn, transcript)
            if not entered_config:
                result["message"] = "Unable to enter configuration mode."
                return result
            config_ready = True

        time.sleep(0.2)
        create_output = _run_telnet_authorize_command(
            tn,
            expected_command,
            enter_until_prompt=True,
            busy_retries=10,
            max_wait_seconds=8,
            step_timeout=0.3,
            max_loops=60,
        )
        _append_authorize_transcript(transcript, expected_command, create_output)
        if _authorize_cli_has_failure(create_output) and not _authorize_cli_is_existing(create_output):
            result["message"] = (
                _clean_cli_response_text(expected_command, create_output)
                or f"Traffic table {expected_name} create failed."
            )
            return result

        # 3. Re-query by name to capture the REAL index the OLT assigned.
        verify_output = _run_telnet_bulk_command(tn, name_command, max_wait_seconds=14)
        _append_authorize_transcript(transcript, f"{name_command} (verify)", verify_output)
        verified_index = _traffic_table_index_from_name_output(verify_output)
        if verified_index is None or expected_name.upper() not in str(verify_output or "").upper():
            result["message"] = f"Traffic table {expected_name} not verified after create."
            return result
        effective_indices[direction] = int(verified_index)

    result["ok"] = True
    result["message"] = "Selected traffic tables ready." if not verify_only else "Selected traffic tables precheck passed."
    result["download_effective_index"] = int(effective_indices.get("download") or int(selected["download"]["index"]))
    result["upload_effective_index"] = int(effective_indices.get("upload") or int(selected["upload"]["index"]))
    result["download_profile_name"] = str(selected["download"].get("name") or result["download_effective_index"]).strip()
    result["upload_profile_name"] = str(selected["upload"].get("name") or result["upload_effective_index"]).strip()
    result["config_ready"] = bool(config_ready)
    return result


def _traffic_table_index_from_name_output(output_text):
    # Huawei OLTs label this row either "Traffic Table Index : N" or the short
    # "TD Index : N" (e.g. MA5683T). Accept both so verification does not fail
    # on a table that was actually created.
    match = re.search(
        r"(?im)^\s*(?:Traffic\s+Table\s+Index|TD\s+Index)\s*:\s*(\d+)\s*$",
        str(output_text or ""),
    )
    return int(match.group(1)) if match else None


def _traffic_table_ids_from_listing(output_text):
    ids = set()
    for line in str(output_text or "").splitlines():
        match = re.match(r"^\s*(\d+)\s+(?:off|\d+)\s+", line)
        if match:
            ids.add(int(match.group(1)))
    ids.update(_parse_used_traffic_table_indices(output_text))
    return ids


def _ensure_speed_profile_table_by_name(tn, selected_item, transcript):
    result = {"ok": False, "index": None, "name": "", "message": "Traffic table verify failed."}
    expected_name = str(selected_item.get("name") or "").strip()
    template_command = _cap_traffic_table_burst_values(str(selected_item.get("command") or "").strip())
    if not expected_name or not template_command:
        result["message"] = "Selected traffic profile missing in DB."
        return result

    name_command = f"display traffic table ip name {expected_name}"
    name_output = _run_telnet_bulk_command(tn, name_command, max_wait_seconds=14)
    _append_authorize_transcript(transcript, name_command, name_output)
    found_index = _traffic_table_index_from_name_output(name_output)
    if found_index is not None and expected_name.upper() in str(name_output or "").upper():
        result.update({"ok": True, "index": int(found_index), "name": expected_name, "message": "Traffic table found."})
        return result

    list_command = "display traffic table ip from-index 0 to-index 1023"
    list_output = _run_telnet_bulk_command(tn, list_command, max_wait_seconds=45)
    _append_authorize_transcript(transcript, list_command, list_output)
    used_ids = _traffic_table_ids_from_listing(list_output)
    picked = _next_available_traffic_table_indices(used_ids, count=1, min_index=0, max_index=1023)
    if not picked:
        result["message"] = "No free traffic table index available."
        return result

    new_index = int(picked[0])
    create_command = _inject_traffic_table_index(template_command, new_index)
    if create_command == template_command:
        create_command = re.sub(
            r"(?i)\btraffic\s+table\s+ip\s+index\s+\d+\b",
            f"traffic table ip index {new_index}",
            template_command,
            count=1,
        )
    create_command = _cap_traffic_table_burst_values(create_command)
    entered_config, config_output = _enter_global_config_mode(tn, transcript=transcript)
    if not entered_config:
        result["message"] = "Unable to enter configuration mode."
        return result
    create_output = _run_telnet_authorize_command(tn, create_command, enter_until_prompt=True, busy_retries=10)
    _append_authorize_transcript(transcript, create_command, create_output)
    if _authorize_cli_has_failure(create_output) and not _authorize_cli_is_existing(create_output):
        result["message"] = _clean_cli_response_text(create_command, create_output) or "Traffic table create failed."
        return result

    verify_output = _run_telnet_bulk_command(tn, name_command, max_wait_seconds=14)
    _append_authorize_transcript(transcript, f"{name_command} (verify)", verify_output)
    verified_index = _traffic_table_index_from_name_output(verify_output)
    if verified_index is None or expected_name.upper() not in str(verify_output or "").upper():
        result["message"] = f"Traffic table {expected_name} was not verified after create."
        return result
    result.update({"ok": True, "index": int(verified_index), "name": expected_name, "message": "Traffic table created."})
    return result


def execute_onu_speed_profile_config(
    olt,
    *,
    frame,
    slot,
    port,
    ont_id,
    service_port_id,
    user_vlan,
    download_profile_index,
    upload_profile_index,
    service_vlan="",
    on_progress=None,
):
    from .models import ConfiguredONU, SpeedProfile

    def _progress(step, label):
        if callable(on_progress):
            try:
                on_progress(step, label)
            except Exception:
                pass

    result = {
        "ok": False,
        "message": "Speed profile update failed.",
        "transcript": "",
        "service_port_id": "",
        "download_profile_index": "",
        "upload_profile_index": "",
        "download_profile_name": "",
        "upload_profile_name": "",
    }
    vlan_value = str(user_vlan or "").strip()
    svlan_value = str(service_vlan or "").strip()
    old_service_port_id = str(service_port_id or "").strip()
    if not vlan_value:
        result["message"] = "User VLAN missing."
        return result
    if not old_service_port_id:
        result["message"] = "Service-port ID missing."
        return result

    _progress(0, "Opening OLT session...")
    tn, status = open_telnet_authenticated_session(olt)
    if tn is None:
        result["message"] = status or "Telnet session could not be opened."
        return result

    transcript = []
    try:
        _prepare_telnet_cli_session(tn, use_paging=True)
        _progress(1, "Checking traffic tables...")
        selected_profiles = _load_selected_speed_profile_templates(download_profile_index, upload_profile_index)
        if not selected_profiles.get("download") or not selected_profiles.get("upload"):
            result["message"] = "Selected speed profile config missing in DB."
            return result
        download_result = _ensure_speed_profile_table_by_name(tn, selected_profiles["download"], transcript)
        if not download_result.get("ok"):
            result["message"] = download_result.get("message") or "Download traffic table verify failed."
            return result
        upload_result = _ensure_speed_profile_table_by_name(tn, selected_profiles["upload"], transcript)
        if not upload_result.get("ok"):
            result["message"] = upload_result.get("message") or "Upload traffic table verify failed."
            return result

        if not str(old_service_port_id or "").strip().isdigit():
            result["message"] = "Service-port ID missing."
            return result

        # Read the existing service-port line first so we preserve its exact
        # structure (gpon path / ont / gemport / tag-transform / multi-service /
        # native-vlan etc.) instead of rebuilding it from assumptions. This
        # mirrors the authorize flow and avoids CLI errors when the ONU was
        # provisioned with a different shape.
        _progress(2, "Preparing service-port...")
        existing_line = _read_service_port_line_strict(tn, old_service_port_id, transcript)
        if not existing_line:
            result["message"] = f"Service-port {old_service_port_id} not found."
            return result

        download_index = int(download_result.get("index") or download_profile_index)
        upload_index = int(upload_result.get("index") or upload_profile_index)
        new_service_port_id = int(old_service_port_id)

        entered_config, config_output = _enter_global_config_mode(tn, transcript=transcript)
        if not entered_config:
            result["message"] = "Unable to enter configuration mode."
            return result

        undo_command = f"undo service-port {new_service_port_id}"
        undo_output = _run_telnet_authorize_command(
            tn,
            undo_command,
            enter_until_prompt=True,
            busy_retries=4,
            max_wait_seconds=10,
            step_timeout=0.25,
            max_loops=80,
        )
        _append_authorize_transcript(transcript, undo_command, undo_output)
        lowered_undo = str(undo_output or "").lower()
        if _is_cli_error_text(undo_output) and "does not exist" not in lowered_undo and "not exist" not in lowered_undo:
            result["message"] = _clean_cli_response_text(undo_command, undo_output) or "Old service-port remove failed."
            return result

        entered_config, config_output = _enter_global_config_mode(tn, transcript=transcript)
        if not entered_config:
            result["message"] = "Unable to re-enter configuration mode for new service-port."
            return result

        # Rebuild from the existing line: always swap the speed (traffic-table)
        # indices; only change the outer service VLAN when an SVLAN was chosen.
        _progress(3, "Applying configuration...")
        service_port_command = _rebuild_service_port_line_for_update(
            existing_line,
            new_service_port_id=new_service_port_id,
            svlan=svlan_value,
            user_vlan=vlan_value,
            inbound_index=upload_index,
            outbound_index=download_index,
        )
        if not service_port_command:
            result["message"] = "Unable to rebuild service-port from existing configuration."
            return result

        service_port_output = _run_telnet_authorize_command(
            tn,
            service_port_command,
            enter_until_prompt=True,
            busy_retries=4,
            max_wait_seconds=10,
            step_timeout=0.25,
            max_loops=80,
        )
        _append_authorize_transcript(transcript, service_port_command, service_port_output)
        if _authorize_cli_has_failure(service_port_output):
            result["message"] = _clean_cli_response_text(service_port_command, service_port_output) or "New service-port create failed."
            return result

        verified_line = _verify_service_port_created(
            tn,
            new_service_port_id,
            transcript,
            attempts=4,
            wait_seconds=0.9,
        )
        if not verified_line:
            result["message"] = f"Service-port {new_service_port_id} was not created."
            return result

        # Outer service VLAN that actually landed (chosen SVLAN, or the one we
        # preserved from the original line).
        outer_vlan_match = re.search(
            r"(?i)\bservice-port\s+\d+\s+vlan\s+(\d+)\b",
            verified_line or service_port_command,
        )
        if svlan_value.isdigit():
            service_vlan_value = int(svlan_value)
        elif outer_vlan_match:
            service_vlan_value = int(outer_vlan_match.group(1))
        elif vlan_value.isdigit():
            service_vlan_value = int(vlan_value)
        else:
            service_vlan_value = 0

        # Save is debounced/scheduled (not run inline), so it is not shown as a
        # live step — the config change itself is already done at this point.
        quit_output = _run_telnet_command(tn, "quit", enter_until_prompt=True)
        _append_authorize_transcript(transcript, "quit", quit_output)
        save_output = _schedule_olt_save_from_command(olt, "speed profile change")
        _append_authorize_transcript(transcript, "save", save_output)
        if _authorize_cli_has_failure(save_output):
            result["message"] = _clean_cli_response_text("save", save_output) or "Save failed."
            return result

        download_name = str(download_result.get("name") or "").strip()
        upload_name = str(upload_result.get("name") or "").strip()
        if not download_name or not upload_name:
            for profile in SpeedProfile.objects.filter(is_active=True):
                if int(profile.index_number or 0) == int(download_profile_index):
                    download_name = download_name or str(profile.download_name or profile.name or "").strip()
                if int(profile.index_number or 0) + 1 == int(upload_profile_index):
                    upload_name = upload_name or str(profile.upload_name or profile.name or "").strip()

        record = ConfiguredONU.objects.filter(
            olt=olt,
            frame=int(frame or 0),
            slot=int(slot),
            port=int(port),
            ont_id=int(ont_id),
        ).first()
        if record is not None:
            def _split_positional_cache(value):
                text = str(value or "")
                if not text.strip():
                    return []
                return [item.strip() for item in text.split(",")]

            service_ports = _split_positional_cache(record.service_port_id_cache)
            service_vlans = _split_positional_cache(record.attached_vlans_cache)
            user_vlans = _split_positional_cache(record.user_vlan_cache)
            download_indices = _split_positional_cache(record.download_profile_index_cache)
            upload_indices = _split_positional_cache(record.upload_profile_index_cache)
            download_names = _split_positional_cache(record.download_profile_name_cache)
            upload_names = _split_positional_cache(record.upload_profile_name_cache)
            row_count = max(len(service_ports), len(service_vlans), len(user_vlans), len(download_indices), len(upload_indices), len(download_names), len(upload_names), 1)
            for bucket in (service_ports, service_vlans, user_vlans, download_indices, upload_indices, download_names, upload_names):
                while len(bucket) < row_count:
                    bucket.append("")
            target_index = next((idx for idx, value in enumerate(service_ports) if value == old_service_port_id), 0)
            service_ports[target_index] = str(new_service_port_id)
            service_vlans[target_index] = str(service_vlan_value)
            user_vlans[target_index] = vlan_value
            download_indices[target_index] = str(download_index)
            upload_indices[target_index] = str(upload_index)
            download_names[target_index] = download_name or str(download_index)
            upload_names[target_index] = upload_name or str(upload_index)
            record.service_port_id_cache = ",".join(service_ports)[:255]
            record.attached_vlans_cache = ",".join(service_vlans)[:255]
            record.user_vlan_cache = ",".join(user_vlans)[:255]
            record.download_profile_index_cache = ",".join(download_indices)[:255]
            record.upload_profile_index_cache = ",".join(upload_indices)[:255]
            record.download_profile_name_cache = ",".join(download_names)[:255]
            record.upload_profile_name_cache = ",".join(upload_names)[:255]
            record.save(update_fields=[
                "service_port_id_cache",
                "attached_vlans_cache",
                "user_vlan_cache",
                "download_profile_index_cache",
                "upload_profile_index_cache",
                "download_profile_name_cache",
                "upload_profile_name_cache",
            ])

        result.update(
            {
                "ok": True,
                "message": "Speed profile updated.",
                "service_port_id": str(new_service_port_id),
                "download_profile_index": str(download_index),
                "upload_profile_index": str(upload_index),
                "download_profile_name": download_name or str(download_index),
                "upload_profile_name": upload_name or str(upload_index),
            }
        )
        return result
    except (socket.timeout, TimeoutError):
        result["message"] = "Telnet timeout while updating speed profile."
        return result
    except (EOFError, OSError) as exc:
        result["message"] = f"Telnet error while updating speed profile: {exc}"
        return result
    finally:
        result["transcript"] = "\n\n".join(part for part in transcript if part).strip()[:16000]
        try:
            _run_telnet_command(tn, "quit")
            _run_telnet_command(tn, "quit")
        except Exception:
            pass
        _close_telnet_session(tn)


def execute_onu_add_service_vlan_config(
    olt,
    *,
    frame,
    slot,
    port,
    ont_id,
    vlan_id=None,
    vlan_ids=None,
    download_profile_index,
    upload_profile_index,
    on_progress=None,
):
    from .models import ConfiguredONU, SpeedProfile

    def _progress(step, label):
        if callable(on_progress):
            try:
                on_progress(step, label)
            except Exception:
                pass

    result = {
        "ok": False,
        "message": "VLAN service-port add failed.",
        "transcript": "",
        "service_port_id": "",
        "vlan": str(vlan_id or "").strip(),
    }
    vlan_values = []
    for item in (vlan_ids if vlan_ids is not None else [vlan_id]):
        text = str(item or "").strip()
        if text and text.isdigit() and text not in vlan_values:
            vlan_values.append(text)
    if not vlan_values:
        result["message"] = "Select valid VLANs."
        return result

    _progress(0, "Opening OLT session...")
    tn, status = open_telnet_authenticated_session(olt)
    if tn is None:
        result["message"] = status or "Telnet session could not be opened."
        return result

    transcript = []
    try:
        _prepare_telnet_cli_session(tn, use_paging=True)
        _progress(1, "Checking traffic tables...")
        traffic_result = _ensure_selected_traffic_tables(
            tn,
            download_profile_index=download_profile_index,
            upload_profile_index=upload_profile_index,
            transcript=transcript,
            verify_only=False,
        )
        if not traffic_result.get("ok"):
            result["message"] = traffic_result.get("message") or "Traffic-table verify failed."
            return result

        entered_config, config_output = _enter_global_config_mode(tn, transcript=transcript)
        if not entered_config:
            result["message"] = "Unable to enter configuration mode."
            return result

        download_index = int(traffic_result.get("download_effective_index") or download_profile_index)
        upload_index = int(traffic_result.get("upload_effective_index") or upload_profile_index)
        created_service_ports = []
        _progress(2, "Preparing service-port...")
        total_vlans = len(vlan_values)
        frame_i, slot_i, port_i, ont_i = int(frame or 0), int(slot or 0), int(port or 0), int(ont_id)

        def _verify_sp(idx):
            """Fast verify with a fallback to the thorough scan when inconclusive."""
            quick = _verify_service_port_robust(tn, idx, slot=slot_i, port=port_i, transcript=transcript)
            if quick is True:
                return True
            if quick is False:
                return False
            return bool(_verify_service_port_created(tn, idx, transcript, attempts=3, wait_seconds=0.9))

        MAX_VLAN_ATTEMPTS = 4
        for vlan_position, vlan_value in enumerate(vlan_values, start=1):
            position = f", {vlan_position}/{total_vlans}" if total_vlans > 1 else ""
            _progress(3, f"Applying configuration (VLAN {vlan_value}{position})...")
            vlan_done = False
            last_err = ""
            vlan_created = False
            for attempt in range(1, MAX_VLAN_ATTEMPTS + 1):
                # A fresh free index every attempt — this is what makes index
                # collisions self-correct instead of failing the whole request.
                next_out = _run_telnet_authorize_command(
                    tn, "display service-port next-free-index", enter_until_prompt=True, busy_retries=4
                )
                _append_authorize_transcript(transcript, "display service-port next-free-index", next_out)
                idx = _parse_next_free_service_port_index(next_out) or _fallback_next_free_service_port_index(olt)
                if not idx:
                    last_err = "Could not read a free service-port index."
                    time.sleep(1.0)
                    continue

                entered_config, _cfg = _enter_global_config_mode(tn, transcript=transcript)
                if not entered_config:
                    last_err = "Unable to enter configuration mode."
                    time.sleep(0.5)
                    continue

                service_port_command = (
                    f"service-port {int(idx)} vlan {int(vlan_value)} "
                    f"gpon {frame_i}/{slot_i}/{port_i} ont {ont_i} gemport 1 "
                    f"multi-service user-vlan {int(vlan_value)} tag-transform translate "
                    f"inbound traffic-table index {int(upload_index)} "
                    f"outbound traffic-table index {int(download_index)}"
                )
                sp_out = _run_telnet_authorize_command(
                    tn, service_port_command, enter_until_prompt=True,
                    busy_retries=6, max_wait_seconds=10, step_timeout=0.25, max_loops=80,
                )
                _append_authorize_transcript(transcript, service_port_command, sp_out)
                low = str(sp_out or "").lower()

                # Service-port (or an equivalent) already there — accept if it is ours.
                if _authorize_cli_is_existing(sp_out):
                    if _verify_sp(idx):
                        created_service_ports.append(str(idx))
                        vlan_done = True
                        break
                    last_err = "Service-port index in use; retrying with a new index."
                    time.sleep(0.6)
                    continue

                # The VLAN isn't created on the OLT yet — create it once, then retry.
                if (("vlan" in low and ("does not exist" in low or "not exist" in low))) and not vlan_created:
                    vlan_created = True
                    _enter_global_config_mode(tn, transcript=transcript)
                    vlan_out = _run_telnet_authorize_command(
                        tn, f"vlan {int(vlan_value)} smart", enter_until_prompt=True, busy_retries=4
                    )
                    _append_authorize_transcript(transcript, f"vlan {int(vlan_value)} smart", vlan_out)
                    time.sleep(0.4)
                    continue

                # OLT busy — back off and retry with a fresh index.
                if _cli_system_busy(sp_out):
                    last_err = "OLT is busy; retrying."
                    time.sleep(1.2)
                    continue

                # A real, non-retryable failure — stop and report it clearly.
                if _authorize_cli_has_failure(sp_out):
                    last_err = _clean_cli_response_text(service_port_command, sp_out) or f"Service-port creation failed for VLAN {vlan_value}."
                    break

                # No failure reported — confirm it actually landed.
                if _verify_sp(idx):
                    created_service_ports.append(str(idx))
                    vlan_done = True
                    break
                last_err = f"Service-port {idx} could not be verified."
                time.sleep(0.6)

            if not vlan_done:
                result["message"] = f"VLAN {vlan_value}: {last_err or 'could not be added.'}"
                if created_service_ports:
                    result["message"] += f" ({len(created_service_ports)} of {total_vlans} VLAN(s) were added.)"
                return result

        # Save is debounced/scheduled (not run inline), so it is not shown as a
        # live step — the VLAN service-port(s) are already created at this point.
        quit_output = _run_telnet_command(tn, "quit", enter_until_prompt=True)
        _append_authorize_transcript(transcript, "quit", quit_output)
        save_output = _schedule_olt_save_from_command(olt, "ONU VLAN add")
        _append_authorize_transcript(transcript, "save", save_output)
        if _authorize_cli_has_failure(save_output):
            result["message"] = _clean_cli_response_text("save", save_output) or "Save failed."
            return result

        download_name = str(traffic_result.get("download_profile_name") or "").strip()
        upload_name = str(traffic_result.get("upload_profile_name") or "").strip()
        if not download_name or not upload_name:
            for profile in SpeedProfile.objects.filter(is_active=True):
                if int(profile.index_number or 0) == int(download_profile_index):
                    download_name = download_name or str(profile.download_name or profile.name or "").strip()
                if int(profile.index_number or 0) + 1 == int(upload_profile_index):
                    upload_name = upload_name or str(profile.upload_name or profile.name or "").strip()

        record = ConfiguredONU.objects.filter(
            olt=olt,
            frame=int(frame or 0),
            slot=int(slot),
            port=int(port),
            ont_id=int(ont_id),
        ).first()
        if record is not None:
            def _split_positional_cache(value):
                text = str(value or "")
                if not text.strip():
                    return []
                return [item.strip() for item in text.split(",")]

            service_ports = _split_positional_cache(record.service_port_id_cache)
            service_vlans = _split_positional_cache(record.attached_vlans_cache)
            user_vlans = _split_positional_cache(record.user_vlan_cache)
            download_indices = _split_positional_cache(record.download_profile_index_cache)
            upload_indices = _split_positional_cache(record.upload_profile_index_cache)
            download_names = _split_positional_cache(record.download_profile_name_cache)
            upload_names = _split_positional_cache(record.upload_profile_name_cache)
            row_count = max(
                len(service_ports),
                len(service_vlans),
                len(user_vlans),
                len(download_indices),
                len(upload_indices),
                len(download_names),
                len(upload_names),
                0,
            )
            for bucket in (service_ports, service_vlans, user_vlans, download_indices, upload_indices, download_names, upload_names):
                while len(bucket) < row_count:
                    bucket.append("")
            for service_port_id, vlan_value in zip(created_service_ports, vlan_values):
                service_ports.append(service_port_id)
                service_vlans.append(vlan_value)
                user_vlans.append(vlan_value)
                download_indices.append(str(download_index))
                upload_indices.append(str(upload_index))
                download_names.append(download_name or str(download_index))
                upload_names.append(upload_name or str(upload_index))
            record.service_port_id_cache = ",".join(service_ports)[:255]
            record.attached_vlans_cache = ",".join(service_vlans)[:255]
            record.user_vlan_cache = ",".join(user_vlans)[:255]
            record.download_profile_index_cache = ",".join(download_indices)[:255]
            record.upload_profile_index_cache = ",".join(upload_indices)[:255]
            record.download_profile_name_cache = ",".join(download_names)[:255]
            record.upload_profile_name_cache = ",".join(upload_names)[:255]
            record.attached_vlans_synced_at = timezone.now()
            record.save(update_fields=[
                "service_port_id_cache",
                "attached_vlans_cache",
                "user_vlan_cache",
                "download_profile_index_cache",
                "upload_profile_index_cache",
                "download_profile_name_cache",
                "upload_profile_name_cache",
                "attached_vlans_synced_at",
            ])

        result.update({
            "ok": True,
            "message": f"VLANs {', '.join(vlan_values)} added.",
            "service_port_id": ",".join(created_service_ports),
        })
        return result
    except (socket.timeout, TimeoutError):
        result["message"] = "Telnet timeout while adding VLAN service-port."
        return result
    except (EOFError, OSError) as exc:
        result["message"] = f"Telnet error while adding VLAN service-port: {exc}"
        return result
    finally:
        result["transcript"] = "\n\n".join(part for part in transcript if part).strip()[:16000]
        try:
            _run_telnet_command(tn, "quit")
            _run_telnet_command(tn, "quit")
        except Exception:
            pass
        _close_telnet_session(tn)


def execute_onu_delete_service_port(olt, slot, port, ont_id, service_port_id, *, frame=0):
    """Remove a single service-port from an ONU and verify it is gone.

    ``undo service-port <id>`` on the OLT, confirmed with the fast targeted
    check. Idempotent: a service-port that is already absent counts as success.
    Caller should re-sync the ONU afterwards so the attached-VLAN list updates.
    """
    result = {"ok": False, "message": "Service-port delete failed.", "transcript": ""}
    sp_id = str(service_port_id or "").strip()
    if not sp_id.isdigit():
        result["message"] = "Invalid service-port ID."
        return result

    tn, status = open_telnet_authenticated_session(olt)
    if tn is None:
        result["message"] = status or "Telnet session could not be opened."
        return result

    transcript = []
    try:
        _prepare_telnet_cli_session(tn, use_paging=True)
        entered_config, _cfg = _enter_global_config_mode(tn, transcript=transcript)
        if not entered_config:
            result["message"] = "Unable to enter configuration mode."
            return result

        undo_command = f"undo service-port {int(sp_id)}"
        undo_output = _run_telnet_authorize_command(
            tn, undo_command, enter_until_prompt=True,
            busy_retries=6, max_wait_seconds=10, step_timeout=0.25, max_loops=80,
        )
        _append_authorize_transcript(transcript, undo_command, undo_output)
        lowered = str(undo_output or "").lower()
        already_gone = ("does not exist" in lowered or "not exist" in lowered)
        if _authorize_cli_has_failure(undo_output) and not already_gone:
            result["message"] = _clean_cli_response_text(undo_command, undo_output) or f"Service-port {sp_id} delete failed."
            return result

        # Confirm it is actually gone (fast targeted check, thorough fallback).
        present = _verify_service_port_robust(tn, sp_id, slot=int(slot or 0), port=int(port or 0), transcript=transcript)
        if present is None:
            present = bool(_verify_service_port_created(tn, sp_id, transcript, attempts=2, wait_seconds=0.8))
        if present is True:
            result["message"] = f"Service-port {sp_id} is still present after delete."
            return result

        quit_output = _run_telnet_command(tn, "quit", enter_until_prompt=True)
        _append_authorize_transcript(transcript, "quit", quit_output)
        save_output = _schedule_olt_save_from_command(olt, "service-port delete")
        _append_authorize_transcript(transcript, "save", save_output)

        result["ok"] = True
        result["message"] = f"Service-port {sp_id} deleted."
        return result
    except (socket.timeout, TimeoutError):
        result["message"] = "Telnet timeout while deleting service-port."
        return result
    except (EOFError, OSError) as exc:
        result["message"] = f"Telnet error while deleting service-port: {exc}"
        return result
    finally:
        result["transcript"] = "\n\n".join(part for part in transcript if part).strip()[:16000]
        try:
            _run_telnet_command(tn, "quit")
            _run_telnet_command(tn, "quit")
        except Exception:
            pass
        _close_telnet_session(tn)


def _find_service_port_line(output_text, service_port_id):
    wanted = str(service_port_id or "").strip()
    if not wanted:
        return ""
    for line in _compact_service_port_config_output(output_text):
        if re.search(rf"(?i)\bservice-port\s+{re.escape(wanted)}\b", line):
            return line.strip()
    return ""


def _output_ends_with_prompt(output_text):
    """True if the last non-empty line is a device prompt (e.g. hostname#).

    Used to tell "the command actually finished and the prompt returned" apart
    from "the read was cut short before the OLT replied" — the latter must be
    retried, not treated as a negative result.
    """
    for line in reversed(str(output_text or "").splitlines()):
        stripped = line.strip()
        if not stripped:
            continue
        return bool(PROMPT_LINE_PATTERN.match(stripped))
    return False


def _verify_service_port_created(tn, service_port_id, transcript=None, *, attempts=3, wait_seconds=0.8):
    service_port_text = str(service_port_id or "").strip()
    for attempt in range(1, int(attempts or 1) + 1):
        if attempt > 1:
            time.sleep(float(wait_seconds or 0.5))
        verify_command = f"display current-configuration | include service-port {int(service_port_text)}"
        # `display current-configuration | include` scans the whole running-config
        # and is slow on large OLTs — wait long enough for the hostname prompt to
        # return before deciding the service-port is missing.
        verify_output = _run_telnet_bulk_command(tn, verify_command, max_wait_seconds=60, poll_seconds=0.15)
        if transcript is not None:
            _append_authorize_transcript(transcript, f"{verify_command} (verify {attempt})", verify_output)
        verified_line = _find_service_port_line(verify_output, service_port_text)
        if verified_line:
            return verified_line
        # If the prompt never came back the read was cut short — keep retrying.
        if not _output_ends_with_prompt(verify_output):
            time.sleep(1.0)
    return ""


def _verify_service_port_robust(tn, service_port_id, *, slot, port, transcript=None):
    """Fast service-port verification.

    Uses the targeted ``display service-port <id>`` (one short reply) instead of
    scanning the entire running-config. Returns:
      True  -> the service-port exists,
      False -> it definitely does not exist,
      None  -> inconclusive (caller should fall back to the thorough scan).
    """
    try:
        idx = int(service_port_id)
    except (TypeError, ValueError):
        return None
    command = f"display service-port {idx}"
    output = _run_telnet_bulk_command(tn, command, max_wait_seconds=12, idle_poke=b"\r\n", poll_seconds=0.15)
    if transcript is not None:
        _append_authorize_transcript(transcript, command, output)
    if _cli_system_busy(output):
        return None
    lowered = str(output or "").lower()
    if "does not exist" in lowered or "not exist" in lowered or "the service port is not" in lowered:
        return False
    # A data row whose first column is our index (optionally referencing F/S/P).
    if re.search(rf"(?im)^\s*{idx}\b", str(output or "")):
        return True
    if re.search(rf"(?i)\bservice-port\s+{idx}\b", str(output or "")):
        return True
    return None


def _read_service_port_line_strict(tn, service_port_id, transcript=None):
    command = f"display current-configuration | include service-port {int(service_port_id)}"
    output = ""
    for attempt in range(1, 11):
        # This scans the entire running-config, so it can take many seconds on a
        # large OLT. Wait generously for the hostname prompt to come back before
        # parsing — otherwise a slow reply looks like "service-port not found".
        output = _run_telnet_bulk_command(
            tn,
            command,
            max_wait_seconds=60,
            idle_poke=b"\r\n",
            poll_seconds=0.15,
        )
        if transcript is not None:
            suffix = "" if attempt == 1 else f" (busy retry {attempt})"
            _append_authorize_transcript(transcript, f"{command}{suffix}", output)
        if _cli_system_busy(output):
            time.sleep(2.0)
            try:
                _touch_telnet_session(tn)
                tn.write(b"\r\n")
                time.sleep(0.25)
                tn.read_very_eager()
            except (OSError, EOFError):
                pass
            continue
        found_line = _find_service_port_line(output, service_port_id)
        if found_line:
            return found_line
        # No match. Only trust an empty result once the prompt has returned (the
        # config genuinely has no such service-port). If the prompt is missing the
        # read was cut short on a slow OLT, so wait and try again.
        if _output_ends_with_prompt(output):
            return ""
        time.sleep(1.0)
    return _find_service_port_line(output, service_port_id)


def _rebuild_service_port_line_for_update(
    existing_line,
    *,
    new_service_port_id,
    svlan="",
    user_vlan="",
    inbound_index=None,
    outbound_index=None,
):
    """Rebuild a service-port command from an existing config line.

    Preserves the original structure (gpon path, ont/gemport, tag-transform,
    multi-service, native-vlan, etc.) and only changes what the caller asks for:
      * always re-points the service-port id,
      * swaps inbound/outbound traffic-table indices (speed profiles),
      * replaces the outer service VLAN only when ``svlan`` is given,
      * replaces the user-vlan only when ``user_vlan`` is given and the line
        already carries one (translate mode).
    """
    command = str(existing_line or "").strip()
    if not command:
        return ""
    # Drop any trailing CLI prompt that leaked into the captured line.
    command = re.sub(r"(?i)\s+[A-Z0-9._-]+(?:\([^)]+\))?[#>].*$", "", command).strip()
    command = " ".join(command.split())
    if not re.match(r"(?i)^service-port\s+\d+\b", command):
        return ""

    command = re.sub(
        r"(?i)^service-port\s+\d+\b",
        f"service-port {int(new_service_port_id)}",
        command,
        count=1,
    )

    # Outer service VLAN — first "vlan N" in the line. count=1 keeps it from
    # touching the later "user-vlan N" token.
    svlan_text = str(svlan or "").strip()
    if svlan_text.isdigit():
        command = re.sub(r"(?i)\bvlan\s+\d+\b", f"vlan {int(svlan_text)}", command, count=1)

    user_vlan_text = str(user_vlan or "").strip().lower()
    if user_vlan_text and re.search(r"(?i)\buser-vlan\s+\S+", command):
        user_vlan_value = "untagged" if user_vlan_text == "untagged" else str(int(user_vlan_text))
        command = re.sub(r"(?i)\buser-vlan\s+\S+", f"user-vlan {user_vlan_value}", command, count=1)

    if inbound_index is not None:
        if re.search(r"(?i)\binbound\s+traffic-table\s+index\s+\d+", command):
            command = re.sub(
                r"(?i)\binbound\s+traffic-table\s+index\s+\d+",
                f"inbound traffic-table index {int(inbound_index)}",
                command,
                count=1,
            )
        else:
            command = f"{command} inbound traffic-table index {int(inbound_index)}"

    if outbound_index is not None:
        if re.search(r"(?i)\boutbound\s+traffic-table\s+index\s+\d+", command):
            command = re.sub(
                r"(?i)\boutbound\s+traffic-table\s+index\s+\d+",
                f"outbound traffic-table index {int(outbound_index)}",
                command,
                count=1,
            )
        else:
            command = f"{command} outbound traffic-table index {int(outbound_index)}"

    return " ".join(command.split())


def _authorize_cli_has_failure(text):
    lowered = str(text or "").strip().lower()
    return _is_cli_error_text(lowered) or "failure:" in lowered or "error:" in lowered


def _authorize_cli_is_existing(text):
    lowered = str(text or "").strip().lower()
    return any(
        token in lowered
        for token in (
            "already exist",
            "already exists",
            "exists already",
            "has been configured",
            "is used",
        )
    )


def _authorize_cli_profile_id_conflict(text):
    lowered = str(text or "").strip().lower()
    return any(
        token in lowered
        for token in (
            "profile name does not match the profile id",
            "does not match the profile id",
            "the profile id has been used",
            "profile-id is used",
            "profile id is used",
        )
    )


def _authorize_cli_duplicate_ont_name(text):
    lowered = str(text or "").strip().lower()
    if not lowered:
        return False
    name_hint = any(token in lowered for token in ("name", "description", "desc"))
    duplicate_hint = any(token in lowered for token in ("same", "duplicate", "already exist", "already exists", "has been used", "is used"))
    return name_hint and duplicate_hint


def _parse_created_ont_id_from_add_output(text):
    output = str(text or "")
    patterns = (
        r"(?im)\bont\s*id\b\s*[:=]?\s*(\d+)\b",
        r"(?im)\bontid\b\s*[:=]?\s*(\d+)\b",
        r"(?im)\bthe\s+new\s+ont\s+id\b\s*[:=]?\s*(\d+)\b",
    )
    for pattern in patterns:
        match = re.search(pattern, output)
        if match:
            try:
                return int(match.group(1))
            except (TypeError, ValueError):
                continue
    return None


def _parse_profile_listing_items(output_text):
    items = []
    for raw_line in str(output_text or "").splitlines():
        line = " ".join(raw_line.strip().split())
        if not line:
            continue
        name_match = re.search(r'(?i)\bprofile-name\s+"([^"]+)"', line)
        id_match = re.search(r'(?i)\bprofile-id\s+(\d+)', line)
        if id_match and name_match:
            items.append({"id": int(id_match.group(1)), "name": name_match.group(1).strip()})
            continue
        compact_match = re.match(r"^\s*(\d+)\s+([A-Za-z0-9_.-][A-Za-z0-9_.\-/]*)\b", line)
        if compact_match and "profile" not in line.lower():
            items.append({"id": int(compact_match.group(1)), "name": compact_match.group(2).strip()})
    deduped = []
    seen = set()
    for item in items:
        key = (int(item["id"]), str(item["name"]).strip().upper())
        if key in seen:
            continue
        seen.add(key)
        deduped.append(item)
    return deduped


def _find_profile_id_by_name(items, target_name):
    target = str(target_name or "").strip().upper()
    if not target:
        return None
    for item in items:
        if str(item.get("name") or "").strip().upper() == target:
            return int(item.get("id") or 0)
    return None


def _find_dba_profile_id_by_max(items, target_max):
    try:
        wanted = int(target_max)
    except (TypeError, ValueError):
        return None
    for item in items or []:
        try:
            if int(item.get("max")) == wanted:
                return int(item.get("id") or 0)
        except (TypeError, ValueError):
            continue
    return None


def _next_free_profile_id(items, min_id=1, prefer_after_max=False):
    used = {
        int(item.get("id") or 0)
        for item in (items or [])
        if str(item.get("id") or "").strip().isdigit()
    }
    candidate = max(int(min_id or 1), 1)
    if prefer_after_max and used:
        candidate = max(candidate, max(used) + 1)
    while candidate in used:
        candidate += 1
    return candidate


def _plan_profile_id(items, *, profile_name, min_id=1, prefer_after_max=False):
    existing_id = _find_profile_id_by_name(items, profile_name)
    if existing_id is not None:
        return {"ok": True, "profile_id": int(existing_id), "reused": True}
    return {"ok": True, "profile_id": int(_next_free_profile_id(items, min_id=min_id, prefer_after_max=prefer_after_max)), "reused": False}


def _load_display_profile_items(tn, command, transcript, *, max_wait_seconds=25):
    output = _run_telnet_command(
        tn,
        command,
        enter_until_prompt=True,
        max_wait_seconds=max_wait_seconds,
        step_timeout=0.45,
        max_loops=max(140, int(max_wait_seconds * 8)),
    )
    _append_authorize_transcript(transcript, command, output)
    return _parse_profile_listing_items(output), output


def _load_display_dba_items(tn, command, transcript, *, max_wait_seconds=25):
    output = _run_telnet_command(
        tn,
        command,
        enter_until_prompt=True,
        max_wait_seconds=max_wait_seconds,
        step_timeout=0.45,
        max_loops=max(140, int(max_wait_seconds * 8)),
    )
    _append_authorize_transcript(transcript, command, output)
    return _parse_dba_profile_entries(output), output


def _append_authorize_transcript(transcript, command, output):
    cleaned = _clean_cli_response_text(command, output)
    if cleaned:
        transcript.append(f"# {command}\n{cleaned}")
    else:
        transcript.append(f"# {command}")


def _sanitize_onu_authorize_desc(value):
    text = str(value or "").strip()
    text = text.replace('"', "")
    text = re.sub(r"\s+", "_", text)
    text = re.sub(r"[^A-Za-z0-9@._-]+", "_", text)
    return text[:128]


def _preferred_sn_auth_serial(value):
    tokens = list(_serial_match_tokens(value))
    hex_tokens = [token for token in tokens if re.fullmatch(r"[0-9A-F]{16}", token)]
    if hex_tokens:
        return sorted(hex_tokens)[0]
    text = re.sub(r"[^A-Z0-9]+", "", str(value or "").upper())
    return text[:64]


def _format_epon_mac_auth(value):
    """Format a MAC for the Huawei EPON ``ont add ... mac-auth`` command.

    EPON ONUs register by MAC (e.g. 24BC-F814-CD96), not the 16-char GPON SN.
    Returns the canonical XXXX-XXXX-XXXX form; falls back to the raw value if it
    is not a 12-hex MAC.
    """
    hexs = re.sub(r"[^0-9A-Fa-f]", "", str(value or "")).upper()
    if len(hexs) == 12:
        return f"{hexs[0:4]}-{hexs[4:8]}-{hexs[8:12]}"
    return str(value or "").strip()


def _parse_next_free_service_port_index(output_text):
    text = str(output_text or "")
    match = re.search(r"(?i)next[-\s]*free[-\s]*index[^0-9]*(\d+)", text)
    if match:
        return int(match.group(1))
    for line in text.splitlines():
        line_match = re.search(r"\b(\d+)\b", line)
        if line_match:
            return int(line_match.group(1))
    return None


def _fallback_next_free_service_port_index(olt):
    from .models import ConfiguredONU

    max_value = 0
    for value in ConfiguredONU.objects.filter(olt=olt).exclude(service_port_id_cache="").values_list("service_port_id_cache", flat=True):
        try:
            max_value = max(max_value, int(str(value).strip()))
        except (TypeError, ValueError):
            continue
    return max_value + 1 if max_value else 1


def _next_free_ont_id_for_port(olt, frame, slot, port):
    from .models import ConfiguredONU

    used = set(
        ConfiguredONU.objects.filter(
            olt=olt,
            frame=int(frame or 0),
            slot=int(slot or 0),
            port=int(port or 0),
        ).values_list("ont_id", flat=True)
    )
    for candidate in range(0, 129):
        if candidate not in used:
            return candidate
    return 0


def _build_default_srvprofile_port_command(pots_ports, eth_ports):
    pots_value = str(pots_ports or "0").strip() or "0"
    eth_value = str(_normalize_authorize_eth_ports(eth_ports)).strip()
    return f"ont-port pots {pots_value} eth {eth_value} catv adaptive"


def _normalize_authorize_eth_ports(eth_ports):
    text = str(eth_ports or "").strip()
    if text in {"", "-", "--", "none", "null"}:
        return 1
    match = re.search(r"\d+", text)
    if not match:
        return 1
    try:
        value = int(match.group(0))
    except (TypeError, ValueError):
        return 1
    return value if value > 0 else 1


def _format_solt_onu_type_name(value):
    text = str(value or "").strip()
    if not text:
        return ""
    if text.upper().endswith("_SOLT"):
        return text
    return f"{text}_SOLT"


def _is_xgpon_bandwidth_failure(output_text):
    return "xgpon bandwidth must be the multiply of 256 kbps" in str(output_text or "").lower()


def _ensure_dba_profile(
    tn,
    *,
    profile_name,
    transcript,
    min_id=100,
    candidate_id=None,
    existing_max_id=None,
    max_bandwidth=1048000,
):
    max_bandwidth = int(max_bandwidth or 1048000)
    if candidate_id is None or existing_max_id is None:
        items, _ = _load_display_dba_items(tn, "display dba-profile all", transcript)
        existing_by_name = _find_profile_id_by_name(items, profile_name)
        if existing_by_name is not None:
            return {"ok": True, "profile_id": int(existing_by_name), "reused": True}
        candidate = _next_free_profile_id(items, min_id=min_id)
        fallback_existing_max_id = _find_dba_profile_id_by_max(items, max_bandwidth)
    else:
        candidate = int(candidate_id)
        fallback_existing_max_id = int(existing_max_id) if existing_max_id else None
    max_candidate = candidate + 80
    while candidate <= max_candidate:
        command = (
            f'dba-profile add profile-id {candidate} profile-name "{profile_name}" '
            f"type4 max {max_bandwidth}"
        )
        output = _run_telnet_authorize_command(tn, command, enter_until_prompt=True)
        _append_authorize_transcript(transcript, command, output)
        lowered = str(output or "").lower()
        if _cli_system_busy(output):
            return {"ok": False, "message": "OLT stayed busy while creating DBA profile. Please try again in a few seconds."}
        if "the dba-profile has already existed" in lowered:
            if fallback_existing_max_id is not None:
                return {"ok": True, "profile_id": int(fallback_existing_max_id), "reused": True}
            items, _ = _load_display_dba_items(tn, "display dba-profile all", transcript)
            existing_max_id = _find_dba_profile_id_by_max(items, max_bandwidth)
            if existing_max_id is not None:
                return {"ok": True, "profile_id": int(existing_max_id), "reused": True}
            existing_id = _find_profile_id_by_name(items, profile_name)
            if existing_id is not None:
                return {"ok": True, "profile_id": int(existing_id), "reused": True}
            candidate = _next_free_profile_id(items, min_id=candidate + 1)
            continue
        if _authorize_cli_profile_id_conflict(output):
            candidate += 1
            continue
        if _authorize_cli_has_failure(output):
            return {"ok": False, "message": _clean_cli_response_text(command, output) or "DBA profile creation failed."}
        return {"ok": True, "profile_id": int(candidate), "reused": False}
    return {"ok": False, "message": "No free DBA profile id available."}


def _ensure_srvprofile(
    tn,
    *,
    profile_name,
    generic_mode,
    vlan_id,
    pots_ports,
    eth_ports,
    transcript,
    min_id=5,
    pon_tech="gpon",
):
    pt = str(pon_tech or "gpon").lower().strip()
    items, _ = _load_display_profile_items(tn, f"display ont-srvprofile {pt} all", transcript, max_wait_seconds=60)
    existing_id = _find_profile_id_by_name(items, profile_name)
    if existing_id is not None:
        return {"ok": True, "profile_id": int(existing_id), "reused": True}

    candidate = _next_free_profile_id(items, min_id=min_id, prefer_after_max=True)
    max_candidate = candidate + 120
    while candidate <= max_candidate:
        command = f'ont-srvprofile {pt} profile-id {candidate} profile-name "{profile_name}"'
        output = _run_telnet_authorize_command(tn, command, enter_until_prompt=True)
        _append_authorize_transcript(transcript, command, output)
        if _authorize_cli_profile_id_conflict(output):
            candidate += 1
            continue
        if _authorize_cli_has_failure(output):
            return {"ok": False, "message": _clean_cli_response_text(command, output) or "OLT rejected service profile creation."}

        if generic_mode:
            commands = ["ont-port pots adaptive eth adaptive catv adaptive"]
            for eth_port in range(1, 9):
                commands.append(f"port vlan eth {eth_port} translation {vlan_id} user-vlan {vlan_id}")
        else:
            commands = [
                _build_default_srvprofile_port_command(pots_ports, eth_ports),
                "ring check enable",
            ]

        for subcommand in commands:
            suboutput = _run_telnet_authorize_command(tn, subcommand, enter_until_prompt=True)
            _append_authorize_transcript(transcript, subcommand, suboutput)
            if _authorize_cli_has_failure(suboutput) and not _authorize_cli_is_existing(suboutput):
                return {"ok": False, "message": _clean_cli_response_text(subcommand, suboutput) or "OLT rejected service profile command."}

        commit_output = _run_telnet_authorize_command(tn, "commit", enter_until_prompt=True)
        _append_authorize_transcript(transcript, "commit", commit_output)
        if _authorize_cli_has_failure(commit_output):
            return {"ok": False, "message": _clean_cli_response_text("commit", commit_output) or "Service profile commit failed."}

        quit_output = _run_telnet_authorize_command(tn, "quit", enter_until_prompt=True)
        _append_authorize_transcript(transcript, "quit", quit_output)
        return {"ok": True, "profile_id": int(candidate), "reused": False}

    return {"ok": False, "message": "No free service profile id available."}


def _ensure_lineprofile(
    tn,
    *,
    profile_name,
    generic_mode,
    vlan_id,
    dba_profile_id,
    transcript,
    min_id=4,
    pon_tech="gpon",
):
    pt = str(pon_tech or "gpon").lower().strip()
    is_epon = pt == "epon"

    items, _ = _load_display_profile_items(tn, f"display ont-lineprofile {pt} all", transcript)
    existing_id = _find_profile_id_by_name(items, profile_name)
    if existing_id is not None:
        return {"ok": True, "profile_id": int(existing_id), "reused": True}

    candidate = _next_free_profile_id(items, min_id=min_id)
    max_candidate = candidate + 120
    while candidate <= max_candidate:
        command = f'ont-lineprofile {pt} profile-id {candidate} profile-name "{profile_name}"'
        output = _run_telnet_authorize_command(tn, command, enter_until_prompt=True)
        _append_authorize_transcript(transcript, command, output)
        if _authorize_cli_profile_id_conflict(output):
            candidate += 1
            continue
        if _authorize_cli_has_failure(output):
            return {"ok": False, "message": _clean_cli_response_text(command, output) or "OLT rejected line profile creation."}

        if is_epon:
            # EPON line profile: bind LLID to DBA profile only — no tcont/gem/FEC
            commands = [
                f"llid dba-profile-id {int(dba_profile_id)}",
            ]
        elif generic_mode:
            commands = [
                f"tcont 1 dba-profile-id {int(dba_profile_id)}",
                "gem add 1 eth tcont 1",
                f"gem mapping 1 1 vlan {vlan_id}",
            ]
        else:
            commands = [
                "fec-upstream enable",
                "tr069-management enable",
                "mapping-mode priority",
                f"tcont 1 dba-profile-id {int(dba_profile_id)}",
                f"tcont 2 dba-profile-id {int(dba_profile_id)}",
                f"tcont 3 dba-profile-id {int(dba_profile_id)}",
                "gem add 1 eth tcont 1",
                "gem add 2 eth tcont 2",
                "gem add 3 eth tcont 3",
                "gem mapping 1 1 priority 0",
                "gem mapping 2 1 priority 2",
                "gem mapping 3 1 priority 5",
            ]

        for subcommand in commands:
            suboutput = _run_telnet_authorize_command(tn, subcommand, enter_until_prompt=True)
            _append_authorize_transcript(transcript, subcommand, suboutput)
            if _authorize_cli_has_failure(suboutput) and not _authorize_cli_is_existing(suboutput):
                return {"ok": False, "message": _clean_cli_response_text(subcommand, suboutput) or "OLT rejected line profile command."}

        commit_output = _run_telnet_authorize_command(tn, "commit", enter_until_prompt=True)
        _append_authorize_transcript(transcript, "commit", commit_output)
        if _authorize_cli_has_failure(commit_output):
            return {"ok": False, "message": _clean_cli_response_text("commit", commit_output) or "Line profile commit failed."}

        quit_output = _run_telnet_authorize_command(tn, "quit", enter_until_prompt=True)
        _append_authorize_transcript(transcript, "quit", quit_output)
        return {"ok": True, "profile_id": int(candidate), "reused": False}

    return {"ok": False, "message": "No free line profile id available."}


def _preflight_authorize_plan(
    tn,
    *,
    profile_name_srv,
    profile_name_line,
    download_profile_index,
    upload_profile_index,
    transcript,
    pon_tech="gpon",
):
    result = {"ok": False, "message": "Authorize preflight failed."}
    pt = str(pon_tech or "gpon").lower().strip()

    dba_items, _ = _load_display_dba_items(tn, "display dba-profile all", transcript)
    dba_plan = {"ok": True, "profile_id": int(_next_free_profile_id(dba_items, min_id=100)), "reused": False}

    srv_items, _ = _load_display_profile_items(tn, f"display ont-srvprofile {pt} all", transcript, max_wait_seconds=60)
    srv_plan = _plan_profile_id(srv_items, profile_name=profile_name_srv, min_id=5, prefer_after_max=True)

    line_items, _ = _load_display_profile_items(tn, f"display ont-lineprofile {pt} all", transcript)
    line_plan = _plan_profile_id(line_items, profile_name=profile_name_line, min_id=4)

    traffic_result = _ensure_selected_traffic_tables(
        tn,
        download_profile_index=download_profile_index,
        upload_profile_index=upload_profile_index,
        transcript=transcript,
        verify_only=True,
    )
    if not traffic_result.get("ok"):
        result["message"] = traffic_result.get("message") or "Traffic-table preflight failed."
        return result

    next_service_port_command = "display service-port next-free-index"
    next_service_port_output = _run_telnet_authorize_command(tn, next_service_port_command, enter_until_prompt=True)
    _append_authorize_transcript(transcript, next_service_port_command, next_service_port_output)
    next_service_port_index = _parse_next_free_service_port_index(next_service_port_output)
    if next_service_port_index is None:
        result["message"] = "Unable to read next free service-port index."
        return result

    result.update(
        {
            "ok": True,
            "dba_profile_id": int(dba_plan["profile_id"]),
            "dba_reused": bool(dba_plan.get("reused")),
            "dba_existing_max_id": int(_find_dba_profile_id_by_max(dba_items, 1048000) or 0),
            "service_profile_id": int(srv_plan["profile_id"]),
            "service_profile_reused": bool(srv_plan.get("reused")),
            "line_profile_id": int(line_plan["profile_id"]),
            "line_profile_reused": bool(line_plan.get("reused")),
            "next_service_port_index": int(next_service_port_index),
        }
    )
    return result


def _encode_onu_sn_for_snmp(sn_auth):
    """Convert an ONU SN string to the raw 8-byte sequence expected by hwGponDeviceOntSn.
    Accepts 16-char hex ('48575443ABCD1234') or 12-char ASCII+hex ('HWTCABCD1234').
    Returns bytes on success, None on unrecognised format.
    """
    cleaned = re.sub(r"[^A-F0-9]", "", str(sn_auth or "").upper())
    if len(cleaned) == 16:
        try:
            return bytes.fromhex(cleaned)
        except ValueError:
            pass
    raw = re.sub(r"[^A-Z0-9]", "", str(sn_auth or "").upper())
    if len(raw) == 12 and re.fullmatch(r"[A-Z]{4}[0-9A-F]{8}", raw):
        try:
            return raw[:4].encode("ascii") + bytes.fromhex(raw[4:])
        except (UnicodeEncodeError, ValueError):
            pass
    return None


def _snmp_find_next_ont_id_for_port(olt, if_index, *, frame, slot, port):
    """Return the lowest available ONT ID (0-127) for a port.
    Combines DB-known IDs with a live SNMP walk of hwGponDeviceOntIndex so that
    externally provisioned ONTs are also avoided.
    Returns None when all 128 slots are occupied.
    """
    from .models import ConfiguredONU

    used = set(
        ConfiguredONU.objects.filter(
            olt=olt,
            frame=int(frame or 0),
            slot=int(slot or 0),
            port=int(port or 0),
        ).values_list("ont_id", flat=True)
    )
    try:
        walked = _snmp_walk_rows(olt, f"1.3.6.1.4.1.2011.6.128.1.1.2.43.1.1.{if_index}", limit=256)
        for oid_text in walked.keys():
            try:
                used.add(int(oid_text.split(".")[-1]))
            except (ValueError, IndexError):
                pass
    except Exception:
        pass

    for candidate in range(0, 128):
        if candidate not in used:
            return candidate
    return None


def _add_onu_via_snmp(olt, slot, port, sn_auth, line_profile_name, srv_profile_name, desc, *, frame=0):
    """Register a new ONT via SNMP SET using hwGponDeviceOntConfigInfoTable.
    Sends a single multi-varbind createAndGo SET that atomically creates the ONT row.
    Falls back to SNMPv1 if SNMPv2c is rejected.

    Returns {"ok": True, "ont_id": N, "message": "..."} on success
         or {"ok": False, "message": "..."} on any failure (caller should fall back to CLI).
    """
    result = {"ok": False, "message": "SNMP ONT add failed.", "ont_id": None}

    if not str(getattr(olt, "snmp_write_community", "") or "").strip():
        result["message"] = "SNMP write community not configured."
        return result

    if_index = _resolve_snmp_gpon_ifindex(olt, slot, port, frame=frame)
    if not if_index:
        result["message"] = "SNMP ifIndex lookup failed — port not found in ifTable."
        return result

    next_ont_id = _snmp_find_next_ont_id_for_port(olt, if_index, frame=frame, slot=slot, port=port)
    if next_ont_id is None:
        result["message"] = "No available ONT ID on this port (all 128 slots occupied)."
        return result

    sn_bytes = _encode_onu_sn_for_snmp(sn_auth)
    if sn_bytes is None:
        result["message"] = f"Cannot encode SN '{sn_auth}' for SNMP — unrecognised format."
        return result

    line_name = str(line_profile_name or "").strip()[:64]
    srv_name = str(srv_profile_name or "").strip()[:64]
    desc_clean = str(desc or "").strip()[:64]
    if not line_name or not srv_name:
        result["message"] = "Profile name empty — cannot SNMP-add ONT."
        return result

    pfx = "1.3.6.1.4.1.2011.6.128.1.1.2.43.1"
    sfx = f"{if_index}.{next_ont_id}"
    oid_sets = [
        (f"{pfx}.2.{sfx}", 1, "Integer"),                 # hwGponDeviceOntAuthMethod = SN(1)
        (f"{pfx}.3.{sfx}", sn_bytes, "OctetString"),      # hwGponDeviceOntSn
        (f"{pfx}.6.{sfx}", 1, "Integer"),                 # hwGponDeviceOntManagementMode = OMCI(1)
        (f"{pfx}.7.{sfx}", line_name, "OctetString"),     # hwGponDeviceOntLineProfName
        (f"{pfx}.8.{sfx}", srv_name, "OctetString"),      # hwGponDeviceOntServiceProfName
        (f"{pfx}.9.{sfx}", desc_clean, "OctetString"),    # hwGponDeviceOntDespt
        (f"{pfx}.10.{sfx}", 4, "Integer"),                # hwGponDeviceOntRowStatus = createAndGo(4)
    ]

    last_error = ""
    for mp_model in (1, 0):
        try:
            err_ind, err_stat, _, _ = _snmp_set_multi(olt, oid_sets, mp_model=mp_model)
            if err_ind:
                last_error = str(err_ind)
                continue
            if err_stat:
                last_error = err_stat.prettyPrint()
                continue
            result["ok"] = True
            result["ont_id"] = next_ont_id
            result["message"] = f"ONT registered via SNMP. ONT-ID: {next_ont_id}"
            return result
        except Exception as exc:
            last_error = str(exc)

    result["message"] = f"SNMP ONT createAndGo failed: {last_error or 'no response from OLT'}"
    return result


def authorize_autofind_onu(
    olt,
    *,
    frame,
    slot,
    port,
    sn,
    onu_type_name,
    vlan_ids,
    download_profile_index,
    download_profile_name,
    upload_profile_index,
    upload_profile_name,
    subscriber_name,
    onu_mode,
    onu_type_serial,
    pots_ports,
    eth_ports,
    service_vlan="",
    tag_transform="",
    on_progress=None,
):
    from .models import ConfiguredONU

    def _emit(step, label):
        if callable(on_progress):
            try:
                on_progress(step, label)
            except Exception:
                pass

    result = {
        "ok": False,
        "message": "Authorize failed.",
        "transcript": "",
        "ont_id": None,
        "service_port_ids": [],
        "line_profile_id": None,
        "service_profile_id": None,
        "record_id": None,
    }
    vlan_values = [str(item).strip() for item in (vlan_ids or []) if str(item).strip()]
    if not vlan_values:
        result["message"] = "No VLAN selected."
        return result

    sn_auth = _preferred_sn_auth_serial(sn)
    if not sn_auth:
        result["message"] = "ONU serial is missing."
        return result

    primary_vlan = vlan_values[0]
    service_vlan_value = str(service_vlan or "").strip()
    use_svlan = bool(service_vlan_value)
    service_tag_transform = str(tag_transform or "default").strip().lower()
    if use_svlan and service_tag_transform not in {"default", "translate"}:
        result["message"] = "Invalid tag-transform selected."
        return result
    effective_eth_ports = _normalize_authorize_eth_ports(eth_ports)
    generic_mode = False

    # ── Detect PON technology from OLT card cache (GPON / EPON / XGS-PON) ──
    pon_tech = _slot_pon_tech(olt, slot)          # "GPON" | "EPON" | "XGS-PON" | "XG-PON"
    is_epon = pon_tech.upper() == "EPON"
    pon_tech_cli = "epon" if is_epon else "gpon"  # CLI keyword for profile commands

    if is_epon:
        dba_profile_name = "SOLT_1G_EPON"
        dba_max_bandwidth = 1000000
        line_profile_name = "SOLT_FLEXIBLE_EPON"
    else:
        dba_profile_name = "SOLT_DEFAULT_TCONT_1G"
        dba_max_bandwidth = 1048000
        line_profile_name = "SOLT_GPON"

    srv_profile_name = f"Generic_V{primary_vlan}" if generic_mode else _format_solt_onu_type_name(onu_type_name)
    srv_profile_seed = 5
    line_profile_seed = 4
    subscriber_desc = _sanitize_onu_authorize_desc(subscriber_name)

    _emit(0, "Opening Telnet session...")
    last_retryable_message = ""
    for attempt in range(1, 3):
        transcript = []
        tn, status = open_telnet_authenticated_session(olt)
        if tn is None:
            result["message"] = status or "Telnet session could not be opened."
            return result

        try:
            _emit(0, "Telnet session opened.")
            if attempt > 1:
                _append_authorize_transcript(transcript, f"authorize retry attempt {attempt}", "Reopened the Telnet session after a transient transport failure.")

            _emit(1, "Checking required profiles...")
            _prepare_telnet_cli_session(tn, use_paging=False)
            entered_config, config_output = _enter_config_mode(tn)
            _append_authorize_transcript(transcript, "config", config_output)
            if not entered_config:
                result["message"] = "Unable to enter configuration mode."
                result["transcript"] = "\n\n".join(transcript)[:16000]
                return result

            preflight = _preflight_authorize_plan(
                tn,
                profile_name_srv=srv_profile_name,
                profile_name_line=line_profile_name,
                download_profile_index=download_profile_index,
                upload_profile_index=upload_profile_index,
                transcript=transcript,
                pon_tech=pon_tech_cli,
            )
            if not preflight.get("ok"):
                result["message"] = preflight.get("message") or "Authorize preflight failed."
                result["transcript"] = "\n\n".join(transcript)[:16000]
                return result

            dba_result = _ensure_dba_profile(
                tn,
                profile_name=dba_profile_name,
                transcript=transcript,
                min_id=100,
                candidate_id=preflight.get("dba_profile_id"),
                existing_max_id=preflight.get("dba_existing_max_id"),
                max_bandwidth=dba_max_bandwidth,
            )
            if not dba_result.get("ok"):
                result["message"] = dba_result.get("message") or "DBA profile setup failed."
                result["transcript"] = "\n\n".join(transcript)[:16000]
                return result

            srv_profile_result = _ensure_srvprofile(
                tn,
                profile_name=srv_profile_name,
                generic_mode=generic_mode,
                vlan_id=primary_vlan,
                pots_ports=pots_ports,
                eth_ports=effective_eth_ports,
                transcript=transcript,
                min_id=srv_profile_seed,
                pon_tech=pon_tech_cli,
            )
            if not srv_profile_result.get("ok"):
                result["message"] = srv_profile_result.get("message") or "Service profile creation failed."
                result["transcript"] = "\n\n".join(transcript)[:16000]
                return result

            line_profile_result = _ensure_lineprofile(
                tn,
                profile_name=line_profile_name,
                generic_mode=generic_mode,
                vlan_id=primary_vlan,
                dba_profile_id=int(dba_result["profile_id"]),
                transcript=transcript,
                min_id=line_profile_seed,
                pon_tech=pon_tech_cli,
            )
            if not line_profile_result.get("ok"):
                result["message"] = line_profile_result.get("message") or "Line profile creation failed."
                result["transcript"] = "\n\n".join(transcript)[:16000]
                return result

            _emit(2, "Preparing traffic tables...")
            traffic_result = _ensure_selected_traffic_tables(
                tn,
                download_profile_index=download_profile_index,
                upload_profile_index=upload_profile_index,
                transcript=transcript,
            )
            if not traffic_result.get("ok"):
                result["message"] = traffic_result.get("message") or "Selected speed profile push failed."
                result["transcript"] = "\n\n".join(transcript)[:16000]
                return result
            effective_download_profile_index = int(traffic_result.get("download_effective_index") or int(download_profile_index))
            effective_upload_profile_index = int(traffic_result.get("upload_effective_index") or int(upload_profile_index))

            _emit(3, "Adding and binding the ONU...")
            # ── ONT add: SNMP-first, Telnet CLI fallback ──────────────────────────
            snmp_ont_result = _add_onu_via_snmp(
                olt,
                int(slot or 0),
                int(port or 0),
                sn_auth,
                line_profile_name=line_profile_name,
                srv_profile_name=srv_profile_name,
                desc=subscriber_desc[:64],
                frame=int(frame or 0),
            )

            interface_command = f"interface {pon_tech_cli} {int(frame or 0)}/{int(slot or 0)}"
            authorized_desc = subscriber_desc

            if snmp_ont_result.get("ok"):
                ont_id = snmp_ont_result["ont_id"]
                _append_authorize_transcript(transcript, "ont add (SNMP)", snmp_ont_result["message"])
                # Enter interface context so native-VLAN commands run in the right mode
                interface_output = _run_telnet_authorize_command(tn, interface_command, enter_until_prompt=True)
                _append_authorize_transcript(transcript, interface_command, interface_output)
                if _authorize_cli_has_failure(interface_output):
                    result["message"] = _clean_cli_response_text(interface_command, interface_output) or "Unable to enter GPON interface for native VLAN after SNMP add."
                    result["transcript"] = "\n\n".join(transcript)[:16000]
                    return result
            else:
                # ── CLI fallback ───────────────────────────────────────────────────
                _append_authorize_transcript(
                    transcript,
                    "ont add SNMP failed — CLI fallback",
                    snmp_ont_result.get("message") or "SNMP ONT add unavailable.",
                )
                interface_output = _run_telnet_authorize_command(tn, interface_command, enter_until_prompt=True)
                _append_authorize_transcript(transcript, interface_command, interface_output)
                if _authorize_cli_has_failure(interface_output):
                    result["message"] = _clean_cli_response_text(interface_command, interface_output) or "Unable to enter GPON interface."
                    result["transcript"] = "\n\n".join(transcript)[:16000]
                    return result

                add_output = ""
                add_command = ""
                last_duplicate_name_output = ""
                # EPON registers by MAC and needs an explicit ONT-ID (GPON auto-
                # assigns it from sn-auth). Pick the next free ONT-ID and format
                # the MAC as XXXX-XXXX-XXXX.
                epon_ont_id = _next_free_ont_id_for_port(olt, frame, slot, port) if is_epon else None
                # Use the RAW autofind MAC, not sn_auth: _preferred_sn_auth_serial()
                # is GPON 16-char-SN logic that ASCII-mangles a MAC (E4A8 -> 45344138).
                epon_mac = _format_epon_mac_auth(sn) if is_epon else ""
                for desc_attempt in range(0, 6):
                    candidate_desc = subscriber_desc if desc_attempt == 0 else f"{subscriber_desc}({desc_attempt})"
                    candidate_desc = candidate_desc[:128]
                    if is_epon:
                        add_command = (
                            f'ont add {int(port)} {int(epon_ont_id)} mac-auth {epon_mac} oam '
                            f'ont-lineprofile-id {int(line_profile_result["profile_id"])} '
                            f'ont-srvprofile-id {int(srv_profile_result["profile_id"])} '
                            f'desc "{candidate_desc}"'
                        )
                    else:
                        add_command = (
                            f'ont add {int(port)} sn-auth "{sn_auth}" omci '
                            f'ont-lineprofile-id {int(line_profile_result["profile_id"])} '
                            f'ont-srvprofile-id {int(srv_profile_result["profile_id"])} '
                            f'desc "{candidate_desc}"'
                        )
                    add_output = _run_telnet_authorize_command(tn, add_command, enter_until_prompt=True)
                    _append_authorize_transcript(transcript, add_command, add_output)
                    if not _authorize_cli_has_failure(add_output):
                        authorized_desc = candidate_desc
                        break
                    if _is_xgpon_bandwidth_failure(add_output):
                        _append_authorize_transcript(transcript, "XGPON fallback", "GPON line profile rejected by XGPON bandwidth rule. Switching to SOLT_XGPON line profile.")
                        quit_interface_output = _run_telnet_authorize_command(tn, "quit", enter_until_prompt=True)
                        _append_authorize_transcript(transcript, "quit", quit_interface_output)
                        entered_config, config_output = _enter_global_config_mode(tn, transcript=transcript)
                        if not entered_config:
                            result["message"] = "Unable to enter configuration mode for XGPON fallback."
                            result["transcript"] = "\n\n".join(transcript)[:16000]
                            return result
                        xgpon_dba_result = _ensure_dba_profile(
                            tn,
                            profile_name="SOLT_XGPON_1G",
                            transcript=transcript,
                            min_id=100,
                            max_bandwidth=1024000,
                        )
                        if not xgpon_dba_result.get("ok"):
                            result["message"] = xgpon_dba_result.get("message") or "XGPON DBA profile setup failed."
                            result["transcript"] = "\n\n".join(transcript)[:16000]
                            return result
                        xgpon_line_profile_result = _ensure_lineprofile(
                            tn,
                            profile_name="SOLT_XGPON",
                            generic_mode=generic_mode,
                            vlan_id=primary_vlan,
                            dba_profile_id=int(xgpon_dba_result["profile_id"]),
                            transcript=transcript,
                            min_id=line_profile_seed,
                        )
                        if not xgpon_line_profile_result.get("ok"):
                            result["message"] = xgpon_line_profile_result.get("message") or "XGPON line profile creation failed."
                            result["transcript"] = "\n\n".join(transcript)[:16000]
                            return result
                        interface_output = _run_telnet_authorize_command(tn, interface_command, enter_until_prompt=True)
                        _append_authorize_transcript(transcript, interface_command, interface_output)
                        if _authorize_cli_has_failure(interface_output):
                            result["message"] = _clean_cli_response_text(interface_command, interface_output) or "Unable to re-enter GPON interface for XGPON retry."
                            result["transcript"] = "\n\n".join(transcript)[:16000]
                            return result
                        line_profile_result = xgpon_line_profile_result
                        add_command = (
                            f'ont add {int(port)} sn-auth "{sn_auth}" omci '
                            f'ont-lineprofile-id {int(line_profile_result["profile_id"])} '
                            f'ont-srvprofile-id {int(srv_profile_result["profile_id"])} '
                            f'desc "{candidate_desc}"'
                        )
                        add_output = _run_telnet_authorize_command(tn, add_command, enter_until_prompt=True)
                        _append_authorize_transcript(transcript, add_command, add_output)
                        if not _authorize_cli_has_failure(add_output):
                            authorized_desc = candidate_desc
                            break
                    if _authorize_cli_duplicate_ont_name(add_output):
                        last_duplicate_name_output = add_output
                        continue
                    result["message"] = _clean_cli_response_text(add_command, add_output) or "OLT rejected ONU add command."
                    result["transcript"] = "\n\n".join(transcript)[:16000]
                    return result
                else:
                    result["message"] = _clean_cli_response_text(add_command, last_duplicate_name_output or add_output) or "OLT rejected ONU add command because the ONU name already exists."
                    result["transcript"] = "\n\n".join(transcript)[:16000]
                    return result
                if is_epon:
                    # We supplied the ONT-ID explicitly for EPON; prefer the OLT's
                    # echoed value but fall back to the one we requested.
                    ont_id = _parse_created_ont_id_from_add_output(add_output)
                    if ont_id is None:
                        ont_id = epon_ont_id
                else:
                    ont_id = _parse_created_ont_id_from_add_output(add_output)
                if ont_id is None:
                    result["message"] = "ONT add succeeded but OLT did not return the ONT ID."
                    result["transcript"] = "\n\n".join(transcript)[:16000]
                    return result
            # ── end ONT add block ───────────────────────────────────────────────────

            if str(primary_vlan).lower() != "untagged":
                for eth_port in range(1, int(effective_eth_ports) + 1):
                    native_vlan_command = (
                        f"ont port native-vlan {int(port)} {int(ont_id)} "
                        f"eth {eth_port} vlan {primary_vlan} priority 0"
                    )
                    native_vlan_output = _run_telnet_authorize_command(tn, native_vlan_command, enter_until_prompt=True)
                    _append_authorize_transcript(transcript, native_vlan_command, native_vlan_output)
                    # Native-VLAN errors are non-fatal; service-port binding below is authoritative.

            quit_interface_output = _run_telnet_authorize_command(tn, "quit", enter_until_prompt=True)
            _append_authorize_transcript(transcript, "quit", quit_interface_output)

            next_service_port_command = "display service-port next-free-index"
            next_service_port_output = _run_telnet_authorize_command(tn, next_service_port_command, enter_until_prompt=True)
            _append_authorize_transcript(transcript, next_service_port_command, next_service_port_output)
            next_service_port_index = _parse_next_free_service_port_index(next_service_port_output)
            if next_service_port_index is None:
                next_service_port_index = int(preflight.get("next_service_port_index") or 0) or _fallback_next_free_service_port_index(olt)

            created_service_ports = []
            current_service_port_index = int(next_service_port_index)
            created_service_vlans = []
            created_user_vlans = []
            for vlan_value in vlan_values:
                outer_vlan = service_vlan_value if use_svlan else vlan_value
                user_vlan_token = str(vlan_value).strip()
                service_tag_transform_value = service_tag_transform if use_svlan else ("default" if user_vlan_token.lower() == "untagged" else "translate")
                if is_epon:
                    # EPON service-port: no gemport, uses "epon" + "ont".
                    service_port_command = (
                        f"service-port {current_service_port_index} vlan {outer_vlan} "
                        f"epon {int(frame or 0)}/{int(slot or 0)}/{int(port or 0)} ont {ont_id} "
                        f"multi-service user-vlan {user_vlan_token} tag-transform {service_tag_transform_value} "
                        f"inbound traffic-table index {effective_upload_profile_index} "
                        f"outbound traffic-table index {effective_download_profile_index}"
                    )
                else:
                    service_port_command = (
                        f"service-port {current_service_port_index} vlan {outer_vlan} "
                        f"gpon {int(frame or 0)}/{int(slot or 0)}/{int(port or 0)} ont {ont_id} gemport 1 "
                        f"multi-service user-vlan {user_vlan_token} tag-transform {service_tag_transform_value} "
                        f"inbound traffic-table index {effective_upload_profile_index} "
                        f"outbound traffic-table index {effective_download_profile_index}"
                    )
                service_port_output = _run_telnet_authorize_command(tn, service_port_command, enter_until_prompt=True)
                _append_authorize_transcript(transcript, service_port_command, service_port_output)
                if _authorize_cli_has_failure(service_port_output):
                    result["message"] = _clean_cli_response_text(service_port_command, service_port_output) or "Service-port creation failed."
                    result["transcript"] = "\n\n".join(transcript)[:16000]
                    return result
                created_service_ports.append(str(current_service_port_index))
                created_service_vlans.append(str(outer_vlan))
                created_user_vlans.append(user_vlan_token)
                current_service_port_index += 1

            quit_config_output = _run_telnet_authorize_command(tn, "quit", enter_until_prompt=True)
            _append_authorize_transcript(transcript, "quit", quit_config_output)
            _emit(4, "Saving the configuration...")
            save_output = _schedule_olt_save_from_command(olt, "ONU authorize")
            _append_authorize_transcript(transcript, "save", save_output)
            if _authorize_cli_has_failure(save_output):
                result["message"] = _clean_cli_response_text("save", save_output) or "Save failed."
                result["transcript"] = "\n\n".join(transcript)[:16000]
                return result

            now = timezone.now()
            record, _ = ConfiguredONU.objects.get_or_create(
                olt=olt,
                frame=int(frame or 0),
                slot=int(slot or 0),
                port=int(port or 0),
                ont_id=int(ont_id),
            )
            record.sn = (_format_epon_mac_auth(sn) if is_epon else sn_auth)[:64]
            record.description = str(authorized_desc or subscriber_name or "").strip()[:255]
            record.onu_type_cache = _format_solt_onu_type_name(onu_type_name)[:128]
            record.onu_mode_cache = str(onu_mode or "").strip()[:64]
            record.attached_vlans_cache = ",".join(created_service_vlans or vlan_values)[:255]
            record.attached_vlans_synced_at = now
            record.service_port_id_cache = ",".join(created_service_ports)[:255]
            record.user_vlan_cache = ",".join(created_user_vlans or vlan_values)[:255]
            record.download_profile_index_cache = str(effective_download_profile_index)[:255]
            record.upload_profile_index_cache = str(effective_upload_profile_index)[:255]
            record.download_profile_name_cache = str(download_profile_name or "").strip()[:255]
            record.upload_profile_name_cache = str(upload_profile_name or "").strip()[:255]
            record.ethernet_port_config_cache = json.dumps(
                {
                    str(eth_port): {
                        "mode": "access",
                        "vlan": str(primary_vlan),
                        "status": "enabled",
                        "allowed_vlans": "",
                    }
                    for eth_port in range(1, int(effective_eth_ports) + 1)
                },
                separators=(",", ":"),
            )
            record.status_updated_at = now
            if not record.status_first_seen_at:
                record.status_first_seen_at = now
            # Mark this ONU as authorized through OptiVerse (not imported).
            record.configured_via_app = True

            identity_payload = fetch_authorized_onu_snmp_identity(
                olt,
                int(slot or 0),
                int(port or 0),
                int(ont_id),
                frame=int(frame or 0),
                attempts=4,
                delay_seconds=0.85,
            )
            identity_type = str(identity_payload.get("onu_type") or "").strip()
            identity_distance = str(identity_payload.get("ont_distance_m") or "").strip()
            if identity_type:
                record.onu_type_cache = identity_type[:128]
            if identity_distance:
                record.ont_distance_m = identity_distance[:32]
            _append_authorize_transcript(
                transcript,
                "post-authorize snmp identity",
                (
                    f"Type: {identity_type or '-'}\n"
                    f"Distance: {identity_distance or '-'}\n"
                    f"Type status: {identity_payload.get('type_status') or '-'}\n"
                    f"Distance status: {identity_payload.get('distance_status') or '-'}"
                ),
            )
            record.save()

            result.update(
                {
                    "ok": True,
                    "message": "ONU authorized successfully.",
                    "transcript": "\n\n".join(transcript)[:16000],
                    "ont_id": ont_id,
                    "service_port_ids": created_service_ports,
                    "line_profile_id": int(line_profile_result["profile_id"]),
                    "service_profile_id": int(srv_profile_result["profile_id"]),
                    "record_id": record.id,
                }
            )
            return result
        except (socket.timeout, TimeoutError, EOFError, OSError) as exc:
            last_retryable_message = str(exc or "").strip()
            _append_authorize_transcript(transcript, f"authorize transport error attempt {attempt}", last_retryable_message or exc.__class__.__name__)
            if attempt < 2 and _is_retryable_authorize_exception(exc):
                continue
            if isinstance(exc, (socket.timeout, TimeoutError)):
                result["message"] = "Telnet timeout while authorizing ONU."
            else:
                result["message"] = f"Telnet error while authorizing ONU: {exc}"
            result["transcript"] = "\n\n".join(transcript)[:16000]
            return result
        finally:
            try:
                _close_telnet_session(tn)
            except Exception:
                pass

    if last_retryable_message:
        result["message"] = f"Telnet session became unstable during authorization: {last_retryable_message}"
    return result


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
        mgmt_vlan_id = None
        ip_brief_output = _run_telnet_command(tn, "display ip interface brief", enter_until_prompt=True)
        mgmt_vlan_id = _extract_management_vlan_id_from_ip_brief(ip_brief_output, olt.ip_address)
        for row in rows:
            vlan_id = int(row.get("vlan_id") or 0)
            row["description"] = desc_map.get(vlan_id, row.get("description", "")) or "-"
            row["is_management"] = bool(mgmt_vlan_id and vlan_id == mgmt_vlan_id)
        result["rows"] = rows
        if rows and not desc_map:
            result["status"] = f"VLANs fetched: {len(rows)} | No VLAN descriptions found on OLT"
        else:
            result["status"] = f"VLANs fetched: {len(rows)} | Descriptions mapped: {len(desc_map)}"
        if mgmt_vlan_id:
            result["status"] = f"{result['status']} | Mgmt VLAN: {mgmt_vlan_id}"
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


def _extract_management_vlan_id_from_ip_brief(output, target_ip):
    ip_text = str(target_ip or "").strip()
    if not ip_text:
        return None
    text = str(output or "")
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or ip_text not in line:
            continue
        match = re.match(r"(?i)^vlanif\s*(\d+)\s+", line)
        if match:
            try:
                return int(match.group(1))
            except (TypeError, ValueError):
                return None
        if re.match(r"(?i)^meth\d*\s+", line):
            return None
    return None


def fetch_management_vlan_id(olt):
    tn, status = open_telnet_authenticated_session(olt)
    if tn is None:
        return None
    try:
        _prepare_telnet_cli_session(tn, use_paging=True)
        output = _run_telnet_command(tn, "display ip interface brief", enter_until_prompt=True)
        return _extract_management_vlan_id_from_ip_brief(output, olt.ip_address)
    except (socket.timeout, TimeoutError, EOFError, OSError):
        return None
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


def _read_telnet_capability_dump(tn, command, *, max_wait_seconds=600, heartbeat=None):
    """Stream a very large CLI dump (e.g. ``display ont capability all``) to its end.

    Reads the whole output up to the hostname prompt, handling ``--More--``
    paging by sending space. Designed for 100k+ line output: chunks are appended
    to a list (no O(n^2) re-splitting) and only a short tail is scanned for the
    prompt / paging markers. ``heartbeat(bytes_read)`` is called ~every 5s so a
    long-running read can report progress.
    """
    _touch_telnet_session(tn)
    try:
        tn.read_very_eager()
    except (OSError, EOFError):
        pass
    try:
        tn.write((command + "\r\n").encode("ascii", errors="ignore"))
    except EOFError:
        return ""

    chunks = []
    tail = ""
    start_ts = time.time()
    last_hb = start_ts
    bytes_read = 0
    idle = 0
    prompt_re = re.compile(r"(?m)^[^\r\n]*[>#\]]\s*$")
    more_re = re.compile(r"(?i)-+\s*more\s*-+|--more--|press\s+space|press\s+'?q'?")
    got_payload = False
    while (time.time() - start_ts) < max_wait_seconds:
        try:
            data = tn.read_very_eager().decode("ascii", errors="ignore")
        except EOFError:
            break
        if data:
            idle = 0
            cleaned = ANSI_ESCAPE_PATTERN.sub("", data)
            chunks.append(cleaned)
            bytes_read += len(cleaned)
            got_payload = got_payload or bool(cleaned.strip())
            tail = (tail + cleaned)[-400:]
            if more_re.search(tail):
                try:
                    tn.write(b" ")
                except EOFError:
                    break
                tail = ""
                continue
            if got_payload and prompt_re.search(tail):
                break
        else:
            idle += 1
            if got_payload and prompt_re.search(tail) and idle >= 2:
                break
            if idle >= 40:
                break
            time.sleep(0.2)
        if heartbeat is not None and (time.time() - last_hb) >= 5:
            last_hb = time.time()
            try:
                heartbeat(bytes_read)
            except Exception:
                pass
    return "".join(chunks)


def _parse_ont_capability_port(output, slot, port):
    """Parse a per-port ``display ont capability 0/<slot> <port> all`` dump.

    The port is fixed by the command, so each block's ONT-ID + Equipment ID is
    mapped onto the known (slot, port). Returns {(slot, port, ont_id): equipment_id}.
    """
    result = {}
    cur_ont = None
    ont_re = re.compile(r"(?i)^ONT\s+ID\s*:\s*(\d+)")
    eq_re = re.compile(r"(?i)^Equipment\s+ID\s*:\s*(.+?)\s*$")
    for raw in str(output or "").splitlines():
        line = raw.strip()
        if not line:
            continue
        m = ont_re.match(line)
        if m:
            cur_ont = int(m.group(1))
            continue
        m = eq_re.match(line)
        if m and cur_ont is not None:
            equipment_id = m.group(1).strip()[:128]
            if equipment_id and equipment_id != "-":
                result[(int(slot), int(port), cur_ont)] = equipment_id
            cur_ont = None
    return result


def sync_onu_equipment_ids_for_olt(olt, *, only_missing=False, progress_callback=None, note_callback=None):
    """Fill every ONU's type (Equipment ID) via per-PON-port CLI capability dumps.

    Walks each PON port that has ONUs and runs ``display ont capability 0/<slot>
    <port> all``. Each port's output is small, so the read is fast and reliable —
    unlike one giant ``display ont capability all`` whose 100k+ line output can
    break the telnet session on a large OLT. ONU types fill in progressively and a
    dropped session only affects one port (we reconnect and continue). Covers ALL
    ONUs (online + offline) on GPON / EPON / XGS-PON.
    """
    from django.utils import timezone
    from .models import ConfiguredONU

    records = {
        (int(r.slot), int(r.port), int(r.ont_id)): r
        for r in ConfiguredONU.objects.filter(olt=olt).only("id", "slot", "port", "ont_id", "onu_type_cache", "capability_synced_at")
    }
    if not records:
        return {"checked": 0, "updated": 0, "status": "No ONU records to check."}

    ports = sorted({(slot, port) for (slot, port, _ont) in records.keys()})

    tn, status = open_telnet_authenticated_session(olt)
    if tn is None:
        return {"checked": 0, "updated": 0, "status": status or "Telnet session could not be opened."}

    now = timezone.now()
    updated = []
    parsed_total = 0
    try:
        _prepare_telnet_cli_session(tn, use_paging=True)
        for idx, (slot, port) in enumerate(ports, start=1):
            command = f"display ont capability 0/{int(slot)} {int(port)} all"
            output = ""
            for attempt in (1, 2):
                try:
                    output = _read_telnet_capability_dump(tn, command, max_wait_seconds=120)
                    break
                except (socket.timeout, TimeoutError, EOFError, OSError):
                    # Session dropped — reconnect once and retry this port.
                    _close_telnet_session(tn)
                    tn, _ = open_telnet_authenticated_session(olt)
                    if tn is None:
                        break
                    _prepare_telnet_cli_session(tn, use_paging=True)
            if tn is None:
                break

            port_map = _parse_ont_capability_port(output, slot, port)
            parsed_total += len(port_map)
            batch = []
            for key, equipment_id in port_map.items():
                record = records.get(key)
                if not record:
                    continue
                if equipment_id != (record.onu_type_cache or ""):
                    record.onu_type_cache = equipment_id
                    record.capability_synced_at = now
                    batch.append(record)
                elif not record.capability_synced_at:
                    record.capability_synced_at = now
                    batch.append(record)
            if batch:
                ConfiguredONU.objects.bulk_update(batch, ["onu_type_cache", "capability_synced_at"], batch_size=500)
                updated.extend(batch)
            if note_callback:
                try:
                    note_callback(idx, len(ports), len(updated))
                except Exception:
                    pass

        if progress_callback:
            try:
                progress_callback(len(records), len(updated))
            except Exception:
                pass
        return {
            "checked": len(records),
            "updated": len(updated),
            "status": f"ONU types from CLI (per-port): {parsed_total} parsed across {len(ports)} port(s), {len(updated)} updated.",
        }
    finally:
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
    status_samples = []
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

            if not record.capability_synced_at:
                record.capability_synced_at = now
                bulk.append(record)
        if bulk:
            ConfiguredONU.objects.bulk_update(
                bulk,
                [
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
    runtime_onu_mode = (runtime_snapshot.get("onu_mode") or "").strip()
    if not getattr(record, "configured_via_app", False):
        runtime_onu_mode = "routing"
    mapped_values = {
        "onu_type_cache": (capability_snapshot.get("equipment_id") or runtime_snapshot.get("ont_equipment_id") or "").strip()[:128],
        "onu_mode_cache": runtime_onu_mode[:64],
        "online_duration_cache": (runtime_snapshot.get("online_duration") or "").strip()[:64],
        "last_up_time_cache": (runtime_snapshot.get("last_up_time") or "").strip()[:64],
        "last_down_time_cache": (runtime_snapshot.get("last_down_time") or "").strip()[:64],
        "last_down_cause_cache": (runtime_snapshot.get("last_down_cause") or "").strip()[:128],
        "battery_state_cache": (runtime_snapshot.get("battery_state") or "").strip()[:64],
        "ont_distance_m": (runtime_snapshot.get("ont_distance_m") or "").strip()[:32],
    }

    runtime_cache_fields = {
        "online_duration_cache",
        "last_up_time_cache",
        "last_down_time_cache",
        "last_down_cause_cache",
        "battery_state_cache",
    }
    runtime_has_values = False
    # Never wipe a previously-fetched value with a blank read (these fields are not
    # always present in every firmware's command output).
    protected_blank_fields = {
        "onu_type_cache",
        "onu_mode_cache",
        "ont_distance_m",
    }
    for field_name, value in mapped_values.items():
        if field_name in runtime_cache_fields and not value:
            continue
        if field_name in protected_blank_fields and not value:
            continue
        if field_name in runtime_cache_fields:
            runtime_has_values = True
        if value != (getattr(record, field_name, "") or ""):
            setattr(record, field_name, value)
            changed = True

    if runtime_has_values:
        record.runtime_synced_at = now
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
        record.save(
            update_fields=[
                "onu_type_cache",
                "onu_mode_cache",
                "online_duration_cache",
                "last_up_time_cache",
                "last_down_time_cache",
                "last_down_cause_cache",
                "battery_state_cache",
                "runtime_synced_at",
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
    try:
        _prepare_telnet_cli_session(tn, use_paging=True)
        for record in records:
            checked += 1
            result = _sync_record_detail_fields_via_telnet(tn, record, now=now)
            if result["changed"]:
                updated += 1
            bulk.append(record)

        if bulk:
            ConfiguredONU.objects.bulk_update(
                bulk,
                [
                    "onu_type_cache",
                    "onu_mode_cache",
                    "online_duration_cache",
                    "last_up_time_cache",
                    "last_down_time_cache",
                    "last_down_cause_cache",
                    "battery_state_cache",
                    "runtime_synced_at",
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


def _is_running_config_noise(line):
    """True for telnet/CLI noise that must never be merged into a config line."""
    text = str(line or "").strip()
    if not text:
        return True
    low = text.lower()
    noise_tokens = (
        "<cr>", "press space", "press enter", "--more--", "to break",
        "display current-config", "command:", "building config",
        "please wait", "it will take a long", "ctrl_c", "scroll 512",
    )
    if any(token in low for token in noise_tokens):
        return True
    # Paging lines like "---- More ( Press 'Q' to break ) ----".
    if "more" in low and ("break" in low or "press" in low or re.search(r"-{2,}", text)):
        return True
    if re.match(r"(?i)^[a-z0-9._-]+(?:\([^)]+\))?[#>]\s*$", text):  # bare device prompt
        return True
    if re.match(r"^[-=~]{2,}\s*$", text):  # separator rules
        return True
    if text in ("%", "^"):
        return True
    return False


def fetch_single_ont_running_config(olt, slot, port, ont_id, expected_sn=""):
    result = {
        "ok": False,
        "command": f"display current-configuration ont 0/{int(slot)}/{int(port)} {int(ont_id)}",
        "output": "",
        "message": "",
    }
    is_ma5608t = "ma5608t" in str(getattr(olt, "hardware_version", "") or "").strip().lower()
    # PON tech decides the running-config keyword: EPON service-ports use "epon"
    # (and have NO gemport), GPON/XGS use "gpon ... gemport". A hardcoded "gpon
    # gemport" filter silently returns nothing on EPON, so the config showed empty.
    pon_kw = "epon" if str(_slot_pon_tech(olt, slot) or "").upper() == "EPON" else "gpon"
    primary_command = f"display current-configuration ont 0/{int(slot)}/{int(port)} {int(ont_id)}"
    service_port_command = f"display current-configuration | include {pon_kw} 0/{int(slot)}/{int(port)} ont {int(ont_id)}"
    result["command"] = primary_command

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
        cleaned_text = re.sub(r"(?im)^\s*please\s+wait.*$", "", cleaned_text)
        cleaned_text = re.sub(r"(?im)^\s*building\s+configuration.*$", "", cleaned_text)
        cleaned_text = re.sub(r"(?im)^\s*current\s+configuration.*$", "", cleaned_text)
        cleaned_text = re.sub(r"(?im)^\s*!\s*$", "", cleaned_text)
        cleaned_text = re.sub(r"(?im)-+\s*more\s*\(\s*press\s+'?q'?\s+to\s+break\s*\)\s*-+\s*return", "", cleaned_text)
        cleaned_text = re.sub(r"(?im)-+\s*more\s*-+", "", cleaned_text)
        cleaned_text = "".join(ch for ch in cleaned_text if (ch == "\n" or ch == "\r" or ch == "\t" or 32 <= ord(ch) <= 126))
        cleaned_text = re.sub(r"[ \t]{2,}", " ", cleaned_text)
        lines = []
        for raw_line in cleaned_text.splitlines():
            line = raw_line.rstrip()
            if not line:
                continue
            if _is_running_config_noise(line):
                continue  # never merge telnet/CLI noise into a config line
            if lines and not line.lower().startswith(("interface ", "ont ", "service-port ")):
                lines[-1] = f"{lines[-1]} {line.strip()}".strip()
            else:
                lines.append(line)
        cleaned_text = "\n".join(lines)
        cleaned_text = re.sub(r"\n{3,}", "\n\n", cleaned_text).strip()
        return cleaned_text

    expected_sn_text = str(expected_sn or "").strip().upper()

    # Matches the "<port> <ont_id>" token pair (e.g. "0 11") that scopes a line
    # to THIS ONT — used to keep ont add / ont port / TR069 lines for this ont.
    ont_ref_pattern = re.compile(rf"(?:^|\s){int(port)}\s+{int(ont_id)}(?:\s|$)")

    def _extract_primary_lines(output_text):
        filtered = []
        for raw_line in str(output_text or "").splitlines():
            stripped = raw_line.strip()
            if not stripped:
                continue
            low = stripped.lower()
            if low.startswith(("interface gpon ", "interface epon ", "interface xgpon ")):
                filtered.append(stripped)
                continue
            if _is_running_config_noise(stripped):
                continue
            # Keep every ONT-scoped config line for this ont: ont add,
            # ont port native-vlan / vlan, ont-srvprofile-id, and TR069 lines
            # (ont ipconfig / ont tr069-server-config / ont wan-config ...).
            if (low.startswith("ont ") or low.startswith("ont-srvprofile-id ")) and ont_ref_pattern.search(stripped):
                filtered.append(stripped)
        if expected_sn_text:
            matching_add_lines = [
                line for line in filtered
                if line.lower().startswith("ont add ")
                and expected_sn_text in str(line or "").upper()
            ]
            if matching_add_lines:
                filtered = [
                    line for line in filtered
                    if (not line.lower().startswith("ont add ")) or line in matching_add_lines
                ]
        deduped = []
        for line in filtered:
            if line not in deduped:
                deduped.append(line)
        return deduped

    def _extract_service_port_lines(output_text):
        filtered = []
        current = ""
        for raw_line in str(output_text or "").splitlines():
            stripped = raw_line.strip()
            if not stripped:
                continue
            lowered = stripped.lower()
            if lowered.startswith("service-port "):
                if current:
                    filtered.append(" ".join(current.split()))
                current = stripped
                continue
            if current:
                # Only merge genuine wrapped continuation — drop telnet/CLI noise
                # so it never ends up appended to a service-port line.
                if _is_running_config_noise(stripped):
                    continue
                current = f"{current} {stripped}"
        if current:
            filtered.append(" ".join(current.split()))
        deduped = []
        for line in filtered:
            if not _service_port_line_matches_onu(line, 0, slot, port, ont_id):
                continue
            if line not in deduped:
                deduped.append(line)
        return deduped

    def _is_proper_running_config_output(output_text):
        text = str(output_text or "").strip()
        lowered = text.lower()
        if not text:
            return False
        bad_tokens = (
            "---- more",
            "press 'q' to break",
            "press q to break",
            "{ <cr>",
            "display current-configuration",
            "command:",
            "please wait",
            "building configuration",
        )
        if any(token in lowered for token in bad_tokens):
            return False
        lines = [line.strip() for line in text.splitlines() if line.strip()]
        if not lines:
            return False
        # "ont" (no space) also covers ont-srvprofile-id / ont-lineprofile lines.
        allowed_prefixes = ("interface ", "ont", "service-port ")
        if any(not line.lower().startswith(allowed_prefixes) for line in lines):
            return False
        return any(line.lower().startswith(("ont add ", "ont port ", "service-port ")) for line in lines)

    def _attempt(conservative=False):
        tn, status = open_telnet_authenticated_session(olt)
        if tn is None:
            return None, status or "Telnet session could not be opened."
        try:
            _prepare_telnet_cli_session(tn, use_paging=(conservative and not is_ma5608t))
            primary_wait = 14 if is_ma5608t else (18 if conservative else 22)
            primary_output = _run_telnet_bulk_command(tn, primary_command, max_wait_seconds=primary_wait, idle_poke=b" ", poll_seconds=0.12)
            cleaned_primary_output = _clean_running_config_output(primary_command, primary_output)
            if _telnet_auth_output_detected(cleaned_primary_output):
                raise OSError("Telnet session returned to login prompt.")
            primary_lines = _extract_primary_lines(cleaned_primary_output)
            service_port_lines = _extract_service_port_lines(cleaned_primary_output)

            if not primary_lines:
                safe_commands = (
                    f"display current-configuration | include ont add {int(port)} {int(ont_id)}",
                    f"display current-configuration | include ont-srvprofile-id {int(port)} {int(ont_id)}",
                    f"display current-configuration | include ont port native-vlan {int(port)} {int(ont_id)}",
                    f"display current-configuration | include ont port vlan {int(port)} {int(ont_id)}",
                )
                cleaned_primary_output = ""
                for safe_command in safe_commands:
                    safe_output = _run_telnet_bulk_command(tn, safe_command, max_wait_seconds=6, idle_poke=b" ", poll_seconds=0.12)
                    if _telnet_auth_output_detected(safe_output):
                        raise OSError("Telnet session returned to login prompt.")
                    cleaned_safe_output = _clean_running_config_output(safe_command, safe_output)
                    cleaned_primary_output = f"{cleaned_primary_output}\n{cleaned_safe_output}".strip()
                    for line in _extract_primary_lines(cleaned_safe_output):
                        if line not in primary_lines:
                            primary_lines.append(line)
                    for line in _extract_service_port_lines(cleaned_safe_output):
                        if line not in service_port_lines:
                            service_port_lines.append(line)
            if not primary_lines:
                return "", ""
            service_port_output = _run_telnet_bulk_command(tn, service_port_command, max_wait_seconds=10 if is_ma5608t else 14, poll_seconds=0.12)
            if _telnet_auth_output_detected(service_port_output):
                raise OSError("Telnet session returned to login prompt.")
            for line in _extract_service_port_lines(_clean_running_config_output(service_port_command, service_port_output)):
                if line not in service_port_lines:
                    service_port_lines.append(line)
            final_sections = ["\n".join(primary_lines)]
            if service_port_lines:
                final_sections.append("\n".join(service_port_lines))
            final_output = "\n\n".join(section for section in final_sections if section).strip()
            if not _is_proper_running_config_output(final_output):
                return "", "Running configuration output was incomplete. Retrying..."
            return final_output, ""
        finally:
            try:
                _run_telnet_command(tn, "quit")
                _run_telnet_command(tn, "quit")
            except Exception:
                pass
            _close_telnet_session(tn)

    last_error = ""
    attempt_modes = (False, True, False)
    for index, conservative in enumerate(attempt_modes, start=1):
        try:
            final_output, open_error = _attempt(conservative=conservative)
            if open_error:
                last_error = open_error
                if index < len(attempt_modes):
                    time.sleep(1.5)
                continue
            if final_output:
                result["ok"] = True
                result["output"] = final_output[:16000]
                result["message"] = "Live running configuration fetched."
                return result
        except (socket.timeout, TimeoutError):
            last_error = "Running configuration command timed out."
        except (EOFError, OSError) as exc:
            last_error = f"Running configuration fetch failed: {exc}"
        if index < len(attempt_modes):
            time.sleep(0.5)

    if _telnet_auth_output_detected(last_error):
        result["message"] = "Telnet login failed: username/password invalid."
    else:
        result["message"] = last_error or "No running configuration output returned."
    return result


def _parse_native_vlan_value_for_eth(output_text, port, ont_id, eth_port):
    pattern = re.compile(
        rf"(?i)ont\s+port\s+native-vlan\s+{int(port)}\s+{int(ont_id)}\s+eth\s+{int(eth_port)}\s+vlan\s+(\d+)\b"
    )
    for raw_line in str(output_text or "").splitlines():
        line = " ".join(str(raw_line or "").strip().split())
        if not line:
            continue
        match = pattern.search(line)
        if match:
            return str(match.group(1))
    return ""


def _find_port_config_line_for_eth(output_text, command_prefix, port, ont_id, eth_port):
    pattern = re.compile(
        rf"(?i)^{re.escape(command_prefix)}\s+{int(port)}\s+{int(ont_id)}\s+eth\s+{int(eth_port)}\b.*$"
    )
    for raw_line in str(output_text or "").splitlines():
        line = " ".join(str(raw_line or "").strip().split())
        if not line:
            continue
        if pattern.search(line):
            return line
    return ""


def _parse_all_undo_port_vlan_commands(output_text, port, ont_id, eth_port):
    """Return ALL undo commands for every ont port vlan line on this eth port.
    Needed for trunk cleanup where multiple VLAN lines may exist."""
    transparent_pattern = re.compile(
        rf"(?i)^ont\s+port\s+vlan\s+{int(port)}\s+{int(ont_id)}\s+eth\s+{int(eth_port)}\s+transparent$"
    )
    translation_pattern = re.compile(
        rf"(?i)^ont\s+port\s+vlan\s+{int(port)}\s+{int(ont_id)}\s+eth\s+{int(eth_port)}\s+translation\s+(\d+)\s+(\d+)\s+user-vlan\s+\d+\s+\d+$"
    )
    # Simple two-arg format: ont port vlan {port} {ont_id} eth {eth_port} {vlan_id} {inner_vlan}
    simple_pattern = re.compile(
        rf"(?i)^ont\s+port\s+vlan\s+{int(port)}\s+{int(ont_id)}\s+eth\s+{int(eth_port)}\s+(\d+)\s+(\d+)$"
    )
    undos = []
    seen = set()
    for raw_line in str(output_text or "").splitlines():
        line = " ".join(str(raw_line or "").strip().split())
        if not line or line in seen:
            continue
        seen.add(line)
        if transparent_pattern.search(line):
            undos.append(f"undo ont port vlan {int(port)} {int(ont_id)} eth {int(eth_port)} transparent")
            continue
        m = translation_pattern.search(line)
        if m:
            undos.append(f"undo ont port vlan {int(port)} {int(ont_id)} eth {int(eth_port)} {m.group(1)} {m.group(2)}")
            continue
        m2 = simple_pattern.search(line)
        if m2:
            undos.append(f"undo ont port vlan {int(port)} {int(ont_id)} eth {int(eth_port)} {m2.group(1)} {m2.group(2)}")
    return undos


def _parse_undo_native_vlan_command(output_text, port, ont_id, eth_port):
    pattern = re.compile(
        rf"(?i)^ont\s+port\s+native-vlan\s+{int(port)}\s+{int(ont_id)}\s+eth\s+{int(eth_port)}\s+vlan\s+(\d+)\s+priority\s+(\d+)$"
    )
    for raw_line in str(output_text or "").splitlines():
        line = " ".join(str(raw_line or "").strip().split())
        if not line:
            continue
        match = pattern.search(line)
        if match:
            return f"undo ont port native-vlan {int(port)} {int(ont_id)} eth {int(eth_port)} vlan {match.group(1)} priority {match.group(2)}"
    return ""


def _cli_command_has_hard_failure(output_text):
    lowered = str(output_text or "").lower()
    if _is_cli_error_text(output_text):
        return True
    failure_tokens = (
        "failure:",
        "failed:",
        "operation failed",
        "parameter error",
        "error:",
    )
    return any(token in lowered for token in failure_tokens)


def _normalize_cli_command_spacing(text):
    return re.sub(r"\s+", " ", str(text or "").strip())


def execute_onu_ethernet_port_access_config(olt, slot, port, ont_id, eth_port, vlan_id):
    result = {
        "ok": False,
        "message": "",
        "transcript": "",
        "verified_vlan": str(vlan_id),
    }
    tn, status = open_telnet_authenticated_session(olt)
    if tn is None:
        result["message"] = status
        return result

    transcript = []
    _pon_tech_cli = "epon" if _slot_pon_tech(olt, slot).upper() == "EPON" else "gpon"
    try:
        _prepare_telnet_cli_session(tn, use_paging=False)

        primary_command = f"display current-configuration ont 0/{int(slot)}/{int(port)} {int(ont_id)}"
        primary_before_output = _run_telnet_bulk_command(tn, primary_command, max_wait_seconds=10)
        _append_authorize_transcript(transcript, primary_command, primary_before_output)
        undo_vlan_commands = _parse_all_undo_port_vlan_commands(
            str(primary_before_output or ""),
            port,
            ont_id,
            eth_port,
        )
        existing_access_line = _find_port_config_line_for_eth(
            str(primary_before_output or ""),
            "ont port native-vlan",
            port,
            ont_id,
            eth_port,
        )
        existing_access_vlan = _parse_native_vlan_value_for_eth(str(primary_before_output or ""), port, ont_id, eth_port)
        if existing_access_line and existing_access_vlan == str(vlan_id) and not undo_vlan_commands:
            result["ok"] = True
            result["verified_vlan"] = str(vlan_id)
            result["message"] = "Already in access on same VLAN"
            return result

        config_output = _run_telnet_command(tn, "config")
        _append_authorize_transcript(transcript, "config", config_output)
        if _cli_command_has_hard_failure(config_output):
            result["message"] = _clean_cli_response_text("config", config_output) or "Config mode failed."
            return result

        interface_command = f"interface {_pon_tech_cli} 0/{int(slot)}"
        interface_output = _run_telnet_command(tn, interface_command)
        _append_authorize_transcript(transcript, interface_command, interface_output)
        if _cli_command_has_hard_failure(interface_output):
            result["message"] = _clean_cli_response_text(interface_command, interface_output) or "Interface open failed."
            return result
        for undo_cmd in undo_vlan_commands:
            undo_out = _run_telnet_command(tn, undo_cmd)
            _append_authorize_transcript(transcript, undo_cmd, undo_out)
            if _cli_command_has_hard_failure(undo_out):
                result["message"] = _clean_cli_response_text(undo_cmd, undo_out) or "Port VLAN cleanup failed."
                return result

        native_vlan_command = (
            f"ont port native-vlan {int(port)} {int(ont_id)} "
            f"eth {int(eth_port)} vlan {int(vlan_id)} priority 0"
        )
        native_vlan_output = _run_telnet_command(tn, native_vlan_command)
        _append_authorize_transcript(transcript, native_vlan_command, native_vlan_output)
        native_lower = str(native_vlan_output or "").lower()
        repeated_config = "make configuration repeatedly" in native_lower
        if _cli_command_has_hard_failure(native_vlan_output):
            result["message"] = _clean_cli_response_text(native_vlan_command, native_vlan_output) or "Access VLAN failed."
            return result
        if ("failure" in native_lower or "failed" in native_lower) and not repeated_config:
            result["message"] = _clean_cli_response_text(native_vlan_command, native_vlan_output) or "Access VLAN failed."
            return result

        quit_output = _run_telnet_command(tn, "quit")
        _append_authorize_transcript(transcript, "quit", quit_output)
        save_output = _schedule_olt_save_from_command(olt, "ethernet access mode")
        _append_authorize_transcript(transcript, "save", save_output)
        primary_after_output = _run_telnet_bulk_command(tn, primary_command, max_wait_seconds=10)
        _append_authorize_transcript(transcript, primary_command, primary_after_output)
        access_line = _find_port_config_line_for_eth(
            str(primary_after_output or ""),
            "ont port native-vlan",
            port,
            ont_id,
            eth_port,
        )
        transparent_line = _find_port_config_line_for_eth(
            str(primary_after_output or ""),
            "ont port vlan",
            port,
            ont_id,
            eth_port,
        )
        verified_vlan = _parse_native_vlan_value_for_eth(str(primary_after_output or ""), port, ont_id, eth_port)
        if access_line and verified_vlan == str(vlan_id) and not transparent_line:
            result["verified_vlan"] = verified_vlan
            result["ok"] = True
            result["message"] = (
                f"Access VLAN {int(vlan_id)} already set"
                if repeated_config
                else f"Access VLAN {int(vlan_id)} applied"
            )
            return result

        result["verified_vlan"] = str(vlan_id)
        result["ok"] = True
        result["message"] = (
            f"Access VLAN {int(vlan_id)} already set"
            if repeated_config
            else f"Access VLAN {int(vlan_id)} applied"
        )
        return result
    finally:
        result["transcript"] = "\n\n".join(part for part in transcript if part).strip()
        try:
            _run_telnet_command(tn, "quit")
            _run_telnet_command(tn, "quit")
        except Exception:
            pass
        _close_telnet_session(tn)


def execute_onu_ethernet_port_transparent_config(olt, slot, port, ont_id, eth_port):
    result = {
        "ok": False,
        "message": "",
        "transcript": "",
        "verified_vlan": "1",
    }
    tn, status = open_telnet_authenticated_session(olt)
    if tn is None:
        result["message"] = status
        return result

    transcript = []
    _pon_tech_cli = "epon" if _slot_pon_tech(olt, slot).upper() == "EPON" else "gpon"
    try:
        _prepare_telnet_cli_session(tn, use_paging=False)

        primary_command = f"display current-configuration ont 0/{int(slot)}/{int(port)} {int(ont_id)}"
        primary_output = _run_telnet_bulk_command(tn, primary_command, max_wait_seconds=10)
        _append_authorize_transcript(transcript, primary_command, primary_output)
        undo_vlan_commands = _parse_all_undo_port_vlan_commands(str(primary_output or ""), port, ont_id, eth_port)
        undo_native_vlan_command = _parse_undo_native_vlan_command(str(primary_output or ""), port, ont_id, eth_port)

        config_output = _run_telnet_command(tn, "config")
        _append_authorize_transcript(transcript, "config", config_output)
        if _is_cli_error_text(config_output):
            result["message"] = _clean_cli_response_text("config", config_output) or "Config mode failed."
            return result

        interface_command = f"interface {_pon_tech_cli} 0/{int(slot)}"
        interface_output = _run_telnet_command(tn, interface_command)
        _append_authorize_transcript(transcript, interface_command, interface_output)
        if _cli_command_has_hard_failure(interface_output):
            result["message"] = _clean_cli_response_text(interface_command, interface_output) or "Interface open failed."
            return result

        for undo_cmd in undo_vlan_commands:
            undo_out = _run_telnet_command(tn, undo_cmd)
            _append_authorize_transcript(transcript, undo_cmd, undo_out)
            if _cli_command_has_hard_failure(undo_out):
                result["message"] = _clean_cli_response_text(undo_cmd, undo_out) or "Port VLAN cleanup failed."
                return result

        if undo_native_vlan_command:
            native_vlan_reset_command = (
                f"ont port native-vlan {int(port)} {int(ont_id)} "
                f"eth {int(eth_port)} vlan 1 priority 0"
            )
            undo_native_vlan_output = _run_telnet_command(tn, native_vlan_reset_command)
            _append_authorize_transcript(transcript, native_vlan_reset_command, undo_native_vlan_output)
            if _cli_command_has_hard_failure(undo_native_vlan_output):
                result["message"] = _clean_cli_response_text(native_vlan_reset_command, undo_native_vlan_output) or "Native VLAN reset failed."
                return result

        transparent_command = (
            f"ont port vlan {int(port)} {int(ont_id)} "
            f"eth {int(eth_port)} transparent"
        )
        transparent_output = _run_telnet_command(tn, transparent_command)
        _append_authorize_transcript(transcript, transparent_command, transparent_output)
        native_lower = str(transparent_output or "").lower()
        repeated_config = "make configuration repeatedly" in native_lower
        already_configured = "already configured" in native_lower
        transparent_verify_ok = False
        if _cli_command_has_hard_failure(transparent_output) or (("failure" in native_lower or "failed" in native_lower) and not repeated_config):
            if already_configured:
                transparent_verify_ok = True
            if not transparent_verify_ok:
                result["message"] = _clean_cli_response_text(transparent_command, transparent_output) or "Transparent mode failed."
                return result

        quit_output = _run_telnet_command(tn, "quit")
        _append_authorize_transcript(transcript, "quit", quit_output)
        save_output = _schedule_olt_save_from_command(olt, "ethernet transparent mode")
        _append_authorize_transcript(transcript, "save", save_output)
        result["ok"] = True
        result["message"] = "Transparent mode already set" if (repeated_config or transparent_verify_ok) else "Transparent mode applied"
        return result
    finally:
        result["transcript"] = "\n\n".join(part for part in transcript if part).strip()
        try:
            _run_telnet_command(tn, "quit")
            _run_telnet_command(tn, "quit")
        except Exception:
            pass
        _close_telnet_session(tn)


def execute_onu_ethernet_port_lan_config(olt, slot, port, ont_id, eth_port):
    result = {
        "ok": False,
        "message": "",
        "transcript": "",
    }
    tn, status = open_telnet_authenticated_session(olt)
    if tn is None:
        result["message"] = status
        return result

    transcript = []
    _pon_tech_cli = "epon" if _slot_pon_tech(olt, slot).upper() == "EPON" else "gpon"
    try:
        _prepare_telnet_cli_session(tn, use_paging=False)
        primary_command = f"display current-configuration ont 0/{int(slot)}/{int(port)} {int(ont_id)}"
        primary_output = _run_telnet_bulk_command(tn, primary_command, max_wait_seconds=10)
        _append_authorize_transcript(transcript, primary_command, primary_output)
        undo_vlan_commands = _parse_all_undo_port_vlan_commands(str(primary_output or ""), port, ont_id, eth_port)
        undo_native_vlan_command = _parse_undo_native_vlan_command(str(primary_output or ""), port, ont_id, eth_port)

        config_output = _run_telnet_command(tn, "config")
        _append_authorize_transcript(transcript, "config", config_output)
        if _cli_command_has_hard_failure(config_output):
            result["message"] = _clean_cli_response_text("config", config_output) or "Config mode failed."
            return result

        interface_command = f"interface {_pon_tech_cli} 0/{int(slot)}"
        interface_output = _run_telnet_command(tn, interface_command)
        _append_authorize_transcript(transcript, interface_command, interface_output)
        if _cli_command_has_hard_failure(interface_output):
            result["message"] = _clean_cli_response_text(interface_command, interface_output) or "Interface open failed."
            return result

        for undo_cmd in undo_vlan_commands:
            undo_out = _run_telnet_command(tn, undo_cmd)
            _append_authorize_transcript(transcript, undo_cmd, undo_out)
            if _cli_command_has_hard_failure(undo_out):
                result["message"] = _clean_cli_response_text(undo_cmd, undo_out) or "Port VLAN cleanup failed."
                return result

        native_vlan_reset_command = (
            f"ont port native-vlan {int(port)} {int(ont_id)} "
            f"eth {int(eth_port)} vlan 1 priority 0"
        )
        if undo_native_vlan_command:
            native_vlan_reset_output = _run_telnet_command(tn, native_vlan_reset_command)
            _append_authorize_transcript(transcript, native_vlan_reset_command, native_vlan_reset_output)
            if _cli_command_has_hard_failure(native_vlan_reset_output):
                result["message"] = _clean_cli_response_text(native_vlan_reset_command, native_vlan_reset_output) or "Native VLAN reset failed."
                return result

        quit_output = _run_telnet_command(tn, "quit")
        _append_authorize_transcript(transcript, "quit", quit_output)
        save_output = _schedule_olt_save_from_command(olt, "ethernet LAN mode")
        _append_authorize_transcript(transcript, "save", save_output)
        primary_after_output = _run_telnet_bulk_command(tn, primary_command, max_wait_seconds=10)
        _append_authorize_transcript(transcript, primary_command, primary_after_output)
        remaining_port_vlan = _find_port_config_line_for_eth(
            str(primary_after_output or ""),
            "ont port vlan",
            port,
            ont_id,
            eth_port,
        )
        remaining_native_vlan = _find_port_config_line_for_eth(
            str(primary_after_output or ""),
            "ont port native-vlan",
            port,
            ont_id,
            eth_port,
        )
        remaining_native_vlan_is_non_default = False
        if remaining_native_vlan:
            match = re.search(r"(?i)\bvlan\s+(\d+)\b", str(remaining_native_vlan))
            remaining_native_vlan_is_non_default = bool(match and match.group(1) != "1")
        if remaining_port_vlan or remaining_native_vlan_is_non_default:
            result["message"] = _normalize_cli_command_spacing(native_vlan_reset_command if undo_native_vlan_command else (undo_port_vlan_command or "LAN cleanup failed."))
            return result
        result["ok"] = True
        result["message"] = "LAN mode applied"
        return result
    finally:
        result["transcript"] = "\n\n".join(part for part in transcript if part).strip()
        try:
            _run_telnet_command(tn, "quit")
            _run_telnet_command(tn, "quit")
        except Exception:
            pass
        _close_telnet_session(tn)


def execute_onu_ethernet_port_trunk_config(olt, slot, port, ont_id, eth_port, vlan_ids):
    """Configure ONU eth port in trunk mode (multiple tagged VLANs).

    Steps:
      1. Read current config.
      2. Undo ALL existing ont port vlan lines for this eth port (transparent / any prior trunk VLANs).
      3. Undo existing native-vlan (reset to VLAN 1).
      4. Add each allowed VLAN:  ont port vlan {port} {ont_id} eth {eth_port} {vlan} 0
      5. Schedule save.
    """
    result = {"ok": False, "message": "", "transcript": ""}

    vlan_list = [str(v).strip() for v in (vlan_ids or []) if str(v).strip()]
    if not vlan_list:
        result["message"] = "No VLANs selected for trunk."
        return result

    tn, status = open_telnet_authenticated_session(olt)
    if tn is None:
        result["message"] = status
        return result

    transcript = []
    _pon_tech_cli = "epon" if _slot_pon_tech(olt, slot).upper() == "EPON" else "gpon"
    try:
        _prepare_telnet_cli_session(tn, use_paging=False)
        primary_command = f"display current-configuration ont 0/{int(slot)}/{int(port)} {int(ont_id)}"
        primary_output = _run_telnet_bulk_command(tn, primary_command, max_wait_seconds=10)
        _append_authorize_transcript(transcript, primary_command, primary_output)

        undo_vlan_commands = _parse_all_undo_port_vlan_commands(str(primary_output or ""), port, ont_id, eth_port)
        undo_native_vlan_command = _parse_undo_native_vlan_command(str(primary_output or ""), port, ont_id, eth_port)

        config_output = _run_telnet_command(tn, "config")
        _append_authorize_transcript(transcript, "config", config_output)
        if _cli_command_has_hard_failure(config_output):
            result["message"] = _clean_cli_response_text("config", config_output) or "Config mode failed."
            return result

        interface_command = f"interface {_pon_tech_cli} 0/{int(slot)}"
        interface_output = _run_telnet_command(tn, interface_command)
        _append_authorize_transcript(transcript, interface_command, interface_output)
        if _cli_command_has_hard_failure(interface_output):
            result["message"] = _clean_cli_response_text(interface_command, interface_output) or "Interface open failed."
            return result

        # ── 1. Remove all existing port VLAN entries ──────────────────────────
        for undo_cmd in undo_vlan_commands:
            undo_out = _run_telnet_command(tn, undo_cmd)
            _append_authorize_transcript(transcript, undo_cmd, undo_out)
            if _cli_command_has_hard_failure(undo_out):
                result["message"] = _clean_cli_response_text(undo_cmd, undo_out) or "Port VLAN cleanup failed."
                return result

        # ── 2. Reset native VLAN to 1 (LAN default) ──────────────────────────
        if undo_native_vlan_command:
            reset_cmd = f"ont port native-vlan {int(port)} {int(ont_id)} eth {int(eth_port)} vlan 1 priority 0"
            reset_out = _run_telnet_command(tn, reset_cmd)
            _append_authorize_transcript(transcript, reset_cmd, reset_out)
            if _cli_command_has_hard_failure(reset_out):
                result["message"] = _clean_cli_response_text(reset_cmd, reset_out) or "Native VLAN reset failed."
                return result

        # ── 3. Add each trunk VLAN ────────────────────────────────────────────
        added = []
        for vlan in vlan_list:
            trunk_cmd = f"ont port vlan {int(port)} {int(ont_id)} eth {int(eth_port)} {vlan} 0"
            trunk_out = _run_telnet_command(tn, trunk_cmd)
            _append_authorize_transcript(transcript, trunk_cmd, trunk_out)
            low = str(trunk_out or "").lower()
            repeated = "make configuration repeatedly" in low
            if _cli_command_has_hard_failure(trunk_out) and not repeated:
                result["message"] = _clean_cli_response_text(trunk_cmd, trunk_out) or f"Trunk VLAN {vlan} failed."
                return result
            added.append(vlan)

        quit_output = _run_telnet_command(tn, "quit")
        _append_authorize_transcript(transcript, "quit", quit_output)
        _schedule_olt_save_from_command(olt, "ethernet trunk mode")
        result["ok"] = True
        result["message"] = f"Trunk mode applied — VLANs: {', '.join(added)}"
        return result
    finally:
        result["transcript"] = "\n\n".join(part for part in transcript if part).strip()
        try:
            _run_telnet_command(tn, "quit")
            _run_telnet_command(tn, "quit")
        except Exception:
            pass
        _close_telnet_session(tn)


def execute_onu_catv_operational_state(olt, slot, port, ont_id, enabled, *, catv_port=1, frame=0):
    result = {"ok": False, "message": "", "transcript": ""}
    tn, status = open_telnet_authenticated_session(olt)
    if tn is None:
        result["message"] = status or "Telnet session could not be opened."
        return result

    transcript = []
    try:
        _prepare_telnet_cli_session(tn, use_paging=False)
        config_output = _run_telnet_command(tn, "config")
        _append_authorize_transcript(transcript, "config", config_output)
        if _cli_command_has_hard_failure(config_output):
            result["message"] = _clean_cli_response_text("config", config_output) or "Config mode failed."
            return result

        # Enter the PON interface matching THIS board's technology (EPON / GPON /
        # XGS-PON) — a hardcoded "interface gpon" fails on EPON boards.
        board_tech = _slot_pon_tech(olt, int(slot))
        interface_kinds = _pon_interface_kinds_for_board(board_tech)
        board_kind, interface_output, entered_iface = _enter_interface_context(
            tn, interface_kinds, int(frame or 0), int(slot)
        )
        _append_authorize_transcript(
            transcript,
            f"interface {board_kind or interface_kinds[0]} {int(frame or 0)}/{int(slot)}",
            interface_output,
        )
        if not entered_iface:
            result["message"] = _clean_cli_response_text("interface", interface_output) or f"Unable to enter {board_tech} interface 0/{int(slot)}."
            return result

        state = "on" if enabled else "off"
        command = f"ont port attribute {int(port)} {int(ont_id)} catv {int(catv_port)} operational-state {state}"
        output = _run_telnet_command(tn, command)
        _append_authorize_transcript(transcript, command, output)
        cleaned = _clean_cli_response_text(command, output)
        repeated_warning = "make configuration repeatedly" in cleaned.lower()
        if _cli_command_has_hard_failure(output) and not repeated_warning:
            result["message"] = cleaned or "CATV command failed."
            return result

        quit_output = _run_telnet_command(tn, "quit")
        _append_authorize_transcript(transcript, "quit", quit_output)
        save_output = _schedule_olt_save_from_command(olt, "CATV state change")
        _append_authorize_transcript(transcript, "save", save_output)
        result["ok"] = True
        result["message"] = "CATV Enabled" if enabled else "CATV Disabled"
        return result
    except Exception as exc:
        result["message"] = f"CATV command failed: {exc}"
        return result
    finally:
        result["transcript"] = "\n\n".join(part for part in transcript if part).strip()
        try:
            _run_telnet_command(tn, "quit")
            _run_telnet_command(tn, "quit")
        except Exception:
            pass
        _close_telnet_session(tn)


def _compact_service_port_config_output(output_text):
    merged = []
    current = ""

    def _push_current():
        nonlocal current
        if current:
            cleaned = " ".join(current.split())
            cleaned = re.sub(r"(?i)\s+[A-Z0-9._-]+(?:\([^)]+\))?[#>]\s*$", "", cleaned).strip()
            if cleaned:
                merged.append(cleaned)
            current = ""

    for raw_line in str(output_text or "").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        lowered = line.lower()
        if PROMPT_LINE_PATTERN.match(line):
            _push_current()
            continue
        if lowered.startswith(("command:", "display current-configuration", "it will take a long time", "you can press ctrl_c", "scroll 512")):
            continue
        if lowered.startswith(("failure:", "error:", "return")):
            _push_current()
            continue
        if re.match(r"(?i)^service-port\s+\d+\b", line):
            _push_current()
            current = line
            continue
        if current:
            current = f"{current} {line}"
    _push_current()
    return merged


def _service_port_line_matches_onu(line, frame, slot, port, ont_id):
    """Return True only when a service-port line references this exact ONU."""
    try:
        frame = int(frame or 0)
        slot = int(slot)
        port = int(port)
        ont_id = int(ont_id)
    except (TypeError, ValueError):
        return False
    pattern = re.compile(
        rf"(?i)\b(?:gpon|epon|xgpon)\s+{frame}\s*/\s*{slot}\s*/\s*{port}\s+ont\s+{ont_id}(?!\d)\b"
    )
    return bool(pattern.search(str(line or "")))


def _filter_service_port_config_for_onu(output_text, frame, slot, port, ont_id):
    return "\n".join(
        line for line in _compact_service_port_config_output(output_text)
        if _service_port_line_matches_onu(line, frame, slot, port, ont_id)
    )


def _parse_service_port_details_from_current_config(output_text, profile_name_map=None):
    profile_name_map = profile_name_map or {}
    vlan_ids = []
    service_port_ids = []
    user_vlan_ids = []
    download_profile_names = []
    upload_profile_names = []
    download_profile_indices = []
    upload_profile_indices = []
    for line in _compact_service_port_config_output(output_text):
        lowered = line.lower()
        if "service-port " not in lowered:
            continue
        service_port_match = re.search(r"(?i)\bservice-port\s+(\d+)\b", line)
        if not service_port_match:
            continue
        service_port_id = service_port_match.group(1).strip()
        if not service_port_id or service_port_id in service_port_ids:
            continue
        vlan_match = re.search(r"(?i)\bvlan\s+(\d+)\b", line)
        vlan_id = vlan_match.group(1).strip() if vlan_match else ""
        if vlan_id and vlan_id not in vlan_ids:
            vlan_ids.append(vlan_id)
        user_vlan_match = re.search(r"(?i)\buser-vlan\s+(\d+|untagged)\b", line)
        user_vlan_id = (user_vlan_match.group(1).strip().lower() if user_vlan_match else vlan_id)
        inbound_match = re.search(r"(?i)\binbound\s+traffic-table\s+index\s+(\d+)\b", line)
        outbound_match = re.search(r"(?i)\boutbound\s+traffic-table\s+index\s+(\d+)\b", line)
        inbound_index = inbound_match.group(1).strip() if inbound_match else ""
        outbound_index = outbound_match.group(1).strip() if outbound_match else ""
        # Some service-ports use the rx-cttr / tx-cttr form instead of
        # inbound/outbound traffic-table: rx-cttr = downstream (download),
        # tx-cttr = upstream (upload).
        if not inbound_index:
            tx_match = re.search(r"(?i)\btx-cttr\s+(\d+)\b", line)
            inbound_index = tx_match.group(1).strip() if tx_match else ""
        if not outbound_index:
            rx_match = re.search(r"(?i)\brx-cttr\s+(\d+)\b", line)
            outbound_index = rx_match.group(1).strip() if rx_match else ""
        # Append exactly ONE entry per service-port to every parallel list (empty
        # placeholder when a value is missing) so the lists stay position-aligned
        # — otherwise a service-port without a profile shifts the columns.
        service_port_ids.append(service_port_id)
        user_vlan_ids.append(user_vlan_id)
        upload_profile_indices.append(inbound_index)
        upload_profile_names.append(str(profile_name_map.get(inbound_index) or inbound_index) if inbound_index else "")
        download_profile_indices.append(outbound_index)
        download_profile_names.append(str(profile_name_map.get(outbound_index) or outbound_index) if outbound_index else "")

    return {
        "attached_vlans": ",".join(vlan_ids)[:255],
        "service_port_ids": service_port_ids,
        "user_vlans": user_vlan_ids,
        "download_profile_names": download_profile_names,
        "upload_profile_names": upload_profile_names,
        "download_profile_indices": download_profile_indices,
        "upload_profile_indices": upload_profile_indices,
    }


def _parse_service_port_detail_map_from_current_config(output_text, profile_name_map=None):
    detail_map = {}
    for line in _compact_service_port_config_output(output_text):
        lowered = line.lower()
        if "service-port " not in lowered:
            continue
        match = re.search(
            r"(?i)\b(?:gpon|epon|xgpon)\s+(\d+)\s*/\s*(\d+)\s*/\s*(\d+)\s+ont\s+(\d+)\b",
            line,
        )
        if not match:
            continue
        frame, slot, port, ont_id = [int(part) for part in match.groups()]
        details = _parse_service_port_details_from_current_config(line, profile_name_map)
        key = (frame, slot, port, ont_id)
        existing = detail_map.get(key)
        if not existing:
            detail_map[key] = details
            continue

        existing_vlans = [vlan for vlan in str(existing.get("attached_vlans") or "").split(",") if vlan]
        for vlan in str(details.get("attached_vlans") or "").split(","):
            if vlan and vlan not in existing_vlans:
                existing_vlans.append(vlan)
        existing["attached_vlans"] = ",".join(existing_vlans)[:255]

        # Append each new service-port together with ITS aligned values to every
        # parallel list, keeping them all the same length (position-matched).
        def _at(values, i):
            return values[i] if (values and i < len(values)) else ""

        existing_ids = existing.setdefault("service_port_ids", [])
        new_ids = details.get("service_port_ids") or []
        for i, service_port_id in enumerate(new_ids):
            if service_port_id and service_port_id in existing_ids:
                continue
            existing_ids.append(service_port_id)
            existing.setdefault("user_vlans", []).append(_at(details.get("user_vlans"), i))
            existing.setdefault("download_profile_names", []).append(_at(details.get("download_profile_names"), i))
            existing.setdefault("upload_profile_names", []).append(_at(details.get("upload_profile_names"), i))
            existing.setdefault("download_profile_indices", []).append(_at(details.get("download_profile_indices"), i))
            existing.setdefault("upload_profile_indices", []).append(_at(details.get("upload_profile_indices"), i))
    return detail_map


def _load_speed_profile_name_map():
    from .models import SpeedProfile

    profile_name_map = {}
    for profile in SpeedProfile.objects.filter(is_active=True):
        index_base = int(profile.index_number or 0)
        if index_base:
            if profile.download_name:
                profile_name_map[str(index_base)] = str(profile.download_name).strip()
            elif profile.name:
                profile_name_map[str(index_base)] = str(profile.name).strip()
            upload_index = index_base + 1
            if profile.upload_name:
                profile_name_map[str(upload_index)] = str(profile.upload_name).strip()
    return profile_name_map


def _parse_traffic_table_index_name_map(lines):
    index_name_map = {}
    for raw_line in lines:
        line = " ".join(str(raw_line or "").strip().split())
        if not line:
            continue
        match = re.search(r'(?i)\btraffic\s+table\s+ip\s+index\s+(\d+)\s+name\s+"([^"]+)"', line)
        if not match:
            continue
        index_name_map[str(int(match.group(1)))] = match.group(2).strip()
    return index_name_map


def _ensure_speed_profile_name_map_for_indices(tn, indices, profile_name_map=None):
    profile_name_map = dict(profile_name_map or {})
    requested = [str(idx).strip() for idx in indices if str(idx).strip()]
    if not requested:
        return profile_name_map

    fetched_lines = []
    for index_text in dict.fromkeys(requested):
        command = f"display current-configuration | include traffic table ip index {index_text}"
        output = _run_telnet_bulk_command(tn, command, max_wait_seconds=8)
        cleaned = _clean_cli_transcript_block(command, output)
        for raw_line in str(cleaned or "").splitlines():
            line = raw_line.strip()
            if line:
                fetched_lines.append(line)
    profile_name_map.update(_parse_traffic_table_index_name_map(fetched_lines))
    return profile_name_map


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


def _sync_record_attached_vlans_via_telnet(tn, record, now=None, max_wait_seconds=35, allow_empty_overwrite=False):
    now = now or timezone.now()
    pon_kw = "epon" if str(_slot_pon_tech(record.olt, record.slot) or "").upper() == "EPON" else "gpon"
    command = f"display current-configuration | include {pon_kw} 0/{int(record.slot)}/{int(record.port)} ont {int(record.ont_id)}"
    # _run_telnet_bulk_command returns the moment the OLT's "hostname#" prompt
    # comes back (output complete); otherwise it waits up to max_wait_seconds.
    output = _run_telnet_bulk_command(tn, command, max_wait_seconds=max_wait_seconds)
    filtered_output = _filter_service_port_config_for_onu(
        output,
        int(record.frame or 0),
        int(record.slot),
        int(record.port),
        int(record.ont_id),
    )
    preview_details = _parse_service_port_details_from_current_config(filtered_output, {})
    requested_indices = (preview_details.get("download_profile_indices") or []) + (preview_details.get("upload_profile_indices") or [])
    profile_name_map = _ensure_speed_profile_name_map_for_indices(tn, requested_indices, _load_speed_profile_name_map())
    details = _parse_service_port_details_from_current_config(filtered_output, profile_name_map)
    has_existing_config = any(
        str(getattr(record, field, "") or "").strip()
        for field in (
            "attached_vlans_cache",
            "service_port_id_cache",
            "user_vlan_cache",
            "download_profile_index_cache",
            "upload_profile_index_cache",
            "download_profile_name_cache",
            "upload_profile_name_cache",
        )
    )
    if has_existing_config and not allow_empty_overwrite and not (details.get("service_port_ids") or []):
        return {
            "record": record,
            "changed": False,
            "vlan_value": record.attached_vlans_cache or "",
            "details": {
                "attached_vlans": record.attached_vlans_cache or "",
                "service_port_ids": [x.strip() for x in str(record.service_port_id_cache or "").split(",") if x.strip()],
                "user_vlans": [x.strip() for x in str(record.user_vlan_cache or "").split(",") if x.strip()],
                "download_profile_names": [x.strip() for x in str(record.download_profile_name_cache or "").split(",") if x.strip()],
                "upload_profile_names": [x.strip() for x in str(record.upload_profile_name_cache or "").split(",") if x.strip()],
            },
            "command": command,
            "output": filtered_output or output,
            "preserved_existing": True,
        }
    return _apply_service_port_details_to_record(record, details, now=now, command=command, output=filtered_output or output)


def _apply_service_port_details_to_record(record, details, now=None, command="", output=""):
    now = now or timezone.now()
    # Keep empty placeholders (no filtering) so every parallel cache stays the
    # same length and position-aligned with service_port_ids — that is what
    # keeps each row's speed profile under the correct VLAN.
    vlan_value = details["attached_vlans"][:255]
    service_port_value = ",".join(str(item) for item in (details.get("service_port_ids") or []))[:255]
    user_vlan_value = ",".join(str(item) for item in (details.get("user_vlans") or []))[:255]
    download_profile_index_value = ",".join(str(item) for item in (details.get("download_profile_indices") or []))[:255]
    upload_profile_index_value = ",".join(str(item) for item in (details.get("upload_profile_indices") or []))[:255]
    download_profile_name_value = ",".join(str(item) for item in (details.get("download_profile_names") or []))[:255]
    upload_profile_name_value = ",".join(str(item) for item in (details.get("upload_profile_names") or []))[:255]
    imported_mode_value = "routing" if not getattr(record, "configured_via_app", False) else (record.onu_mode_cache or "")
    changed = any([
        vlan_value != (record.attached_vlans_cache or ""),
        service_port_value != (record.service_port_id_cache or ""),
        user_vlan_value != (record.user_vlan_cache or ""),
        download_profile_index_value != (record.download_profile_index_cache or ""),
        upload_profile_index_value != (record.upload_profile_index_cache or ""),
        download_profile_name_value != (record.download_profile_name_cache or ""),
        upload_profile_name_value != (record.upload_profile_name_cache or ""),
        imported_mode_value != (record.onu_mode_cache or ""),
    ])
    record.attached_vlans_cache = vlan_value
    record.service_port_id_cache = service_port_value
    record.user_vlan_cache = user_vlan_value
    record.download_profile_index_cache = download_profile_index_value
    record.upload_profile_index_cache = upload_profile_index_value
    record.download_profile_name_cache = download_profile_name_value
    record.upload_profile_name_cache = upload_profile_name_value
    record.onu_mode_cache = imported_mode_value[:64]
    record.attached_vlans_synced_at = now
    return {
        "record": record,
        "changed": changed,
        "vlan_value": vlan_value,
        "details": details,
        "command": command,
        "output": output,
    }


def sync_single_onu_attached_vlans(olt, slot, port, ont_id, *, record=None, allow_empty_overwrite=False):
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
        # Single-ONU "Fetch Current Config": wait up to 1 minute for the full output
        # (returns immediately once the hostname# prompt is back).
        sync_payload = _sync_record_attached_vlans_via_telnet(
            tn,
            record,
            now=now,
            max_wait_seconds=60,
            allow_empty_overwrite=allow_empty_overwrite,
        )
        record.save(update_fields=[
            "attached_vlans_cache",
            "attached_vlans_synced_at",
            "service_port_id_cache",
            "user_vlan_cache",
            "download_profile_index_cache",
            "upload_profile_index_cache",
            "download_profile_name_cache",
            "upload_profile_name_cache",
            "onu_mode_cache",
        ])
        return {
            "ok": True,
            "updated": bool(sync_payload.get("changed")),
            "status": "ONU attached VLANs synced.",
            "vlan_value": sync_payload.get("vlan_value") or "",
            "details": sync_payload.get("details") or {},
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


def sync_onu_attached_vlans_for_olt(
    olt,
    limit=None,
    start_pk=None,
    fallback_missing=True,
    progress_callback=None,
    only_missing=False,
    imported_only=False,
):
    from django.utils import timezone
    from .models import ConfiguredONU

    qs = ConfiguredONU.objects.filter(olt=olt).order_by("id")
    if imported_only:
        qs = qs.filter(configured_via_app=False)
    if only_missing:
        qs = qs.filter(
            Q(attached_vlans_cache="")
            | Q(service_port_id_cache="")
            | Q(user_vlan_cache="")
            | Q(download_profile_name_cache="")
            | Q(upload_profile_name_cache="")
        )
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
        bulk_command = "display current-configuration | include service-port"
        bulk_output = _run_telnet_bulk_command(tn, bulk_command, max_wait_seconds=90)
        preview_detail_map = _parse_service_port_detail_map_from_current_config(bulk_output, {})
        requested_indices = []
        for details in preview_detail_map.values():
            requested_indices.extend(details.get("download_profile_indices") or [])
            requested_indices.extend(details.get("upload_profile_indices") or [])
        profile_name_map = _ensure_speed_profile_name_map_for_indices(tn, requested_indices, _load_speed_profile_name_map())
        bulk_detail_map = _parse_service_port_detail_map_from_current_config(bulk_output, profile_name_map)
        # The bulk "display current-configuration | include service-port" lists EVERY
        # service-port on the OLT in one command. When it returned data, an ONU absent
        # from it simply has no service-port configured — so a per-ONU telnet read would
        # just confirm "nothing" at huge cost (1000s of reads = 30+ min). Only fall back
        # per-ONU when the bulk itself came back empty (e.g. firmware without `| include`).
        bulk_worked = bool(bulk_detail_map)
        for record in records:
            checked += 1
            key = (int(record.frame or 0), int(record.slot), int(record.port), int(record.ont_id))
            details = bulk_detail_map.get(key)
            if details:
                sync_payload = _apply_service_port_details_to_record(
                    record,
                    details,
                    now=now,
                    command=bulk_command,
                    output=bulk_output,
                )
            elif fallback_missing and not bulk_worked:
                sync_payload = _sync_record_attached_vlans_via_telnet(tn, record, now=now)
            else:
                continue
            if sync_payload.get("changed"):
                updated += 1
            bulk.append(record)
            if progress_callback and (checked % 200 == 0 or checked == len(records)):
                progress_callback(checked, len(records), updated)

        if bulk:
            ConfiguredONU.objects.bulk_update(
                bulk,
                [
                    "attached_vlans_cache",
                    "attached_vlans_synced_at",
                    "service_port_id_cache",
                    "user_vlan_cache",
                    "download_profile_index_cache",
                    "upload_profile_index_cache",
                    "download_profile_name_cache",
                    "upload_profile_name_cache",
                    "onu_mode_cache",
                ],
                batch_size=200,
            )
        return {
            "olt": olt.name,
            "checked": checked,
            "updated": updated,
            "status": f"Service-port VLANs checked {checked}, updated {updated}, bulk matched {len(bulk_detail_map)}",
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
    def _clean_mac_address_lines(command, output):
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
        cleaned = re.sub(r"(?im)-+\s*more\s*\(\s*press\s+'?q'?\s+to\s+break\s*\)\s*-+\s*return", "", cleaned)
        cleaned = re.sub(r"(?im)-+\s*more\s*-+", "", cleaned)
        if _telnet_auth_output_detected(cleaned):
            return None
        cleaned = "".join(ch for ch in cleaned if (ch == "\n" or ch == "\r" or ch == "\t" or 32 <= ord(ch) <= 126))
        mac_lines = []
        for raw_line in cleaned.splitlines():
            line = re.sub(r"[ \t]{2,}", " ", raw_line.strip())
            if not line:
                continue
            lower = line.lower()
            if lower.startswith(("srv-p", "index", "total:", "note:", "f--", "a--", "v/e--", "ppp--")):
                continue
            if re.search(r"\b(?:static|dynamic)\b", lower) and re.search(r"\b(?:gpon|epon|eth|xpon)\b", lower):
                # Columns: SRV-P  BUNDLE  TYPE  MAC  MAC-TYPE  F/S/P  VPI(=ONT)  VCI(=GEM)  VLAN
                m = re.match(
                    r"^(\d+)\s+\S+\s+\S+\s+([0-9a-fA-F][0-9a-fA-F:.\-]{10,16})\s+\S+\s+"
                    r"\d+\s*/\s*\d+\s*/\s*\d+\s+(\S+)\s+(\S+)\s+(\d+)\s*$",
                    line,
                )
                if m:
                    srvp, mac, _ont, gem, vlan = m.group(1), m.group(2), m.group(3), m.group(4), m.group(5)
                    mac_lines.append(f"MACROW|{mac}|{vlan}|{gem}|{srvp}")
                else:
                    mac_lines.append(line)
        return mac_lines

    def _clean_port_state_output(command, output):
        cleaned = _clean_cli_response_text(command, output)
        cleaned = re.sub(r"(?im)^[^\r\n]*display\s+ont\s+port\s+state[^\r\n]*$", "", cleaned)
        cleaned = re.sub(r"(?im)^[^\r\n]*\{\s*<cr>\|[^\r\n]*\}\s*:\s*$", "", cleaned)
        lines = []
        capture = False
        for raw_line in cleaned.splitlines():
            line = raw_line.rstrip()
            stripped = line.strip()
            if not stripped:
                continue
            if "ONT-ID" in stripped and "Speed" in stripped:
                capture = True
                lines.append("  --------------------------------------------------------------------------")
                lines.append("  ONT-ID   ONT      ONT       Speed(Mbps)   Duplex   LinkState  RingStatus")
                lines.append("           port-ID  Port-type")
                lines.append("  --------------------------------------------------------------------------")
                continue
            if not capture:
                continue
            if re.match(r"^-{5,}$", stripped):
                continue
            if re.match(rf"^{int(ont_id)}\s+\d+\s+", stripped):
                lines.append("  " + stripped)
        if lines:
            lines.append("  --------------------------------------------------------------------------")
        return "\n".join(lines).strip()

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

    def _fetch_wan_interface_lines(tn):
        wan_command = f"display ont wan-info 0/{int(slot)} {int(port)} {int(ont_id)}"
        wan_output = _run_telnet_bulk_command(tn, wan_command, max_wait_seconds=14)
        if _telnet_auth_output_detected(wan_output):
            return None
        if "unknown command" in str(wan_output or "").lower() or "parameter error" in str(wan_output or "").lower():
            return []
        # Key fields per WAN interface, in display order.
        wanted = [
            ("name", "Name"),
            ("service type", "Service type"),
            ("connection type", "Connection type"),
            ("ipv4 connection status", "IPv4 status"),
            ("ipv4 access type", "Access type"),
            ("ipv4 address", "IPv4 address"),
            ("default gateway", "Gateway"),
            ("manage vlan", "Manage VLAN"),
            ("mac address", "MAC address"),
            ("ipv4 switch", "IPv4 switch"),
        ]
        wanted_keys = {k for k, _ in wanted}
        interfaces = []
        cur = None
        for raw in str(wan_output or "").splitlines():
            line = " ".join(raw.strip().split())
            if ":" not in line:
                continue
            key, val = line.split(":", 1)
            k = key.strip().lower()
            v = val.strip()
            if k == "index":
                if cur:
                    interfaces.append(cur)
                cur = {"_index": v}
                continue
            if cur is None:
                cur = {}
            if k in wanted_keys:
                cur[k] = v
        if cur:
            interfaces.append(cur)
        lines = []
        for n, iface in enumerate(interfaces, start=1):
            lines.append(f"Interface {iface.get('_index') or n}")
            for k, label in wanted:
                if iface.get(k):
                    lines.append(f"{label}: {iface[k]}")
        return lines

    try:
        _prepare_telnet_cli_session(tn, use_paging=False)

        wan_lines = _fetch_wan_interface_lines(tn)
        if wan_lines is None:
            result["message"] = "Telnet login failed: username/password invalid."
            return result

        command = f"display mac-address port 0/{int(slot)}/{int(port)} ont {int(ont_id)}"
        output = _run_telnet_bulk_command(tn, command, max_wait_seconds=12)
        mac_lines = _clean_mac_address_lines(command, output)
        if mac_lines is None:
            result["message"] = "Telnet login failed: username/password invalid."
            return result

        config_ok, config_output = _enter_config_mode(tn)
        if config_ok:
            # Enter the interface matching the board technology (EPON/GPON/XGS-PON)
            # so the ONT port-state read works on EPON boards too.
            board_tech = _slot_pon_tech(olt, int(slot))
            _enter_interface_context(tn, _pon_interface_kinds_for_board(board_tech), 0, int(slot))
        port_state_command = f"display ont port state {int(port)} {int(ont_id)} eth-port all"
        port_state_output = _run_telnet_bulk_command(tn, port_state_command, max_wait_seconds=10)
        port_state_cleaned = _clean_port_state_output(port_state_command, port_state_output)
        if not port_state_cleaned and not config_ok:
            port_state_cleaned = _clean_port_state_output(port_state_command, config_output)

        sections = []
        if wan_lines:
            sections.append("ONU WAN Interfaces")
            sections.extend(wan_lines)
        if mac_lines:
            sections.append("MACs on OLT from this ONU")
            sections.extend(mac_lines)
        if port_state_cleaned:
            sections.append("Ethernet Ports")
            sections.append(port_state_cleaned)
        cleaned = "\n".join(sections).strip()
        if cleaned:
            result["ok"] = True
            result["output"] = cleaned[:14000]
            result["message"] = "Live WAN / MAC / Ethernet ports fetched."
            return result
        result["message"] = "No MAC or Ethernet port data returned for this ONU."
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


def _debounced_snmp_runtime_status(record, snmp_status):
    status = str(snmp_status or "").strip().lower()
    if status not in {"online", "offline"}:
        return ""
    current_status = str(getattr(record, "derived_status", "") or "").strip().lower()
    control_flag = str(getattr(record, "control_flag", "") or "").strip().lower()
    if current_status == "admin_disabled" and any(
        token in control_flag for token in ("disabled", "disable", "shutdown", "deactivated", "deactive")
    ):
        return "admin_disabled"
    return status


_ONU_STATUS_SYNC_PROGRESS_LOCK = threading.Lock()
_ONU_STATUS_SYNC_PROGRESS_FILE_LOCK = threading.Lock()
_ONU_STATUS_SYNC_PROGRESS = {
    "running": False,
    "cycle_started_at": None,
    "cycle_completed_at": None,
    "next_run_at": None,
    "total_olts": 0,
    "olts": {},
}


def _onu_status_progress_file_path():
    configured = str(getattr(settings, "ONU_STATUS_SYNC_PROGRESS_FILE", "") or "").strip()
    if configured:
        return configured
    return os.path.join(str(getattr(settings, "BASE_DIR", "") or "."), "onu_status_sync_progress.json")


def _onu_status_progress_datetime(value):
    if not value:
        return ""
    try:
        return timezone.localtime(value).isoformat()
    except Exception:
        return str(value)


def _onu_status_progress_snapshot_unlocked():
    olts = []
    for item in (_ONU_STATUS_SYNC_PROGRESS.get("olts") or {}).values():
        olts.append(dict(item))
    olts.sort(key=lambda item: str(item.get("olt") or "").lower())
    checked = sum(int(item.get("checked") or 0) for item in olts)
    total = sum(int(item.get("total") or 0) for item in olts)
    done_olts = sum(1 for item in olts if item.get("done"))
    failed_olts = sum(1 for item in olts if item.get("failed"))
    running_olts = sum(1 for item in olts if item.get("running"))
    total_olts = int(_ONU_STATUS_SYNC_PROGRESS.get("total_olts") or len(olts))
    return {
        "running": bool(_ONU_STATUS_SYNC_PROGRESS.get("running")),
        "cycle_started_at": _onu_status_progress_datetime(_ONU_STATUS_SYNC_PROGRESS.get("cycle_started_at")),
        "cycle_completed_at": _onu_status_progress_datetime(_ONU_STATUS_SYNC_PROGRESS.get("cycle_completed_at")),
        "next_run_at": _onu_status_progress_datetime(_ONU_STATUS_SYNC_PROGRESS.get("next_run_at")),
        "total_olts": total_olts,
        "done_olts": done_olts,
        "failed_olts": failed_olts,
        "running_olts": running_olts,
        "checked": checked,
        "total": total,
        "percent": round((checked / total) * 100, 1) if total else 0,
        "olts": olts,
        "updated_at": _onu_status_progress_datetime(timezone.now()),
    }


def _write_onu_status_progress_file_unlocked():
    """Persist progress for the web process.

    Background sync runs in a separate systemd worker process in production,
    while the progress endpoint is served by Daphne. A tiny atomically-replaced
    JSON file is enough to share this UI-only state without adding DB churn.
    """
    path = _onu_status_progress_file_path()
    if not path:
        return
    payload = _onu_status_progress_snapshot_unlocked()
    tmp_path = f"{path}.tmp"
    try:
        directory = os.path.dirname(path)
        if directory:
            os.makedirs(directory, exist_ok=True)
        with _ONU_STATUS_SYNC_PROGRESS_FILE_LOCK:
            with open(tmp_path, "w", encoding="utf-8") as handle:
                json.dump(payload, handle, separators=(",", ":"))
            os.replace(tmp_path, path)
    except Exception:
        try:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
        except Exception:
            pass


def _read_onu_status_progress_file():
    path = _onu_status_progress_file_path()
    if not path:
        return None
    try:
        with open(path, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
        if not isinstance(payload, dict):
            return None
        return payload
    except Exception:
        return None


def start_onu_status_sync_progress(olt_rows):
    now = timezone.now()
    olts = {}
    for row in olt_rows or []:
        olt_id = int(row.get("id") if isinstance(row, dict) else getattr(row, "id", 0) or 0)
        if not olt_id:
            continue
        olts[str(olt_id)] = {
            "olt_id": olt_id,
            "olt": str(row.get("name") if isinstance(row, dict) else getattr(row, "name", "") or ""),
            "running": False,
            "done": False,
            "failed": False,
            "checked": 0,
            "total": 0,
            "updated": 0,
            "status_changed": 0,
            "message": "Waiting for this OLT...",
            "started_at": "",
            "completed_at": "",
        }
    with _ONU_STATUS_SYNC_PROGRESS_LOCK:
        _ONU_STATUS_SYNC_PROGRESS.update({
            "running": True,
            "cycle_started_at": now,
            "cycle_completed_at": None,
            "next_run_at": None,
            "total_olts": len(olts),
            "olts": olts,
        })
        _write_onu_status_progress_file_unlocked()


def update_onu_status_sync_progress(olt_id, **kwargs):
    now = timezone.now()
    key = str(int(olt_id or 0))
    if key == "0":
        return
    with _ONU_STATUS_SYNC_PROGRESS_LOCK:
        olts = _ONU_STATUS_SYNC_PROGRESS.setdefault("olts", {})
        entry = olts.setdefault(key, {
            "olt_id": int(olt_id),
            "olt": str(kwargs.get("olt") or ""),
            "running": False,
            "done": False,
            "failed": False,
            "checked": 0,
            "total": 0,
            "updated": 0,
            "status_changed": 0,
            "message": "",
            "started_at": "",
            "completed_at": "",
        })
        if kwargs.get("running") and not entry.get("started_at"):
            entry["started_at"] = _onu_status_progress_datetime(now)
        if kwargs.get("done") or kwargs.get("failed"):
            entry["completed_at"] = _onu_status_progress_datetime(now)
        for field in ("olt", "running", "done", "failed", "checked", "total", "updated", "status_changed", "message"):
            if field in kwargs:
                entry[field] = kwargs[field]
        _write_onu_status_progress_file_unlocked()


def finish_onu_status_sync_progress(next_run_at=None):
    now = timezone.now()
    with _ONU_STATUS_SYNC_PROGRESS_LOCK:
        _ONU_STATUS_SYNC_PROGRESS.update({
            "running": False,
            "cycle_completed_at": now,
            "next_run_at": next_run_at,
        })
        _write_onu_status_progress_file_unlocked()


def schedule_onu_status_sync_progress(next_run_at=None):
    with _ONU_STATUS_SYNC_PROGRESS_LOCK:
        _ONU_STATUS_SYNC_PROGRESS.update({
            "running": False,
            "next_run_at": next_run_at,
        })
        _write_onu_status_progress_file_unlocked()


def get_onu_status_sync_progress():
    with _ONU_STATUS_SYNC_PROGRESS_LOCK:
        snapshot = _onu_status_progress_snapshot_unlocked()
    file_snapshot = _read_onu_status_progress_file()
    if file_snapshot and (
        not snapshot.get("next_run_at")
        or (not snapshot.get("running") and not snapshot.get("olts") and file_snapshot.get("next_run_at"))
        or file_snapshot.get("running")
    ):
        return file_snapshot
    return snapshot


def sync_runtime_statuses_for_olt(olt, only_non_online=True, limit=None, start_pk=None, write_samples=True, on_progress=None):
    from django.utils import timezone
    from .models import ConfiguredONU
    if write_samples:
        from .models import ONUStatusSample

    if getattr(olt, "pricing_access_locked", False):
        message = "Skipped: OLT subscription is locked or expired."
        if on_progress:
            on_progress({
                "checked": 0,
                "total": 0,
                "updated": 0,
                "status_changed": 0,
                "running": False,
                "done": True,
                "message": message,
            })
        return {
            "olt": olt.name,
            "checked": 0,
            "updated": 0,
            "status": message,
            "last_pk": start_pk or 0,
            "wrapped": False,
        }

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
        if on_progress:
            on_progress({"checked": 0, "total": 0, "updated": 0, "status_changed": 0, "done": True, "message": "No ONU records to check."})
        return {"olt": olt.name, "checked": 0, "updated": 0, "status": "No ONU records to check.", "last_pk": start_pk or 0, "wrapped": wrapped}

    record_slots = {int(record.slot) for record in records}
    epon_slots = {
        int(record.slot)
        for record in records
        if str(_slot_pon_tech(olt, int(record.slot)) or "").upper() == "EPON"
    }
    all_records_are_epon = bool(record_slots) and record_slots == epon_slots
    total_records = len(records)
    updated = 0
    checked = 0
    bulk = []
    status_samples = []
    status_changed = 0
    now = timezone.now()
    try:
        if on_progress:
            on_progress({"checked": 0, "total": total_records, "updated": 0, "status_changed": 0, "running": True, "message": "Fetching ONU status from SNMP..."})
        trap_status_map = get_active_onu_trap_status_map(olt)
        snmp_result = {"items": {}, "truncated": False, "status": "Skipped GPON SNMP status walk for EPON batch."} if all_records_are_epon else fetch_olt_snmp_status_map(olt)
        snmp_status_map = snmp_result.get("items") or {}
        epon_inventory_map = {}
        if epon_slots:
            inventory_result = fetch_configured_onu_status_rows(olt, epon_slots)
            for row in inventory_result.get("rows") or []:
                try:
                    key = (int(row.get("slot") or 0), int(row.get("port") or 0), int(row.get("ont_id") or 0))
                except (TypeError, ValueError):
                    continue
                if key[0] not in epon_slots:
                    continue
                status_value = derive_inventory_onu_status(row)
                signal_bucket = str(row.get("signal_bucket") or "").strip()
                if status_value == "offline" and signal_bucket in {"good", "warn", "bad"}:
                    status_value = "online"
                epon_inventory_map[key] = {
                    "status": status_value,
                    "run_state": str(row.get("run_state") or "").strip().lower(),
                    "control_flag": str(row.get("control_flag") or "").strip().lower(),
                    "signal_bucket": signal_bucket,
                }
                if status_value:
                    snmp_status_map[key] = status_value
        if not snmp_status_map:
            message = snmp_result.get("status") or "No SNMP ONU status data returned."
            if on_progress:
                on_progress({
                    "checked": 0,
                    "total": total_records,
                    "updated": 0,
                    "status_changed": 0,
                    "running": False,
                    "done": True,
                    "failed": True,
                    "message": message,
                })
            return {
                "olt": olt.name,
                "checked": 0,
                "updated": 0,
                "status": message,
                "last_pk": records[-1].id if records else (start_pk or 0),
                "wrapped": wrapped,
            }
        snmp_complete = bool(snmp_status_map) and not bool(snmp_result.get("truncated"))
        for record in records:
            checked += 1
            changed = False
            record_key = (int(record.slot), int(record.port), int(record.ont_id))
            inventory_status = epon_inventory_map.get(record_key)
            snmp_status = str(snmp_status_map.get(record_key) or "").strip().lower()
            if not snmp_status and snmp_complete:
                snmp_status = "offline"
            debounced_snmp_status = _debounced_snmp_runtime_status(record, snmp_status)
            runtime_run_state = "online" if debounced_snmp_status == "online" else "offline" if debounced_snmp_status == "offline" else ""
            if inventory_status and inventory_status.get("run_state"):
                runtime_run_state = inventory_status["run_state"]
            if runtime_run_state and runtime_run_state != (record.run_state or "").strip().lower():
                record.run_state = runtime_run_state
                changed = True
            if inventory_status:
                control_flag = str(inventory_status.get("control_flag") or "").strip()
                if control_flag and control_flag != (record.control_flag or "").strip().lower():
                    record.control_flag = control_flag[:32]
                    changed = True

            trap_status = trap_status_map.get((int(record.slot), int(record.port), int(record.ont_id)))
            runtime_status = trap_status or debounced_snmp_status or str(record.derived_status or "").strip().lower()
            runtime_source = "trap" if trap_status else "inventory_runtime" if inventory_status else "snmp_runtime" if debounced_snmp_status else (record.status_source or "")
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

            if write_samples and runtime_status:
                status_samples.append(
                    ONUStatusSample(
                        olt=olt,
                        slot=int(record.slot),
                        port=int(record.port),
                        ont_id=int(record.ont_id),
                        status=str(runtime_status or "").strip().lower()[:32],
                        source=str(runtime_source or "")[:32],
                    )
                )

            if changed:
                updated += 1
                bulk.append(record)
            if on_progress and (checked == 1 or checked % 100 == 0 or checked == total_records):
                on_progress({
                    "checked": checked,
                    "total": total_records,
                    "updated": updated,
                    "status_changed": status_changed,
                    "running": True,
                    "message": f"{checked} of {total_records} ONU status records checked.",
                })

        if bulk:
            ConfiguredONU.objects.bulk_update(
                bulk,
                [
                    "run_state",
                    "control_flag",
                    "onu_rx",
                    "olt_rx",
                    "tx_power",
                    "signal_bucket",
                    "derived_status",
                    "status_source",
                    "status_first_seen_at",
                    "status_updated_at",
                ],
                batch_size=200,
            )
        if write_samples and status_samples:
            ONUStatusSample.objects.bulk_create(status_samples, batch_size=200)
        final_message = f"Completed: {checked} checked, {updated} updated."
        if snmp_result.get("truncated"):
            final_message += " SNMP walk reached its limit; unmatched ONUs were left unchanged."
        if on_progress:
            on_progress({
                "checked": checked,
                "total": total_records,
                "updated": updated,
                "status_changed": status_changed,
                "running": False,
                "done": True,
                "message": final_message,
            })
        return {
            "olt": olt.name,
            "checked": checked,
            "updated": updated,
            "status": final_message,
            "last_pk": records[-1].id if records else (start_pk or 0),
            "wrapped": wrapped,
        }
    except Exception as exc:
        if on_progress:
            on_progress({
                "checked": checked,
                "total": total_records,
                "updated": updated,
                "status_changed": status_changed,
                "running": False,
                "done": True,
                "failed": True,
                "message": f"SNMP error during runtime sync: {exc}",
            })
        return {
            "olt": olt.name,
            "checked": checked,
            "updated": updated,
            "status": f"SNMP error during runtime sync: {exc}",
            "last_pk": records[-1].id if records else (start_pk or 0),
            "wrapped": wrapped,
        }


def should_record_onu_optical_sample(olt, slot, port, ont_id, *, now=None):
    """Return True when the ONU optical history needs a new persisted sample."""
    from .models import ONUOpticalSample

    interval_seconds = int(getattr(settings, "OLT_ONU_OPTICAL_SAMPLE_INTERVAL_SECONDS", 3600) or 3600)
    if interval_seconds <= 0:
        return True
    now = now or timezone.now()
    latest = (
        ONUOpticalSample.objects.filter(
            olt=olt,
            slot=int(slot),
            port=int(port),
            ont_id=int(ont_id),
        )
        .order_by("-sampled_at")
        .values_list("sampled_at", flat=True)
        .first()
    )
    return not latest or (now - latest).total_seconds() >= interval_seconds


def recent_onu_optical_sample_keys(olt, *, now=None):
    """Return ONU keys that already have an optical sample inside the interval."""
    from .models import ONUOpticalSample

    interval_seconds = int(getattr(settings, "OLT_ONU_OPTICAL_SAMPLE_INTERVAL_SECONDS", 3600) or 3600)
    if interval_seconds <= 0:
        return set()
    now = now or timezone.now()
    since = now - datetime.timedelta(seconds=interval_seconds)
    return {
        (int(slot), int(port), int(ont_id))
        for slot, port, ont_id in ONUOpticalSample.objects.filter(
            olt=olt,
            sampled_at__gte=since,
        ).values_list("slot", "port", "ont_id").distinct()
    }


def sync_onu_signals_from_snmp(olt, *, overwrite=False):
    """Bulk-fetch ONU optical signals for ALL ONUs via SNMP and persist to DB.

    Uses fetch_olt_snmp_onu_signal_map which does a single SNMP walk covering
    every ONU on the OLT (GPON + EPON) in seconds.  Much faster than the
    Telnet-based per-port approach used by fetch_ont_optical_subset.

    Args:
        overwrite: if True, overwrite existing non-empty signal values.
                   if False (default), only fill in empty/missing fields.
    """
    from .models import ConfiguredONU, ONUOpticalSample

    all_records = {
        (int(r.slot), int(r.port), int(r.ont_id)): r
        for r in ConfiguredONU.objects.filter(olt=olt).order_by("id")
    }
    total = len(all_records)

    to_update = []
    samples = []
    now = timezone.now()
    recent_sample_keys = recent_onu_optical_sample_keys(olt, now=now)
    filled = 0
    single_retry_limit = max(0, int(getattr(settings, "OLT_ONU_SIGNAL_SINGLE_RETRY_LIMIT", 120) or 0))
    stale_after_seconds = max(0, int(getattr(settings, "OLT_ONU_OPTICAL_STALE_AFTER_SECONDS", 21600) or 0))
    fresh_recent_keys = set()
    if stale_after_seconds > 0:
        fresh_since = now - datetime.timedelta(seconds=stale_after_seconds)
        fresh_recent_keys = {
            (int(slot), int(port), int(ont_id))
            for slot, port, ont_id in ONUOpticalSample.objects.filter(
                olt=olt,
                sampled_at__gte=fresh_since,
                sample_source__in=[ONUOpticalSample.SOURCE_FRESH, ONUOpticalSample.SOURCE_SINGLE_RETRY],
            ).values_list("slot", "port", "ont_id").distinct()
        }

    def _record_has_cached_signal(record):
        return any(
            str(getattr(record, field, "") or "").strip() not in {"", "--"}
            for field in ("onu_rx", "olt_rx", "tx_power")
        )

    def _cached_sample_source(record):
        if stale_after_seconds <= 0:
            return ONUOpticalSample.SOURCE_CARRIED
        key = (int(record.slot), int(record.port), int(record.ont_id))
        return ONUOpticalSample.SOURCE_CARRIED if key in fresh_recent_keys else ONUOpticalSample.SOURCE_STALE

    def _append_sample(key, record, source):
        if key in recent_sample_keys:
            return False
        if str(getattr(record, "derived_status", "") or "").strip().lower() != "online":
            return False
        if not _record_has_cached_signal(record):
            return False
        samples.append(ONUOpticalSample(
            olt=olt,
            slot=record.slot,
            port=record.port,
            ont_id=record.ont_id,
            onu_rx=record.onu_rx or "",
            olt_rx=record.olt_rx or "",
            tx_power=record.tx_power or "",
            sample_source=source,
        ))
        recent_sample_keys.add(key)
        return True

    def _append_cached_sample(key, record):
        return _append_sample(key, record, _cached_sample_source(record))

    def _apply_signal_to_record(record, signal):
        onu_rx = str(signal.get("onu_rx") or "").strip()
        olt_rx = str(signal.get("olt_rx") or "").strip()
        tx_power = str(signal.get("tx_power") or "").strip()

        if not any(v and v != "--" for v in (onu_rx, olt_rx, tx_power)):
            return False

        def _missing(val):
            v = (val or "").strip()
            return not v or v == "--"

        changed = False
        if onu_rx and onu_rx != "--" and (overwrite or _missing(record.onu_rx)):
            record.onu_rx = onu_rx[:32]
            changed = True
        if olt_rx and olt_rx != "--" and (overwrite or _missing(record.olt_rx)):
            record.olt_rx = olt_rx[:32]
            changed = True
        if tx_power and tx_power != "--" and (overwrite or _missing(record.tx_power)):
            record.tx_power = tx_power[:32]
            changed = True

        if changed:
            sig_src = record.olt_rx if (record.olt_rx and record.olt_rx != "--") else record.onu_rx
            record.signal_bucket = _signal_bucket_from_dbm_text(sig_src)
            record.status_updated_at = now
        return changed

    snmp_result = fetch_olt_snmp_onu_signal_map(olt)
    items = snmp_result.get("items") or {}
    if not items:
        cached_samples = 0
        for key, record in all_records.items():
            if _append_cached_sample(key, record):
                cached_samples += 1
        if samples:
            ONUOpticalSample.objects.bulk_create(samples, batch_size=500, ignore_conflicts=False)
        return {
            "status": f"{snmp_result.get('status') or 'SNMP signal map returned no data.'}; cached samples written: {cached_samples}.",
            "filled": 0,
            "total": total,
            "snmp_items": 0,
            "cached_samples": cached_samples,
        }

    for key, signal in items.items():
        record = all_records.get(key)
        if not record:
            continue

        changed = _apply_signal_to_record(record, signal)
        if changed:
            to_update.append(record)
            filled += 1

        _append_sample(key, record, ONUOpticalSample.SOURCE_FRESH)

    single_retry_samples = 0
    single_retry_updates = 0
    single_retry_checked = 0
    cached_samples = 0
    for key, record in all_records.items():
        if key in items:
            continue
        if single_retry_checked < single_retry_limit and str(getattr(record, "derived_status", "") or "").strip().lower() == "online":
            single_retry_checked += 1
            try:
                signal = fetch_single_onu_snmp_signal(olt, record.slot, record.port, record.ont_id)
            except Exception:
                signal = {}
            if signal and any(str(signal.get(field) or "").strip() not in {"", "--"} for field in ("onu_rx", "olt_rx", "tx_power")):
                if _apply_signal_to_record(record, signal):
                    to_update.append(record)
                    single_retry_updates += 1
                if _append_sample(key, record, ONUOpticalSample.SOURCE_SINGLE_RETRY):
                    single_retry_samples += 1
                continue
        if _append_cached_sample(key, record):
            cached_samples += 1

    if to_update:
        ConfiguredONU.objects.bulk_update(
            to_update,
            ["onu_rx", "olt_rx", "tx_power", "signal_bucket", "status_updated_at"],
            batch_size=300,
        )
    if samples:
        ONUOpticalSample.objects.bulk_create(samples, batch_size=500, ignore_conflicts=False)

    return {
        "status": (
            f"SNMP signals: {filled}/{total} ONUs updated "
            f"({len(items)} SNMP entries; {single_retry_samples} single retries; {cached_samples} cached samples)."
        ),
        "filled": filled,
        "total": total,
        "snmp_items": len(items),
        "cached_samples": cached_samples,
        "single_retry_checked": single_retry_checked,
        "single_retry_updates": single_retry_updates,
        "single_retry_samples": single_retry_samples,
    }


def sync_missing_online_onu_power_for_olt(olt, limit=120):
    """Fill missing signal data for online ONUs.

    Strategy:
      1. SNMP bulk walk — fills all missing signals at once (fast, seconds).
      2. Telnet fallback — for any records still missing after SNMP.
    """
    from django.utils import timezone
    from .models import ConfiguredONU, ONUOpticalSample

    # ── 1. SNMP bulk attempt — 2 retries before giving up ───────────────────
    _SNMP_RETRIES = 2
    for _attempt in range(_SNMP_RETRIES):
        try:
            snmp_result = sync_onu_signals_from_snmp(olt, overwrite=False)
            if int(snmp_result.get("filled") or 0) > 0:
                return {
                    "checked": int(snmp_result.get("total") or 0),
                    "updated": int(snmp_result.get("filled") or 0),
                    "status": snmp_result.get("status") or "",
                    "source": "snmp",
                }
        except Exception:
            pass
        if _attempt < _SNMP_RETRIES - 1:
            time.sleep(3)

    # ── 2. Telnet fallback — only after all SNMP retries failed ──────────────
    # Match both empty string AND "--" (inventory sync stores "--" on optical timeout)
    records = list(
        ConfiguredONU.objects.filter(olt=olt, derived_status="online")
        .filter(Q(onu_rx="") | Q(onu_rx="--") | Q(olt_rx="") | Q(olt_rx="--"))
        .order_by("slot", "port", "ont_id")[:limit]
    )
    if not records:
        return {"checked": 0, "updated": 0, "status": "No online ONUs missing signal."}

    keys = [(int(record.slot), int(record.port), int(record.ont_id)) for record in records]
    optical_map = fetch_ont_optical_subset(olt, keys)
    updated_records = []
    samples = []
    now = timezone.now()
    recent_sample_keys = recent_onu_optical_sample_keys(olt, now=now)
    for record in records:
        key = (int(record.slot), int(record.port), int(record.ont_id))
        signal = optical_map.get(key) or {}
        onu_rx = str(signal.get("onu_rx") or "").strip()
        olt_rx = str(signal.get("olt_rx") or "").strip()
        tx_power = str(signal.get("tx_power") or "").strip()
        if not any(value and value != "--" for value in (onu_rx, olt_rx)):
            continue
        if onu_rx and onu_rx != "--":
            record.onu_rx = onu_rx[:32]
        if olt_rx and olt_rx != "--":
            record.olt_rx = olt_rx[:32]
        if tx_power and tx_power != "--":
            record.tx_power = tx_power[:32]
        _sig_src = record.olt_rx if (record.olt_rx and record.olt_rx != "--") else record.onu_rx
        record.signal_bucket = _signal_bucket_from_dbm_text(_sig_src)
        record.status_updated_at = now
        updated_records.append(record)
        if key not in recent_sample_keys:
            samples.append(
                ONUOpticalSample(
                    olt=olt,
                    slot=record.slot,
                    port=record.port,
                    ont_id=record.ont_id,
                    onu_rx=record.onu_rx,
                    olt_rx=record.olt_rx,
                    tx_power=record.tx_power,
                    sample_source=ONUOpticalSample.SOURCE_FRESH,
                )
            )
            recent_sample_keys.add(key)

    if updated_records:
        ConfiguredONU.objects.bulk_update(
            updated_records,
            ["onu_rx", "olt_rx", "tx_power", "signal_bucket", "status_updated_at"],
            batch_size=200,
        )
    if samples:
        ONUOpticalSample.objects.bulk_create(samples, batch_size=200)
    return {
        "checked": len(records),
        "updated": len(updated_records),
        "status": f"Online missing signal checked {len(records)}, updated {len(updated_records)}",
    }


def sync_online_onu_power_for_olt(olt, limit=None, start_pk=0):
    from django.utils import timezone
    from .models import ConfiguredONU, ONUOpticalSample

    base_qs = ConfiguredONU.objects.filter(olt=olt, derived_status="online").order_by("id")
    qs = base_qs.filter(pk__gt=int(start_pk or 0)) if int(start_pk or 0) > 0 else base_qs
    records = list(qs[:limit] if limit else qs)
    wrapped = False
    if not records and int(start_pk or 0) > 0:
        wrapped = True
        records = list(base_qs[:limit] if limit else base_qs)
    if not records:
        return {"checked": 0, "updated": 0, "status": "No online ONUs found.", "last_pk": 0}

    keys = [(int(record.slot), int(record.port), int(record.ont_id)) for record in records]
    optical_map = fetch_ont_optical_subset(olt, keys)
    updated_records = []
    samples = []
    now = timezone.now()
    recent_sample_keys = recent_onu_optical_sample_keys(olt, now=now)
    for record in records:
        key = (int(record.slot), int(record.port), int(record.ont_id))
        signal = optical_map.get(key) or {}
        onu_rx = str(signal.get("onu_rx") or "").strip()
        olt_rx = str(signal.get("olt_rx") or "").strip()
        tx_power = str(signal.get("tx_power") or "").strip()
        if not any(value and value != "--" for value in (onu_rx, olt_rx, tx_power)):
            continue
        if onu_rx and onu_rx != "--":
            record.onu_rx = onu_rx[:32]
        if olt_rx and olt_rx != "--":
            record.olt_rx = olt_rx[:32]
        if tx_power and tx_power != "--":
            record.tx_power = tx_power[:32]
        _sig_src = record.olt_rx if (record.olt_rx and record.olt_rx != "--") else record.onu_rx
        record.signal_bucket = _signal_bucket_from_dbm_text(_sig_src)
        record.status_updated_at = now
        updated_records.append(record)
        if key not in recent_sample_keys:
            samples.append(
                ONUOpticalSample(
                    olt=olt,
                    slot=record.slot,
                    port=record.port,
                    ont_id=record.ont_id,
                    onu_rx=record.onu_rx,
                    olt_rx=record.olt_rx,
                    tx_power=record.tx_power,
                    sample_source=ONUOpticalSample.SOURCE_FRESH,
                )
            )
            recent_sample_keys.add(key)

    if updated_records:
        ConfiguredONU.objects.bulk_update(
            updated_records,
            ["onu_rx", "olt_rx", "tx_power", "signal_bucket", "status_updated_at"],
            batch_size=200,
        )
    if samples:
        ONUOpticalSample.objects.bulk_create(samples, batch_size=500)
    return {
        "checked": len(records),
        "updated": len(updated_records),
        "status": f"Online ONU power checked {len(records)}, updated {len(updated_records)}",
        "last_pk": 0 if wrapped else int(records[-1].pk),
    }


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
                        "type": (
                            current.get("ont equipmentid")
                            or current.get("ont equipment id")
                            or current.get("ont extended model")
                            or current.get("ont model")
                            or "-"
                        ),
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
        elif key == "ont mac" and value:
            # EPON autofind identifies ONTs by MAC (e.g. E4A8-B6A4-2B92), not SN.
            # Keep the dashed MAC form for display/authorize (mac-auth).
            current["sn_display"] = value.strip()
            current["pon_type"] = _normalize_autofind_pon_type(global_pon_type or "EPON")

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
        if not re.search(r"(?i)\bont\s+sn\b|\bont\s+mac\b|\bautofind\s+ont\b", str(output or "")):
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
        command = f"display vlan {int(start_vlan)} to {int(end_vlan)}"
        output = _run_telnet_command(tn, command, enter_until_prompt=True)
        rows = _parse_vlan_table(output)
        expected = {int(vlan_id) for vlan_id in range(int(start_vlan), int(end_vlan) + 1)}
        found = {int(row.get("vlan_id") or 0) for row in rows if int(row.get("vlan_id") or 0)}
        result["ok"] = expected.issubset(found)
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
    result["message"] = "VLAN range created."
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


def _vlan_cli_is_idempotent(text, *, remove=False):
    """True when a Huawei VLAN error just means the change was already in place.

    These are safe to treat as success so the flow does not break when a VLAN /
    port-binding already exists (add) or is already gone (remove).
    """
    lowered = str(text or "").strip().lower()
    if not lowered:
        return False
    add_tokens = (
        "already exist",          # covers "already exists"
        "already been added",
        "already added",
        "already in the vlan",
        "already configured",
        "same as before",
        "the configuration is the same",
        "may already exist",
        "vlan(s) may already",
    )
    if any(token in lowered for token in add_tokens):
        return True
    if remove:
        remove_tokens = (
            "does not exist",
            "not exist",
            "not found",
            "not in the vlan",
            "is not configured",
        )
        if any(token in lowered for token in remove_tokens):
            return True
    return False


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
    if vlan_id < 1 or vlan_id > 4094:
        result["message"] = "VLAN ID must be between 1 and 4094."
        return result
    description = str(description or "").strip()[:32]
    tn, status = open_telnet_authenticated_session(olt)
    if tn is None:
        result["message"] = status or "Telnet session could not be opened."
        return result

    transcript_parts = []
    try:
        _prepare_telnet_cli_session(tn, use_paging=False)
        entered_config, config_output = _enter_config_mode(tn)
        if config_output:
            transcript_parts.append(str(config_output).strip())
        if not entered_config:
            result["message"] = "Unable to enter configuration mode."
            result["transcript"] = "\n".join(part for part in transcript_parts if part)
            return result

        create_command = f"vlan {int(vlan_id)} smart"
        create_output = _run_telnet_command(tn, create_command, enter_until_prompt=True)
        if create_output:
            transcript_parts.append(str(create_output).strip())

        create_text = str(create_output or "").strip()
        already_existed = _vlan_cli_is_idempotent(create_text)
        if _is_cli_error_text(create_text) and not already_existed:
            result["message"] = _clean_cli_response_text(create_command, create_output) or "OLT rejected VLAN create command."
            result["transcript"] = "\n".join(part for part in transcript_parts if part)
            return result

        # Setting a VLAN description on Huawei is a separate global command —
        # "vlan desc <id> description <text>" — not a bare "description" in the
        # config view (that returns "Unknown command"). A description failure
        # must NOT break VLAN creation, so it is only a warning.
        description_warning = ""
        if description:
            desc_command = f"vlan desc {int(vlan_id)} description {description}"
            desc_output = _run_telnet_command(tn, desc_command, enter_until_prompt=True)
            if desc_output:
                transcript_parts.append(str(desc_output).strip())
            desc_text = str(desc_output or "").strip()
            if _is_cli_error_text(desc_text) and not _vlan_cli_is_idempotent(desc_text):
                description_warning = " (description could not be set)"

        quit_output = _run_telnet_command(tn, "quit", enter_until_prompt=True)
        if quit_output:
            transcript_parts.append(str(quit_output).strip())
        save_output = _schedule_olt_save_from_command(olt, "VLAN create")
        if save_output:
            transcript_parts.append(str(save_output).strip())

        result["ok"] = True
        result["message"] = ("Already exists" if already_existed else "Created") + description_warning
        result["transcript"] = "\n".join(part for part in transcript_parts if part)
        return result
    except (socket.timeout, TimeoutError):
        result["message"] = "Telnet timeout while creating VLAN."
        result["transcript"] = "\n".join(part for part in transcript_parts if part)
        return result
    except EOFError:
        result["message"] = "Telnet connection closed while creating VLAN."
        result["transcript"] = "\n".join(part for part in transcript_parts if part)
        return result
    except OSError as exc:
        result["message"] = f"Telnet error while creating VLAN: {exc}"
        result["transcript"] = "\n".join(part for part in transcript_parts if part)
        return result
    finally:
        _close_telnet_session(tn)


def _parse_uplink_port_command_parts(port_name):
    text = str(port_name or "").strip().lower()
    text = text.replace("ethernet", "").replace("gigabitethernet", "").replace("xge", "")
    match = re.search(r"(\d+)\s*/\s*(\d+)\s*/\s*(\d+)", text)
    if not match:
        return None
    frame, slot, port = [int(part) for part in match.groups()]
    return frame, slot, port


def _parse_display_port_vlan_ids(output_text):
    vlan_ids = set()
    for raw_line in str(output_text or "").splitlines():
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("-"):
            continue
        if re.search(r"(?i)\b(total|native\s+vlan|command|display\s+port\s+vlan)\b", stripped):
            continue
        for token in re.findall(r"\b\d{1,4}\b", stripped):
            try:
                value = int(token)
            except (TypeError, ValueError):
                continue
            if 1 <= value <= 4094:
                vlan_ids.add(value)
    return vlan_ids


def _parse_display_port_vlan_snapshot(output_text):
    vlan_ids = sorted(_parse_display_port_vlan_ids(output_text))
    native_vlan = ""
    match = re.search(r"(?i)\bNative\s+VLAN\s*:\s*(\d+)", str(output_text or ""))
    if match:
        native_vlan = match.group(1).strip()
    return {
        "tagged_vlans": ", ".join(str(vlan_id) for vlan_id in vlan_ids) if vlan_ids else "-",
        "pvid_untag": native_vlan or "-",
    }


def refresh_uplink_vlan_snapshot(olt):
    result = {
        "ok": False,
        "rows": list(getattr(olt, "uplink_cache", []) or []),
        "status": "No uplink ports in database.",
        "updated": 0,
    }
    rows = list(getattr(olt, "uplink_cache", []) or [])
    if not rows:
        return result

    tn, status = open_telnet_authenticated_session(olt)
    if tn is None:
        result["status"] = status or "Telnet session could not be opened."
        return result

    updated = 0
    try:
        _prepare_telnet_cli_session(tn, use_paging=True)
        for row in rows:
            port_name = str((row or {}).get("port") or "").strip()
            parsed_port = _parse_uplink_port_command_parts(port_name)
            if not parsed_port:
                continue
            frame, slot, port = parsed_port
            command = f"display port vlan {frame}/{slot}/{port}"
            output = _run_telnet_command(tn, command, enter_until_prompt=True, max_wait_seconds=25, step_timeout=0.6)
            snapshot = _parse_display_port_vlan_snapshot(output)
            if snapshot["tagged_vlans"] != (row.get("tagged_vlans") or "-") or snapshot["pvid_untag"] != (row.get("pvid_untag") or "-"):
                row["tagged_vlans"] = snapshot["tagged_vlans"]
                row["pvid_untag"] = snapshot["pvid_untag"]
                updated += 1
        # Also refresh the link-aggregation (LAG) info so the Aggregate column
        # populates on a "Refresh VLANs" too (reuse the open session).
        agg_map = _fetch_link_aggregation_map(olt, tn=tn)
        for row in rows:
            parsed_port = _parse_uplink_port_command_parts(str((row or {}).get("port") or "").strip())
            fsp = "/".join(str(int(v)) for v in parsed_port) if parsed_port else ""
            row["aggregate"] = agg_map.get(fsp) or {}
        olt.uplink_cache = rows
        olt.uplink_status = f"Uplink VLANs refreshed: {updated} port(s) updated."
        olt.uplink_refreshed_at = timezone.now()
        olt.save(update_fields=["uplink_cache", "uplink_status", "uplink_refreshed_at"])
        result.update({
            "ok": True,
            "rows": rows,
            "status": olt.uplink_status,
            "updated": updated,
        })
        return result
    except (socket.timeout, TimeoutError):
        result["status"] = "Telnet timeout while refreshing uplink VLANs."
        return result
    except (EOFError, OSError) as exc:
        result["status"] = f"Telnet error while refreshing uplink VLANs: {exc}"
        return result
    finally:
        _close_telnet_session(tn)


def configure_vlan_uplink_port(olt, vlan_id, uplink_port, *, create_vlan=False, remove=False):
    result = {
        "ok": False,
        "message": "VLAN uplink command failed.",
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
    parsed_port = _parse_uplink_port_command_parts(uplink_port)
    if not parsed_port:
        result["message"] = "Invalid uplink port."
        return result
    frame, slot, port = parsed_port

    tn, status = open_telnet_authenticated_session(olt)
    if tn is None:
        result["message"] = status or "Telnet session could not be opened."
        return result

    transcript_parts = []
    try:
        _prepare_telnet_cli_session(tn, use_paging=False)
        entered_config, config_output = _enter_config_mode(tn)
        if config_output:
            transcript_parts.append(str(config_output).strip())
        if not entered_config:
            result["message"] = "Unable to enter configuration mode."
            result["transcript"] = "\n".join(part for part in transcript_parts if part)
            return result

        if create_vlan and not remove:
            create_command = f"vlan {vlan_id} smart"
            create_output = _run_telnet_command(tn, create_command, enter_until_prompt=True)
            if create_output:
                transcript_parts.append(str(create_output).strip())
            create_text = str(create_output or "").strip()
            if _is_cli_error_text(create_text) and not _vlan_cli_is_idempotent(create_text):
                result["message"] = _clean_cli_response_text(create_command, create_output) or "OLT rejected VLAN command."
                result["transcript"] = "\n".join(part for part in transcript_parts if part)
                return result

        action_command = (
            f"undo port vlan {vlan_id} {frame}/{slot} {port}"
            if remove
            else f"port vlan {vlan_id} {frame}/{slot} {port}"
        )
        action_output = _run_telnet_command(tn, action_command, enter_until_prompt=True)
        if action_output:
            transcript_parts.append(str(action_output).strip())
        action_text = str(action_output or "").strip()
        # "already added" (add) or "does not exist" (remove) means the desired
        # state is already in place — don't break the flow on those.
        if _is_cli_error_text(action_text) and not _vlan_cli_is_idempotent(action_text, remove=remove):
            result["message"] = _clean_cli_response_text(action_command, action_output) or "OLT rejected VLAN uplink command."
            result["transcript"] = "\n".join(part for part in transcript_parts if part)
            return result

        verify_command = f"display port vlan {frame}/{slot}/{port}"
        verify_output = _run_telnet_command(tn, verify_command, enter_until_prompt=True)
        if verify_output:
            transcript_parts.append(str(verify_output).strip())
        verified_vlans = _parse_display_port_vlan_ids(verify_output)
        verified = int(vlan_id) not in verified_vlans if remove else int(vlan_id) in verified_vlans
        if not verified:
            result["message"] = (
                f"VLAN {vlan_id} command completed but was not verified on uplink {uplink_port}."
            )
            result["transcript"] = "\n".join(part for part in transcript_parts if part)
            return result

        quit_output = _run_telnet_command(tn, "quit", enter_until_prompt=True)
        if quit_output:
            transcript_parts.append(str(quit_output).strip())
        save_output = _schedule_olt_save_from_command(olt, "VLAN uplink change")
        if save_output:
            transcript_parts.append(str(save_output).strip())

        result["ok"] = True
        result["message"] = (
            f"VLAN {vlan_id} removed from uplink {uplink_port}."
            if remove
            else f"VLAN {vlan_id} added to uplink {uplink_port}."
        )
        result["transcript"] = "\n".join(part for part in transcript_parts if part)
        return result
    except (socket.timeout, TimeoutError):
        result["message"] = "Telnet timeout during VLAN uplink command."
        result["transcript"] = "\n".join(part for part in transcript_parts if part)
        return result
    except EOFError:
        result["message"] = "Telnet connection closed during VLAN uplink command."
        result["transcript"] = "\n".join(part for part in transcript_parts if part)
        return result
    except OSError as exc:
        result["message"] = f"Telnet error during VLAN uplink command: {exc}"
        result["transcript"] = "\n".join(part for part in transcript_parts if part)
        return result
    finally:
        _close_telnet_session(tn)


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
                row["sfp_tx"] = _format_sfp_tx_dbm(sfp_tx) or sfp_tx


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
    for olt in OLT.objects.filter(olt_background_enabled_q(now)).only("id", "name", "ip_address", "snmp_port", "snmp_community"):
        snapshot = fetch_snmp_pon_aggregate_counters(olt)
        if not snapshot.get("ok"):
            continue
        in_octets = _db_safe_int(snapshot.get("in_octets"))
        out_octets = _db_safe_int(snapshot.get("out_octets"))
        in_packets = _db_safe_int(snapshot.get("in_packets"))
        out_packets = _db_safe_int(snapshot.get("out_packets"))
        total_in_octets = _db_safe_int(total_in_octets + in_octets)
        total_out_octets = _db_safe_int(total_out_octets + out_octets)
        total_in_packets = _db_safe_int(total_in_packets + in_packets)
        total_out_packets = _db_safe_int(total_out_packets + out_packets)
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

    if getattr(olt, "pricing_access_locked", False):
        return None

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
        in_octets=_db_safe_int(snapshot.get("in_octets")),
        out_octets=_db_safe_int(snapshot.get("out_octets")),
        in_packets=_db_safe_int(snapshot.get("in_packets")),
        out_packets=_db_safe_int(snapshot.get("out_packets")),
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
    for olt in OLT.objects.filter(olt_background_enabled_q(now)).only("id", "ip_address", "snmp_port", "snmp_community"):
        snapshot = fetch_snmp_pon_port_counters(olt)
        if not snapshot.get("ok"):
            continue
        for row in snapshot.get("rows") or []:
            samples.append(
                PONPortTrafficSample(
                    olt=olt,
                    slot=int(row.get("slot") or 0),
                    port=int(row.get("port") or 0),
                    in_octets=_db_safe_int(row.get("in_octets")),
                    out_octets=_db_safe_int(row.get("out_octets")),
                    in_packets=_db_safe_int(row.get("in_packets")),
                    out_packets=_db_safe_int(row.get("out_packets")),
                )
            )
    if not samples:
        return None
    PONPortTrafficSample.objects.bulk_create(samples, batch_size=500)
    return samples[0]


def record_pon_port_traffic_sample_for_olt(olt, force=False, min_interval_seconds=15):
    from .models import PONPortTrafficSample

    if getattr(olt, "pricing_access_locked", False):
        return None

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
            in_octets=_db_safe_int(row.get("in_octets")),
            out_octets=_db_safe_int(row.get("out_octets")),
            in_packets=_db_safe_int(row.get("in_packets")),
            out_packets=_db_safe_int(row.get("out_packets")),
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
    for olt in OLT.objects.filter(olt_background_enabled_q(now)).only("id", "ip_address", "snmp_port", "snmp_community"):
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
                    in_octets=_db_safe_int(row.get("in_octets")),
                    out_octets=_db_safe_int(row.get("out_octets")),
                )
            )
    if not samples:
        return None
    UplinkPortTrafficSample.objects.bulk_create(samples, batch_size=500)
    return samples[0]


def record_uplink_port_traffic_sample_for_olt(olt, force=False, min_interval_seconds=15):
    from .models import UplinkPortTrafficSample

    if getattr(olt, "pricing_access_locked", False):
        return None

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
                in_octets=_db_safe_int(row.get("in_octets")),
                out_octets=_db_safe_int(row.get("out_octets")),
                sampled_at=sample_time,
            )
        )
    if not samples:
        return None
    UplinkPortTrafficSample.objects.bulk_create(samples, batch_size=500)
    return samples[0]


def record_onu_traffic_sample(olt, slot, port, ont_id):
    from .models import ONUTrafficSample

    if getattr(olt, "pricing_access_locked", False):
        return {"ok": False, "status": "OLT subscription is locked."}

    counters = fetch_single_onu_snmp_traffic_counters(olt, slot, port, ont_id)
    if not counters.get("ok"):
        return {"ok": False, "status": counters.get("status") or "SNMP ONU traffic unavailable"}

    now = timezone.now()
    previous = (
        ONUTrafficSample.objects.filter(olt=olt, slot=int(slot), port=int(port), ont_id=int(ont_id))
        .order_by("-sampled_at")
        .first()
    )
    up_bytes = _db_safe_int(counters.get("up_bytes"))
    down_bytes = _db_safe_int(counters.get("down_bytes"))
    up_packets = _db_safe_int(counters.get("up_packets"))
    down_packets = _db_safe_int(counters.get("down_packets"))
    up_bps = 0.0
    down_bps = 0.0
    if previous:
        seconds = max(1.0, (now - previous.sampled_at).total_seconds())
        if up_bytes >= int(previous.up_bytes or 0):
            up_bps = ((up_bytes - int(previous.up_bytes or 0)) * 8) / seconds
        if down_bytes >= int(previous.down_bytes or 0):
            down_bps = ((down_bytes - int(previous.down_bytes or 0)) * 8) / seconds

    sample = ONUTrafficSample.objects.create(
        olt=olt,
        slot=int(slot),
        port=int(port),
        ont_id=int(ont_id),
        up_bytes=up_bytes,
        down_bytes=down_bytes,
        up_packets=up_packets,
        down_packets=down_packets,
        up_bps=up_bps,
        down_bps=down_bps,
    )
    return {
        "ok": True,
        "sample": sample,
        "up_bps": round(up_bps, 2),
        "down_bps": round(down_bps, 2),
        "status": counters.get("status") or "SNMP ONU traffic fetched",
    }


def record_recent_onu_traffic_samples(max_keys=None, active_within_hours=None, min_interval_seconds=None):
    """Refresh ONU traffic samples only for ONUs that users recently opened.

    Polling every ONU's traffic counters would be too heavy. This keeps graphs
    useful for active ONUs while protecting the server and OLTs from load spikes.
    """
    from django.db.models import Max
    from .models import OLT, ONUTrafficSample

    max_keys = int(max_keys or getattr(settings, "OLT_ONU_TRAFFIC_BACKGROUND_MAX_KEYS", 200) or 200)
    active_within_hours = int(active_within_hours or getattr(settings, "OLT_ONU_TRAFFIC_BACKGROUND_ACTIVE_HOURS", 24) or 24)
    min_interval_seconds = int(min_interval_seconds or getattr(settings, "OLT_ONU_TRAFFIC_BACKGROUND_SECONDS", 600) or 600)
    if max_keys <= 0:
        return {"checked": 0, "sampled": 0, "status": "ONU traffic background sampling disabled."}

    now = timezone.now()
    active_since = now - datetime.timedelta(hours=max(1, active_within_hours))
    due_before = now - datetime.timedelta(seconds=max(60, min_interval_seconds))
    latest_rows = (
        ONUTrafficSample.objects
        .filter(sampled_at__gte=active_since)
        .values("olt_id", "slot", "port", "ont_id")
        .annotate(latest=Max("sampled_at"))
        .filter(latest__lt=due_before)
        .order_by("latest")[:max_keys]
    )
    rows = list(latest_rows)
    if not rows:
        return {"checked": 0, "sampled": 0, "status": "No recent ONU traffic samples are due."}

    olt_map = {
        int(olt.id): olt
        for olt in OLT.objects.filter(olt_background_enabled_q(now), id__in={int(row["olt_id"]) for row in rows})
        .only("id", "ip_address", "snmp_port", "snmp_community", "pricing_locked", "pricing_expires_at")
    }
    checked = 0
    sampled = 0
    for row in rows:
        olt = olt_map.get(int(row["olt_id"]))
        if not olt:
            continue
        checked += 1
        try:
            result = record_onu_traffic_sample(olt, int(row["slot"]), int(row["port"]), int(row["ont_id"]))
            if result.get("ok"):
                sampled += 1
        except Exception:
            continue
    return {"checked": checked, "sampled": sampled, "status": f"Recent ONU traffic sampled {sampled}/{checked}."}


def _delete_old_rows_in_chunks(model, cutoff, *, batch_size=5000, max_batches=4):
    deleted_total = 0
    batch_size = max(100, int(batch_size or 5000))
    max_batches = max(1, int(max_batches or 1))
    for _ in range(max_batches):
        ids = list(
            model.objects.filter(sampled_at__lt=cutoff)
            .order_by("pk")
            .values_list("pk", flat=True)[:batch_size]
        )
        if not ids:
            break
        deleted, _ = model.objects.filter(pk__in=ids).delete()
        deleted_total += int(deleted or 0)
        if len(ids) < batch_size:
            break
    return deleted_total


def prune_sample_history():
    """Trim old high-volume samples in small batches to keep SQLite responsive."""
    from .models import (
        DashboardStatusSample,
        ONUOpticalSample,
        ONUStatusSample,
        ONUTrafficSample,
        PONTrafficSample,
        PONPortTrafficSample,
        UplinkPortTrafficSample,
    )

    retention_days = getattr(settings, "OLT_SAMPLE_RETENTION_DAYS", {}) or {}
    defaults = {
        "onu_optical": 15,
        "onu_status": 30,
        "onu_traffic": 30,
        "pon_traffic": 30,
        "pon_port_traffic": 30,
        "uplink_port_traffic": 30,
        "dashboard_status": 180,
    }
    models = {
        "onu_optical": ONUOpticalSample,
        "onu_status": ONUStatusSample,
        "onu_traffic": ONUTrafficSample,
        "pon_traffic": PONTrafficSample,
        "pon_port_traffic": PONPortTrafficSample,
        "uplink_port_traffic": UplinkPortTrafficSample,
        "dashboard_status": DashboardStatusSample,
    }
    batch_size = int(getattr(settings, "OLT_SAMPLE_RETENTION_BATCH_SIZE", 5000) or 5000)
    max_batches = int(getattr(settings, "OLT_SAMPLE_RETENTION_MAX_BATCHES_PER_MODEL", 4) or 4)
    now = timezone.now()
    deleted_by_model = {}
    for key, model in models.items():
        days = int(retention_days.get(key, defaults[key]) or 0)
        if days <= 0:
            continue
        cutoff = now - datetime.timedelta(days=days)
        try:
            deleted_by_model[key] = _delete_old_rows_in_chunks(
                model,
                cutoff,
                batch_size=batch_size,
                max_batches=max_batches,
            )
        except OperationalError:
            deleted_by_model[key] = 0
    return deleted_by_model


def dashboard_online_status_q():
    return Q(derived_status__iexact="online")


def olt_background_enabled_q(now=None):
    """Return the OLT filter used by background polling/sampling jobs.

    Locked or expired OLTs stay visible from stored DB data, but they must not
    consume SNMP/Telnet/background resources until the subscription is renewed.
    """
    now = now or timezone.now()
    return Q(pricing_locked=False) & (Q(pricing_expires_at__isnull=True) | Q(pricing_expires_at__gt=now))


def _extract_cached_onu_count(value, key):
    if isinstance(value, dict):
        try:
            return int(value.get(key.lower()) or value.get(key) or 0)
        except (TypeError, ValueError):
            return 0
    match = re.search(rf"{re.escape(str(key))}\s*:?\s*(\d+)", str(value or ""), flags=re.IGNORECASE)
    if not match:
        return 0
    try:
        return int(match.group(1))
    except (TypeError, ValueError):
        return 0


def _dashboard_status_counts_from_queryset(qs):
    from django.db.models import Count, Q
    online_q = dashboard_online_status_q()
    counts = qs.aggregate(
        total_onus=Count('id'),
        online_onus=Count('id', filter=online_q),
        admin_disabled=Count('id', filter=Q(derived_status='admin_disabled')),
        power_failure=Count('id', filter=Q(derived_status='power_failure')),
        loss_of_signal=Count('id', filter=Q(derived_status='loss_of_signal')),
        signal_warn=Count('id', filter=online_q & Q(signal_bucket='warn')),
        signal_bad=Count('id', filter=online_q & Q(signal_bucket='bad')),
    )
    return counts


def _refresh_dashboard_onu_statuses_from_snmp():
    """Refresh ONU online/offline state before taking dashboard samples."""
    from .models import OLT

    refreshed = 0
    updated = 0
    for olt in OLT.objects.filter(olt_background_enabled_q()).only("id", "name", "snmp_last_status").order_by("id"):
        try:
            result = sync_runtime_statuses_for_olt(olt, only_non_online=False, limit=None, write_samples=False)
            refreshed += int(result.get("checked") or 0)
            updated += int(result.get("updated") or 0)
        except Exception:
            continue
    return {"checked": refreshed, "updated": updated}


def record_dashboard_status_samples(force=False, refresh_onu_statuses=False, bypass_force_throttle=False):
    from .models import ConfiguredONU, DashboardStatusSample, OLT
    from django.db import transaction
    from django.db.models import Count, Q

    if refresh_onu_statuses:
        _refresh_dashboard_onu_statuses_from_snmp()

    global _DASHBOARD_STATUS_SAMPLE_LAST_FORCE_TS
    now_ts = time.time()
    if force and not bypass_force_throttle and (now_ts - _DASHBOARD_STATUS_SAMPLE_LAST_FORCE_TS) < 5:
        return False
    if not _DASHBOARD_STATUS_SAMPLE_LOCK.acquire(blocking=False):
        return False
    boundary = _current_dashboard_sample_boundary()
    try:
        latest = DashboardStatusSample.objects.order_by('-sampled_at').first()
        if latest and not force and latest.sampled_at >= boundary:
            return False

        global_counts = _dashboard_status_counts_from_queryset(ConfiguredONU.objects.all())
        online_q = dashboard_online_status_q()
        grouped_counts = {
            int(row['olt_id']): row
            for row in ConfiguredONU.objects.values('olt_id').annotate(
                total_onus=Count('id'),
                online_onus=Count('id', filter=online_q),
                admin_disabled=Count('id', filter=Q(derived_status='admin_disabled')),
                power_failure=Count('id', filter=Q(derived_status='power_failure')),
                loss_of_signal=Count('id', filter=Q(derived_status='loss_of_signal')),
                signal_warn=Count('id', filter=online_q & Q(signal_bucket='warn')),
                signal_bad=Count('id', filter=online_q & Q(signal_bucket='bad')),
            )
        }
        olts = list(OLT.objects.only('id', 'autofind_onu_count', 'autofind_new_count', 'autofind_resync_count'))
        samples = [
            DashboardStatusSample(
                olt=None,
                sampled_at=boundary,
                total_onus=int(global_counts.get('total_onus') or 0),
                online_onus=int(global_counts.get('online_onus') or 0),
                offline_onus=max(0, int(global_counts.get('total_onus') or 0) - int(global_counts.get('online_onus') or 0)),
                wait_for_authorize_total=sum(olt.autofind_onu_count or 0 for olt in olts),
                wait_for_authorize_new_total=sum(olt.autofind_new_count or 0 for olt in olts),
                wait_for_authorize_resync_total=sum(olt.autofind_resync_count or 0 for olt in olts),
                admin_disabled=int(global_counts.get('admin_disabled') or 0),
                power_failure=int(global_counts.get('power_failure') or 0),
                loss_of_signal=int(global_counts.get('loss_of_signal') or 0),
                signal_warn=int(global_counts.get('signal_warn') or 0),
                signal_bad=int(global_counts.get('signal_bad') or 0),
            )
        ]

        for olt in olts:
            counts = grouped_counts.get(int(olt.id), {})
            total = int(counts.get('total_onus') or 0)
            online = min(total, int(counts.get('online_onus') or 0))
            samples.append(
                DashboardStatusSample(
                    olt_id=olt.id,
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

        with transaction.atomic():
            if force:
                DashboardStatusSample.objects.filter(sampled_at__gte=boundary).delete()
            DashboardStatusSample.objects.bulk_create(samples, batch_size=200)
        if force:
            _DASHBOARD_STATUS_SAMPLE_LAST_FORCE_TS = now_ts
        return True
    finally:
        _DASHBOARD_STATUS_SAMPLE_LOCK.release()


def ensure_dashboard_status_samples_for_scope(olt_id=None):
    from .models import DashboardStatusSample

    latest_qs = DashboardStatusSample.objects.filter(olt_id=olt_id) if olt_id else DashboardStatusSample.objects.filter(olt__isnull=True)
    try:
        return latest_qs.order_by('-sampled_at').first()
    except OperationalError:
        return None


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


def read_telnet_raw(tn):
    """Non-blocking raw read for the interactive terminal.

    Returns whatever bytes are currently buffered, decoded as text with the
    device's control bytes (backspace, CR, ANSI escapes) left intact so a real
    terminal emulator can render them faithfully. Returns ``None`` if the
    session has closed, ``""`` when nothing is available right now.
    """
    if tn is None:
        return None
    try:
        data = tn.read_very_eager()
    except EOFError:
        return None
    except OSError:
        return None
    if not data:
        return ""
    _touch_telnet_session(tn)
    return data.decode("utf-8", errors="replace")


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
                    raw_output = _schedule_olt_save_from_command(olt, "SNMP configuration")
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

