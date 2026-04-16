import csv
import datetime
import ipaddress
import json
import re
import socket
import telnetlib
import threading
import time
from urllib.parse import urlencode
from zoneinfo import ZoneInfo

from django.contrib import messages
from django.contrib.sessions.exceptions import SessionInterrupted
from django.contrib.auth.decorators import login_required
from django.core.paginator import Paginator
from django.db import OperationalError
from django.db.models import Q
from django.http import HttpResponse, JsonResponse
from django.urls import reverse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST

from .forms import DBAProfileAddForm, OLTForm, VLANAddForm, VLANBulkAddForm
from .models import ConfiguredONU, DashboardStatusSample, OLT, OLTLoginHistory, ONUOpticalSample, ONUTrapEvent
from .services import get_olt_adapter
from .utils import (
    _dashboard_status_counts_from_queryset,
    add_dba_profile,
    add_vlan,
    add_vlan_range,
    build_dba_profile_row,
    delete_vlan_netconf,
    close_telnet_session,
    fetch_configured_onus_snapshot,
    fetch_dba_profile_snapshot,
    fetch_dba_profile_configuration,
    fetch_single_dba_profile,
    fetch_ont_optical_subset,
    fetch_ont_optical_subset_meta,
    fetch_single_ont_optical_info,
    fetch_single_ont_runtime_snapshot,
    fetch_single_ont_capability_snapshot,
    fetch_snmp_snapshot,
    fetch_telnet_version_snapshot,
    fetch_ont_autofind_snapshot,
    fetch_uplink_snapshot,
    fetch_vlan_range,
    fetch_vlan_snapshot,
    fetch_single_vlan,
    push_snmp_config_over_telnet,
    refresh_saved_pon_counts_from_inventory,
    save_dba_profile_snapshot,
    save_pon_ports_snapshot,
    save_uplink_snapshot,
    save_vlan_snapshot,
    sync_configured_onus_inventory,
    derive_inventory_onu_status,
    ensure_dashboard_status_samples_for_scope,
    map_onu_alarm_to_status,
    _parse_ont_duration_to_seconds,
    record_dashboard_status_samples,
)

_OLT_REFRESH_LOCK_GUARD = threading.Lock()
_OLT_REFRESH_LOCKS = {}
_PON_CACHE_LOCK = threading.Lock()
_PON_CACHE = {}
_PON_REFRESHING = set()
_SNAPSHOT_CACHE_LOCK = threading.Lock()
_SNAPSHOT_CACHE = {}
_SNAPSHOT_REFRESHING = set()
_UPLINK_CACHE_LOCK = threading.Lock()
_UPLINK_CACHE = {}
_VLAN_REFRESH_LOCK = threading.Lock()
_VLAN_REFRESHING = set()
_DBA_PROFILE_REFRESH_LOCK = threading.Lock()
_DBA_PROFILE_REFRESHING = set()
_AUTOFIND_REFRESH_GUARD = threading.Lock()
_AUTOFIND_REFRESH_THREAD = None
_CONFIGURED_ONU_CACHE_LOCK = threading.Lock()
_CONFIGURED_ONU_CACHE = {}
_CONFIGURED_ONU_SYNC_LOCK = threading.Lock()
_CONFIGURED_ONU_SYNCING = set()
_DEVICE_SNAPSHOT_SYNC_LOCK = threading.Lock()
_DEVICE_SNAPSHOT_SYNCING = set()
_DEVICE_SNAPSHOT_SCAN_LOCK = threading.Lock()
_LAST_DEVICE_SNAPSHOT_SCAN = None
PON_CACHE_SECONDS = 120
SNAPSHOT_CACHE_SECONDS = 90
CONFIGURED_ONU_CACHE_SECONDS = 180
CONFIGURED_ONU_SYNC_SECONDS = 300
DEVICE_SNAPSHOT_SCAN_SECONDS = 300
DASHBOARD_UPTIME_REFRESH_SECONDS = 900
_CLI_SESSIONS_LOCK = threading.Lock()
_CLI_SESSIONS = {}
CLI_SESSION_IDLE_SECONDS = 900


def _get_olt_refresh_lock(olt_id):
    with _OLT_REFRESH_LOCK_GUARD:
        lock = _OLT_REFRESH_LOCKS.get(olt_id)
        if lock is None:
            lock = threading.Lock()
            _OLT_REFRESH_LOCKS[olt_id] = lock
        return lock


def _try_acquire_olt_live_lock(olt_id, timeout=0.2):
    lock = _get_olt_refresh_lock(olt_id)
    if not lock.acquire(timeout=timeout):
        return None
    return lock


def _acquire_olt_live_lock_with_retry(olt_id, attempts=3, timeout=1.5, delay=0.6):
    for attempt in range(attempts):
        lock = _try_acquire_olt_live_lock(olt_id, timeout=timeout)
        if lock is not None:
            return lock
        if attempt < attempts - 1:
            time.sleep(delay)
    return None


def _is_retryable_telnet_status_text(status):
    text = str(status or "").lower()
    retry_tokens = (
        "timeout",
        "connection error",
        "connection closed",
        "device busy",
        "prompt not detected",
    )
    return any(token in text for token in retry_tokens)


def _fetch_dba_profile_snapshot_with_retry(olt, attempts=3, delay=0.8):
    latest = {"status": "DBA profiles unavailable", "rows": []}
    for attempt in range(attempts):
        latest = fetch_dba_profile_snapshot(olt)
        if (latest.get("rows") or []) or not _is_retryable_telnet_status_text(latest.get("status")):
            return latest
        if attempt < attempts - 1:
            time.sleep(delay)
    return latest


def _fetch_dba_profile_configuration_with_retry(olt, profile_id, profile_name="", attempts=3, delay=0.8):
    latest = {"ok": False, "message": "Profile configuration unavailable.", "transcript": "", "output": ""}
    for attempt in range(attempts):
        latest = fetch_dba_profile_configuration(olt, profile_id, profile_name)
        if latest.get("ok") or not _is_retryable_telnet_status_text(latest.get("message")):
            return latest
        if attempt < attempts - 1:
            time.sleep(delay)
    return latest


def _fetch_vlan_snapshot_with_retry(olt, attempts=3, delay=0.8):
    latest = {"status": "VLAN data unavailable", "rows": []}
    for attempt in range(attempts):
        latest = fetch_vlan_snapshot(olt)
        if (latest.get("rows") or []) or not _is_retryable_telnet_status_text(latest.get("status")):
            return latest
        if attempt < attempts - 1:
            time.sleep(delay)
    return latest


def _get_cached_pon_ports(olt_id, allow_stale=False):
    now = timezone.now()
    with _PON_CACHE_LOCK:
        row = _PON_CACHE.get(olt_id)
        if not row:
            return None, "", False
        cached_at = row.get("cached_at")
        if not cached_at:
            _PON_CACHE.pop(olt_id, None)
            return None, "", False
        age = (now - cached_at).total_seconds()
        is_fresh = age <= PON_CACHE_SECONDS
        if not is_fresh and not allow_stale:
            _PON_CACHE.pop(olt_id, None)
            return None, "", False
        return row.get("groups") or [], row.get("status") or "", is_fresh


def _set_cached_pon_ports(olt_id, groups, status):
    with _PON_CACHE_LOCK:
        _PON_CACHE[olt_id] = {
            "groups": groups or [],
            "status": (status or "")[:300],
            "cached_at": timezone.now(),
        }


def _sum_onu_counts(groups):
    online = 0
    offline = 0
    for group in groups or []:
        for row in group.get("ports", []):
            try:
                online += int(row.get("onus_online", 0) or 0)
            except (TypeError, ValueError):
                pass
            try:
                offline += int(row.get("onus_offline", 0) or 0)
            except (TypeError, ValueError):
                pass
    return online, offline


def _summarize_uplinks(rows):
    total = len(rows or [])
    up = 0
    down = 0
    for row in rows or []:
        status = str(row.get("oper_status", "")).strip().upper()
        if status == "UP":
            up += 1
        elif status == "DOWN":
            down += 1
    return {
        "total": total,
        "up": up,
        "down": down,
    }


def _safe_int(value, default=0):
    try:
        return int(str(value).strip())
    except (TypeError, ValueError, AttributeError):
        return default


def _format_gbps(bits_per_second):
    if bits_per_second is None or bits_per_second < 0:
        return "--"
    gbps = bits_per_second / 1_000_000_000
    if gbps >= 1:
        return f"{gbps:.2f} Gbps"
    mbps = bits_per_second / 1_000_000
    if mbps >= 1:
        return f"{mbps:.0f} Mbps"
    kbps = bits_per_second / 1_000
    if kbps >= 1:
        return f"{kbps:.0f} Kbps"
    return "0 bps"


def _compute_uplink_traffic(previous_data, current_data, elapsed_seconds):
    if not previous_data or not current_data or elapsed_seconds <= 0:
        return "--"
    previous_rows = {
        str(row.get("index")): row
        for row in (previous_data.get("rows") or [])
        if row.get("index") is not None
    }
    total_bits_per_second = 0.0
    matched = 0
    for row in current_data.get("rows") or []:
        index = str(row.get("index"))
        previous_row = previous_rows.get(index)
        if not previous_row:
            continue
        current_total = _safe_int(row.get("in_octets")) + _safe_int(row.get("out_octets"))
        previous_total = _safe_int(previous_row.get("in_octets")) + _safe_int(previous_row.get("out_octets"))
        delta_octets = current_total - previous_total
        if delta_octets < 0:
            continue
        total_bits_per_second += (delta_octets * 8.0) / elapsed_seconds
        matched += 1
    if matched == 0:
        return "--"
    return _format_gbps(total_bits_per_second)


def _get_cached_snapshot(olt_id, allow_stale=False):
    now = timezone.now()
    with _SNAPSHOT_CACHE_LOCK:
        row = _SNAPSHOT_CACHE.get(olt_id)
        if not row:
            return None, False
        cached_at = row.get("cached_at")
        if not cached_at:
            _SNAPSHOT_CACHE.pop(olt_id, None)
            return None, False
        age = (now - cached_at).total_seconds()
        is_fresh = age <= SNAPSHOT_CACHE_SECONDS
        if not is_fresh and not allow_stale:
            _SNAPSHOT_CACHE.pop(olt_id, None)
            return None, False
        return row.get("snapshot"), is_fresh


def _set_cached_snapshot(olt_id, snapshot):
    with _SNAPSHOT_CACHE_LOCK:
        _SNAPSHOT_CACHE[olt_id] = {
            "snapshot": snapshot or {},
            "cached_at": timezone.now(),
        }


def _get_cached_uplink(olt_id):
    with _UPLINK_CACHE_LOCK:
        row = _UPLINK_CACHE.get(olt_id)
        if not row:
            return None
        return row.get("data") or {"status": "", "rows": []}


def _get_cached_uplink_bundle(olt_id):
    with _UPLINK_CACHE_LOCK:
        row = _UPLINK_CACHE.get(olt_id)
        if not row:
            return None
        return {
            "data": row.get("data") or {"status": "", "rows": []},
            "cached_at": row.get("cached_at"),
        }


def _set_cached_uplink(olt_id, data):
    now = timezone.now()
    with _UPLINK_CACHE_LOCK:
        previous = _UPLINK_CACHE.get(olt_id)
        prepared = dict(data or {"status": "", "rows": []})
        if previous:
            previous_data = previous.get("data") or {"status": "", "rows": []}
            previous_cached_at = previous.get("cached_at")
            elapsed_seconds = (now - previous_cached_at).total_seconds() if previous_cached_at else 0
            prepared["traffic_gbps"] = _compute_uplink_traffic(previous_data, prepared, elapsed_seconds)
        else:
            prepared["traffic_gbps"] = prepared.get("traffic_gbps") or "--"
        _UPLINK_CACHE[olt_id] = {
            "data": prepared,
            "cached_at": now,
        }
        return prepared


def _get_cached_configured_onus(olt_id, allow_stale=False):
    now = timezone.now()
    with _CONFIGURED_ONU_CACHE_LOCK:
        row = _CONFIGURED_ONU_CACHE.get(olt_id)
        if not row:
            return None, "", False
        cached_at = row.get("cached_at")
        if not cached_at:
            _CONFIGURED_ONU_CACHE.pop(olt_id, None)
            return None, "", False
        age = (now - cached_at).total_seconds()
        is_fresh = age <= CONFIGURED_ONU_CACHE_SECONDS
        if not is_fresh and not allow_stale:
            _CONFIGURED_ONU_CACHE.pop(olt_id, None)
            return None, "", False
        return row.get("rows") or [], row.get("status") or "", is_fresh


def _set_cached_configured_onus(olt_id, rows, status):
    with _CONFIGURED_ONU_CACHE_LOCK:
        _CONFIGURED_ONU_CACHE[olt_id] = {
            "rows": rows or [],
            "status": (status or "")[:300],
            "cached_at": timezone.now(),
        }


def _configured_rows_need_refresh(rows):
    if not rows:
        return True
    sample = list(rows[:20])
    if not sample:
        return True
    described = 0
    for row in sample:
        if str(row.get("description") or "").strip():
            described += 1
    return described < max(3, len(sample) // 2)


def _configured_onu_record_to_row(record):
    description = (record.description or "").strip()
    sn = (record.sn or "").strip()
    return {
        "frame": int(record.frame or 0),
        "slot": int(record.slot or 0),
        "port": int(record.port or 0),
        "ont_id": int(record.ont_id or 0),
        "sn": sn,
        "control_flag": (record.control_flag or "").strip(),
        "run_state": (record.run_state or "").strip(),
        "config_state": (record.config_state or "").strip(),
        "match_state": (record.match_state or "").strip(),
        "protect_side": (record.protect_side or "").strip(),
        "description": description,
        "address": (record.address or "").strip(),
        "contact": (record.contact or "").strip(),
        "onu_rx": (record.onu_rx or "").strip() or "--",
        "olt_rx": (record.olt_rx or "").strip() or "--",
        "tx_power": (record.tx_power or "").strip() or "--",
        "signal_bucket": (record.signal_bucket or "").strip(),
        "derived_status": (record.derived_status or "").strip(),
        "status_source": (record.status_source or "").strip(),
        "status_first_seen_at": record.status_first_seen_at,
        "status_updated_at": record.status_updated_at,
        "raw_line": record.raw_line or "",
        "fsp": f"{int(record.frame or 0)}/{int(record.slot or 0)}/{int(record.port or 0)}",
    }


def _clean_onu_detail_text(value, max_length):
    text = str(value or "").strip()
    return text[:max_length]


def _configured_onu_inventory_is_stale(olt):
    latest_synced_at = (
        ConfiguredONU.objects.filter(olt_id=olt.pk)
        .order_by("-synced_at")
        .values_list("synced_at", flat=True)
        .first()
    )
    if latest_synced_at is None:
        return True
    age = (timezone.now() - latest_synced_at).total_seconds()
    return age >= CONFIGURED_ONU_SYNC_SECONDS


def _refresh_configured_onu_inventory_worker(olt_id):
    try:
        olt = OLT.objects.filter(pk=olt_id).first()
        if not olt:
            return
        sync_configured_onus_inventory(olt)
        rows = [
            _configured_onu_record_to_row(record)
            for record in ConfiguredONU.objects.filter(olt=olt).order_by("slot", "port", "ont_id")
        ]
        if rows:
            _set_cached_configured_onus(olt_id, rows, f"Configured ONUs loaded: {len(rows)}")
    finally:
        with _CONFIGURED_ONU_SYNC_LOCK:
            _CONFIGURED_ONU_SYNCING.discard(olt_id)


def _schedule_configured_onu_inventory_refresh(olt_id):
    with _CONFIGURED_ONU_SYNC_LOCK:
        if olt_id in _CONFIGURED_ONU_SYNCING:
            return
        _CONFIGURED_ONU_SYNCING.add(olt_id)
    threading.Thread(target=_refresh_configured_onu_inventory_worker, args=(olt_id,), daemon=True).start()


def _schedule_missing_onu_inventory_syncs():
    existing_olt_ids = set(
        ConfiguredONU.objects.order_by().values_list("olt_id", flat=True).distinct()
    )
    missing_olt_ids = [
        olt_id
        for olt_id in OLT.objects.values_list("id", flat=True)
        if olt_id not in existing_olt_ids
    ]
    for olt_id in missing_olt_ids:
        _schedule_configured_onu_inventory_refresh(olt_id)


def _get_or_sync_configured_onu_rows(olt):
    records = list(
        ConfiguredONU.objects.filter(olt=olt).order_by("slot", "port", "ont_id")
    )
    if not records:
        sync_configured_onus_inventory(olt)
        records = list(
            ConfiguredONU.objects.filter(olt=olt).order_by("slot", "port", "ont_id")
        )
    elif _configured_onu_inventory_is_stale(olt):
        _schedule_configured_onu_inventory_refresh(olt.pk)
    rows = [_configured_onu_record_to_row(record) for record in records]
    status = f"Configured ONUs loaded: {len(rows)}" if rows else "No configured ONUs found."
    return rows, status


def _refresh_snapshot_worker(olt_id):
    try:
        olt = OLT.objects.filter(pk=olt_id).first()
        if not olt:
            return
        adapter = get_olt_adapter(olt)
        snapshot = adapter.fetch_device_snapshot(olt)
        _set_cached_snapshot(olt_id, snapshot)
        update_fields = []
        fetched_sw = (snapshot.get('sw_version') or '').strip()
        if fetched_sw and fetched_sw.lower() != 'unknown' and fetched_sw != (olt.sw_version or ''):
            olt.sw_version = fetched_sw
            update_fields.append('sw_version')
        fetched_uptime = str(snapshot.get('uptime') or '').strip()
        fetched_temp = str(snapshot.get('temperature') or '').strip()
        if fetched_uptime and fetched_uptime != '--' and fetched_uptime != (olt.dashboard_uptime or ''):
            olt.dashboard_uptime = fetched_uptime
            update_fields.append('dashboard_uptime')
        if fetched_temp and fetched_temp != '--' and fetched_temp != (olt.dashboard_temperature or ''):
            olt.dashboard_temperature = fetched_temp
            update_fields.append('dashboard_temperature')
        olt.dashboard_snapshot_refreshed_at = timezone.now()
        update_fields.append('dashboard_snapshot_refreshed_at')
        if update_fields:
            olt.save(update_fields=update_fields)
    finally:
        with _SNAPSHOT_CACHE_LOCK:
            _SNAPSHOT_REFRESHING.discard(olt_id)


def _schedule_snapshot_refresh(olt_id):
    with _SNAPSHOT_CACHE_LOCK:
        if olt_id in _SNAPSHOT_REFRESHING:
            return
        _SNAPSHOT_REFRESHING.add(olt_id)
    threading.Thread(target=_refresh_snapshot_worker, args=(olt_id,), daemon=True).start()


def _refresh_pon_worker(olt_id):
    try:
        olt = OLT.objects.filter(pk=olt_id).first()
        if not olt:
            return
        adapter = get_olt_adapter(olt)
        groups, status = adapter.fetch_pon_ports(olt)
        if groups:
            _set_cached_pon_ports(olt_id, groups, status)
            save_pon_ports_snapshot(olt, groups, status)
    finally:
        with _PON_CACHE_LOCK:
            _PON_REFRESHING.discard(olt_id)


def _schedule_pon_refresh(olt_id):
    with _PON_CACHE_LOCK:
        if olt_id in _PON_REFRESHING:
            return
        _PON_REFRESHING.add(olt_id)
    threading.Thread(target=_refresh_pon_worker, args=(olt_id,), daemon=True).start()


def _refresh_vlan_worker(olt_id):
    try:
        olt = OLT.objects.filter(pk=olt_id).first()
        if not olt:
            return
        vlan_data = fetch_vlan_snapshot(olt)
        save_vlan_snapshot(olt, vlan_data)
    finally:
        with _VLAN_REFRESH_LOCK:
            _VLAN_REFRESHING.discard(olt_id)


def _refresh_dba_profile_worker(olt_id):
    try:
        olt = OLT.objects.filter(pk=olt_id).first()
        if not olt:
            return
        dba_profile_data = fetch_dba_profile_snapshot(olt)
        save_dba_profile_snapshot(olt, dba_profile_data)
    finally:
        with _DBA_PROFILE_REFRESH_LOCK:
            _DBA_PROFILE_REFRESHING.discard(olt_id)


def _schedule_vlan_refresh(olt_id):
    with _VLAN_REFRESH_LOCK:
        if olt_id in _VLAN_REFRESHING:
            return
        _VLAN_REFRESHING.add(olt_id)
    threading.Thread(target=_refresh_vlan_worker, args=(olt_id,), daemon=True).start()


def _schedule_dba_profile_refresh(olt_id):
    with _DBA_PROFILE_REFRESH_LOCK:
        if olt_id in _DBA_PROFILE_REFRESHING:
            return
        _DBA_PROFILE_REFRESHING.add(olt_id)
    threading.Thread(target=_refresh_dba_profile_worker, args=(olt_id,), daemon=True).start()


def _get_dba_profile_reference_rows(olt):
    live_snapshot = fetch_dba_profile_snapshot(olt)
    live_rows = list((live_snapshot or {}).get("rows") or [])
    if live_rows:
        save_dba_profile_snapshot(olt, live_snapshot)
        return live_rows, live_snapshot.get("status") or ""
    saved_rows = list(getattr(olt, "dba_profile_cache", []) or [])
    if saved_rows:
        return saved_rows, ""
    return saved_rows, (live_snapshot or {}).get("status") or ""


def _safe_session_set(request, key, value):
    try:
        request.session[key] = value
        request.session.modified = True
        return True
    except SessionInterrupted:
        return False
    except Exception:
        return False


def _safe_session_pop(request, key, default=None):
    try:
        return request.session.pop(key, default)
    except SessionInterrupted:
        return default
    except Exception:
        return default


def _store_dba_profile_form_state(request, olt_pk, form, non_field_errors=None, transcript=""):
    return _safe_session_set(
        request,
        f"dba_profile_form_state_{olt_pk}",
        {
            "data": dict(form.data) if getattr(form, "data", None) else {},
            "non_field_errors": list(non_field_errors or []),
            "transcript": str(transcript or ""),
        },
    )


def _restore_dba_profile_form_state(request, olt, rows):
    state = _safe_session_pop(request, f"dba_profile_form_state_{olt.pk}", None)
    reserved_ids = {int(row.get("profile_id")) for row in (rows or []) if str(row.get("profile_id", "")).isdigit()}
    reserved_names = {str(row.get("profile_name") or "").strip() for row in (rows or []) if str(row.get("profile_name") or "").strip()}
    if not state:
        return DBAProfileAddForm(reserved_ids=reserved_ids, reserved_names=reserved_names)

    form = DBAProfileAddForm(
        data=state.get("data") or None,
        reserved_ids=reserved_ids,
        reserved_names=reserved_names,
    )
    form.is_valid()
    for message in state.get("non_field_errors") or []:
        form.add_error(None, message)
    transcript = state.get("transcript") or ""
    if form.errors:
        transcript = ""
    return form, transcript


def _store_dba_profile_config_state(request, olt_pk, row=None, output="", transcript="", message=""):
    return _safe_session_set(
        request,
        f"dba_profile_config_state_{olt_pk}",
        {
            "row": row or {},
            "output": str(output or ""),
            "transcript": str(transcript or ""),
            "message": str(message or ""),
        },
    )


def _restore_dba_profile_config_state(request, olt_pk):
    return _safe_session_pop(request, f"dba_profile_config_state_{olt_pk}", None)


def _store_dba_profile_notice(request, olt_pk, notice=""):
    return _safe_session_set(request, f"dba_profile_notice_{olt_pk}", str(notice or ""))


def _restore_dba_profile_notice(request, olt_pk):
    return _safe_session_pop(request, f"dba_profile_notice_{olt_pk}", "")


def _render_olt_profiles_response(request, pk, *, form=None, transcript="", config=None, notice=""):
    request._olt_view_section = "profiles"
    request._dba_profile_override = {
        "form": form,
        "transcript": transcript or "",
        "config": config,
        "notice": notice or "",
    }


def _format_onu_display_name(value, fallback=""):
    text = str(value or "").strip()
    if not text:
        return str(fallback or "").strip()
    lowered = text.lower()
    marker = "_zone"
    idx = lowered.find(marker)
    if idx != -1:
        text = text[:idx]
    return text.strip(" _-") or str(fallback or "").strip()


def _format_onu_serial_display(value):
    text = str(value or "").strip().upper()
    if not text:
        return "-"
    if re.fullmatch(r"[0-9A-F]{16}", text):
        prefix_hex = text[:8]
        suffix = text[8:]
        try:
            prefix = bytes.fromhex(prefix_hex).decode("ascii", errors="strict")
        except (TypeError, ValueError, UnicodeDecodeError):
            return text
        if all(32 <= ord(ch) <= 126 for ch in prefix):
            return f"{prefix.upper()}{suffix}"
    return text


def _normalize_search_token(value):
    return re.sub(r"[^A-Z0-9]+", "", str(value or "").upper())


def _normalize_serial_search_token(value):
    token = _normalize_search_token(value)
    return token.translate(str.maketrans({
        "O": "0",
        "I": "1",
        "L": "1",
        "B": "8",
    }))


def _normalize_onu_serial_token(value):
    return _normalize_search_token(value)


def _configured_onu_matches_search(record, query):
    raw_query = str(query or "").strip()
    if not raw_query:
        return True

    lowered_query = raw_query.lower()
    serial_display = _format_onu_serial_display(record.sn)
    onu_label = f"{record.olt.name} gpon-onu_{int(record.frame or 0)}/{int(record.slot or 0)}/{int(record.port or 0)}:{int(record.ont_id or 0)}"
    display_name = _format_onu_display_name(record.description, serial_display or onu_label)

    text_candidates = [
        record.description,
        display_name,
        serial_display,
        record.sn,
        record.olt.name,
        onu_label,
    ]
    if any(lowered_query in str(item or "").lower() for item in text_candidates):
        return True

    query_norm = _normalize_search_token(raw_query)
    serial_query_norm = _normalize_serial_search_token(raw_query)
    if not query_norm:
        return False

    normalized_candidates = [
        _normalize_search_token(display_name),
        _normalize_search_token(serial_display),
        _normalize_search_token(record.sn),
        _normalize_search_token(record.description),
        _normalize_search_token(record.olt.name),
        _normalize_search_token(onu_label),
    ]
    if any(query_norm in candidate for candidate in normalized_candidates if candidate):
        return True

    serial_candidates = [
        _normalize_serial_search_token(serial_display),
        _normalize_serial_search_token(record.sn),
    ]
    return any(serial_query_norm in candidate for candidate in serial_candidates if candidate)
    return olt_view(request, pk)


def _store_vlan_form_state(request, olt_pk, form, non_field_errors=None, transcript=""):
    return _safe_session_set(
        request,
        f"vlan_form_state_{olt_pk}",
        {
            "data": dict(form.data) if getattr(form, "data", None) else {},
            "non_field_errors": list(non_field_errors or []),
            "transcript": str(transcript or ""),
        },
    )


def _restore_vlan_form_state(request, olt, rows):
    state = _safe_session_pop(request, f"vlan_form_state_{olt.pk}", None)
    reserved_ids = {int(row.get("vlan_id")) for row in (rows or []) if str(row.get("vlan_id", "")).isdigit()}
    if not state:
        return VLANAddForm(reserved_ids=reserved_ids)
    form = VLANAddForm(
        data=state.get("data") or None,
        reserved_ids=reserved_ids,
    )
    form.is_valid()
    for message in state.get("non_field_errors") or []:
        form.add_error(None, message)
    transcript = state.get("transcript") or ""
    if form.errors:
        transcript = ""
    return form, transcript


def _store_vlan_notice(request, olt_pk, notice=""):
    return _safe_session_set(request, f"vlan_notice_{olt_pk}", str(notice or ""))


def _restore_vlan_notice(request, olt_pk):
    return _safe_session_pop(request, f"vlan_notice_{olt_pk}", "")


def _render_olt_vlans_response(request, pk, *, form=None, bulk_form=None, transcript="", bulk_transcript="", notice=""):
    request._olt_view_section = "vlans"
    request._vlan_override = {
        "form": form,
        "bulk_form": bulk_form,
        "transcript": transcript or "",
        "bulk_transcript": bulk_transcript or "",
        "notice": notice or "",
    }
    return olt_view(request, pk)


def _store_vlan_bulk_form_state(request, olt_pk, form, non_field_errors=None, transcript=""):
    return _safe_session_set(
        request,
        f"vlan_bulk_form_state_{olt_pk}",
        {
            "data": dict(form.data) if getattr(form, "data", None) else {},
            "non_field_errors": list(non_field_errors or []),
            "transcript": str(transcript or ""),
        },
    )


def _restore_vlan_bulk_form_state(request, olt, rows):
    state = _safe_session_pop(request, f"vlan_bulk_form_state_{olt.pk}", None)
    reserved_ids = {int(row.get("vlan_id")) for row in (rows or []) if str(row.get("vlan_id", "")).isdigit()}
    if not state:
        return VLANBulkAddForm(reserved_ids=reserved_ids)
    form = VLANBulkAddForm(data=state.get("data") or None, reserved_ids=reserved_ids)
    form.is_valid()
    for message in state.get("non_field_errors") or []:
        form.add_error(None, message)
    transcript = state.get("transcript") or ""
    if form.errors:
        transcript = ""
    return form, transcript


def _refresh_cards_worker(olt_id):
    try:
        olt = OLT.objects.filter(pk=olt_id).first()
        if not olt:
            return
        _refresh_olt_cards_cache(olt)
    finally:
        return


def _schedule_cards_refresh(olt_id):
    threading.Thread(target=_refresh_cards_worker, args=(olt_id,), daemon=True).start()


def _refresh_uplink_worker(olt_id):
    try:
        olt = OLT.objects.filter(pk=olt_id).first()
        if not olt:
            return
        uplink_data = fetch_uplink_snapshot(olt)
        _set_cached_uplink(olt.pk, uplink_data)
        save_uplink_snapshot(olt, uplink_data)

        snmp_snapshot = fetch_snmp_snapshot(olt)
        _set_cached_snapshot(olt.pk, snmp_snapshot)
        fetched_sw = (snmp_snapshot.get('sw_version') or '').strip()
        fetched_model = (snmp_snapshot.get('model') or '').strip()
        update_fields = []
        if fetched_sw and fetched_sw.lower() != 'unknown' and fetched_sw != (olt.sw_version or ''):
            olt.sw_version = fetched_sw
            update_fields.append('sw_version')
        if fetched_model and fetched_model.lower() != 'unknown' and fetched_model != (olt.hardware_version or ''):
            olt.hardware_version = fetched_model
            update_fields.append('hardware_version')
        if update_fields:
            olt.save(update_fields=update_fields)
    finally:
        with _UPLINK_CACHE_LOCK:
            _UPLINK_CACHE.setdefault(olt_id, _UPLINK_CACHE.get(olt_id, {"data": {"status": "", "rows": []}, "cached_at": timezone.now()}))


def _schedule_uplink_refresh(olt_id):
    threading.Thread(target=_refresh_uplink_worker, args=(olt_id,), daemon=True).start()


def _refresh_device_snapshots_worker(olt_id):
    try:
        olt = OLT.objects.filter(pk=olt_id).first()
        if not olt:
            return
        adapter = get_olt_adapter(olt)
        if not (olt.olt_cards_cache or []):
            cards, status = adapter.fetch_cards(olt)
            if cards:
                olt.olt_cards_cache = cards
            olt.olt_cards_status = (status or "")[:300]
            olt.olt_cards_refreshed_at = timezone.now()
            olt.save(update_fields=["olt_cards_cache", "olt_cards_status", "olt_cards_refreshed_at"])
        if not (getattr(olt, "pon_ports_cache", []) or []):
            groups, status = adapter.fetch_pon_ports(olt)
            if groups:
                _set_cached_pon_ports(olt_id, groups, status)
                save_pon_ports_snapshot(olt, groups, status)
        if not (getattr(olt, "uplink_cache", []) or []):
            uplink_data = fetch_uplink_snapshot(olt)
            _set_cached_uplink(olt_id, uplink_data)
            save_uplink_snapshot(olt, uplink_data)
        if not (getattr(olt, "dba_profile_cache", []) or []):
            dba_profile_data = fetch_dba_profile_snapshot(olt)
            save_dba_profile_snapshot(olt, dba_profile_data)
    finally:
        with _DEVICE_SNAPSHOT_SYNC_LOCK:
            _DEVICE_SNAPSHOT_SYNCING.discard(olt_id)


def _schedule_device_snapshots_refresh(olt_id):
    with _DEVICE_SNAPSHOT_SYNC_LOCK:
        if olt_id in _DEVICE_SNAPSHOT_SYNCING:
            return
        _DEVICE_SNAPSHOT_SYNCING.add(olt_id)
    threading.Thread(target=_refresh_device_snapshots_worker, args=(olt_id,), daemon=True).start()


def _schedule_missing_device_snapshots_if_due():
    global _LAST_DEVICE_SNAPSHOT_SCAN
    now = timezone.now()
    with _DEVICE_SNAPSHOT_SCAN_LOCK:
        if _LAST_DEVICE_SNAPSHOT_SCAN and (now - _LAST_DEVICE_SNAPSHOT_SCAN).total_seconds() < DEVICE_SNAPSHOT_SCAN_SECONDS:
            return
        _LAST_DEVICE_SNAPSHOT_SCAN = now
    for olt in OLT.objects.only("id", "olt_cards_cache", "pon_ports_cache").all():
        if not (olt.olt_cards_cache or []) or not (getattr(olt, "pon_ports_cache", []) or []):
            _schedule_device_snapshots_refresh(olt.pk)


def _cards_signature(cards):
    return {(str(card.get('slot', '')), str(card.get('model_type', ''))) for card in cards}


def _request_client_ip(request):
    if request is None:
        return None
    candidates = []
    for header in (
        "HTTP_CF_CONNECTING_IP",
        "HTTP_TRUE_CLIENT_IP",
        "HTTP_X_REAL_IP",
        "HTTP_X_FORWARDED_FOR",
        "REMOTE_ADDR",
    ):
        raw = str(request.META.get(header) or "").strip()
        if not raw:
            continue
        if header == "HTTP_X_FORWARDED_FOR":
            candidates.extend(part.strip() for part in raw.split(",") if part.strip())
        else:
            candidates.append(raw)

    first_valid = None
    for value in candidates:
        try:
            parsed = ipaddress.ip_address(value)
        except ValueError:
            continue
        if first_valid is None:
            first_valid = value
        if parsed.is_global:
            return value
    return first_valid


def _record_olt_login(olt, user, action, details='', request=None, onu=''):
    username = ''
    if user and user.is_authenticated:
        username = getattr(user, 'username', '') or getattr(user, 'email', '') or str(user)
    OLTLoginHistory.objects.create(
        olt=olt,
        user=user if user and user.is_authenticated else None,
        username=username,
        action=action[:50],
        onu=(onu or '')[:120],
        ip_address=_request_client_ip(request),
        details=(details or '')[:300],
    )


def _sync_snmp_after_save(olt):
    pushed_ok, push_status = push_snmp_config_over_telnet(
        olt,
        olt.snmp_community,
        olt.snmp_write_community,
    )
    if not pushed_ok:
        olt.snmp_last_status = (push_status or 'SNMP push failed.')[:300]
        olt.snmp_last_synced_at = timezone.now()
        olt.save(update_fields=['snmp_last_status', 'snmp_last_synced_at'])
        return False, push_status

    snapshot = fetch_snmp_snapshot(olt)
    status_text = str(snapshot.get('status', '') or 'SNMP synced')
    update_fields = ['snmp_last_status', 'snmp_last_synced_at']
    olt.snmp_last_status = status_text[:300]
    olt.snmp_last_synced_at = timezone.now()

    model = (snapshot.get('model') or '').strip()
    sw_version = (snapshot.get('sw_version') or '').strip()
    if model and model.lower() != 'unknown' and model != (olt.hardware_version or ''):
        olt.hardware_version = model
        update_fields.append('hardware_version')
    if sw_version and sw_version.lower() != 'unknown' and sw_version != (olt.sw_version or ''):
        olt.sw_version = sw_version
        update_fields.append('sw_version')

    olt.save(update_fields=update_fields)
    return True, status_text


def _fetch_snmp_only_after_save(olt):
    snapshot = fetch_snmp_snapshot(olt)
    status_text = str(snapshot.get('status', '') or 'SNMP fetched')
    update_fields = ['snmp_last_status', 'snmp_last_synced_at']
    olt.snmp_last_status = status_text[:300]
    olt.snmp_last_synced_at = timezone.now()

    model = (snapshot.get('model') or '').strip()
    sw_version = (snapshot.get('sw_version') or '').strip()
    if model and model.lower() != 'unknown' and model != (olt.hardware_version or ''):
        olt.hardware_version = model
        update_fields.append('hardware_version')
    if sw_version and sw_version.lower() != 'unknown' and sw_version != (olt.sw_version or ''):
        olt.sw_version = sw_version
        update_fields.append('sw_version')

    olt.save(update_fields=update_fields)
    lowered = status_text.lower()
    failed_tokens = (
        "unavailable",
        "not installed",
        "timeout",
        "no response",
        "status error",
        "failed",
    )
    return not any(token in lowered for token in failed_tokens), status_text


def _autofind_counts_need_refresh(selected_olt_id=None):
    now = timezone.now()
    qs = OLT.objects.all().only("id", "autofind_onu_count", "autofind_status", "autofind_refreshed_at")
    if selected_olt_id:
        qs = qs.filter(pk=selected_olt_id)
    rows = list(qs)
    if not rows:
        return False
    for olt in rows:
        status_text = str(getattr(olt, "autofind_status", "") or "").lower()
        refreshed_at = getattr(olt, "autofind_refreshed_at", None)
        stale = not refreshed_at or (now - refreshed_at).total_seconds() >= 900
        failed = any(token in status_text for token in ("timeout", "unavailable", "connection closed", "login failed", "error"))
        if stale or failed:
            return True
    return False


def _refresh_autofind_counts_worker(selected_olt_id=None):
    try:
        qs = OLT.objects.all().only("id")
        if selected_olt_id:
            qs = qs.filter(pk=selected_olt_id)
        for olt in qs:
            try:
                sync_olt_autofind_count(olt)
            except Exception:
                continue
    finally:
        global _AUTOFIND_REFRESH_THREAD
        with _AUTOFIND_REFRESH_GUARD:
            _AUTOFIND_REFRESH_THREAD = None


def _schedule_autofind_counts_refresh(selected_olt_id=None):
    global _AUTOFIND_REFRESH_THREAD
    with _AUTOFIND_REFRESH_GUARD:
        if _AUTOFIND_REFRESH_THREAD and _AUTOFIND_REFRESH_THREAD.is_alive():
            return
        _AUTOFIND_REFRESH_THREAD = threading.Thread(
            target=_refresh_autofind_counts_worker,
            args=(selected_olt_id,),
            name="autofind-count-refresh",
            daemon=True,
        )
        _AUTOFIND_REFRESH_THREAD.start()



def _uptime_minutes(uptime_text):
    text = (uptime_text or '').strip()
    if not text or text == '--':
        return None

    match = re.search(r"(\d+)\s*day\(s\),\s*(\d{1,2}):(\d{2})", text, flags=re.IGNORECASE)
    if match:
        days = int(match.group(1))
        hours = int(match.group(2))
        minutes = int(match.group(3))
        return (days * 24 * 60) + (hours * 60) + minutes

    alt = re.search(
        r"(\d+)\s*day\(s\),\s*(\d+)\s*hour\(s\),\s*(\d+)\s*minute\(s\)",
        text,
        flags=re.IGNORECASE,
    )
    if alt:
        days = int(alt.group(1))
        hours = int(alt.group(2))
        minutes = int(alt.group(3))
        return (days * 24 * 60) + (hours * 60) + minutes

    hm = re.search(r"\b(\d{1,2}):(\d{2})\b", text)
    if hm:
        hours = int(hm.group(1))
        minutes = int(hm.group(2))
        return (hours * 60) + minutes

    return None


def _parse_dbm_value(text):
    value = str(text or "").strip()
    if not value or value == "--":
        return None
    match = re.search(r"(-?\d+(?:\.\d+)?)", value)
    if not match:
        return None
    try:
        return float(match.group(1))
    except (TypeError, ValueError):
        return None


def _classify_onu_signal(olt_rx_text):
    olt_rx = _parse_dbm_value(olt_rx_text)
    if olt_rx is None:
        return ""
    if -27.0 <= olt_rx <= -8.0:
        return "good"
    if (-30.0 <= olt_rx < -27.0) or (-8.0 < olt_rx <= -6.0):
        return "warn"
    return "bad"


def _parse_temperature_celsius(text):
    value = str(text or "").strip()
    if not value or value == "--":
        return None
    match = re.search(r"(-?\d+(?:\.\d+)?)", value)
    if not match:
        return None
    try:
        return float(match.group(1))
    except (TypeError, ValueError):
        return None


def _clean_ui_status(status_text, fallback, has_data=False):
    text = str(status_text or "").strip()
    if not text:
        return fallback
    lowered = text.lower()
    noisy_tokens = (
        "error",
        "failed",
        "timeout",
        "rejected",
        "connection closed",
        "not available",
        "invalid",
        "denied",
    )
    if any(token in lowered for token in noisy_tokens):
        return "Cached device data" if has_data else fallback
    return text[:120]


def _build_saved_device_snapshot(olt):
    return {
        'status': olt.snmp_last_status or 'Saved device data',
        'sys_name': olt.name,
        'sys_descr': '',
        'model': olt.hardware_version or 'Unknown',
        'sw_version': olt.sw_version or 'Unknown',
        'uptime': '--',
        'temperature': '--',
    }


def _is_known_device_value(value):
    text = str(value or "").strip()
    return bool(text and text.lower() != "unknown" and text != "--")


def _should_fetch_telnet_version_details(olt, snapshot):
    snapshot = snapshot or {}
    if _is_known_device_value(olt.hardware_version) and _is_known_device_value(olt.sw_version):
        return False

    effective_model_known = _is_known_device_value(snapshot.get('model')) or _is_known_device_value(olt.hardware_version)
    effective_sw_known = _is_known_device_value(snapshot.get('sw_version')) or _is_known_device_value(olt.sw_version)
    return not (effective_model_known and effective_sw_known)


def _should_fetch_telnet_uptime(snapshot):
    return not _is_known_device_value(snapshot.get('uptime'))


def _serialize_olt_details_snapshot(olt, snapshot):
    snapshot = dict(snapshot or {})
    model = snapshot.get('model') or olt.hardware_version or 'Unknown'
    sw_version = snapshot.get('sw_version') or olt.sw_version or 'Unknown'
    uptime = snapshot.get('uptime') or '--'
    temperature = snapshot.get('temperature') or '--'
    snapshot_payload = {
        'status': snapshot.get('status') or olt.snmp_last_status or 'Device data unavailable',
        'sys_name': snapshot.get('sys_name') or olt.name,
        'sys_descr': snapshot.get('sys_descr') or '',
        'model': model,
        'sw_version': sw_version,
        'uptime': uptime,
        'temperature': temperature,
    }
    uptime_minutes = _uptime_minutes(uptime)
    temperature_celsius = _parse_temperature_celsius(temperature)
    snapshot_has_data = any(
        str(snapshot_payload.get(key) or "").strip() not in {"", "--", "Unknown"}
        for key in ("sys_name", "model", "sw_version")
    )
    return {
        'snapshot': snapshot_payload,
        'snapshot_status_display': _clean_ui_status(
            snapshot_payload.get('status'),
            'Device data unavailable',
            has_data=snapshot_has_data,
        ),
        'software_display': sw_version or 'Unknown',
        'banner_uptime': uptime,
        'banner_uptime_ok': bool(uptime_minutes is not None and uptime_minutes > 120),
        'temperature_alert': bool(temperature_celsius is not None and temperature_celsius > 50),
    }


def _dashboard_snapshot_due(olt):
    last = getattr(olt, "dashboard_snapshot_refreshed_at", None)
    if not last:
        return True
    return (timezone.now() - last).total_seconds() >= DASHBOARD_UPTIME_REFRESH_SECONDS


def _schedule_dashboard_snapshot_refreshes():
    for olt in OLT.objects.only("id", "dashboard_snapshot_refreshed_at").all():
        if _dashboard_snapshot_due(olt):
            _schedule_snapshot_refresh(olt.pk)


def _collect_dashboard_olt_uptimes(selected_olt_id=None):
    rows = []
    try:
        query = OLT.objects.only(
            "id",
            "name",
            "dashboard_uptime",
            "dashboard_temperature",
            "dashboard_snapshot_refreshed_at",
        ).order_by("name")
        for olt in query:
            uptime = str(olt.dashboard_uptime or "--").strip() or "--"
            temperature = str(olt.dashboard_temperature or "--").strip() or "--"
            temperature_c = _parse_temperature_celsius(temperature)
            rows.append({
                "id": olt.id,
                "name": olt.name,
                "uptime": uptime,
                "uptime_ok": bool((_uptime_minutes(uptime) or 0) > 120) if uptime != "--" else False,
                "temperature": temperature,
                "temperature_alert": bool(temperature_c is not None and temperature_c > 50),
                "selected": bool(selected_olt_id and olt.id == selected_olt_id),
            })
    except OperationalError:
        for olt in OLT.objects.only("id", "name").order_by("name"):
            rows.append({
                "id": olt.id,
                "name": olt.name,
                "uptime": "--",
                "uptime_ok": False,
                "temperature": "--",
                "temperature_alert": False,
                "selected": bool(selected_olt_id and olt.id == selected_olt_id),
            })
    rows.sort(key=lambda row: (not row["temperature_alert"], row["name"].lower()))
    return rows


def _collect_dashboard_snmp_down_olts():
    rows = []
    down_tokens = (
        "timeout",
        "no response",
        "timed out",
        "snmp timeout",
    )
    try:
        query = OLT.objects.only("id", "name", "snmp_last_status", "snmp_last_synced_at").order_by("name")
        for olt in query:
            status = str(getattr(olt, "snmp_last_status", "") or "").strip()
            synced_at = getattr(olt, "snmp_last_synced_at", None)
            if not synced_at:
                continue
            try:
                age_seconds = (timezone.now() - synced_at).total_seconds()
            except Exception:
                continue
            if age_seconds > 1800:
                continue
            lowered = status.lower()
            if not any(token in lowered for token in down_tokens):
                continue
            rows.append({
                "id": olt.id,
                "name": olt.name,
                "status": status or "SNMP no response on UDP 161",
            })
    except OperationalError:
        return []
    return rows


def _dashboard_graph_config(range_key="24h"):
    range_key = str(range_key or "24h").lower()
    now = timezone.now()
    if range_key == "1h":
        return {
            "key": "1h",
            "label": "Hourly",
            "since": now - timezone.timedelta(hours=1),
            "bucket_minutes": 10,
            "label_format": "%H:%M",
        }
    if range_key == "7d":
        return {
            "key": "7d",
            "label": "Weekly",
            "since": now - timezone.timedelta(days=7),
            "bucket_days": 1,
            "label_format": "%d %b",
        }
    if range_key == "4w":
        return {
            "key": "4w",
            "label": "Monthly",
            "since": now - timezone.timedelta(days=28),
            "bucket_days": 7,
            "label_format": "%d %b",
        }
    if range_key == "12m":
        return {
            "key": "12m",
            "label": "Yearly",
            "since": now - timezone.timedelta(days=365),
            "bucket_months": 1,
            "label_format": "%b %Y",
        }
    return {
        "key": "24h",
        "label": "Daily",
        "since": now - timezone.timedelta(hours=24),
        "bucket_hours": 4,
        "label_format": "%d %b %H:%M",
    }


def _bucket_dashboard_datetime(local_dt, config):
    if "bucket_minutes" in config:
        minutes = int(config["bucket_minutes"])
        floored_minute = (local_dt.minute // minutes) * minutes
        return local_dt.replace(minute=floored_minute, second=0, microsecond=0)
    if "bucket_hours" in config:
        hours = int(config["bucket_hours"])
        floored_hour = (local_dt.hour // hours) * hours
        return local_dt.replace(hour=floored_hour, minute=0, second=0, microsecond=0)
    if "bucket_days" in config:
        days = int(config["bucket_days"])
        base = local_dt.replace(hour=0, minute=0, second=0, microsecond=0)
        if days <= 1:
            return base
        anchor = config["since"].astimezone(ZoneInfo("Asia/Karachi")).replace(hour=0, minute=0, second=0, microsecond=0)
        delta_days = max(0, (base.date() - anchor.date()).days)
        floored_days = (delta_days // days) * days
        return anchor + timezone.timedelta(days=floored_days)
    if "bucket_months" in config:
        months = int(config["bucket_months"])
        month_index = ((local_dt.month - 1) // months) * months + 1
        return local_dt.replace(month=month_index, day=1, hour=0, minute=0, second=0, microsecond=0)
    return local_dt.replace(minute=0, second=0, microsecond=0)


def _advance_dashboard_bucket(local_dt, config):
    if "bucket_minutes" in config:
        return local_dt + timezone.timedelta(minutes=int(config["bucket_minutes"]))
    if "bucket_hours" in config:
        return local_dt + timezone.timedelta(hours=int(config["bucket_hours"]))
    if "bucket_days" in config:
        return local_dt + timezone.timedelta(days=int(config["bucket_days"]))
    if "bucket_months" in config:
        months = int(config["bucket_months"])
        year = local_dt.year
        month = local_dt.month + months
        while month > 12:
            month -= 12
            year += 1
        return local_dt.replace(year=year, month=month, day=1, hour=0, minute=0, second=0, microsecond=0)
    return local_dt + timezone.timedelta(hours=1)


def _build_dashboard_status_graph(olt_id=None, range_key="24h"):
    config = _dashboard_graph_config(range_key)
    qs = DashboardStatusSample.objects.filter(sampled_at__gte=config["since"])
    if olt_id:
        qs = qs.filter(olt_id=olt_id)
    else:
        qs = qs.filter(olt__isnull=True)
    rows = list(
        qs.order_by("sampled_at").values(
            "sampled_at",
            "online_onus",
            "offline_onus",
            "admin_disabled",
            "power_failure",
            "loss_of_signal",
        )
    )
    grouped = {}
    for row in rows:
        sampled_at = row.get("sampled_at")
        if not sampled_at:
            continue
        local_dt = timezone.localtime(sampled_at, ZoneInfo("Asia/Karachi"))
        bucket = _bucket_dashboard_datetime(local_dt, config)
        bucket_key = bucket.isoformat()
        bucket_row = grouped.setdefault(
            bucket_key,
            {
                "bucket": bucket,
                "count": 0,
                "online": 0,
                "offline": 0,
                "admin_disabled": 0,
                "power_failure": 0,
                "loss_of_signal": 0,
            },
        )
        bucket_row["count"] += 1
        bucket_row["online"] += int(row.get("online_onus") or 0)
        bucket_row["offline"] += int(row.get("offline_onus") or 0)
        bucket_row["admin_disabled"] += int(row.get("admin_disabled") or 0)
        bucket_row["power_failure"] += int(row.get("power_failure") or 0)
        bucket_row["loss_of_signal"] += int(row.get("loss_of_signal") or 0)
    points = []
    for bucket_key in sorted(grouped.keys()):
        row = grouped[bucket_key]
        local_bucket = row["bucket"]
        count = max(1, int(row["count"]))
        points.append({
            "x": local_bucket.isoformat(),
            "label": local_bucket.strftime(config["label_format"]),
            "online": int(round(row["online"] / count)),
            "offline": int(round(row["offline"] / count)),
            "admin_disabled": int(round(row["admin_disabled"] / count)),
            "power_failure": int(round(row["power_failure"] / count)),
            "loss_of_signal": int(round(row["loss_of_signal"] / count)),
        })
    if points:
        normalized_points = []
        point_map = {point["x"]: point for point in points}
        start_bucket = _bucket_dashboard_datetime(timezone.localtime(config["since"], ZoneInfo("Asia/Karachi")), config)
        end_bucket = _bucket_dashboard_datetime(timezone.localtime(timezone.now(), ZoneInfo("Asia/Karachi")), config)
        cursor = start_bucket
        last_point = None
        while cursor <= end_bucket:
            key = cursor.isoformat()
            point = point_map.get(key)
            if point is None and last_point is not None:
                point = {
                    "x": key,
                    "label": cursor.strftime(config["label_format"]),
                    "online": last_point["online"],
                    "offline": last_point["offline"],
                    "admin_disabled": last_point["admin_disabled"],
                    "power_failure": last_point["power_failure"],
                    "loss_of_signal": last_point["loss_of_signal"],
                }
            elif point is None:
                cursor = _advance_dashboard_bucket(cursor, config)
                continue
            normalized_points.append(point)
            last_point = point
            cursor = _advance_dashboard_bucket(cursor, config)
        points = normalized_points
    latest = points[-1] if points else {"online": 0, "offline": 0, "admin_disabled": 0, "power_failure": 0, "loss_of_signal": 0}
    return {
        "range_key": config["key"],
        "range_label": config["label"],
        "points": points,
        "latest": latest,
    }


def _signal_payload_from_values(onu_rx, olt_rx):
    signal_class = _classify_onu_signal(olt_rx)
    return {
        "onu_rx": onu_rx or "--",
        "olt_rx": olt_rx or "--",
        "signal_class": signal_class,
        "signal_visible": any(str(value or "").strip() not in {"", "--"} for value in (onu_rx, olt_rx)),
    }


def _signal_bucket_for_value(olt_rx):
    return _classify_onu_signal(olt_rx) or ""


def _recent_onu_signal_visibilities(olt, slot, port, ont_id, minutes=15, limit=8):
    since = timezone.now() - timezone.timedelta(minutes=minutes)
    rows = (
        ONUOpticalSample.objects.filter(
            olt=olt,
            slot=slot,
            port=port,
            ont_id=ont_id,
            sampled_at__gte=since,
        )
        .order_by("-sampled_at")
        .values("onu_rx", "olt_rx")[:limit]
    )
    visibilities = []
    for row in reversed(list(rows)):
        visible = any(str(row.get(key) or "").strip() not in {"", "--"} for key in ("onu_rx", "olt_rx"))
        visibilities.append(bool(visible))
    return visibilities


def _resolve_signal_refresh_status(record, visible_now):
    current_status = _normalize_configured_status(record.derived_status, run_state=record.run_state)
    if current_status in {"admin_disabled", "power_failure", "loss_of_signal"}:
        return current_status, record.status_source or "inventory"

    history = _recent_onu_signal_visibilities(record.olt, record.slot, record.port, record.ont_id)
    history.append(bool(visible_now))

    visible_streak = 0
    for state in reversed(history):
        if state:
            visible_streak += 1
        else:
            break

    transitions = 0
    for prev, curr in zip(history, history[1:]):
        if prev != curr:
            transitions += 1

    has_visible = any(history)
    has_hidden = any(not item for item in history)

    if visible_now:
        return "online", "signal_refresh"

    if has_visible:
        return "offline", "signal_refresh"
    if current_status == "power_flap":
        return "offline", "signal_refresh"
    if transitions >= 2:
        return "offline", "signal_refresh"
    return "offline", "signal_refresh"


def _normalize_configured_status(value, run_state=""):
    text = str(value or "").strip().lower()
    if text == "power_flap":
        return "offline"
    if text in {"online", "offline", "admin_disabled", "power_failure", "loss_of_signal"}:
        return text
    return "online" if str(run_state or "").strip().lower() == "online" else "offline"


def _configured_status_label(value, run_state=""):
    normalized = _normalize_configured_status(value, run_state=run_state)
    labels = {
        "online": "Online",
        "offline": "Offline",
        "admin_disabled": "Admin Disabled",
        "power_failure": "Power Failure",
        "loss_of_signal": "Loss Of Signal",
    }
    return labels.get(normalized, "Offline")


def _configured_status_class(value, run_state=""):
    normalized = _normalize_configured_status(value, run_state=run_state)
    if normalized == "online":
        return "good"
    if normalized in {"admin_disabled", "loss_of_signal"}:
        return "warn"
    return "bad"


def _status_from_runtime_snapshot(runtime_snapshot, fallback_value="", fallback_run_state=""):
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
    return _normalize_configured_status(fallback_value, run_state=fallback_run_state or snapshot.get("run_state"))


def _format_status_age_text(dt):
    if not dt:
        return ""
    try:
        local_dt = timezone.localtime(dt, ZoneInfo("Asia/Karachi"))
    except Exception:
        local_dt = timezone.localtime(dt)
    return f"({local_dt.strftime('%d %b %Y %I:%M %p')})"


def _format_relative_time_text(dt):
    if not dt:
        return ""
    try:
        local_dt = timezone.localtime(dt, ZoneInfo("Asia/Karachi"))
    except Exception:
        local_dt = timezone.localtime(dt)
    now = timezone.localtime(timezone.now(), ZoneInfo("Asia/Karachi"))
    delta = now - local_dt
    total_seconds = max(0, int(delta.total_seconds()))
    if total_seconds < 60:
        return "just now"

    days, remainder = divmod(total_seconds, 86400)
    hours, remainder = divmod(remainder, 3600)
    minutes, _ = divmod(remainder, 60)

    parts = []
    if days:
        parts.append(f"{days} day{'s' if days != 1 else ''}")
    if hours:
        parts.append(f"{hours} hour{'s' if hours != 1 else ''}")
    if minutes:
        parts.append(f"{minutes} minute{'s' if minutes != 1 else ''}")

    if not parts:
        return "just now"
    return f"{' '.join(parts)} ago"


def _format_onu_distance_text(distance_value):
    text = str(distance_value or "").strip()
    if not text or text in {"-", "--"}:
        return ""
    match = re.search(r"\d+", text)
    if not match:
        return ""
    return f"({int(match.group(0))}m)"


def _parse_onu_runtime_datetime(text):
    raw = str(text or "").strip()
    if not raw:
        return None
    candidates = (
        "%Y-%m-%d %H:%M:%S%z",
        "%Y-%m-%d %H:%M:%S",
    )
    for pattern in candidates:
        try:
            parsed = datetime.datetime.strptime(raw, pattern)
            if parsed.tzinfo is None:
                parsed = timezone.make_aware(parsed, ZoneInfo("Asia/Karachi"))
            return parsed
        except (TypeError, ValueError):
            continue
    return None


def _status_age_text_from_onu_runtime(status_value, runtime_snapshot):
    runtime_snapshot = runtime_snapshot or {}
    now = timezone.now()
    normalized = _normalize_configured_status(status_value)

    if normalized == "online":
        up_time = _parse_onu_runtime_datetime(runtime_snapshot.get("last_up_time"))
        if up_time:
            return _format_status_age_text(up_time)
        seconds = _parse_ont_duration_to_seconds(runtime_snapshot.get("online_duration"))
        if seconds is not None:
            started_at = now - timezone.timedelta(seconds=seconds)
            return _format_status_age_text(started_at)

    down_time = _parse_onu_runtime_datetime(runtime_snapshot.get("last_down_time"))
    if down_time:
        return _format_status_age_text(down_time)

    if normalized != "online":
        up_time = _parse_onu_runtime_datetime(runtime_snapshot.get("last_up_time"))
        if up_time:
            return _format_status_age_text(up_time)
    return ""


def _status_since_datetime_from_onu_runtime(status_value, runtime_snapshot):
    runtime_snapshot = runtime_snapshot or {}
    now = timezone.now()
    normalized = _normalize_configured_status(status_value)

    if normalized == "online":
        up_time = _parse_onu_runtime_datetime(runtime_snapshot.get("last_up_time"))
        if up_time:
            return up_time
        seconds = _parse_ont_duration_to_seconds(runtime_snapshot.get("online_duration"))
        if seconds is not None:
            return now - timezone.timedelta(seconds=seconds)
        return None

    down_time = _parse_onu_runtime_datetime(runtime_snapshot.get("last_down_time"))
    if down_time:
        return down_time
    return None


def _get_onu_signal_history(olt, slot, port, ont_id, hours=24):
    since = timezone.now() - timezone.timedelta(hours=hours)
    rows = (
        ONUOpticalSample.objects.filter(
            olt=olt,
            slot=slot,
            port=port,
            ont_id=ont_id,
            sampled_at__gte=since,
        )
        .order_by("sampled_at")
        .values("sampled_at", "onu_rx", "olt_rx", "tx_power")
    )
    history = []
    for row in rows:
        history.append(
            {
                "sampled_at": timezone.localtime(row["sampled_at"]).isoformat(),
                "onu_rx": row.get("onu_rx") or "--",
                "olt_rx": row.get("olt_rx") or "--",
                "tx_power": row.get("tx_power") or "--",
            }
        )
    return history


def _cli_session_key(user_id, olt_id):
    return f"{user_id}:{olt_id}"


def _cleanup_expired_cli_sessions():
    now = timezone.now()
    expired_keys = []
    with _CLI_SESSIONS_LOCK:
        for key, data in _CLI_SESSIONS.items():
            updated_at = data.get('updated_at')
            if updated_at is None:
                expired_keys.append(key)
                continue
            if (now - updated_at).total_seconds() > CLI_SESSION_IDLE_SECONDS:
                expired_keys.append(key)
        for key in expired_keys:
            tn = _CLI_SESSIONS[key].get('tn')
            close_telnet_session(tn)
            del _CLI_SESSIONS[key]


def _close_user_cli_session(user_id, olt_id):
    key = _cli_session_key(user_id, olt_id)
    with _CLI_SESSIONS_LOCK:
        existing = _CLI_SESSIONS.pop(key, None)
    if existing:
        close_telnet_session(existing.get('tn'))


def _refresh_olt_cards_cache(olt):
    refresh_lock = _get_olt_refresh_lock(olt.pk)
    if not refresh_lock.acquire(timeout=0.3):
        status = 'Refresh already running for this OLT. Please wait a few seconds and try again.'
        return olt.olt_cards_cache or [], status, [], False

    old_cards = olt.olt_cards_cache or []
    old_sig = _cards_signature(old_cards)
    try:
        adapter = get_olt_adapter(olt)
        new_cards, status = adapter.fetch_cards(olt)
        if new_cards:
            olt.olt_cards_cache = new_cards
        olt.olt_cards_status = status[:300]
        olt.olt_cards_refreshed_at = timezone.now()
        olt.save(update_fields=['olt_cards_cache', 'olt_cards_status', 'olt_cards_refreshed_at'])

        new_sig = _cards_signature(olt.olt_cards_cache or [])
        added = sorted(new_sig - old_sig)
        return olt.olt_cards_cache or [], olt.olt_cards_status, added, True
    finally:
        refresh_lock.release()

@login_required
def olt_list(request):
    _schedule_missing_device_snapshots_if_due()
    _schedule_dashboard_snapshot_refreshes()
    try:
        record_dashboard_status_samples()
    except OperationalError:
        pass

    olt_filter = (request.GET.get('olt') or '').strip()
    selected_olt = None
    onu_qs = ConfiguredONU.objects.all()
    if olt_filter:
        try:
            selected_olt = OLT.objects.only("id", "name", "autofind_onu_count", "autofind_new_count", "autofind_resync_count").filter(pk=int(olt_filter)).first()
        except (TypeError, ValueError):
            selected_olt = None
        if selected_olt:
            onu_qs = onu_qs.filter(olt_id=selected_olt.pk)
    if _autofind_counts_need_refresh(selected_olt.pk if selected_olt else None):
        _schedule_autofind_counts_refresh(selected_olt.pk if selected_olt else None)

    dashboard_counts = _dashboard_status_counts_from_queryset(onu_qs)
    total_all = int(dashboard_counts.get("total_onus") or 0)
    total_online = int(dashboard_counts.get("online_onus") or 0)
    total_offline = max(0, total_all - total_online)
    if selected_olt:
        total_wait_for_authorize = int(getattr(selected_olt, "autofind_onu_count", 0) or 0)
        total_wait_for_authorize_new = int(getattr(selected_olt, "autofind_new_count", 0) or 0)
        total_wait_for_authorize_resync = int(getattr(selected_olt, "autofind_resync_count", 0) or 0)
    else:
        total_wait_for_authorize = sum(
            OLT.objects.values_list("autofind_onu_count", flat=True)
        )
        total_wait_for_authorize_new = sum(
            OLT.objects.values_list("autofind_new_count", flat=True)
        )
        total_wait_for_authorize_resync = sum(
            OLT.objects.values_list("autofind_resync_count", flat=True)
        )
    total_admin_disabled = int(dashboard_counts.get("admin_disabled") or 0)
    total_loss_of_signal = int(dashboard_counts.get("loss_of_signal") or 0)
    total_power_failure = int(dashboard_counts.get("power_failure") or 0)
    total_signal_warn = int(dashboard_counts.get("signal_warn") or 0)
    total_signal_bad = int(dashboard_counts.get("signal_bad") or 0)
    latest_dashboard_sample_at = (
        DashboardStatusSample.objects.order_by("-sampled_at").values_list("sampled_at", flat=True).first()
    )
    dashboard_last_sample_display = (
        timezone.localtime(latest_dashboard_sample_at, ZoneInfo("Asia/Karachi")).strftime("%Y-%m-%d %I:%M:%S %p")
        if latest_dashboard_sample_at
        else timezone.localtime(timezone.now(), ZoneInfo("Asia/Karachi")).strftime("%Y-%m-%d %I:%M:%S %p")
    )

    configured_signal_base = reverse('configured_onus')
    warning_params = {'signal': 'warning'}
    critical_params = {'signal': 'critical'}
    admin_disabled_params = {'status': 'admin_disabled'}
    loss_of_signal_params = {'status': 'loss_of_signal'}
    power_failure_params = {'status': 'power_failure'}
    if selected_olt:
        warning_params['olt'] = selected_olt.pk
        critical_params['olt'] = selected_olt.pk
        admin_disabled_params['olt'] = selected_olt.pk
        loss_of_signal_params['olt'] = selected_olt.pk
        power_failure_params['olt'] = selected_olt.pk

    context = {
        'dashboard_total_onus': total_all,
        'dashboard_wait_for_authorize_total': total_wait_for_authorize,
        'dashboard_wait_for_authorize_new_total': total_wait_for_authorize_new,
        'dashboard_wait_for_authorize_resync_total': total_wait_for_authorize_resync,
        'dashboard_online_total': total_online,
        'dashboard_offline_total': total_offline,
        'dashboard_admin_disabled_total': total_admin_disabled,
        'dashboard_loss_of_signal_total': total_loss_of_signal,
        'dashboard_power_failure_total': total_power_failure,
        'dashboard_signal_warn_total': total_signal_warn,
        'dashboard_signal_bad_total': total_signal_bad,
        'dashboard_signal_total': total_signal_warn + total_signal_bad,
        'dashboard_validated_at': timezone.localtime(),
        'dashboard_last_sample_at': latest_dashboard_sample_at,
        'dashboard_last_sample_display': dashboard_last_sample_display,
        'dashboard_olt_uptimes': _collect_dashboard_olt_uptimes(selected_olt.pk if selected_olt else None),
        'dashboard_snmp_down_olts': _collect_dashboard_snmp_down_olts(),
        'dashboard_selected_olt': selected_olt,
        'dashboard_scope_title': f"{selected_olt.name} snapshot" if selected_olt else "Live subscriber snapshot",
        'dashboard_scope_kicker': selected_olt.name if selected_olt else "ONU Overview",
        'dashboard_warning_url': f"{configured_signal_base}?{urlencode(warning_params)}",
        'dashboard_critical_url': f"{configured_signal_base}?{urlencode(critical_params)}",
        'dashboard_admin_disabled_url': f"{configured_signal_base}?{urlencode(admin_disabled_params)}",
        'dashboard_loss_of_signal_url': f"{configured_signal_base}?{urlencode(loss_of_signal_params)}",
        'dashboard_power_failure_url': f"{configured_signal_base}?{urlencode(power_failure_params)}",
        'dashboard_graph': _build_dashboard_status_graph(selected_olt.pk if selected_olt else None, '1h'),
    }
    return render(request, 'oltmanager/olt_list.html', context)


@login_required
def dashboard_status_graph(request):
    range_key = (request.GET.get("range") or "24h").strip().lower()
    olt_filter = (request.GET.get("olt") or "").strip()
    olt_id = None
    if olt_filter.isdigit():
        olt_id = int(olt_filter)
    try:
        record_dashboard_status_samples()
    except OperationalError:
        pass
    try:
        payload = _build_dashboard_status_graph(olt_id, range_key)
    except OperationalError:
        payload = {
            "range_key": range_key,
            "range_label": "Unavailable",
            "points": [],
            "latest": {"online": 0, "offline": 0, "admin_disabled": 0, "power_failure": 0, "loss_of_signal": 0},
        }
    return JsonResponse({"ok": True, **payload})


@login_required
def dashboard_olt_uptimes(request):
    force_refresh = str(request.GET.get("force") or "").strip().lower() in {"1", "true", "yes", "refresh"}
    _schedule_dashboard_snapshot_refreshes()
    selected_olt_filter = (request.GET.get("olt") or "").strip()
    onu_qs = ConfiguredONU.objects.all()
    selected_olt_id = None
    if selected_olt_filter.isdigit():
        selected_olt_id = int(selected_olt_filter)
        onu_qs = onu_qs.filter(olt_id=selected_olt_id)
    if force_refresh:
        refresh_qs = OLT.objects.all()
        if selected_olt_id:
            refresh_qs = refresh_qs.filter(pk=selected_olt_id)
        for olt in refresh_qs:
            try:
                _fetch_snmp_only_after_save(olt)
            except Exception:
                pass
            _schedule_snapshot_refresh(olt.pk)
        try:
            record_dashboard_status_samples(force=True)
        except OperationalError:
            pass
    rows = _collect_dashboard_olt_uptimes()
    down_rows = _collect_dashboard_snmp_down_olts()
    if _autofind_counts_need_refresh(selected_olt_id):
        _schedule_autofind_counts_refresh(selected_olt_id)
    dashboard_counts = _dashboard_status_counts_from_queryset(onu_qs)
    total_all = int(dashboard_counts.get("total_onus") or 0)
    total_online = int(dashboard_counts.get("online_onus") or 0)
    total_offline = max(0, total_all - total_online)
    total_admin_disabled = int(dashboard_counts.get("admin_disabled") or 0)
    total_loss_of_signal = int(dashboard_counts.get("loss_of_signal") or 0)
    total_power_failure = int(dashboard_counts.get("power_failure") or 0)
    total_signal_warn = int(dashboard_counts.get("signal_warn") or 0)
    total_signal_bad = int(dashboard_counts.get("signal_bad") or 0)
    latest_dashboard_sample_at = (
        DashboardStatusSample.objects.order_by("-sampled_at").values_list("sampled_at", flat=True).first()
    )
    if selected_olt_id:
        selected = OLT.objects.filter(pk=selected_olt_id).only("autofind_onu_count", "autofind_new_count", "autofind_resync_count").first()
        total_wait_for_authorize = int(getattr(selected, "autofind_onu_count", 0) or 0)
        total_wait_for_authorize_new = int(getattr(selected, "autofind_new_count", 0) or 0)
        total_wait_for_authorize_resync = int(getattr(selected, "autofind_resync_count", 0) or 0)
    else:
        total_wait_for_authorize = sum(OLT.objects.values_list("autofind_onu_count", flat=True))
        total_wait_for_authorize_new = sum(OLT.objects.values_list("autofind_new_count", flat=True))
        total_wait_for_authorize_resync = sum(OLT.objects.values_list("autofind_resync_count", flat=True))
    latest_dashboard_sample_at = (
        DashboardStatusSample.objects.order_by("-sampled_at").values_list("sampled_at", flat=True).first()
    )
    refreshed_at = timezone.localtime(timezone.now(), ZoneInfo("Asia/Karachi")).strftime("%Y-%m-%d %I:%M:%S %p")
    dashboard_last_updated = (
        timezone.localtime(latest_dashboard_sample_at, ZoneInfo("Asia/Karachi")).strftime("%Y-%m-%d %I:%M:%S %p")
        if latest_dashboard_sample_at
        else refreshed_at
    )
    with _SNAPSHOT_CACHE_LOCK:
        updating = bool(_SNAPSHOT_REFRESHING)
    return JsonResponse({
        "ok": True,
        "rows": rows,
        "down_rows": down_rows,
        "summary": {
            "total_onus": total_all,
            "wait_for_authorize_total": total_wait_for_authorize,
            "wait_for_authorize_new_total": total_wait_for_authorize_new,
            "wait_for_authorize_resync_total": total_wait_for_authorize_resync,
            "online_total": total_online,
            "offline_total": total_offline,
            "admin_disabled_total": total_admin_disabled,
            "loss_of_signal_total": total_loss_of_signal,
            "power_failure_total": total_power_failure,
            "signal_warn_total": total_signal_warn,
            "signal_bad_total": total_signal_bad,
            "signal_total": total_signal_warn + total_signal_bad,
        },
        "refreshed_at": refreshed_at,
        "dashboard_last_updated": dashboard_last_updated,
        "updating": updating,
    })


@login_required
def configured_onus(request):
    search_query = (request.GET.get('q') or '').strip()
    olt_filter = (request.GET.get('olt') or '').strip()
    board_filter = (request.GET.get('board') or '').strip()
    port_filter = (request.GET.get('port') or '').strip()
    status_filter = (request.GET.get('status') or '').strip().lower()
    signal_filter = (request.GET.get('signal') or '').strip().lower()
    sort_filter = (request.GET.get('sort') or '').strip().lower()
    if signal_filter == "warning":
        signal_filter = "warn"
    elif signal_filter == "critical":
        signal_filter = "bad"

    records_qs = (
        ConfiguredONU.objects.select_related("olt")
        .only(
            "olt__name",
            "olt_id",
            "frame",
            "slot",
            "port",
            "ont_id",
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
            "raw_line",
        )
        .order_by("olt__name", "slot", "port", "ont_id")
    )
    if olt_filter:
        records_qs = records_qs.filter(olt_id=olt_filter)
    if board_filter:
        records_qs = records_qs.filter(slot=board_filter)
    if port_filter:
        records_qs = records_qs.filter(port=port_filter)
    if status_filter == "online":
        records_qs = records_qs.filter(Q(derived_status__iexact="online") | Q(run_state__iexact="online"))
    elif status_filter == "offline":
        records_qs = records_qs.exclude(Q(derived_status__iexact="online") | Q(run_state__iexact="online"))
    elif status_filter in {"admin_disabled", "power_failure", "loss_of_signal"}:
        records_qs = records_qs.filter(derived_status=status_filter)
    if signal_filter:
        records_qs = records_qs.filter(signal_bucket=signal_filter)
    if search_query:
        records_qs = [
            record
            for record in records_qs
            if _configured_onu_matches_search(record, search_query)
        ]
    if sort_filter == "signal":
        def _signal_sort_key(record):
            bucket = (getattr(record, "signal_bucket", "") or "").strip() or _classify_onu_signal(getattr(record, "olt_rx", ""))
            has_signal = 1 if bucket else 0
            bucket_rank = {"good": 3, "warn": 2, "bad": 1}.get(bucket, 0)
            return (
                -has_signal,
                -bucket_rank,
                str(getattr(record, "olt__name", "") or getattr(getattr(record, "olt", None), "name", "")),
                int(getattr(record, "slot", 0) or 0),
                int(getattr(record, "port", 0) or 0),
                int(getattr(record, "ont_id", 0) or 0),
            )
        records_qs = sorted(records_qs, key=_signal_sort_key)

    paginator = Paginator(records_qs, 100)
    page_number = request.GET.get('page') or 1
    page_obj = paginator.get_page(page_number)

    rows = []
    for record in page_obj.object_list:
        row = _configured_onu_record_to_row(record)
        enriched = dict(row)
        enriched["olt_name"] = record.olt.name
        enriched["olt_id"] = record.olt_id
        enriched["sn"] = _format_onu_serial_display(row.get("sn"))
        enriched["display_name"] = _format_onu_display_name(
            (row.get("description") or "").strip(),
            enriched["sn"] or f"{record.olt.name}-{row.get('ont_id')}",
        )
        enriched["status_value"] = _normalize_configured_status(row.get("derived_status"), run_state=row.get("run_state"))
        enriched["status_label"] = _configured_status_label(row.get("derived_status"), run_state=row.get("run_state"))
        enriched["status_class"] = _configured_status_class(row.get("derived_status"), run_state=row.get("run_state"))
        enriched["onu_label"] = f"{record.olt.name} gpon-onu_{row.get('fsp')}:{row.get('ont_id')}"
        enriched["signal_class"] = (row.get("signal_bucket") or "").strip() or _classify_onu_signal(row.get("olt_rx"))
        rows.append(enriched)

    available_olts = [{"id": str(olt.pk), "name": olt.name} for olt in OLT.objects.all().order_by('id')]
    available_boards = sorted({str(slot) for slot in ConfiguredONU.objects.order_by().values_list("slot", flat=True).distinct()}, key=lambda x: int(x))
    available_ports = [str(i) for i in range(16)]
    start_index = page_obj.start_index() if paginator.count else 0
    end_index = page_obj.end_index() if paginator.count else 0
    latest_inventory_sync = ConfiguredONU.objects.order_by("-synced_at").values_list("synced_at", flat=True).first()
    latest_inventory_sync_display = ""
    if latest_inventory_sync:
        latest_inventory_sync = timezone.localtime(latest_inventory_sync, ZoneInfo("Asia/Karachi"))
        latest_inventory_sync_display = latest_inventory_sync.strftime("%Y-%m-%d %I:%M:%S %p")

    context = {
        "configured_onu_rows": rows,
        "configured_onu_page": page_obj,
        "configured_onu_paginator": paginator,
        "configured_onu_total": paginator.count,
        "configured_onu_status": "",
        "configured_onu_start": start_index,
        "configured_onu_end": end_index,
        "configured_onu_status_filter": status_filter,
        "configured_onu_signal_filter": signal_filter,
        "configured_onu_sort_filter": sort_filter,
        "configured_onu_search_query": search_query,
        "configured_onu_olt_filter": olt_filter,
        "configured_onu_board_filter": board_filter,
        "configured_onu_port_filter": port_filter,
        "configured_onu_filter_olts": available_olts,
        "configured_onu_filter_boards": available_boards,
        "configured_onu_filter_ports": available_ports,
        "configured_onu_last_sync_at": latest_inventory_sync,
        "configured_onu_last_sync_display": latest_inventory_sync_display,
        "configured_onu_signal_refresh_url": reverse("configured_onu_signals_refresh"),
    }
    return render(request, "oltmanager/configured_onus.html", context)


@login_required
def unconfigured_onus(request):
    selected_olts = [value for value in request.GET.getlist("olts") if str(value).isdigit()]
    search_query = (request.GET.get("q") or "").strip().lower()

    all_olts = list(OLT.objects.only("id", "name", "ip_address").order_by("name"))
    existing_onus = list(
        ConfiguredONU.objects.select_related("olt")
        .only("olt_id", "olt__name", "slot", "port", "ont_id", "sn")
        .exclude(sn="")
    )
    existing_by_serial = {}
    for record in existing_onus:
        token = _normalize_onu_serial_token(record.sn)
        if token and token not in existing_by_serial:
            existing_by_serial[token] = record

    grouped_rows = []
    statuses = []
    total_new = 0
    total_resync = 0
    if selected_olts:
        selected_map = {str(olt.id): olt for olt in all_olts if str(olt.id) in set(selected_olts)}
        for index, olt_id in enumerate(selected_olts, start=1):
            olt = selected_map.get(str(olt_id))
            if not olt:
                continue
            snapshot = fetch_ont_autofind_snapshot(olt)
            statuses.append(f"{olt.name}: {snapshot.get('status') or 'Autofind unavailable'}")
            olt_rows = []
            for row in snapshot.get("rows") or []:
                item = dict(row)
                item["olt_id"] = olt.id
                item["olt_name"] = olt.name
                serial_token = _normalize_onu_serial_token(item.get("sn"))
                existing_record = existing_by_serial.get(serial_token)
                category = "resync" if existing_record else "new"
                item["category"] = category
                item["category_label"] = "Resync" if existing_record else "New"
                item["existing_onu_url"] = (
                    reverse(
                        "configured_onu_detail",
                        kwargs={
                            "olt_pk": existing_record.olt_id,
                            "slot": int(existing_record.slot or 0),
                            "port": int(existing_record.port or 0),
                            "ont_id": int(existing_record.ont_id or 0),
                        },
                    )
                    if existing_record
                    else ""
                )
                if existing_record:
                    total_resync += 1
                else:
                    total_new += 1
                if search_query:
                    haystack = " ".join([
                        str(item.get("olt_name") or ""),
                        str(item.get("pon_type") or ""),
                        str(item.get("board") or ""),
                        str(item.get("port") or ""),
                        str(item.get("sn") or ""),
                        str(item.get("category_label") or ""),
                        str(item.get("type") or ""),
                        str(item.get("autofind_time") or ""),
                    ]).lower()
                    if search_query not in haystack:
                        continue
                olt_rows.append(item)
            olt_rows.sort(key=lambda row: (int(row.get("board") or 0), int(row.get("port") or 0), str(row.get("sn") or "")))
            grouped_rows.append({
                "index": index,
                "olt_id": olt.id,
                "olt_name": olt.name,
                "rows": olt_rows,
                "count": len(olt_rows),
                "status": snapshot.get("status") or "Autofind unavailable",
            })
    total_rows = sum(group["count"] for group in grouped_rows)
    context = {
        "unconfigured_groups": grouped_rows,
        "unconfigured_selected_olts": selected_olts,
        "unconfigured_filter_olts": [{"id": str(olt.id), "name": olt.name, "ip": olt.ip_address} for olt in all_olts],
        "unconfigured_search_query": request.GET.get("q", "").strip(),
        "unconfigured_status": " | ".join(statuses),
        "unconfigured_total": total_rows,
        "unconfigured_new_total": total_new,
        "unconfigured_resync_total": total_resync,
    }
    return render(request, "oltmanager/unconfigured_onus.html", context)


def _active_trap_status_for_onu(olt, slot, port, ont_id):
    priority = {
        "admin_disabled": 0,
        "power_failure": 1,
        "loss_of_signal": 2,
    }
    best = ""
    events = ONUTrapEvent.objects.filter(
        olt=olt,
        slot=slot,
        port=port,
        ont_id=ont_id,
        is_active=True,
    ).only("mapped_status", "alarm_code", "alarm_name")
    for event in events:
        mapped = (event.mapped_status or "").strip() or map_onu_alarm_to_status(event.alarm_code, event.alarm_name)
        if not mapped:
            continue
        if not best or priority.get(mapped, 99) < priority.get(best, 99):
            best = mapped
    return best


def _update_configured_onu_status_from_traps(olt, slot, port, ont_id):
    record = ConfiguredONU.objects.filter(
        olt=olt,
        slot=slot,
        port=port,
        ont_id=ont_id,
    ).first()
    if not record:
        return None
    trap_status = _active_trap_status_for_onu(olt, slot, port, ont_id)
    fallback_status = derive_inventory_onu_status({
        "control_flag": record.control_flag,
        "run_state": record.run_state,
        "config_state": record.config_state,
    })
    new_status = trap_status or fallback_status
    new_source = "trap" if trap_status else "inventory"
    changed = (
        new_status != (record.derived_status or "").strip()
        or new_source != (record.status_source or "").strip()
    )
    if changed:
        if new_status != (record.derived_status or "").strip() or not record.status_first_seen_at:
            record.status_first_seen_at = timezone.now()
        record.derived_status = new_status
        record.status_source = new_source
        record.status_updated_at = timezone.now()
        record.save(update_fields=["derived_status", "status_source", "status_first_seen_at", "status_updated_at"])
    return record


@csrf_exempt
@require_POST
def onu_trap_ingest(request):
    try:
        payload = json.loads(request.body.decode("utf-8"))
    except (TypeError, ValueError, json.JSONDecodeError):
        return JsonResponse({"ok": False, "error": "Invalid JSON payload."}, status=400)

    events = payload if isinstance(payload, list) else [payload]
    processed = 0
    updated = 0
    ignored = 0

    for item in events:
        if not isinstance(item, dict):
            ignored += 1
            continue
        olt = None
        olt_ip = str(item.get("olt_ip") or item.get("ip_address") or "").strip()
        olt_name = str(item.get("olt_name") or "").strip()
        if olt_ip:
            olt = OLT.objects.filter(ip_address=olt_ip).first()
        if olt is None and olt_name:
            olt = OLT.objects.filter(name=olt_name).first()
        if olt is None:
            ignored += 1
            continue
        try:
            slot = int(item.get("slot"))
            port = int(item.get("port"))
            ont_id = int(item.get("ont_id"))
        except (TypeError, ValueError):
            ignored += 1
            continue

        alarm_code = str(item.get("alarm_code") or item.get("code") or item.get("alarmId") or item.get("alarm_id") or "").strip()
        alarm_name = str(item.get("alarm_name") or item.get("name") or item.get("alarmName") or item.get("alarm_name_text") or "").strip()
        extra_text = " ".join(
            str(item.get(field) or "").strip()
            for field in (
                "message",
                "description",
                "details",
                "specific_problem",
                "specificProblem",
                "probable_cause",
                "probableCause",
                "trap_oid",
                "oid",
                "alarm_type",
                "alarmType",
                "event_type",
                "eventType",
                "category",
                "severity_text",
            )
            if str(item.get(field) or "").strip()
        )
        mapped_status = map_onu_alarm_to_status(alarm_code, alarm_name, extra_text=extra_text)
        if not mapped_status:
            ignored += 1
            continue

        severity = str(item.get("severity") or "").strip()
        state_text = " ".join(
            str(item.get(field) or "").strip().lower()
            for field in ("event_state", "state", "action", "operation", "alarm_state", "alarmState")
            if str(item.get(field) or "").strip()
        )
        is_active = not any(token in state_text for token in ("clear", "cleared", "recover", "recovered", "inactive", "off", "resume", "normal"))
        alarm_key = alarm_code or re.sub(r"[^a-z0-9]+", "_", alarm_name.strip().lower()).strip("_")
        if not alarm_key:
            ignored += 1
            continue

        ONUTrapEvent.objects.update_or_create(
            olt=olt,
            slot=slot,
            port=port,
            ont_id=ont_id,
            alarm_key=alarm_key[:96],
            defaults={
                "alarm_code": alarm_code[:64],
                "alarm_name": alarm_name[:255],
                "mapped_status": mapped_status[:32],
                "severity": severity[:32],
                "is_active": is_active,
                "raw_payload": json.dumps(item, ensure_ascii=True)[:4000],
            },
        )
        if _update_configured_onu_status_from_traps(olt, slot, port, ont_id):
            updated += 1
        processed += 1

    return JsonResponse({
        "ok": True,
        "processed": processed,
        "updated": updated,
        "ignored": ignored,
    })


@login_required
@require_POST
def configured_onu_signals_refresh(request):
    try:
        payload = json.loads(request.body.decode("utf-8"))
    except (TypeError, ValueError, json.JSONDecodeError):
        return JsonResponse({"ok": False, "error": "Invalid payload."}, status=400)

    items = payload.get("onus") or []
    detail_refresh = bool(payload.get("detail"))
    grouped = {}
    for item in items:
        try:
            olt_id = int(item.get("olt_id"))
            slot = int(item.get("slot"))
            port = int(item.get("port"))
            ont_id = int(item.get("ont_id"))
        except (TypeError, ValueError, AttributeError):
            continue
        grouped.setdefault(olt_id, set()).add((slot, port, ont_id))

    response_items = {}
    for olt_id, onu_keys in grouped.items():
        olt = OLT.objects.filter(pk=olt_id).first()
        if not olt:
            continue
        optical_bundle = fetch_ont_optical_subset_meta(olt, sorted(onu_keys))
        optical_map = optical_bundle.get("items") or {}
        fetch_ok = bool(optical_bundle.get("ok"))
        successful_ports = {tuple(item) for item in (optical_bundle.get("successful_ports") or set())}
        db_updates = []
        samples = []
        for slot, port, ont_id in onu_keys:
            record = ConfiguredONU.objects.filter(
                olt=olt,
                slot=slot,
                port=port,
                ont_id=ont_id,
            ).first()
            key = f"{olt_id}:{slot}:{port}:{ont_id}"
            port_fetch_ok = (int(slot), int(port)) in successful_ports
            if not port_fetch_ok and record is not None:
                response_items[key] = _signal_payload_from_values(record.onu_rx, record.olt_rx)
                response_items[key]["status_value"] = _normalize_configured_status(record.derived_status, run_state=record.run_state)
                response_items[key]["status_label"] = _configured_status_label(record.derived_status, run_state=record.run_state)
                response_items[key]["status_class"] = _configured_status_class(record.derived_status, run_state=record.run_state)
                response_items[key]["status_age_text"] = _format_status_age_text(
                    record.status_first_seen_at or record.status_updated_at
                )
                if detail_refresh and len(onu_keys) == 1:
                    response_items[key]["signal_distance_text"] = _format_onu_distance_text(
                        getattr(record, "ont_distance_m", "") if hasattr(record, "ont_distance_m") else ""
                    )
                continue

            signal = optical_map.get((slot, port, ont_id), {"onu_rx": "--", "olt_rx": "--", "tx_power": "--"})
            payload_row = _signal_payload_from_values(signal.get("onu_rx"), signal.get("olt_rx"))
            response_items[key] = dict(payload_row)

            if record:
                now = timezone.now()
                record.onu_rx = payload_row["onu_rx"] if payload_row["onu_rx"] != "--" else ""
                record.olt_rx = payload_row["olt_rx"] if payload_row["olt_rx"] != "--" else ""
                record.tx_power = (signal.get("tx_power") or "") if (signal.get("tx_power") or "") != "--" else ""
                record.signal_bucket = payload_row["signal_class"] or ""
                next_status, next_source = _resolve_signal_refresh_status(record, payload_row["signal_visible"])
                if next_status != _normalize_configured_status(record.derived_status, run_state=record.run_state):
                    record.status_first_seen_at = now
                elif not record.status_first_seen_at:
                    record.status_first_seen_at = now
                record.derived_status = next_status
                record.status_source = next_source
                record.status_updated_at = now
                response_items[key]["status_value"] = _normalize_configured_status(record.derived_status, run_state=record.run_state)
                response_items[key]["status_label"] = _configured_status_label(record.derived_status, run_state=record.run_state)
                response_items[key]["status_class"] = _configured_status_class(record.derived_status, run_state=record.run_state)
                response_items[key]["status_age_text"] = _format_status_age_text(
                    record.status_first_seen_at or record.status_updated_at
                )
                db_updates.append(record)
                if detail_refresh and len(onu_keys) == 1:
                    runtime_snapshot = fetch_single_ont_runtime_snapshot(olt, slot, port, ont_id)
                    if runtime_snapshot:
                        response_items[key]["status_age_text"] = _status_age_text_from_onu_runtime(
                            response_items[key]["status_value"],
                            runtime_snapshot,
                        ) or _format_status_age_text(record.status_first_seen_at or record.status_updated_at)
                        since_dt = _status_since_datetime_from_onu_runtime(
                            response_items[key]["status_value"],
                            runtime_snapshot,
                        )
                        response_items[key]["status_since_label"] = (
                            "Online Since" if _normalize_configured_status(response_items[key]["status_value"]) == "online" else "Status Since"
                        )
                        response_items[key]["status_since_text"] = _format_relative_time_text(since_dt)
                        response_items[key]["signal_distance_text"] = _format_onu_distance_text(
                            runtime_snapshot.get("ont_distance_m")
                        )
            samples.append(
                ONUOpticalSample(
                    olt=olt,
                    slot=slot,
                    port=port,
                    ont_id=ont_id,
                    onu_rx=payload_row["onu_rx"] if payload_row["onu_rx"] != "--" else "",
                    olt_rx=payload_row["olt_rx"] if payload_row["olt_rx"] != "--" else "",
                    tx_power=(signal.get("tx_power") or "") if (signal.get("tx_power") or "") != "--" else "",
                )
            )
        if db_updates:
            ConfiguredONU.objects.bulk_update(
                db_updates,
                ["onu_rx", "olt_rx", "tx_power", "signal_bucket", "derived_status", "status_source", "status_first_seen_at", "status_updated_at"],
                batch_size=200,
            )
            try:
                record_dashboard_status_samples(force=True)
            except OperationalError:
                pass
        if samples and fetch_ok:
            ONUOpticalSample.objects.bulk_create(samples, batch_size=200)

    return JsonResponse({"ok": True, "items": response_items})


@login_required
def configured_onu_detail(request, olt_pk, slot, port, ont_id):
    olt = get_object_or_404(OLT, pk=olt_pk)
    record = ConfiguredONU.objects.filter(
        olt=olt,
        slot=slot,
        port=port,
        ont_id=ont_id,
    ).first()
    if record is None:
        sync_configured_onus_inventory(olt)
        record = ConfiguredONU.objects.filter(
            olt=olt,
            slot=slot,
            port=port,
            ont_id=ont_id,
        ).first()

    if request.method == "POST" and record is not None:
        action = (request.POST.get("action") or "").strip().lower()
        if action == "save_contact_info":
            address = _clean_onu_detail_text(request.POST.get("address"), 255)
            contact = _clean_onu_detail_text(request.POST.get("contact"), 64)
            record.address = address
            record.contact = contact
            record.save(update_fields=["address", "contact"])
            messages.success(request, "ONU contact details updated.")
            return redirect("configured_onu_detail", olt_pk=olt.pk, slot=slot, port=port, ont_id=ont_id)

    selected_onu = _configured_onu_record_to_row(record) if record else None

    if selected_onu is None:
        selected_onu = {
            "slot": slot,
            "port": port,
            "ont_id": ont_id,
            "fsp": f"0/{slot}/{port}",
            "sn": "",
            "description": "",
            "run_state": "",
        }

    selected_onu["display_name"] = _format_onu_display_name(
        (selected_onu.get("description") or "").strip(),
        _format_onu_serial_display(selected_onu.get("sn")) or f"{olt.name}-{ont_id}",
    )
    selected_onu["sn"] = _format_onu_serial_display(selected_onu.get("sn"))
    selected_onu["onu_label"] = f"gpon-onu_0/{slot}/{port}:{ont_id}"
    runtime_snapshot = fetch_single_ont_runtime_snapshot(olt, slot, port, ont_id)
    capability_snapshot = fetch_single_ont_capability_snapshot(olt, slot, port, ont_id)
    trap_status = _active_trap_status_for_onu(olt, slot, port, ont_id)
    effective_status = trap_status or _normalize_configured_status(
        selected_onu.get("derived_status"),
        run_state=selected_onu.get("run_state"),
    )
    if record is not None:
        now = timezone.now()
        update_fields = []
        if effective_status != _normalize_configured_status(record.derived_status, run_state=record.run_state):
            record.derived_status = effective_status
            record.status_source = "trap" if trap_status else (record.status_source or "inventory")
            record.status_updated_at = now
            record.status_first_seen_at = now
            update_fields.extend(["derived_status", "status_source", "status_updated_at", "status_first_seen_at"])
        elif not record.status_first_seen_at:
            record.status_first_seen_at = now
            update_fields.append("status_first_seen_at")

        if update_fields:
            record.save(update_fields=update_fields)
            try:
                record_dashboard_status_samples(force=True)
            except OperationalError:
                pass

    selected_onu["status_value"] = effective_status
    selected_onu["status_text"] = _configured_status_label(effective_status, run_state=runtime_snapshot.get("run_state") or selected_onu.get("run_state"))
    selected_onu["status_class"] = _configured_status_class(effective_status, run_state=runtime_snapshot.get("run_state") or selected_onu.get("run_state"))
    selected_onu["onu_type"] = (
        (capability_snapshot.get("equipment_id") or "").strip()
        or (runtime_snapshot.get("ont_equipment_id") or "").strip()
        or "-"
    )
    selected_onu["attached_vlans"] = (runtime_snapshot.get("attached_vlans") or "").strip() or "-"
    selected_onu["onu_mode"] = (runtime_snapshot.get("onu_mode") or "").strip() or "-"
    selected_onu["uplink_pon_ports"] = (capability_snapshot.get("uplink_pon_ports") or "").strip() or "-"
    selected_onu["pots_ports"] = (capability_snapshot.get("pots_ports") or "").strip() or "-"
    selected_onu["eth_ports"] = (capability_snapshot.get("eth_ports") or "").strip() or "-"
    selected_onu["catv_uni_ports"] = (capability_snapshot.get("catv_uni_ports") or "").strip() or "-"
    selected_onu["last_down_cause"] = (runtime_snapshot.get("last_down_cause") or "").strip()
    selected_onu["battery_state"] = (runtime_snapshot.get("battery_state") or "").strip()
    selected_onu["ont_distance_m"] = (runtime_snapshot.get("ont_distance_m") or "").strip()
    selected_onu["status_age_text"] = _status_age_text_from_onu_runtime(
        effective_status,
        runtime_snapshot,
    ) or _format_status_age_text(
        selected_onu.get("status_first_seen_at") or selected_onu.get("status_updated_at")
    )
    status_since_dt = _status_since_datetime_from_onu_runtime(effective_status, runtime_snapshot)
    selected_onu["status_since_label"] = "Online Since" if _normalize_configured_status(effective_status) == "online" else "Status Since"
    selected_onu["status_since_text"] = _format_relative_time_text(status_since_dt)
    if all(str(selected_onu.get(key, "")).strip() in {"", "--"} for key in ("onu_rx", "olt_rx")):
        live_signal = fetch_single_ont_optical_info(olt, slot, port, ont_id)
        if live_signal:
            selected_onu["onu_rx"] = live_signal.get("onu_rx", "--")
            selected_onu["tx_power"] = live_signal.get("tx_power", "--")
            selected_onu["olt_rx"] = live_signal.get("olt_rx", "--")
    selected_onu["signal_distance_text"] = _format_onu_distance_text(selected_onu.get("ont_distance_m"))
    selected_onu["signal_class"] = _classify_onu_signal(selected_onu.get("olt_rx"))
    signal_visible = any(str(selected_onu.get(key, "")).strip() not in {"", "--"} for key in ("onu_rx", "olt_rx"))
    signal_history = _get_onu_signal_history(olt, slot, port, ont_id, hours=24)

    context = {
        "olt": olt,
        "slot": slot,
        "port": port,
        "ont_id": ont_id,
        "fsp": f"0/{slot}/{port}",
        "onu": selected_onu,
        "onu_signal_visible": signal_visible,
        "onu_signal_history_json": json.dumps(signal_history),
        "olt_filter_url": f"{reverse('configured_onus')}?olt={olt.pk}",
        "board_filter_url": f"{reverse('configured_onus')}?olt={olt.pk}&board={slot}",
        "port_filter_url": f"{reverse('configured_onus')}?olt={olt.pk}&board={slot}&port={port}",
        "onu_signal_refresh_url": reverse("configured_onu_signals_refresh"),
    }
    return render(request, "oltmanager/configured_onu_detail.html", context)


@login_required
def settings_home(request):
    return render(request, "oltmanager/settings_home.html")


@login_required
def olt_settings_olt(request):
    _schedule_missing_device_snapshots_if_due()
    olts = OLT.objects.all()
    telnet_pk = request.GET.get('telnet_pk')
    telnet_result = (request.GET.get('telnet_result') or '').lower()
    telnet_note = (request.GET.get('telnet_note') or '').strip()[:160]
    try:
        telnet_pk = int(telnet_pk) if telnet_pk else None
    except (TypeError, ValueError):
        telnet_pk = None
    if telnet_result not in {'pass', 'fail'}:
        telnet_result = ''
        telnet_note = ''
    return render(
        request,
        'oltmanager/olt_settings_olt.html',
        {
            'olts': olts,
            'telnet_pk': telnet_pk,
            'telnet_result': telnet_result,
            'telnet_note': telnet_note,
        },
    )


@login_required
def olt_add(request):
    if request.method == 'POST':
        form = OLTForm(request.POST)
        if form.is_valid():
            olt = form.save()
            snmp_mode = form.cleaned_data.get('snmp_mode') or 'manual'
            if snmp_mode == 'generate':
                snmp_ok, snmp_status = _sync_snmp_after_save(olt)
                success_text = 'OLT added and SNMP generated/pushed successfully.'
                failure_text = f"OLT added, but SNMP generate/push failed: {snmp_status}"
            else:
                snmp_ok, snmp_status = _fetch_snmp_only_after_save(olt)
                success_text = 'OLT added and SNMP fetched successfully.'
                failure_text = f"OLT added, but SNMP fetch failed: {snmp_status}"
            _schedule_device_snapshots_refresh(olt.pk)
            _schedule_configured_onu_inventory_refresh(olt.pk)
            if snmp_ok:
                messages.success(request, success_text)
            else:
                messages.warning(request, failure_text)
            return redirect('olt_settings_olt')
    else:
        form = OLTForm()
    return render(
        request,
        'oltmanager/olt_form.html',
        {
            'form': form,
            'form_title': 'Add New OLT',
            'form_subtle': 'Enter device information for Telnet-based access.',
            'back_fallback_url': reverse('olt_settings_olt'),
            'cancel_url': reverse('olt_settings_olt'),
        },
    )


@login_required
def olt_edit(request, pk):
    olt = get_object_or_404(OLT, pk=pk)
    if request.method == 'POST':
        form = OLTForm(request.POST, instance=olt)
        if form.is_valid():
            olt = form.save()
            snmp_mode = form.cleaned_data.get('snmp_mode') or 'manual'
            if snmp_mode == 'generate':
                snmp_ok, snmp_status = _sync_snmp_after_save(olt)
                success_text = 'OLT settings updated and SNMP generated/pushed successfully.'
                failure_text = f"OLT settings updated, but SNMP generate/push failed: {snmp_status}"
            else:
                snmp_ok, snmp_status = _fetch_snmp_only_after_save(olt)
                success_text = 'OLT settings updated and SNMP fetched successfully.'
                failure_text = f"OLT settings updated, but SNMP fetch failed: {snmp_status}"
            _schedule_device_snapshots_refresh(olt.pk)
            _schedule_configured_onu_inventory_refresh(olt.pk)
            if snmp_ok:
                messages.success(request, success_text)
            else:
                messages.warning(request, failure_text)
            return redirect('olt_view', pk=pk)
    else:
        form = OLTForm(instance=olt)
    details_url = f"{reverse('olt_view', kwargs={'pk': pk})}?section=olt-details"
    return render(
        request,
        'oltmanager/olt_form.html',
        {
            'form': form,
            'form_title': 'Edit OLT settings',
            'form_subtle': 'Update device information.',
            'back_fallback_url': details_url,
            'cancel_url': details_url,
        },
    )


@login_required
def olt_delete(request, pk):
    olt = get_object_or_404(OLT, pk=pk)
    if request.method == 'POST':
        olt.delete()
        return redirect('olt_settings_olt')
    return render(request, 'oltmanager/olt_confirm_delete.html', {'olt': olt})


@login_required
def olt_telnet_connect(request, pk):
    olt = get_object_or_404(OLT, pk=pk)
    if request.method != 'POST':
        return redirect('olt_settings_olt')

    adapter = get_olt_adapter(olt)
    tn, status = adapter.open_telnet_session(olt)
    result = 'fail'
    note = status or 'Connection failed.'
    try:
        if tn is not None:
            result = 'pass'
            note = 'Telnet connected'
            _record_olt_login(olt, request.user, 'telnet_connect', 'Manual telnet connect from settings page', request=request)
    except (socket.timeout, TimeoutError):
        result = 'fail'
        note = 'Telnet timeout'
    except OSError as exc:
        result = 'fail'
        note = f"Telnet error: {exc}"
    finally:
        if tn is not None:
            try:
                tn.close()
            except OSError:
                pass

    params = urlencode({'telnet_pk': olt.pk, 'telnet_result': result, 'telnet_note': note[:160]})
    return redirect(f"{reverse('olt_settings_olt')}?{params}")


@login_required
def olt_view(request, pk):
    olt = get_object_or_404(OLT, pk=pk)
    available_sections = {
        'olt-details',
        'olt-cards',
        'history',
        'pon-ports',
        'uplink',
        'vlans',
        'profiles',
        'advanced',
    }
    selected_section = getattr(request, "_olt_view_section", None) or request.GET.get('section', 'olt-details')
    if selected_section not in available_sections:
        selected_section = 'olt-details'

    olt_cards = []
    olt_cards_status = ''
    pon_port_groups = []
    pon_ports_status = ''
    snmp_snapshot = {
        'status': olt.snmp_last_status or 'SNMP not fetched yet',
        'sys_name': olt.name,
        'sys_descr': '',
        'model': olt.hardware_version or 'Unknown',
        'sw_version': olt.sw_version or 'Unknown',
        'uptime': '--',
    }
    uplink_data = {'status': 'SNMP interfaces not fetched', 'rows': []}
    vlan_data = {'status': 'VLANs not fetched', 'rows': []}
    vlan_add_form = VLANAddForm()
    vlan_bulk_form = VLANBulkAddForm()
    vlan_transcript = ""
    vlan_bulk_transcript = ""
    vlan_notice = ""
    vlan_override = getattr(request, "_vlan_override", None)
    dba_profile_data = {'status': 'DBA profiles not fetched', 'rows': []}
    dba_profile_form = DBAProfileAddForm()
    dba_profile_transcript = ""
    dba_profile_config = None
    dba_profile_notice = ""
    dba_profile_override = getattr(request, "_dba_profile_override", None)
    history_rows = []
    if selected_section == 'history':
        history_rows = list(olt.login_history.select_related('olt').all()[:100])

    if selected_section == 'olt-cards':
        if olt.olt_cards_cache:
            olt_cards = olt.olt_cards_cache
            olt_cards_status = _clean_ui_status(olt.olt_cards_status, 'Loaded from database', has_data=bool(olt_cards))
        else:
            _schedule_device_snapshots_refresh(olt.pk)
            olt_cards = []
            olt_cards_status = 'Snapshot is being prepared. Open again shortly or use Refresh Ports.'

    if selected_section == 'pon-ports':
        saved_groups = list(getattr(olt, "pon_ports_cache", []) or [])
        if saved_groups:
            pon_port_groups = saved_groups
            pon_ports_status = _clean_ui_status(olt.pon_ports_status, 'Loaded from database', has_data=bool(saved_groups))
            _set_cached_pon_ports(olt.pk, pon_port_groups, pon_ports_status)
        else:
            _schedule_device_snapshots_refresh(olt.pk)
            pon_port_groups = []
            pon_ports_status = 'Snapshot is being prepared. Open again shortly or use Refresh PON Ports.'

    if selected_section == 'olt-details':
        snmp_snapshot = _build_saved_device_snapshot(olt)
    if selected_section == 'uplink':
        saved_uplink_rows = list(getattr(olt, "uplink_cache", []) or [])
        if saved_uplink_rows:
            uplink_data = {
                'status': _clean_ui_status(getattr(olt, "uplink_status", ""), 'Loaded from database', has_data=True),
                'rows': saved_uplink_rows,
            }
        else:
            _schedule_device_snapshots_refresh(olt.pk)
            uplink_data = {'status': 'Snapshot is being prepared. Open again shortly or use Refresh Ports.', 'rows': []}

    if selected_section == 'vlans':
        saved_vlan_rows = list(getattr(olt, "vlan_cache", []) or [])
        if saved_vlan_rows:
            vlan_data = {
                'status': _clean_ui_status(getattr(olt, "vlan_status", ""), 'Loaded from database', has_data=True),
                'rows': saved_vlan_rows,
            }
        else:
            vlan_data = {
                'status': _clean_ui_status(
                    getattr(olt, "vlan_status", ""),
                    'No VLAN snapshot in database. Use Refresh VLANs.',
                    has_data=False,
                ),
                'rows': [],
            }
        if vlan_override:
            vlan_add_form = vlan_override.get("form") or VLANAddForm(
                reserved_ids={int(row.get("vlan_id")) for row in (vlan_data.get('rows') or []) if str(row.get("vlan_id", "")).isdigit()},
            )
            vlan_bulk_form = vlan_override.get("bulk_form") or VLANBulkAddForm(
                reserved_ids={int(row.get("vlan_id")) for row in (vlan_data.get('rows') or []) if str(row.get("vlan_id", "")).isdigit()},
            )
            vlan_transcript = vlan_override.get("transcript") or ""
            vlan_bulk_transcript = vlan_override.get("bulk_transcript") or ""
            vlan_notice = vlan_override.get("notice") or ""
        else:
            restored_vlan = _restore_vlan_form_state(request, olt, vlan_data.get('rows') or [])
            if isinstance(restored_vlan, tuple):
                vlan_add_form, vlan_transcript = restored_vlan
            else:
                vlan_add_form = restored_vlan
            restored_vlan_bulk = _restore_vlan_bulk_form_state(request, olt, vlan_data.get('rows') or [])
            if isinstance(restored_vlan_bulk, tuple):
                vlan_bulk_form, vlan_bulk_transcript = restored_vlan_bulk
            else:
                vlan_bulk_form = restored_vlan_bulk
            vlan_notice = _restore_vlan_notice(request, olt.pk)

    if selected_section == 'profiles':
        saved_dba_rows = list(getattr(olt, "dba_profile_cache", []) or [])
        if saved_dba_rows:
            dba_profile_data = {
                'status': _clean_ui_status(getattr(olt, "dba_profile_status", ""), 'Loaded from database', has_data=True),
                'rows': saved_dba_rows,
            }
        else:
            _schedule_device_snapshots_refresh(olt.pk)
            dba_profile_data = {'status': 'Snapshot is being prepared. Open again shortly or use Refresh Profiles.', 'rows': []}
        if dba_profile_override:
            dba_profile_form = dba_profile_override.get("form") or DBAProfileAddForm(
                reserved_ids={int(row.get("profile_id")) for row in (dba_profile_data.get('rows') or []) if str(row.get("profile_id", "")).isdigit()},
                reserved_names={str(row.get("profile_name") or "").strip() for row in (dba_profile_data.get('rows') or []) if str(row.get("profile_name") or "").strip()},
            )
            dba_profile_transcript = dba_profile_override.get("transcript") or ""
            dba_profile_config = dba_profile_override.get("config")
            dba_profile_notice = dba_profile_override.get("notice") or ""
        else:
            restored = _restore_dba_profile_form_state(request, olt, dba_profile_data.get('rows') or [])
            if isinstance(restored, tuple):
                dba_profile_form, dba_profile_transcript = restored
            else:
                dba_profile_form = restored
            dba_profile_config = _restore_dba_profile_config_state(request, olt.pk)
            dba_profile_notice = _restore_dba_profile_notice(request, olt.pk)

    snapshot_bundle = _serialize_olt_details_snapshot(olt, snmp_snapshot)
    snapshot = snapshot_bundle['snapshot']
    software_display = snapshot_bundle['software_display'] if selected_section == 'olt-details' else (olt.sw_version or 'Unknown')
    banner_uptime = snapshot_bundle['banner_uptime'] if selected_section == 'olt-details' else '--'
    banner_uptime_ok = snapshot_bundle['banner_uptime_ok'] if selected_section == 'olt-details' else False
    temperature_alert = snapshot_bundle['temperature_alert'] if selected_section == 'olt-details' else False
    snapshot_status_display = snapshot_bundle['snapshot_status_display']
    pon_ports_status_display = _clean_ui_status(pon_ports_status, 'No PON ports found.', has_data=bool(pon_port_groups))
    uplink_status_display = _clean_ui_status(uplink_data.get('status'), 'No uplink data found.', has_data=bool(uplink_data.get('rows')))
    vlan_status_display = _clean_ui_status(vlan_data.get('status'), 'No VLAN data found.', has_data=bool(vlan_data.get('rows')))
    dba_profile_status_display = _clean_ui_status(dba_profile_data.get('status'), 'No DBA profiles found.', has_data=bool(dba_profile_data.get('rows')))
    context = {
        'olt': olt,
        'snapshot': snapshot,
        'snapshot_status_display': snapshot_status_display,
        'olt_cards': olt_cards,
        'olt_cards_status': olt_cards_status,
        'selected_section': selected_section,
        'software_display': software_display or 'Unknown',
        'banner_uptime': banner_uptime,
        'banner_uptime_ok': banner_uptime_ok,
        'temperature_alert': temperature_alert,
        'pon_port_groups': pon_port_groups,
        'pon_ports_status': pon_ports_status,
        'pon_ports_status_display': pon_ports_status_display,
        'pon_ports_refresh_data_url': reverse('olt_pon_ports_refresh_data', kwargs={'pk': olt.pk}),
        'snmp_snapshot': snmp_snapshot,
        'uplink_data': uplink_data,
        'uplink_status_display': uplink_status_display,
        'vlan_data': vlan_data,
        'vlan_status_display': vlan_status_display,
        'vlan_add_form': vlan_add_form,
        'vlan_bulk_form': vlan_bulk_form,
        'vlan_transcript': vlan_transcript,
        'vlan_bulk_transcript': vlan_bulk_transcript,
        'vlan_notice': vlan_notice,
        'dba_profile_data': dba_profile_data,
        'dba_profile_status_display': dba_profile_status_display,
        'dba_profile_form': dba_profile_form,
        'dba_profile_transcript': dba_profile_transcript,
        'dba_profile_config': dba_profile_config,
        'dba_profile_notice': dba_profile_notice,
        'history_rows': history_rows,
        'olt_details_refresh_url': reverse('olt_details_refresh', kwargs={'pk': olt.pk}),
    }
    return render(request, 'oltmanager/olt_view.html', context)


@login_required
def olt_details_refresh(request, pk):
    olt = get_object_or_404(OLT, pk=pk)
    live_lock = _try_acquire_olt_live_lock(olt.pk)
    if live_lock is None:
        payload = _serialize_olt_details_snapshot(olt, _build_saved_device_snapshot(olt))
        return JsonResponse({
            'ok': False,
            'busy': True,
            'message': 'Device busy. Showing saved data.',
            **payload,
        })

    try:
        snapshot = fetch_snmp_snapshot(olt)
        need_telnet_details = _should_fetch_telnet_version_details(olt, snapshot)
        need_telnet_uptime = _should_fetch_telnet_uptime(snapshot)
        if need_telnet_details or need_telnet_uptime:
            telnet_snapshot = fetch_telnet_version_snapshot(olt)
            telnet_sw = str(telnet_snapshot.get('sw_version') or '').strip()
            telnet_model = str(telnet_snapshot.get('model') or '').strip()
            telnet_uptime = str(telnet_snapshot.get('uptime') or '').strip()
            if need_telnet_details and telnet_sw and telnet_sw.lower() != 'unknown':
                snapshot['sw_version'] = telnet_sw
            if need_telnet_details and telnet_model and telnet_model.lower() != 'unknown':
                snapshot['model'] = telnet_model
            if need_telnet_uptime and telnet_uptime and telnet_uptime != '--':
                snapshot['uptime'] = telnet_uptime
        _set_cached_snapshot(olt.pk, snapshot)

        update_fields = []
        fetched_sw = (snapshot.get('sw_version') or '').strip()
        if fetched_sw and fetched_sw.lower() != 'unknown' and fetched_sw != (olt.sw_version or ''):
            olt.sw_version = fetched_sw
            update_fields.append('sw_version')
        fetched_model = (snapshot.get('model') or '').strip()
        if fetched_model and fetched_model.lower() != 'unknown' and fetched_model != (olt.hardware_version or ''):
            olt.hardware_version = fetched_model
            update_fields.append('hardware_version')
        fetched_status = (snapshot.get('status') or '').strip()
        if fetched_status:
            olt.snmp_last_status = fetched_status[:300]
            olt.snmp_last_synced_at = timezone.now()
            update_fields.extend(['snmp_last_status', 'snmp_last_synced_at'])
        if update_fields:
            olt.save(update_fields=list(dict.fromkeys(update_fields)))

        payload = _serialize_olt_details_snapshot(olt, snapshot)
        return JsonResponse({'ok': True, **payload})
    finally:
        live_lock.release()


@login_required
def olt_cli_window(request, pk):
    olt = get_object_or_404(OLT, pk=pk)
    return render(request, 'oltmanager/olt_cli_window.html', {'olt': olt})


@login_required
@require_POST
def olt_cli_open(request, pk):
    olt = get_object_or_404(OLT, pk=pk)
    _cleanup_expired_cli_sessions()
    _close_user_cli_session(request.user.id, olt.pk)

    adapter = get_olt_adapter(olt)
    tn, status = adapter.open_telnet_session(olt)
    if tn is None:
        return JsonResponse({'ok': False, 'message': status}, status=400)

    key = _cli_session_key(request.user.id, olt.pk)
    with _CLI_SESSIONS_LOCK:
        _CLI_SESSIONS[key] = {
            'tn': tn,
            'updated_at': timezone.now(),
        }
    _record_olt_login(olt, request.user, 'cli_open', 'Interactive CLI session opened', request=request)
    prompt_output = adapter.run_session_command(tn, "")
    return JsonResponse({'ok': True, 'output': prompt_output or 'CLI connected.'})


@login_required
@require_POST
def olt_cli_run(request, pk):
    olt = get_object_or_404(OLT, pk=pk)
    _cleanup_expired_cli_sessions()
    adapter = get_olt_adapter(olt)

    key = _cli_session_key(request.user.id, olt.pk)
    with _CLI_SESSIONS_LOCK:
        session = _CLI_SESSIONS.get(key)
    if not session:
        return JsonResponse({'ok': False, 'message': 'CLI session not connected.'}, status=400)

    tn = session.get('tn')
    raw_input = request.POST.get('data')
    command = request.POST.get('command')
    try:
        output = ''
        command_text = ''
        if raw_input is not None:
            adapter.send_session_input(tn, raw_input)
            if raw_input == "\t":
                output = adapter.read_session_output(tn, wait=0.12, rounds=10)
            elif raw_input in ("\r", "\n", "\r\n") or str(raw_input).startswith("\u001b"):
                output = adapter.read_session_output(tn, wait=0.10, rounds=12)
            elif raw_input in ("\b", "\u007f"):
                output = adapter.read_session_output(tn, wait=0.03, rounds=5)
            else:
                output = adapter.read_session_output(tn, wait=0.02, rounds=2)
        else:
            command_text = (command or '').strip()
            if not command_text:
                return JsonResponse({'ok': False, 'message': 'Command is empty.'}, status=400)
            lines = [line.strip() for line in command_text.splitlines() if line.strip()]
            output_chunks = []
            for line in lines:
                output_chunks.append(adapter.run_session_command(tn, line))
            output = '\n'.join([chunk for chunk in output_chunks if chunk]).strip()

        with _CLI_SESSIONS_LOCK:
            if key in _CLI_SESSIONS:
                _CLI_SESSIONS[key]['updated_at'] = timezone.now()
        if raw_input is None and command_text:
            _record_olt_login(olt, request.user, 'cli_command', f"Command: {command_text.splitlines()[0][:180]}", request=request)
        if raw_input is not None:
            return JsonResponse({'ok': True, 'output': output or ''})
        return JsonResponse({'ok': True, 'output': output or 'Command executed.'})
    except (socket.timeout, TimeoutError):
        return JsonResponse({'ok': False, 'message': 'CLI command timeout.'}, status=400)
    except OSError as exc:
        return JsonResponse({'ok': False, 'message': f'CLI command error: {exc}'}, status=400)


@login_required
@require_POST
def olt_cli_close(request, pk):
    olt = get_object_or_404(OLT, pk=pk)
    _close_user_cli_session(request.user.id, olt.pk)
    _record_olt_login(olt, request.user, 'cli_close', 'Interactive CLI session closed', request=request)
    return JsonResponse({'ok': True, 'message': 'CLI session closed.'})


@login_required
def olt_refresh_ports(request, pk):
    olt = get_object_or_404(OLT, pk=pk)
    if request.method != 'POST':
        return redirect('olt_view', pk=pk)
    _schedule_cards_refresh(olt.pk)
    _record_olt_login(olt, request.user, 'refresh_cards', 'OLT cards refresh started', request=request)
    return redirect(f"{redirect('olt_view', pk=pk).url}?section=olt-cards")


@login_required
@require_POST
def olt_refresh_pon_ports(request, pk):
    olt = get_object_or_404(OLT, pk=pk)
    _schedule_pon_refresh(olt.pk)
    _record_olt_login(olt, request.user, 'refresh_pon', 'PON ports refresh started', request=request)
    return redirect(f"{redirect('olt_view', pk=pk).url}?section=pon-ports")


@login_required
def olt_pon_ports_refresh_data(request, pk):
    olt = get_object_or_404(OLT, pk=pk)
    refreshed = False
    try:
        refreshed = refresh_saved_pon_counts_from_inventory(olt)
    except OperationalError:
        refreshed = False

    groups = list(getattr(olt, "pon_ports_cache", []) or [])
    status_text = _clean_ui_status(
        getattr(olt, "pon_ports_status", ""),
        "No PON ports found.",
        has_data=bool(groups),
    )
    refreshed_at = getattr(olt, "pon_ports_refreshed_at", None)
    refreshed_display = (
        timezone.localtime(refreshed_at, ZoneInfo("Asia/Karachi")).strftime("%Y-%m-%d %I:%M:%S %p")
        if refreshed_at
        else ""
    )
    return JsonResponse({
        "ok": True,
        "groups": groups,
        "status": status_text,
        "refreshed": refreshed,
        "refreshed_at": refreshed_display,
    })


@login_required
@require_POST
def olt_refresh_uplink(request, pk):
    olt = get_object_or_404(OLT, pk=pk)
    _schedule_uplink_refresh(olt.pk)
    _record_olt_login(olt, request.user, 'refresh_uplink', 'Uplink refresh started', request=request)
    return redirect(f"{redirect('olt_view', pk=pk).url}?section=uplink")


@login_required
@require_POST
def olt_refresh_vlans(request, pk):
    olt = get_object_or_404(OLT, pk=pk)
    live_lock = _acquire_olt_live_lock_with_retry(olt.pk)
    if live_lock is None:
        messages.warning(request, "Another live OLT task is already running. Please try again in a few seconds.")
        return redirect(f"{redirect('olt_view', pk=pk).url}?section=vlans")
    try:
        vlan_data = _fetch_vlan_snapshot_with_retry(olt)
        save_vlan_snapshot(olt, vlan_data)
        _record_olt_login(olt, request.user, 'refresh_vlans', 'VLAN refresh completed', request=request)
        status_text = str((vlan_data or {}).get("status") or "")
        row_count = len((vlan_data or {}).get("rows") or [])
        if row_count:
            messages.success(request, status_text or f"VLANs fetched: {row_count}")
        elif status_text:
            messages.warning(request, status_text)
    finally:
        live_lock.release()
    return redirect(f"{redirect('olt_view', pk=pk).url}?section=vlans")


@login_required
def olt_add_vlan(request, pk):
    olt = get_object_or_404(OLT, pk=pk)
    if request.method != "POST":
        return redirect(f"{redirect('olt_view', pk=pk).url}?section=vlans")

    saved_reference_rows = list(getattr(olt, "vlan_cache", []) or [])
    reserved_ids = {int(row.get("vlan_id")) for row in saved_reference_rows if str(row.get("vlan_id", "")).isdigit()}
    form = VLANAddForm(request.POST, reserved_ids=reserved_ids)
    if not form.is_valid():
        if not _store_vlan_form_state(request, olt.pk, form):
            return _render_olt_vlans_response(request, pk, form=form)
        return redirect(f"{redirect('olt_view', pk=pk).url}?section=vlans")

    live_lock = _acquire_olt_live_lock_with_retry(olt.pk)
    if live_lock is None:
        live_lock_error = ["Another live OLT task is already running. Please try again in a few seconds."]
        if not _store_vlan_form_state(request, olt.pk, form, live_lock_error):
            form.add_error(None, live_lock_error[0])
            return _render_olt_vlans_response(request, pk, form=form)
        return redirect(f"{redirect('olt_view', pk=pk).url}?section=vlans")

    try:
        cleaned = form.cleaned_data
        previous_count = len(saved_reference_rows)
        add_result = add_vlan(
            olt,
            vlan_id=cleaned["vlan_id"],
            description=cleaned["description"],
        )
        if add_result.get("ok"):
            verify_result = fetch_single_vlan(olt, cleaned["vlan_id"])
            fetched_row = verify_result.get("row")
            fetched_rows = list(saved_reference_rows)
            if fetched_row:
                fetched_rows = [row for row in fetched_rows if int(row.get("vlan_id", -1) or -1) != int(cleaned["vlan_id"])]
                fetched_rows.append(fetched_row)
                fetched_rows.sort(key=lambda row: int(row.get("vlan_id", 0) or 0))
                save_vlan_snapshot(olt, {
                    "rows": fetched_rows,
                    "status": f"VLANs fetched: {len(fetched_rows)}",
                })
            fetched_count = len(fetched_rows)
            vlan_found = fetched_row is not None
            _record_olt_login(
                olt,
                request.user,
                "add_vlan",
                f'VLAN added: id={cleaned["vlan_id"]}, description={cleaned["description"] or "-"}',
                request=request,
            )
            if vlan_found and fetched_count >= previous_count:
                messages.success(request, "VLAN added successfully.")
                notice_text = "VLAN added successfully."
                _store_vlan_notice(request, olt.pk, notice_text)
            else:
                messages.warning(request, "VLAN not created or not detected on OLT after refresh.")
                notice_text = "VLAN not created or not detected on OLT after refresh."
                _store_vlan_notice(request, olt.pk, notice_text)
            success_form = VLANAddForm(reserved_ids={int(row.get("vlan_id")) for row in fetched_rows if str(row.get("vlan_id", "")).isdigit()})
            success_transcript = add_result.get("transcript") or ""
            if not _store_vlan_form_state(request, olt.pk, success_form, transcript=success_transcript):
                return _render_olt_vlans_response(request, pk, form=success_form, transcript=success_transcript, notice=notice_text)
        else:
            error_message = add_result.get("message") or "VLAN create failed."
            error_transcript = add_result.get("transcript") or ""
            _store_vlan_notice(request, olt.pk, f"Not created: {error_message}")
            if not _store_vlan_form_state(request, olt.pk, form, transcript=error_transcript):
                return _render_olt_vlans_response(request, pk, form=form, transcript=error_transcript, notice=f"Not created: {error_message}")
            return redirect(f"{redirect('olt_view', pk=pk).url}?section=vlans")
    finally:
        live_lock.release()

    return redirect(f"{redirect('olt_view', pk=pk).url}?section=vlans")


@login_required
def olt_add_vlan_bulk(request, pk):
    olt = get_object_or_404(OLT, pk=pk)
    if request.method != "POST":
        return redirect(f"{redirect('olt_view', pk=pk).url}?section=vlans")

    saved_reference_rows = list(getattr(olt, "vlan_cache", []) or [])
    reserved_ids = {int(row.get("vlan_id")) for row in saved_reference_rows if str(row.get("vlan_id", "")).isdigit()}
    form = VLANBulkAddForm(request.POST, reserved_ids=reserved_ids)
    if not form.is_valid():
        if not _store_vlan_bulk_form_state(request, olt.pk, form):
            return _render_olt_vlans_response(request, pk, bulk_form=form)
        return redirect(f"{redirect('olt_view', pk=pk).url}?section=vlans")

    live_lock = _acquire_olt_live_lock_with_retry(olt.pk)
    if live_lock is None:
        live_lock_error = ["Another live OLT task is already running. Please try again in a few seconds."]
        if not _store_vlan_bulk_form_state(request, olt.pk, form, live_lock_error):
            form.add_error(None, live_lock_error[0])
            return _render_olt_vlans_response(request, pk, bulk_form=form)
        return redirect(f"{redirect('olt_view', pk=pk).url}?section=vlans")

    try:
        cleaned_range = form.cleaned_data["vlan_range"]
        start_vlan = int(cleaned_range["start"])
        end_vlan = int(cleaned_range["end"])
        previous_rows = list(saved_reference_rows)
        add_result = add_vlan_range(olt, start_vlan, end_vlan)
        if add_result.get("ok"):
            verify_result = fetch_vlan_range(olt, start_vlan, end_vlan)
            fetched_rows = list(previous_rows)
            verified_rows = list(verify_result.get("rows") or [])
            if verified_rows:
                fetched_rows = [
                    row for row in fetched_rows
                    if not (start_vlan <= int(row.get("vlan_id", -1) or -1) <= end_vlan)
                ]
                fetched_rows.extend(verified_rows)
                fetched_rows.sort(key=lambda row: int(row.get("vlan_id", 0) or 0))
                save_vlan_snapshot(olt, {
                    "rows": fetched_rows,
                    "status": f"VLANs fetched: {len(fetched_rows)}",
                })
            expected = (end_vlan - start_vlan) + 1
            verified_ids = {int(row.get("vlan_id", -1) or -1) for row in verified_rows}
            verified_ok = len([vlan_id for vlan_id in range(start_vlan, end_vlan + 1) if vlan_id in verified_ids]) == expected
            _record_olt_login(
                olt,
                request.user,
                "add_vlan_bulk",
                f"VLAN range added: {start_vlan}-{end_vlan}",
                request=request,
            )
            if verified_ok:
                messages.success(request, "VLAN range added successfully.")
                notice_text = "VLAN range added successfully."
            else:
                messages.warning(request, "VLAN range not created or not detected on OLT after refresh.")
                notice_text = "VLAN range not created or not detected on OLT after refresh."
            _store_vlan_notice(request, olt.pk, notice_text)
            success_form = VLANBulkAddForm(
                reserved_ids={int(row.get("vlan_id")) for row in fetched_rows if str(row.get("vlan_id", "")).isdigit()}
            )
            success_transcript = add_result.get("transcript") or ""
            if not _store_vlan_bulk_form_state(request, olt.pk, success_form, transcript=success_transcript):
                return _render_olt_vlans_response(request, pk, bulk_form=success_form, bulk_transcript=success_transcript, notice=notice_text)
        else:
            error_message = add_result.get("message") or "VLAN range create failed."
            error_transcript = add_result.get("transcript") or ""
            _store_vlan_notice(request, olt.pk, f"Not created: {error_message}")
            if not _store_vlan_bulk_form_state(request, olt.pk, form, transcript=error_transcript):
                return _render_olt_vlans_response(request, pk, bulk_form=form, bulk_transcript=error_transcript, notice=f"Not created: {error_message}")
            return redirect(f"{redirect('olt_view', pk=pk).url}?section=vlans")
    finally:
        live_lock.release()

    return redirect(f"{redirect('olt_view', pk=pk).url}?section=vlans")


@login_required
@require_POST
def olt_delete_vlan(request, pk):
    olt = get_object_or_404(OLT, pk=pk)
    vlan_id_raw = request.POST.get("vlan_id")
    try:
        vlan_id = int(vlan_id_raw)
    except (TypeError, ValueError):
        messages.warning(request, "Invalid VLAN ID.")
        return redirect(f"{redirect('olt_view', pk=pk).url}?section=vlans")

    live_lock = _acquire_olt_live_lock_with_retry(olt.pk)
    if live_lock is None:
        messages.warning(request, "Another live OLT task is already running. Please try again in a few seconds.")
        return redirect(f"{redirect('olt_view', pk=pk).url}?section=vlans")

    try:
        delete_result = delete_vlan_netconf(olt, vlan_id)
        if not delete_result.get("ok"):
            error_message = delete_result.get("message") or "VLAN delete failed."
            _store_vlan_notice(request, olt.pk, f"Not deleted: {error_message}")
            messages.warning(request, f"Not deleted: {error_message}")
            return redirect(f"{redirect('olt_view', pk=pk).url}?section=vlans")

        verify_result = fetch_single_vlan(olt, vlan_id)
        vlan_still_present = bool(verify_result.get("ok"))
        if vlan_still_present:
            failure_text = f"VLAN {vlan_id} is still present on the OLT."
            _store_vlan_notice(request, olt.pk, failure_text)
            messages.warning(request, failure_text)
            return redirect(f"{redirect('olt_view', pk=pk).url}?section=vlans")

        current_rows = list(getattr(olt, "vlan_cache", []) or [])
        remaining_rows = [
            row for row in current_rows
            if int(row.get("vlan_id", -1) or -1) != vlan_id
        ]
        save_vlan_snapshot(olt, {
            "rows": remaining_rows,
            "status": f"VLANs fetched: {len(remaining_rows)}",
        })
        _record_olt_login(
            olt,
            request.user,
            "delete_vlan",
            f"VLAN deleted via NETCONF: id={vlan_id}",
            request=request,
        )
        success_text = f"VLAN {vlan_id} deleted successfully."
        _store_vlan_notice(request, olt.pk, success_text)
        messages.success(request, success_text)
    finally:
        live_lock.release()

    return redirect(f"{redirect('olt_view', pk=pk).url}?section=vlans")


@login_required
@require_POST
def olt_refresh_profiles(request, pk):
    olt = get_object_or_404(OLT, pk=pk)
    live_lock = _acquire_olt_live_lock_with_retry(olt.pk)
    if live_lock is None:
        messages.warning(request, "Another live OLT task is already running. Please try again in a few seconds.")
        return redirect(f"{redirect('olt_view', pk=pk).url}?section=profiles")
    try:
        previous_count = len(list(getattr(olt, "dba_profile_cache", []) or []))
        profile_data = _fetch_dba_profile_snapshot_with_retry(olt)
        save_dba_profile_snapshot(olt, profile_data)
        _record_olt_login(olt, request.user, 'refresh_profiles', 'DBA profile refresh completed', request=request)
        status_text = str((profile_data or {}).get("status") or "")
        row_count = len((profile_data or {}).get("rows") or [])
        if previous_count and row_count == previous_count:
            _store_dba_profile_notice(request, olt.pk, "No new profile detected")
        else:
            _store_dba_profile_notice(request, olt.pk, "")
        if row_count:
            messages.success(request, status_text or f"DBA profiles fetched: {row_count}")
        elif status_text:
            messages.warning(request, status_text)
    finally:
        live_lock.release()
    return redirect(f"{redirect('olt_view', pk=pk).url}?section=profiles")


@login_required
def olt_add_profile(request, pk):
    olt = get_object_or_404(OLT, pk=pk)
    if request.method != "POST":
        return redirect(f"{redirect('olt_view', pk=pk).url}?section=profiles")
    saved_reference_rows = list(getattr(olt, "dba_profile_cache", []) or [])
    reserved_ids = {int(row.get("profile_id")) for row in saved_reference_rows if str(row.get("profile_id", "")).isdigit()}
    reserved_names = {str(row.get("profile_name") or "").strip() for row in saved_reference_rows if str(row.get("profile_name") or "").strip()}

    form = DBAProfileAddForm(
        request.POST,
        reserved_ids=reserved_ids,
        reserved_names=reserved_names,
    )
    if not form.is_valid():
        if not _store_dba_profile_form_state(request, olt.pk, form):
            return _render_olt_profiles_response(request, pk, form=form)
        return redirect(f"{redirect('olt_view', pk=pk).url}?section=profiles")

    live_lock = _acquire_olt_live_lock_with_retry(olt.pk)
    if live_lock is None:
        live_lock_error = ["Another live OLT task is already running. Please try again in a few seconds."]
        if not _store_dba_profile_form_state(request, olt.pk, form, live_lock_error):
            form.add_error(None, live_lock_error[0])
            return _render_olt_profiles_response(request, pk, form=form)
        return redirect(f"{redirect('olt_view', pk=pk).url}?section=profiles")

    try:
        cleaned = form.cleaned_data
        previous_count = len(saved_reference_rows)
        add_result = add_dba_profile(
            olt,
            profile_id=cleaned["profile_id"],
            profile_name=cleaned["profile_name"],
            profile_type=cleaned["profile_type"],
            dba_speed=cleaned["dba_speed"],
        )
        if add_result.get("ok"):
            verify_result = fetch_single_dba_profile(olt, cleaned["profile_id"], cleaned["profile_name"])
            fetched_row = verify_result.get("row")
            fetched_rows = list(saved_reference_rows)
            if fetched_row:
                fetched_rows = [row for row in fetched_rows if int(row.get("profile_id", -1) or -1) != int(cleaned["profile_id"])]
                fetched_rows.append(fetched_row)
                fetched_rows.sort(key=lambda row: int(row.get("profile_id", 0) or 0))
                save_dba_profile_snapshot(olt, {
                    "rows": fetched_rows,
                    "status": f"DBA profiles fetched: {len(fetched_rows)}",
                })
            fetched_count = len(fetched_rows)
            profile_found = fetched_row is not None
            _record_olt_login(
                olt,
                request.user,
                "add_dba_profile",
                f'DBA profile added: id={cleaned["profile_id"]}, name={cleaned["profile_name"]}, type={cleaned["profile_type"]}, speed={cleaned["dba_speed"]}Mbps',
                request=request,
            )
            if profile_found:
                messages.success(request, "DBA profile added.")
                notice_text = "Profile added successfully."
                _store_dba_profile_notice(request, olt.pk, notice_text)
            else:
                messages.warning(
                    request,
                    "DBA profile command succeeded, but live fetch did not confirm the new profile yet."
                )
                notice_text = "Profile not created or not detected on OLT after refresh."
                _store_dba_profile_notice(request, olt.pk, notice_text)
            success_form = DBAProfileAddForm(
                reserved_ids={int(row.get("profile_id")) for row in fetched_rows if str(row.get("profile_id", "")).isdigit()},
                reserved_names={str(row.get("profile_name") or "").strip() for row in fetched_rows if str(row.get("profile_name") or "").strip()},
            )
            success_transcript = add_result.get("transcript") or ""
            if not _store_dba_profile_form_state(
                request,
                olt.pk,
                success_form,
                transcript=success_transcript,
            ):
                return _render_olt_profiles_response(
                    request,
                    pk,
                    form=success_form,
                    transcript=success_transcript,
                    notice=notice_text,
                )
        else:
            error_message = add_result.get("message") or "DBA profile add failed."
            error_transcript = add_result.get("transcript") or ""
            _store_dba_profile_notice(request, olt.pk, f"Not created: {error_message}")
            if not _store_dba_profile_form_state(
                request,
                olt.pk,
                form,
                transcript=error_transcript,
            ):
                return _render_olt_profiles_response(
                    request,
                    pk,
                    form=form,
                    transcript=error_transcript,
                    notice=f"Not created: {error_message}",
                )
            return redirect(f"{redirect('olt_view', pk=pk).url}?section=profiles")
    finally:
        live_lock.release()

    return redirect(f"{redirect('olt_view', pk=pk).url}?section=profiles")


@login_required
@require_POST
def olt_profile_configuration(request, pk):
    olt = get_object_or_404(OLT, pk=pk)
    profile_id_raw = str(request.POST.get("profile_id") or "").strip()
    profile_name = str(request.POST.get("profile_name") or "").strip()

    try:
        profile_id = int(profile_id_raw)
    except (TypeError, ValueError):
        _store_dba_profile_config_state(
            request,
            olt.pk,
            row={"profile_id": profile_id_raw, "profile_name": profile_name},
            message="Invalid profile ID.",
        )
        return redirect(f"{redirect('olt_view', pk=pk).url}?section=profiles")

    row = None
    for saved_row in list(getattr(olt, "dba_profile_cache", []) or []):
        if int(saved_row.get("profile_id", -1) or -1) == profile_id:
            row = saved_row
            break
    if row is None:
        row = {"profile_id": profile_id, "profile_name": profile_name}

    live_lock = _acquire_olt_live_lock_with_retry(olt.pk)
    if live_lock is None:
        _store_dba_profile_config_state(
            request,
            olt.pk,
            row=row,
            message="Another live OLT task is already running. Please try again in a few seconds.",
        )
        return redirect(f"{redirect('olt_view', pk=pk).url}?section=profiles")

    try:
        config_result = _fetch_dba_profile_configuration_with_retry(olt, profile_id, profile_name)
    finally:
        live_lock.release()
    _store_dba_profile_config_state(
        request,
        olt.pk,
        row=row,
        output=config_result.get("output") or "",
        transcript=config_result.get("transcript") or "",
        message=config_result.get("message") or "",
    )
    _record_olt_login(
        olt,
        request.user,
        "view_dba_profile_config",
        f'DBA profile configuration viewed: id={profile_id}, name={profile_name or row.get("profile_name") or ""}',
        request=request,
    )
    return redirect(f"{redirect('olt_view', pk=pk).url}?section=profiles")


@login_required
def olt_sync_snmp_legacy(request, pk):
    olt = get_object_or_404(OLT, pk=pk)
    ok, status = _sync_snmp_after_save(olt)
    if ok:
        messages.success(request, 'SNMP synced successfully.')
    else:
        messages.warning(request, f"SNMP sync failed: {status}")
    return redirect('olt_view', pk=pk)


@login_required
def olt_export(request):
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename="olts_list.csv"'

    writer = csv.writer(response)
    writer.writerow(
        [
            'ID',
            'Name',
            'OLT IP',
            'TCP',
            'UDP',
            'OLT hardware version',
            'OLT SW version',
            'Vendor',
        ]
    )
    for olt in OLT.objects.all().order_by('id'):
        writer.writerow(
            [
                olt.id,
                olt.name,
                olt.ip_address,
                olt.port,
                olt.snmp_port,
                olt.hardware_version,
                olt.sw_version,
                olt.vendor,
            ]
        )
    return response






