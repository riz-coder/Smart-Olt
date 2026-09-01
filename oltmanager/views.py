import csv
import datetime
import calendar
import ipaddress
import json
from functools import lru_cache, wraps
from pathlib import Path
import re
import socket
import telnetlib
import threading
import time
import uuid
from urllib.parse import quote_plus, urlencode, urlparse
from zoneinfo import ZoneInfo

from django.contrib import messages
from django.contrib.sessions.exceptions import SessionInterrupted
from django.contrib.auth import get_user_model
from django.contrib.auth.decorators import login_required
from django.contrib.auth.views import LoginView
from django.core.cache import cache
from django.core.paginator import Paginator
from django.db import DatabaseError, OperationalError, close_old_connections
from django.db.models import Case, Count, IntegerField, Max, Q, Value, When
from django.http import HttpResponse, JsonResponse
from django.core.exceptions import PermissionDenied
from django.template.loader import render_to_string
from django.urls import reverse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils.html import format_html
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.cache import never_cache
from django.views.decorators.http import require_POST

from .forms import OLTForm, VLANAddForm, VLANBulkAddForm
from .models import ConfiguredONU, DashboardStatusSample, OLT, OLTLoginHistory, ONUOpticalSample, ONUStatusSample, ONUTrafficSample, ONUTrapEvent, PONTrafficSample, PONPortTrafficSample, SpeedProfile, UplinkPortTrafficSample
from .services import get_olt_adapter
from .utils import (
    _dashboard_status_counts_from_queryset,
    add_vlan,
    add_vlan_range,
    close_telnet_session,
    configure_vlan_uplink_port,
    fetch_ont_optical_subset,
    fetch_single_onu_snmp_signal,
    fetch_single_onu_snmp_status,
    fetch_single_onu_snmp_traffic_counters,
    fetch_single_ont_runtime_snapshot,
    fetch_single_ont_mac_addresses,
    fetch_single_ont_last_down_history,
    fetch_single_ont_running_config,
    fetch_single_ont_live_status,
    fetch_olt_snmp_status_map,
    fetch_olt_snmp_onu_type_map,
    fetch_olt_snmp_onu_type_distance_maps,
    fetch_uplink_mac_addresses,
    fetch_uplink_sfp_ddm,
    fetch_single_onu_snmp_distance,
    fetch_single_onu_snmp_type,
    execute_onu_cli_delete_action,
    find_onu_location_by_sn_cli,
    execute_onu_ethernet_port_access_config,
    execute_onu_catv_operational_state,
    execute_onu_ethernet_port_lan_config,
    execute_onu_ethernet_port_trunk_config,
    execute_onu_add_service_vlan_config,
    execute_onu_delete_service_port,
    execute_onu_speed_profile_config,
    execute_onu_ethernet_port_transparent_config,
    execute_onu_snmp_control_action,
    execute_onu_eth_port_cli_admin_state,
    sync_onu_detail_fields_for_olt,
    sync_onu_equipment_ids_for_olt,
    sync_single_onu_detail_fields,
    sync_onu_attached_vlans_for_olt,
    sync_single_onu_attached_vlans,
    sync_detected_onu_keys_inventory,
    fetch_snmp_snapshot,
    fetch_telnet_version_snapshot,
    fetch_ont_autofind_snapshot,
    fetch_uplink_snapshot,
    fetch_management_vlan_id,
    fetch_vlan_range,
    fetch_vlan_snapshot,
    fetch_single_vlan,
    push_snmp_config_over_telnet,
    refresh_saved_pon_counts_from_inventory,
    refresh_pon_sfp_tx_snapshot,
    refresh_uplink_vlan_snapshot,
    save_pon_ports_snapshot,
    save_uplink_snapshot,
    save_vlan_snapshot,
    sync_configured_onus_inventory,
    derive_inventory_onu_status,
    ensure_dashboard_status_samples_for_scope,
    map_onu_alarm_to_status,
    _parse_ont_duration_to_seconds,
    record_pon_port_traffic_samples,
    record_pon_port_traffic_sample_for_olt,
    record_uplink_port_traffic_samples,
    record_uplink_port_traffic_sample_for_olt,
    record_pon_traffic_sample_for_olt,
    record_pon_traffic_samples,
    record_dashboard_status_samples,
    dashboard_online_status_q,
    get_onu_status_sync_progress,
    sync_speed_profiles_from_file,
    create_speed_profile_in_file,
    delete_speed_profile_from_file,
    speed_profile_onu_usage_counts,
    authorize_autofind_onu,
    sync_onu_signals_from_snmp,
    recent_onu_optical_sample_keys,
    should_record_onu_optical_sample,
    _format_solt_onu_type_name,
    _pon_tech_from_board_type,
)


class RememberMeLoginView(LoginView):
    template_name = 'registration/login.html'

    def form_valid(self, form):
        response = super().form_valid(form)
        if self.request.POST.get('remember_me'):
            self.request.session.set_expiry(60 * 60 * 24 * 14)
        else:
            self.request.session.set_expiry(0)
        return response


def _is_admin_user(user):
    return bool(user and user.is_authenticated and (user.is_staff or user.is_superuser))


def admin_required(view_func):
    @wraps(view_func)
    def _wrapped(request, *args, **kwargs):
        if not _is_admin_user(request.user):
            raise PermissionDenied("Admin access is required.")
        return view_func(request, *args, **kwargs)
    return _wrapped


def _billing_lock_context(olt):
    return {
        "olt": olt,
        "lock_title": "Subscription Required",
        "lock_message": olt.pricing_lock_message or "This OLT is currently locked. Please renew the subscription to continue.",
        "pricing_label": olt.get_pricing_mode_display(),
        "pricing_status": olt.pricing_status_label,
        "pricing_expires_at": olt.pricing_expires_at,
    }


def _render_olt_subscription_locked(request, olt):
    return render(request, "oltmanager/olt_subscription_locked.html", _billing_lock_context(olt), status=402)


def _json_subscription_locked(olt):
    return JsonResponse(
        {
            "ok": False,
            "message": olt.pricing_lock_message or "Subscription expired. Please renew your subscription to access this OLT.",
            "pricing_status": olt.pricing_status_label,
        },
        status=402,
    )


def _deny_olt_access_if_locked(request, olt):
    if not getattr(olt, "pricing_access_locked", False):
        return None
    if request.headers.get("x-requested-with") == "XMLHttpRequest" or "application/json" in request.headers.get("accept", ""):
        return _json_subscription_locked(olt)
    messages.error(request, olt.pricing_lock_message or "Subscription expired. Please renew your subscription to access this OLT.")
    return redirect("olt_view", pk=olt.pk)


def _display_onu_type_name(value):
    text = str(value or "").strip()
    return re.sub(r"(?i)_SOLT$", "", text) if text else ""


def _onu_tech_label(olt, slot):
    """Return the lowercase PON technology prefix for an ONU label based on its slot.

    Reads from olt.pon_ports_cache first, then olt_cards_cache.
    Returns: 'gpon' | 'epon' | 'xgspon' | 'xgpon'
    """
    target = str(slot or "")
    for group in list(getattr(olt, "pon_ports_cache", []) or []):
        if str((group or {}).get("slot", "")) != target:
            continue
        for port_row in (group or {}).get("ports") or []:
            pt = str((port_row or {}).get("type") or "").upper()
            if "XGS" in pt:
                return "xgspon"
            if "XG" in pt:
                return "xgpon"
            if "EPON" in pt:
                return "epon"
            if pt:
                return "gpon"
    for card in list(getattr(olt, "olt_cards_cache", []) or []):
        if str((card or {}).get("slot") or "") != target:
            continue
        rt = str((card or {}).get("real_type") or (card or {}).get("type") or "").upper()
        if "XGS" in rt:
            return "xgspon"
        if "XG" in rt:
            return "xgpon"
        if "EPON" in rt or "EPFD" in rt or "EPFC" in rt:
            return "epon"
        return "gpon"
    return "gpon"


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
_AUTOFIND_REFRESH_GUARD = threading.Lock()
_AUTOFIND_REFRESH_THREAD = None
_AUTOFIND_ROWS_CACHE_LOCK = threading.Lock()
_AUTOFIND_ROWS_CACHE = {}
_AUTOFIND_ROWS_REFRESHING = set()
_AUTOFIND_LIVE_FETCHING = set()
_AUTHORIZE_TASKS_LOCK = threading.Lock()
_AUTHORIZE_TASKS = {}
_MAPPING_CONVERT_TASKS_LOCK = threading.Lock()
_MAPPING_CONVERT_TASKS = {}
_SPEED_PROFILE_TASKS_LOCK = threading.Lock()
_SPEED_PROFILE_TASKS = {}
_NEW_OLT_VLAN_FILL_LOCK = threading.Lock()
_NEW_OLT_VLAN_FILLING = set()
_DEVICE_SNAPSHOT_SYNC_LOCK = threading.Lock()
_DEVICE_SNAPSHOT_SYNCING = set()
_DEVICE_SNAPSHOT_SCAN_LOCK = threading.Lock()
_LAST_DEVICE_SNAPSHOT_SCAN = None
_OLT_ONBOARDING_LOCK = threading.Lock()
_OLT_ONBOARDING_RUNNING = set()
_OLT_ONBOARDING_ABORT_REQUESTED = set()
OLT_ONBOARDING_STALE_SECONDS = 45 * 60
_ONU_ATTACHED_VLAN_SYNC_LOCK = threading.Lock()
_ONU_ATTACHED_VLAN_SYNCING = set()
_ONU_IMPORTED_CONFIG_SYNC_LOCK = threading.Lock()
_ONU_IMPORTED_CONFIG_SYNCING = set()
_ONU_DETAIL_SYNC_LOCK = threading.Lock()
_ONU_DETAIL_SYNCING = set()
_PORT_TRAFFIC_GRAPH_CACHE_LOCK = threading.Lock()
_PORT_TRAFFIC_GRAPH_CACHE = {}
_LIVE_PORT_TRAFFIC_REFRESH_LOCK = threading.Lock()
_LIVE_PORT_TRAFFIC_REFRESHING = set()
_ONU_TRAFFIC_REFRESH_LOCK = threading.Lock()
_ONU_TRAFFIC_REFRESHING = set()
_CONFIGURED_ONU_FILTERS_CACHE_LOCK = threading.Lock()
_CONFIGURED_ONU_FILTERS_CACHE = {"updated_at": None, "boards": None, "olts": None, "latest_sync": None}
_DASHBOARD_ALERT_WIDGET_CACHE_LOCK = threading.Lock()
_DASHBOARD_ALERT_WIDGET_CACHE = {}
_ONU_DETAIL_CACHE_LOCK = threading.Lock()
_ONU_DETAIL_CACHE = {}
_ONU_SIGNAL_HISTORY_CACHE_LOCK = threading.Lock()
_ONU_SIGNAL_HISTORY_CACHE = {}
_ONU_SNMP_STATUS_DEBOUNCE_LOCK = threading.Lock()
_ONU_SNMP_STATUS_DEBOUNCE = {}


def _ready_olts():
    return OLT.objects.filter(is_ready=True)


def _load_ethernet_port_config_cache(record):
    if record is None:
        return {}
    raw_value = str(getattr(record, "ethernet_port_config_cache", "") or "").strip()
    if not raw_value:
        return {}
    try:
        parsed = json.loads(raw_value)
    except (TypeError, ValueError, json.JSONDecodeError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _save_ethernet_port_config_cache(record, config_map):
    if record is None:
        return
    record.ethernet_port_config_cache = json.dumps(config_map, separators=(",", ":"))
    record.save(update_fields=["ethernet_port_config_cache"])
PORT_TRAFFIC_GRAPH_CACHE_TTL = 300
LIVE_PORT_TRAFFIC_GRAPH_CACHE_TTL = 3
PON_CACHE_SECONDS = 120
SNAPSHOT_CACHE_SECONDS = 90
AUTOFIND_ROWS_CACHE_SECONDS = 180
DEVICE_SNAPSHOT_SCAN_SECONDS = 300
DASHBOARD_UPTIME_REFRESH_SECONDS = 120
CONFIGURED_ONU_FILTERS_CACHE_SECONDS = 300
DASHBOARD_ALERT_WIDGET_CACHE_SECONDS = 120
ONU_DETAIL_CACHE_SECONDS = 30
ONU_SIGNAL_HISTORY_CACHE_SECONDS = 60
ONU_TRAFFIC_SAMPLE_SECONDS = 60
ONU_ATTACHED_VLAN_SYNC_SECONDS = 600
_CLI_SESSIONS_LOCK = threading.Lock()
_CLI_SESSIONS = {}
CLI_SESSION_IDLE_SECONDS = 900


def _get_olt_for_view(pk, selected_section):
    heavy_fields = {
        "olt_cards_cache",
        "pon_ports_cache",
        "uplink_cache",
        "vlan_cache",
    }
    needed_by_section = {
        "olt-cards": {"olt_cards_cache"},
        "pon-ports": {"pon_ports_cache"},
        "uplink": {"uplink_cache"},
        "vlans": {"vlan_cache"},
    }.get(selected_section, set())
    defer_fields = sorted(heavy_fields - needed_by_section)
    return get_object_or_404(OLT.objects.defer(*defer_fields), pk=pk)


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


def _fetch_vlan_snapshot_with_retry(olt, attempts=3, delay=0.8):
    latest = {"status": "VLAN data unavailable", "rows": []}
    for attempt in range(attempts):
        latest = fetch_vlan_snapshot(olt)
        if (latest.get("rows") or []) or not _is_retryable_telnet_status_text(latest.get("status")):
            return latest
        if attempt < attempts - 1:
            time.sleep(delay)
    return latest


def _set_cached_pon_ports(olt_id, groups, status):
    with _PON_CACHE_LOCK:
        _PON_CACHE[olt_id] = {
            "groups": groups or [],
            "status": (status or "")[:300],
            "cached_at": timezone.now(),
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


def _set_cached_snapshot(olt_id, snapshot):
    with _SNAPSHOT_CACHE_LOCK:
        _SNAPSHOT_CACHE[olt_id] = {
            "snapshot": snapshot or {},
            "cached_at": timezone.now(),
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


def _configured_onu_record_to_row(record, tech_label=None):
    description = (record.description or "").strip()
    sn = (record.sn or "").strip()
    _tech = tech_label or _onu_tech_label(record.olt, record.slot)
    onu_label = (
        f"{_tech}-onu_{int(record.frame or 0)}/{int(record.slot or 0)}/{int(record.port or 0)}:{int(record.ont_id or 0)}"
    )
    display_name = _format_onu_display_name(
        description,
        _format_onu_serial_display(sn) or onu_label,
    )
    return _hide_offline_onu_power({
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
        "attached_vlans": (record.attached_vlans_cache or "").strip() or "-",
        "onu_type": (record.onu_type_cache or "").strip() or "-",
        "derived_status": (record.derived_status or "").strip(),
        "status_source": (record.status_source or "").strip(),
        "status_first_seen_at": record.status_first_seen_at,
        "status_updated_at": record.status_updated_at,
        "raw_line": record.raw_line or "",
        "fsp": f"{int(record.frame or 0)}/{int(record.slot or 0)}/{int(record.port or 0)}",
        "display_name": display_name,
    })


def _configured_onu_runtime_snapshot_from_record(record):
    if record is None:
        return {}
    onu_mode = (getattr(record, "onu_mode_cache", "") or "").strip()
    if not onu_mode and not getattr(record, "configured_via_app", False):
        onu_mode = "routing"
    return {
        "online_duration": (getattr(record, "online_duration_cache", "") or "").strip(),
        "last_up_time": (getattr(record, "last_up_time_cache", "") or "").strip(),
        "last_down_time": (getattr(record, "last_down_time_cache", "") or "").strip(),
        "last_down_cause": (getattr(record, "last_down_cause_cache", "") or "").strip(),
        "battery_state": (getattr(record, "battery_state_cache", "") or "").strip(),
        "attached_vlans": (getattr(record, "attached_vlans_cache", "") or "").strip(),
        "onu_mode": onu_mode,
        "ont_distance_m": (getattr(record, "ont_distance_m", "") or "").strip(),
        "run_state": (getattr(record, "run_state", "") or "").strip(),
        "config_state": (getattr(record, "config_state", "") or "").strip(),
        "control_flag": (getattr(record, "control_flag", "") or "").strip(),
        "ont_equipment_id": (getattr(record, "onu_type_cache", "") or "").strip(),
    }


def _clean_onu_detail_text(value, max_length):
    text = str(value or "").strip()
    return text[:max_length]


def _split_onu_cache_values(value):
    text = str(value or "")
    if not text.strip():
        return []
    return [part.strip() for part in text.split(",") if part.strip()]


def _normalize_onu_type_key(value):
    return re.sub(r"[^A-Z0-9]+", "", str(value or "").replace("_SOLT", "").upper())


def _onu_type_entry_for_record(record):
    raw_type = str(getattr(record, "onu_type_cache", "") or "").strip()
    normalized = _normalize_onu_type_key(raw_type)
    for item in _load_onu_type_option_rows():
        if normalized in {
            _normalize_onu_type_key(item.get("value")),
            _normalize_onu_type_key(item.get("label")),
        }:
            return item
    return {
        "value": raw_type.replace("_SOLT", "") or "UNKNOWN",
        "label": raw_type or "UNKNOWN",
        "serial_no": 300,
        "ethernet_ports": str(_ethernet_port_count_for_record(record) or 4),
        "voip_ports": "0",
    }


def _ethernet_port_count_for_record(record):
    try:
        payload = json.loads(getattr(record, "ethernet_port_config_cache", "") or "{}")
        keys = [str(key) for key in payload.keys()]
        numbers = [int(key) for key in keys if str(key).isdigit()]
        if numbers:
            return max(numbers)
    except (TypeError, ValueError, json.JSONDecodeError):
        pass
    return 0


def _speed_profile_lookup_by_index():
    lookup = {}
    default_pair = None
    for profile in SpeedProfile.objects.filter(is_active=True).order_by("speed_mbps_value", "name"):
        base_index = int(profile.index_number or 0)
        if not base_index:
            continue
        base_name = (profile.name or "").strip()
        base_name = re.sub(r"(?i)(?:-|_)?(up|down)$", "", base_name).strip(" -_") or base_name
        down_name = (profile.download_name or f"{base_name}-DOWN").strip()
        up_name = (profile.upload_name or f"{base_name}-UP").strip()
        lookup[str(base_index)] = {"name": down_name, "profile": profile}
        lookup[str(base_index + 1)] = {"name": up_name, "profile": profile}
        speed_value = float(profile.speed_mbps_value or 0)
        if default_pair is None and (
            speed_value >= 1000
            or "1G" in str(profile.name or "").upper()
            or "1000" in str(profile.name or "")
        ):
            default_pair = (str(base_index), down_name, str(base_index + 1), up_name)
    if default_pair is None:
        last_profile = SpeedProfile.objects.filter(is_active=True).order_by("speed_mbps_value", "name").last()
        if last_profile is not None and int(last_profile.index_number or 0):
            base_index = int(last_profile.index_number or 0)
            base_name = (last_profile.name or "").strip() or "SOLT-1G"
            default_pair = (
                str(base_index),
                (last_profile.download_name or f"{base_name}-DOWN").strip(),
                str(base_index + 1),
                (last_profile.upload_name or f"{base_name}-UP").strip(),
            )
    return lookup, default_pair


def _first_valid_profile_value(raw_value, lookup, default_value):
    for item in _split_onu_cache_values(raw_value):
        if item in lookup:
            return item, lookup[item]["name"]
    return default_value[0], default_value[1]


def _build_onu_mapping_conversion_plan(record):
    current_mode = str(getattr(record, "mapping_mode_cache", "") or "").strip().lower()
    if current_mode not in {"priority", "vlan"}:
        current_mode = "priority"
    target_mode = "priority" if current_mode == "vlan" else "vlan"

    service_vlans = _split_onu_cache_values(getattr(record, "attached_vlans_cache", ""))
    user_vlans = _split_onu_cache_values(getattr(record, "user_vlan_cache", "")) or service_vlans[:]
    user_vlans = [item for item in user_vlans if item and item != "-"]
    if not user_vlans:
        user_vlans = [item for item in service_vlans if item and item != "-"]

    line_profile_vlans = []
    for index, user_vlan in enumerate(user_vlans):
        candidate = user_vlan
        if str(user_vlan).strip().lower() == "untagged":
            candidate = service_vlans[index] if index < len(service_vlans) else ""
        candidate = str(candidate or "").strip()
        if candidate and candidate.lower() != "untagged" and candidate not in line_profile_vlans:
            line_profile_vlans.append(candidate)

    service_vlan_value = ""
    tag_transform = ""
    clean_service_vlans = [item for item in service_vlans if item and item != "-"]
    if clean_service_vlans and len(set(clean_service_vlans)) == 1:
        only_service_vlan = clean_service_vlans[0]
        if any(str(item).lower() == "untagged" for item in user_vlans) or set(user_vlans) != {only_service_vlan}:
            service_vlan_value = only_service_vlan
            tag_transform = "default" if any(str(item).lower() == "untagged" for item in user_vlans) else "translate"

    speed_lookup, default_speed = _speed_profile_lookup_by_index()
    if default_speed is None:
        return {
            "ok": False,
            "message": "No active 1G/default speed profile is available.",
        }
    download_index, download_name = _first_valid_profile_value(
        getattr(record, "download_profile_index_cache", ""), speed_lookup, (default_speed[0], default_speed[1])
    )
    upload_index, upload_name = _first_valid_profile_value(
        getattr(record, "upload_profile_index_cache", ""), speed_lookup, (default_speed[2], default_speed[3])
    )

    onu_type_entry = _onu_type_entry_for_record(record)
    eth_ports = str(onu_type_entry.get("ethernet_ports") or "").strip() or str(_ethernet_port_count_for_record(record) or 4)
    pots_ports = str(onu_type_entry.get("voip_ports") or "").strip() or "0"

    warnings = []
    if target_mode == "vlan" and _onu_tech_label(record.olt, record.slot) == "epon":
        warnings.append("VLAN Mapping is currently disabled for EPON ONUs.")
    if target_mode == "vlan" and any(str(item).strip().lower() == "untagged" for item in user_vlans):
        warnings.append("VLAN Mapping cannot be used when the ONU User VLAN is untagged.")
    if target_mode == "vlan" and len(line_profile_vlans) > 8:
        warnings.append("VLAN Mapping supports a maximum of 8 line-profile VLAN mappings.")

    return {
        "ok": True,
        "current_mode": current_mode,
        "target_mode": target_mode,
        "current_label": "VLAN Mapping" if current_mode == "vlan" else "PRI Mapping",
        "target_label": "VLAN Mapping" if target_mode == "vlan" else "PRI Mapping",
        "prompt": (
            "Do you want to convert this ONU to VLAN Mapping?"
            if target_mode == "vlan"
            else "Do you want to shift this ONU to PRI Mapping?"
        ),
        "vlan_ids": user_vlans,
        "line_profile_vlan_ids": line_profile_vlans or user_vlans,
        "service_vlan": service_vlan_value,
        "tag_transform": tag_transform,
        "download_profile_index": download_index,
        "download_profile_name": download_name,
        "upload_profile_index": upload_index,
        "upload_profile_name": upload_name,
        "onu_type_name": str(onu_type_entry.get("value") or "").strip(),
        "onu_type_label": str(onu_type_entry.get("label") or "").strip(),
        "onu_type_serial": int(onu_type_entry.get("serial_no") or 300),
        "eth_ports": eth_ports,
        "pots_ports": pots_ports,
        "subscriber_name": str(getattr(record, "description", "") or "").strip() or str(getattr(record, "sn", "") or "").strip(),
        "onu_mode": str(getattr(record, "onu_mode_cache", "") or "").strip().lower() or "routing",
        "service_ports": _split_onu_cache_values(getattr(record, "service_port_id_cache", "")),
        "warnings": warnings,
    }


def _refresh_new_olt_vlan_fill_worker(olt_id):
    try:
        olt = OLT.objects.filter(pk=olt_id).first()
        if not olt:
            return
        sync_configured_onus_inventory(olt)
        result = sync_onu_attached_vlans_for_olt(olt, fallback_missing=True)
        olt.attached_vlan_sync_status = (
            f"New OLT one-time service profile fill | {result.get('status') or ''}"
        )[:300]
        olt.attached_vlan_sync_updated_at = timezone.now()
        olt.attached_vlan_sync_cursor_pk = int(result.get("last_pk") or 0)
        olt.save(update_fields=[
            "attached_vlan_sync_status",
            "attached_vlan_sync_updated_at",
            "attached_vlan_sync_cursor_pk",
        ])
    finally:
        with _NEW_OLT_VLAN_FILL_LOCK:
            _NEW_OLT_VLAN_FILLING.discard(int(olt_id))


def _refresh_onu_attached_vlan_worker(olt_id, slot, port, ont_id):
    try:
        olt = OLT.objects.filter(pk=olt_id).first()
        if not olt:
            return
        sync_single_onu_attached_vlans(olt, slot, port, ont_id)
    finally:
        with _ONU_ATTACHED_VLAN_SYNC_LOCK:
            _ONU_ATTACHED_VLAN_SYNCING.discard((olt_id, int(slot), int(port), int(ont_id)))


def _refresh_imported_onu_config_worker(olt_id):
    try:
        olt = OLT.objects.filter(pk=olt_id).first()
        if not olt:
            return
        result = sync_onu_attached_vlans_for_olt(
            olt,
            fallback_missing=True,
            only_missing=True,
            imported_only=True,
        )
        status_text = str(result.get("status") or "").strip()
        if status_text:
            olt.attached_vlan_sync_status = f"Imported ONU auto config sync | {status_text}"[:300]
            olt.attached_vlan_sync_updated_at = timezone.now()
            olt.attached_vlan_sync_cursor_pk = int(result.get("last_pk") or 0)
            olt.save(
                update_fields=[
                    "attached_vlan_sync_status",
                    "attached_vlan_sync_updated_at",
                    "attached_vlan_sync_cursor_pk",
                ]
            )
    finally:
        with _ONU_IMPORTED_CONFIG_SYNC_LOCK:
            _ONU_IMPORTED_CONFIG_SYNCING.discard(int(olt_id))


def _schedule_imported_onu_config_sync(olt_id):
    sync_key = int(olt_id)
    with _ONU_IMPORTED_CONFIG_SYNC_LOCK:
        if sync_key in _ONU_IMPORTED_CONFIG_SYNCING:
            return
        _ONU_IMPORTED_CONFIG_SYNCING.add(sync_key)
    threading.Thread(
        target=_refresh_imported_onu_config_worker,
        args=(olt_id,),
        daemon=True,
    ).start()


def _schedule_onu_attached_vlan_sync(olt_id, slot, port, ont_id):
    sync_key = (int(olt_id), int(slot), int(port), int(ont_id))
    with _ONU_ATTACHED_VLAN_SYNC_LOCK:
        if sync_key in _ONU_ATTACHED_VLAN_SYNCING:
            return
        _ONU_ATTACHED_VLAN_SYNCING.add(sync_key)
    threading.Thread(
        target=_refresh_onu_attached_vlan_worker,
        args=(olt_id, slot, port, ont_id),
        daemon=True,
    ).start()


def _refresh_onu_detail_worker(olt_id, slot, port, ont_id):
    try:
        olt = OLT.objects.filter(pk=olt_id).first()
        if not olt:
            return
        sync_single_onu_detail_fields(olt, slot, port, ont_id)
    finally:
        with _ONU_DETAIL_SYNC_LOCK:
            _ONU_DETAIL_SYNCING.discard((int(olt_id), int(slot), int(port), int(ont_id)))


def _schedule_onu_detail_sync(olt_id, slot, port, ont_id):
    sync_key = (int(olt_id), int(slot), int(port), int(ont_id))
    with _ONU_DETAIL_SYNC_LOCK:
        if sync_key in _ONU_DETAIL_SYNCING:
            return
        _ONU_DETAIL_SYNCING.add(sync_key)
    threading.Thread(
        target=_refresh_onu_detail_worker,
        args=(olt_id, slot, port, ont_id),
        daemon=True,
    ).start()


def _refresh_snapshot_worker(olt_id):
    try:
        close_old_connections()
        olt = OLT.objects.filter(pk=olt_id).first()
        if not olt:
            return
        adapter = get_olt_adapter(olt)
        snapshot = adapter.fetch_device_snapshot(olt)
        _set_cached_snapshot(olt_id, snapshot)
        update_fields = []
        fetched_sw = _normalize_olt_software_version((snapshot.get('sw_version') or '').strip())
        if fetched_sw and fetched_sw.lower() != 'unknown' and fetched_sw != (olt.sw_version or ''):
            olt.sw_version = fetched_sw
            update_fields.append('sw_version')
        fetched_status = str(snapshot.get('status') or '').strip()
        if fetched_status and not _is_olt_snmp_unreachable(fetched_status):
            olt.snmp_last_status = fetched_status[:300]
            olt.snmp_last_synced_at = timezone.now()
            update_fields.extend(['snmp_last_status', 'snmp_last_synced_at'])
        fetched_uptime = str(snapshot.get('uptime') or '').strip()
        fetched_temp = str(snapshot.get('temperature') or '').strip()
        has_device_metrics = bool(
            (fetched_uptime and fetched_uptime != '--') or
            (fetched_temp and fetched_temp != '--')
        )
        if fetched_uptime and fetched_uptime != '--' and fetched_uptime != (olt.dashboard_uptime or ''):
            olt.dashboard_uptime = fetched_uptime
            update_fields.append('dashboard_uptime')
        if fetched_temp and fetched_temp != '--' and fetched_temp != (olt.dashboard_temperature or ''):
            olt.dashboard_temperature = fetched_temp
            update_fields.append('dashboard_temperature')
        # Do not mark a never-filled dashboard snapshot as fresh if the SNMP
        # fetch returned no uptime/temperature. That lets new OLTs retry soon
        # instead of showing "--" until another unrelated refresh happens.
        if has_device_metrics or olt.dashboard_uptime or olt.dashboard_temperature:
            olt.dashboard_snapshot_refreshed_at = timezone.now()
            update_fields.append('dashboard_snapshot_refreshed_at')
        if update_fields:
            olt.save(update_fields=update_fields)
    except DatabaseError:
        close_old_connections()
    finally:
        close_old_connections()
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


def _olt_view_vlan_autorefresh_key(olt_id, section):
    return f"olt_view_vlan_autorefresh_{int(olt_id)}_{section}"


def _reset_olt_view_vlan_autorefresh_on_new_visit(request, olt_id):
    current_path = reverse("olt_view", kwargs={"pk": int(olt_id)})
    try:
        referrer_path = urlparse(request.META.get("HTTP_REFERER") or "").path
    except Exception:
        referrer_path = ""
    if referrer_path == current_path:
        return
    for section in ("uplink", "vlans"):
        _safe_session_pop(request, _olt_view_vlan_autorefresh_key(olt_id, section), None)


def _should_auto_refresh_olt_vlan_section(request, olt, selected_section):
    if selected_section not in {"uplink", "vlans"}:
        return False
    session_key = _olt_view_vlan_autorefresh_key(olt.pk, selected_section)
    if request.session.get(session_key):
        return False
    return True


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
    text = _normalize_search_token(value)
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


def _build_configured_onu_search_q(search_query):
    raw_query = str(search_query or "").strip()
    if not raw_query:
        return Q()

    db_q = (
        Q(sn__icontains=raw_query)
        | Q(description__icontains=raw_query)
        | Q(olt__name__icontains=raw_query)
    )

    normalized_tokens = _normalize_onu_serial_token(raw_query)
    for token in normalized_tokens:
        db_q |= Q(sn__icontains=token)

    fsp_ont_match = re.search(r"(?:(\d+)\s*/\s*)?(\d+)\s*/\s*(\d+)\s*[:/]\s*(\d+)", raw_query)
    if fsp_ont_match:
        frame_part, slot_part, port_part, ont_part = fsp_ont_match.groups()
        try:
            db_q |= Q(
                frame=int(frame_part or 0),
                slot=int(slot_part),
                port=int(port_part),
                ont_id=int(ont_part),
            )
        except (TypeError, ValueError):
            pass

    return db_q


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


def _store_vlan_notice(request, olt_pk, notice="", ok=None, url=""):
    return _safe_session_set(
        request,
        f"vlan_notice_{olt_pk}",
        {"text": str(notice or ""), "ok": ok, "url": str(url or "")},
    )


def _restore_vlan_notice(request, olt_pk):
    val = _safe_session_pop(request, f"vlan_notice_{olt_pk}", "")
    if isinstance(val, dict):
        return {
            "text": str(val.get("text") or ""),
            "ok": val.get("ok"),
            "url": str(val.get("url") or ""),
        }
    return {"text": str(val or ""), "ok": None, "url": ""}


def _render_olt_vlans_response(request, pk, *, form=None, bulk_form=None, transcript="", bulk_transcript="", notice=""):
    request._olt_view_section = "vlans"
    request._vlan_override = {
        "form": form,
        "bulk_form": bulk_form,
        "transcript": transcript or "",
        "bulk_transcript": bulk_transcript or "",
        "notice": notice or "",
        "notice_url": "",
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
        fetched_sw = _normalize_olt_software_version((snmp_snapshot.get('sw_version') or '').strip())
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
    for olt in _ready_olts().only("id", "olt_cards_cache", "pon_ports_cache").all():
        if not getattr(olt, "is_ready", True):
            continue
        if not (olt.olt_cards_cache or []) or not (getattr(olt, "pon_ports_cache", []) or []):
            _schedule_device_snapshots_refresh(olt.pk)


def _append_olt_onboarding_log(existing_log, message):
    message = str(message or "").strip()
    if not message:
        return str(existing_log or "")
    lines = [line for line in str(existing_log or "").splitlines() if line.strip()]
    if not lines or lines[-1] != message:
        lines.append(message)
    return "\n".join(lines)[-4000:]


class OnboardingAborted(Exception):
    pass


def _request_olt_onboarding_abort(olt_id):
    with _OLT_ONBOARDING_LOCK:
        _OLT_ONBOARDING_ABORT_REQUESTED.add(int(olt_id))


def _clear_olt_onboarding_abort(olt_id):
    with _OLT_ONBOARDING_LOCK:
        _OLT_ONBOARDING_ABORT_REQUESTED.discard(int(olt_id))


def _is_olt_onboarding_abort_requested(olt_id):
    with _OLT_ONBOARDING_LOCK:
        return int(olt_id) in _OLT_ONBOARDING_ABORT_REQUESTED


def _raise_if_olt_onboarding_aborted(olt_id):
    if _is_olt_onboarding_abort_requested(olt_id):
        raise OnboardingAborted("Onboarding aborted by user.")


def _update_olt_onboarding(olt_id, *, status=None, progress=None, message=None, ready=None, finished=False):
    if _is_olt_onboarding_abort_requested(olt_id) and status not in {"aborting", "aborted"}:
        return
    olt = OLT.objects.filter(pk=olt_id).first()
    if not olt:
        return
    update_fields = []
    if status is not None and status != olt.onboarding_status:
        olt.onboarding_status = status
        update_fields.append("onboarding_status")
    if progress is not None and progress != olt.onboarding_progress:
        olt.onboarding_progress = max(0, min(100, int(progress)))
        update_fields.append("onboarding_progress")
    if message is not None:
        message = str(message or "").strip()[:255]
        if message != olt.onboarding_message:
            olt.onboarding_message = message
            update_fields.append("onboarding_message")
        new_log = _append_olt_onboarding_log(olt.onboarding_log, message)
        if new_log != olt.onboarding_log:
            olt.onboarding_log = new_log
            update_fields.append("onboarding_log")
    if ready is not None and bool(ready) != bool(olt.is_ready):
        olt.is_ready = bool(ready)
        update_fields.append("is_ready")
    if finished:
        olt.onboarding_finished_at = timezone.now()
        update_fields.append("onboarding_finished_at")
    if update_fields:
        olt.save(update_fields=list(dict.fromkeys(update_fields)))


def _fail_stale_olt_onboarding_if_needed(olt):
    if not olt or str(getattr(olt, "onboarding_status", "") or "").lower() not in {"queued", "running", "aborting"}:
        return olt
    started_at = getattr(olt, "onboarding_started_at", None)
    if not started_at:
        return olt
    if (timezone.now() - started_at).total_seconds() < OLT_ONBOARDING_STALE_SECONDS:
        return olt
    message = "Onboarding timed out. Please retry after checking OLT SNMP/Telnet reachability."
    OLT.objects.filter(pk=olt.pk, onboarding_status__in=["queued", "running", "aborting"]).update(
        onboarding_status="failed",
        onboarding_progress=100,
        onboarding_message=message,
        onboarding_log=_append_olt_onboarding_log(getattr(olt, "onboarding_log", ""), message),
        onboarding_finished_at=timezone.now(),
        is_ready=False,
    )
    with _OLT_ONBOARDING_LOCK:
        _OLT_ONBOARDING_RUNNING.discard(int(olt.pk))
        _OLT_ONBOARDING_ABORT_REQUESTED.discard(int(olt.pk))
    return OLT.objects.filter(pk=olt.pk).first() or olt


def _onu_onboarding_counts(olt):
    qs = ConfiguredONU.objects.filter(olt=olt)
    total = qs.count()
    detail_ready = qs.exclude(onu_type_cache="").count()
    detail_missing = max(0, total - detail_ready)
    distance_ready = qs.exclude(ont_distance_m="").count()
    distance_missing = max(0, total - distance_ready)
    vlan_ready = qs.exclude(attached_vlans_cache="").count()
    vlan_missing = max(0, total - vlan_ready)
    signal_ready = qs.exclude(Q(onu_rx="") & Q(olt_rx="")).count()
    signal_missing = max(0, total - signal_ready)
    return {
        "total": total,
        "detail_ready": detail_ready,
        "detail_missing": detail_missing,
        "distance_ready": distance_ready,
        "distance_missing": distance_missing,
        "vlan_ready": vlan_ready,
        "vlan_missing": vlan_missing,
        "signal_ready": signal_ready,
        "signal_missing": signal_missing,
    }


def _olt_onboarding_review_counts(olt):
    onu_qs = ConfiguredONU.objects.filter(olt=olt)
    total_onus = onu_qs.count()
    return {
        "olt_details": 1 if _is_known_device_value(getattr(olt, "hardware_version", "")) or _is_known_device_value(getattr(olt, "sw_version", "")) else 0,
        "olt_cards": _onboarding_count_rows(getattr(olt, "olt_cards_cache", []) or []),
        "pon_ports": _onboarding_count_pon_ports(getattr(olt, "pon_ports_cache", []) or []),
        "uplink_ports": _onboarding_count_rows(getattr(olt, "uplink_cache", {}) or {}),
        "vlans": _onboarding_count_rows(getattr(olt, "vlan_cache", {}) or {}),
        "onus": total_onus,
        "onu_vlan_profile": onu_qs.exclude(attached_vlans_cache="").count(),
        "onu_types": onu_qs.exclude(onu_type_cache="").count(),
        "onu_distances": onu_qs.exclude(ont_distance_m="").count(),
        "service_profiles": onu_qs.filter(
            Q(service_port_id_cache__gt="") | Q(download_profile_name_cache__gt="") | Q(upload_profile_name_cache__gt="")
        ).count(),
        "onu_signals": onu_qs.exclude(Q(onu_rx="") & Q(olt_rx="")).count(),
        "total_onus": total_onus,
    }


def _reset_olt_onboarding_data(olt):
    if not olt:
        return
    ConfiguredONU.objects.filter(olt=olt).delete()
    olt.olt_cards_cache = []
    olt.olt_cards_status = ""
    olt.olt_cards_refreshed_at = None
    olt.pon_ports_cache = []
    olt.pon_ports_status = ""
    olt.pon_ports_refreshed_at = None
    olt.uplink_cache = {}
    olt.uplink_status = ""
    olt.uplink_refreshed_at = None
    olt.vlan_cache = {}
    olt.vlan_status = ""
    olt.vlan_refreshed_at = None
    olt.is_ready = False
    olt.onboarding_status = "queued"
    olt.onboarding_progress = 0
    olt.onboarding_message = "OLT saved. Waiting to retry..."
    olt.onboarding_log = "OLT saved. Waiting to retry..."
    olt.onboarding_started_at = timezone.now()
    olt.onboarding_finished_at = None
    olt.save(update_fields=[
        "olt_cards_cache", "olt_cards_status", "olt_cards_refreshed_at",
        "pon_ports_cache", "pon_ports_status", "pon_ports_refreshed_at",
        "uplink_cache", "uplink_status", "uplink_refreshed_at",
        "vlan_cache", "vlan_status", "vlan_refreshed_at",
        "is_ready", "onboarding_status", "onboarding_progress",
        "onboarding_message", "onboarding_log", "onboarding_started_at",
        "onboarding_finished_at",
    ])


def _format_onu_onboarding_counts(counts):
    total = int(counts.get("total") or 0)
    return (
        f"{int(counts.get('detail_ready') or 0)}/{total} ONU types; "
        f"{int(counts.get('distance_ready') or 0)}/{total} distances; "
        f"{int(counts.get('vlan_ready') or 0)}/{total} VLAN/profiles; "
        f"{int(counts.get('signal_ready') or 0)}/{total} signals."
    )


def _sync_onu_type_distance_from_snmp(olt, *, allow_single_fallback=True, progress_callback=None):
    snmp_maps = fetch_olt_snmp_onu_type_distance_maps(olt)
    type_map = snmp_maps.get("type_items") or {}
    distance_map = snmp_maps.get("distance_items") or {}
    records = list(ConfiguredONU.objects.filter(olt=olt).order_by("id"))
    updated = []
    saved = 0

    def _flush_updates():
        nonlocal saved, updated
        if not updated:
            return
        ConfiguredONU.objects.bulk_update(updated, ["onu_type_cache", "ont_distance_m", "capability_synced_at"], batch_size=300)
        saved += len(updated)
        updated = []
        if progress_callback:
            progress_callback(len(records), saved)

    for record in records:
        key = (int(record.slot), int(record.port), int(record.ont_id))
        changed = False
        onu_type = str(type_map.get(key) or "").strip()[:128]
        if allow_single_fallback and not onu_type and not (record.onu_type_cache or "").strip():
            single_type = fetch_single_onu_snmp_type(olt, record.slot, record.port, record.ont_id)
            onu_type = str(single_type.get("onu_type") or "").strip()[:128]
        if onu_type and onu_type != (record.onu_type_cache or ""):
            record.onu_type_cache = onu_type
            changed = True
        distance = str(distance_map.get(key) or "").strip()[:32]
        if allow_single_fallback and not distance and not (record.ont_distance_m or "").strip():
            single_distance = fetch_single_onu_snmp_distance(olt, record.slot, record.port, record.ont_id)
            distance = str(single_distance.get("ont_distance_m") or "").strip()[:32]
        if distance and distance != (record.ont_distance_m or ""):
            record.ont_distance_m = distance
            changed = True
        if changed or not record.capability_synced_at:
            record.capability_synced_at = timezone.now()
            updated.append(record)
        if len(updated) >= 300:
            _flush_updates()
    _flush_updates()
    if progress_callback:
        progress_callback(len(records), saved)
    return {
        "checked": len(records),
        "updated": saved,
        "type_ready": ConfiguredONU.objects.filter(olt=olt).exclude(onu_type_cache="").count(),
        "distance_ready": ConfiguredONU.objects.filter(olt=olt).exclude(ont_distance_m="").count(),
        "status": snmp_maps.get("status") or "",
    }


def _sync_onu_details_background_worker(olt_id):
    try:
        olt = OLT.objects.filter(pk=olt_id).first()
        if not olt:
            return
        counts = _onu_onboarding_counts(olt)
        _record_olt_system_history(
            olt,
            "onu_type_distance_sync",
            f"Background ONU type/distance SNMP fill started. type {counts['detail_ready']}/{counts['total']}, distance {counts['distance_ready']}/{counts['total']}.",
        )
        last_history_saved = -1
        while True:
            pending = ConfiguredONU.objects.filter(olt=olt).filter(
                Q(onu_type_cache="") | Q(ont_distance_m="")
            ).count()
            if pending <= 0:
                break

            def _progress(total, saved):
                nonlocal last_history_saved
                counts_now = _onu_onboarding_counts(olt)
                message = (
                    "Background SNMP ONU type/distance fill: "
                    f"type {counts_now['detail_ready']}/{counts_now['total']}, "
                    f"distance {counts_now['distance_ready']}/{counts_now['total']}."
                )
                _update_olt_onboarding(olt_id, message=message)
                if saved == 0 or saved == last_history_saved:
                    return
                last_history_saved = saved
                _record_olt_system_history(olt, "onu_type_distance_sync", message)

            result = _sync_onu_type_distance_from_snmp(olt, allow_single_fallback=False, progress_callback=_progress)
            counts = _onu_onboarding_counts(olt)
            message = (
                "Background SNMP ONU type/distance fill: "
                f"type {counts['detail_ready']}/{counts['total']}, "
                f"distance {counts['distance_ready']}/{counts['total']}."
            )
            _update_olt_onboarding(olt_id, message=message)
            _record_olt_system_history(olt, "onu_type_distance_sync", message)
            if int(result.get("updated") or 0) <= 0:
                break
            time.sleep(3)
        counts = _onu_onboarding_counts(olt)
        final_message = f"Background SNMP fill finished. {_format_onu_onboarding_counts(counts)}"
        _update_olt_onboarding(olt_id, message=final_message)
        _record_olt_system_history(olt, "onu_type_distance_sync", final_message)
    finally:
        pass


def _onboarding_count_rows(value):
    if isinstance(value, dict):
        return len(value.get("rows") or [])
    if isinstance(value, (list, tuple)):
        return len(value)
    return 0


def _onboarding_count_pon_ports(groups):
    return sum(len(group.get("ports") or []) for group in (groups or []) if isinstance(group, dict))


def _onboarding_require_count(label, count):
    if int(count or 0) <= 0:
        raise ValueError(f"{label} returned no data")
    return count


def _onboarding_value_status(value):
    """Pull the fetch function's own status string out of its return value so the
    real reason (timeout / login / busy / SNMP no-response) is surfaced, not just
    a generic 'returned no data'."""
    if isinstance(value, dict):
        return str(value.get("status") or "").strip()
    if isinstance(value, (list, tuple)) and len(value) >= 2 and isinstance(value[1], str):
        return str(value[1] or "").strip()
    return ""


def _humanize_onboarding_error(text):
    """Translate a raw exception / status into a plain reason a user can act on."""
    t = " ".join(str(text or "").split())
    low = t.lower()
    if "sendall" in low or ("nonetype" in low and "attribute" in low):
        return "OLT closed the Telnet session (it likely hit its concurrent-session limit or was busy) — close other Telnet/CLI sessions and retry"
    if "login failed" in low or "username/password" in low or ("password" in low and "invalid" in low):
        return "Telnet login failed — check the OLT username/password"
    if "could not be opened" in low or "could not open" in low or "session not open" in low:
        return "Could not open a Telnet session to the OLT (busy or refused)"
    if "timed out" in low or "timeout" in low:
        return "Timed out waiting for the OLT (slow or busy device)"
    if "no response" in low or "unreachable" in low:
        return "OLT did not respond (network / SNMP unreachable)"
    if "connection closed" in low or "connection reset" in low or "broken pipe" in low or low.endswith("eof") or "eoferror" in low:
        return "OLT dropped the connection mid-fetch"
    return t
def _run_olt_onboarding_worker(olt_id, snmp_mode):
    try:
        _clear_olt_onboarding_abort(olt_id)
        olt = OLT.objects.filter(pk=olt_id).first()
        if not olt:
            return

        def _run_step(step_label, progress_before, progress_after, fn, attempts=3, delay=1.2, validate=None, success_message=None, allow_failure=False, fallback=None):
            last_exc = None
            for attempt in range(1, attempts + 1):
                _raise_if_olt_onboarding_aborted(olt_id)
                try:
                    if attempt == 1:
                        _update_olt_onboarding(olt_id, progress=progress_before, message=f"{step_label}...")
                    else:
                        reason = _humanize_onboarding_error(last_exc)[:180]
                        reason_text = f" ({reason})" if reason else ""
                        _update_olt_onboarding(olt_id, progress=progress_before, message=f"{step_label} retry {attempt}/{attempts}{reason_text}...")
                    value = fn()
                    _raise_if_olt_onboarding_aborted(olt_id)
                    if validate:
                        try:
                            validate(value)
                        except OnboardingAborted:
                            raise
                        except Exception as ve:
                            # Surface the fetch's OWN status (the real reason) instead
                            # of a bare "returned no data".
                            status_detail = _onboarding_value_status(value)
                            if status_detail and status_detail.lower() not in str(ve).lower():
                                raise ValueError(f"{ve} — {status_detail}") from ve
                            raise
                    ok_message = success_message(value) if success_message else f"{step_label} done."
                    _update_olt_onboarding(olt_id, progress=progress_after, message=f"OK: {ok_message}")
                    return value
                except OnboardingAborted:
                    raise
                except Exception as exc:
                    last_exc = exc
                    if attempt >= attempts:
                        fail_message = f"FAILED: {step_label} not fetched after {attempts} tries. Refresh after OLT add. {_humanize_onboarding_error(exc)}"
                        _update_olt_onboarding(olt_id, progress=progress_after, message=fail_message)
                        if allow_failure:
                            return fallback
                        raise
                    time.sleep(delay)
            raise last_exc

        import_onus = bool(getattr(olt, "import_onus", True))

        _raise_if_olt_onboarding_aborted(olt_id)
        _update_olt_onboarding(
            olt_id,
            status="running",
            progress=5,
            message="OLT saved. Starting onboarding...",
        )

        if str(snmp_mode or "manual").strip().lower() == "generate":
            _update_olt_onboarding(
                olt_id,
                progress=12,
                message="Generating and pushing SNMP configuration...",
            )
            snmp_ok, snmp_status = _sync_snmp_after_save(olt)
        else:
            _update_olt_onboarding(
                olt_id,
                progress=12,
                message="Fetching SNMP details...",
            )
            snmp_ok, snmp_status = _fetch_snmp_only_after_save(olt)
        _raise_if_olt_onboarding_aborted(olt_id)
        if not snmp_ok:
            _update_olt_onboarding(
                olt_id,
                status="failed",
                progress=100,
                message=snmp_status or "SNMP step failed.",
                ready=False,
                finished=True,
            )
            return

        _update_olt_onboarding(olt_id, progress=22, message="OLT details fetched.")
        adapter = get_olt_adapter(olt)

        # Ensure proper model + software in OLT details. SNMP sysDescr is sometimes
        # blank/"Unknown"; in that case read the authoritative values from the CLI
        # `display version` (PRODUCT / VERSION).
        olt = OLT.objects.filter(pk=olt_id).first()
        def _needs(value):
            v = str(value or "").strip().lower()
            return (not v) or v == "unknown"
        if olt and (_needs(olt.hardware_version) or _needs(olt.sw_version)):
            try:
                ver = fetch_telnet_version_snapshot(olt)
                fields = []
                model = str(ver.get("model") or "").strip()
                sw = _normalize_olt_software_version(str(ver.get("sw_version") or "").strip())
                if _needs(olt.hardware_version) and model and model.lower() != "unknown":
                    olt.hardware_version = model
                    fields.append("hardware_version")
                if _needs(olt.sw_version) and sw and sw.lower() != "unknown":
                    olt.sw_version = sw
                    fields.append("sw_version")
                if fields:
                    olt.save(update_fields=fields)
                    _update_olt_onboarding(
                        olt_id,
                        progress=24,
                        message=f"OK: Model/software from CLI: {olt.hardware_version or '-'} / {olt.sw_version or '-'}.",
                    )
            except Exception:
                pass
        _raise_if_olt_onboarding_aborted(olt_id)

        cards, cards_status = _run_step(
            "Fetching OLT cards",
            34,
            44,
            lambda: adapter.fetch_cards(olt),
            validate=lambda value: _onboarding_require_count("OLT cards", _onboarding_count_rows(value[0])),
            success_message=lambda value: f"{_onboarding_count_rows(value[0])} OLT cards fetched.",
            allow_failure=True,
            fallback=([], ""),
        )
        _raise_if_olt_onboarding_aborted(olt_id)
        olt = OLT.objects.filter(pk=olt_id).first()
        if olt:
            if cards:
                olt.olt_cards_cache = cards
            olt.olt_cards_status = str(cards_status or "")[:300]
            olt.olt_cards_refreshed_at = timezone.now()
            olt.save(update_fields=["olt_cards_cache", "olt_cards_status", "olt_cards_refreshed_at"])

        groups, status = _run_step(
            "Fetching PON ports",
            52,
            62,
            lambda: adapter.fetch_pon_ports(olt),
            validate=lambda value: _onboarding_require_count("PON ports", _onboarding_count_pon_ports(value[0])),
            success_message=lambda value: f"{_onboarding_count_pon_ports(value[0])} PON ports fetched.",
            allow_failure=True,
            fallback=([], ""),
        )
        _raise_if_olt_onboarding_aborted(olt_id)
        if groups:
            _set_cached_pon_ports(olt_id, groups, status)
            save_pon_ports_snapshot(olt, groups, status)

        if groups:
            olt = OLT.objects.filter(pk=olt_id).first()
            _run_step(
                "Fetching PON SFP Tx power",
                64,
                68,
                lambda: refresh_pon_sfp_tx_snapshot(olt),
                attempts=2,
                success_message=lambda value: f"SFP Tx fetched for {int((value or {}).get('updated') or 0)} port(s).",
                allow_failure=True,
                fallback={"updated": 0, "status": "SFP Tx fetch failed."},
            )
            _raise_if_olt_onboarding_aborted(olt_id)

        uplink_data = _run_step(
            "Fetching uplink ports",
            70,
            78,
            lambda: fetch_uplink_snapshot(olt),
            validate=lambda value: _onboarding_require_count("uplink ports", _onboarding_count_rows(value)),
            success_message=lambda value: f"{_onboarding_count_rows(value)} uplink ports fetched.",
            allow_failure=True,
            fallback={"rows": [], "status": "Uplink fetch failed after retries."},
        )
        _raise_if_olt_onboarding_aborted(olt_id)
        _set_cached_uplink(olt.pk, uplink_data)
        save_uplink_snapshot(olt, uplink_data)

        if (uplink_data or {}).get("rows"):
            olt = OLT.objects.filter(pk=olt_id).first()
            _run_step(
                "Fetching uplink VLANs",
                80,
                82,
                lambda: refresh_uplink_vlan_snapshot(olt),
                attempts=2,
                success_message=lambda value: f"Uplink VLANs fetched for {int((value or {}).get('updated') or 0)} port(s).",
                allow_failure=True,
                fallback={"updated": 0, "status": "Uplink VLAN fetch failed."},
            )
            _raise_if_olt_onboarding_aborted(olt_id)

        vlan_data = _run_step(
            "Fetching VLANs",
            84,
            90,
            lambda: _fetch_vlan_snapshot_with_retry(olt),
            validate=lambda value: _onboarding_require_count("VLANs", _onboarding_count_rows(value)),
            success_message=lambda value: f"{_onboarding_count_rows(value)} VLANs fetched.",
            allow_failure=True,
            fallback={"rows": [], "status": "VLAN fetch failed after retries."},
        )
        _raise_if_olt_onboarding_aborted(olt_id)
        save_vlan_snapshot(olt, vlan_data)

        if not import_onus:
            # User chose NOT to import ONUs — stop after OLT details/cards/PON/
            # uplink/VLAN and present the review without any ONU data.
            _update_olt_onboarding(
                olt_id,
                progress=100,
                message="OK: ONU import skipped at user's request. OLT details, cards, PON ports, uplink and VLANs fetched.",
            )
            _update_olt_onboarding(
                olt_id,
                status="review",
                progress=100,
                message="Onboarding review ready (ONUs not imported).",
                ready=False,
                finished=True,
            )
            return

        _run_step(
            "Reading configured ONUs",
            94,
            96,
            lambda: sync_configured_onus_inventory(olt),
            validate=lambda value: _onboarding_require_count(
                "configured ONUs",
                int((value or {}).get("count") or 0),
            ),
            success_message=lambda value: f"{int((value or {}).get('count') or 0)} configured ONUs discovered.",
        )
        _raise_if_olt_onboarding_aborted(olt_id)
        olt = OLT.objects.filter(pk=olt_id).first()
        counts = _onu_onboarding_counts(olt)
        _update_olt_onboarding(
            olt_id,
            progress=96,
            message=f"Configured ONUs discovered: {counts['total']}.",
        )

        def _vlan_profile_progress(checked, total, updated):
            ratio = (checked / max(total, 1))
            _update_olt_onboarding(
                olt_id,
                progress=96 + int(ratio * 2),
                message=f"Fetching ONU VLAN/profile details: {checked}/{total} checked, {updated} filled...",
            )

        _run_step(
            "Fetching ONU VLAN and speed profile details",
            98,
            99,
            lambda: sync_onu_attached_vlans_for_olt(olt, fallback_missing=True, progress_callback=_vlan_profile_progress),
            attempts=1,
        )
        _raise_if_olt_onboarding_aborted(olt_id)
        def _type_progress(total, updated):
            _update_olt_onboarding(
                olt_id,
                progress=99,
                message=f"Fetching ONU types: {updated}/{total} filled...",
            )

        def _type_note(done_ports, total_ports, filled):
            _update_olt_onboarding(
                olt_id,
                progress=99,
                message=f"Fetching ONU types: PON port {done_ports}/{total_ports}, {filled} filled...",
            )

        _run_step(
            "Fetching ONU types",
            99,
            100,
            lambda: sync_onu_equipment_ids_for_olt(olt, progress_callback=_type_progress, note_callback=_type_note),
            attempts=1,
            success_message=lambda value: f"{int((value or {}).get('updated') or 0)} ONU type(s) read from OLT.",
            allow_failure=True,
            fallback={"checked": 0, "updated": 0, "status": "ONU type CLI fetch failed."},
        )
        _raise_if_olt_onboarding_aborted(olt_id)

        # ONU signal strengths are filled by the background signal-sample loop
        # after the OLT is added, so they are no longer fetched during onboarding.

        olt = OLT.objects.filter(pk=olt_id).first()
        counts = _onu_onboarding_counts(olt)
        _update_olt_onboarding(
            olt_id,
            progress=100,
            message=_format_onu_onboarding_counts(counts),
        )

        _update_olt_onboarding(
            olt_id,
            status="review",
            progress=100,
            message=f"Onboarding review ready. {_format_onu_onboarding_counts(counts)}",
            ready=False,
            finished=True,
        )
    except OnboardingAborted:
        OLT.objects.filter(pk=olt_id).delete()
    except Exception as exc:
        _update_olt_onboarding(
            olt_id,
            status="failed",
            progress=100,
            message=f"Onboarding failed: {exc}",
            ready=False,
            finished=True,
        )
    finally:
        with _OLT_ONBOARDING_LOCK:
            _OLT_ONBOARDING_RUNNING.discard(int(olt_id))
            _OLT_ONBOARDING_ABORT_REQUESTED.discard(int(olt_id))


def _schedule_olt_onboarding(olt_id, snmp_mode):
    olt_id = int(olt_id or 0)
    if olt_id <= 0:
        return
    with _OLT_ONBOARDING_LOCK:
        if olt_id in _OLT_ONBOARDING_RUNNING:
            return
        _OLT_ONBOARDING_RUNNING.add(olt_id)
    threading.Thread(
        target=_run_olt_onboarding_worker,
        args=(olt_id, snmp_mode),
        name=f"olt-onboarding-{olt_id}",
        daemon=True,
    ).start()


def _active_olt_onboarding():
    return (
        OLT.objects
        .filter(onboarding_status__in=["queued", "running", "aborting"])
        .order_by("onboarding_started_at", "id")
        .first()
    )


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


def _record_olt_system_history(olt, action, details='', onu=''):
    if not olt:
        return
    OLTLoginHistory.objects.create(
        olt=olt,
        user=None,
        username='system',
        action=str(action or '')[:50],
        onu=(onu or '')[:120],
        ip_address='',
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

    snapshot = fetch_snmp_snapshot(olt, include_entity_metrics=False, operation_timeout=3.0)
    status_text = str(snapshot.get('status', '') or 'SNMP synced')
    update_fields = ['snmp_last_status', 'snmp_last_synced_at']
    olt.snmp_last_status = status_text[:300]
    olt.snmp_last_synced_at = timezone.now()

    model = (snapshot.get('model') or '').strip()
    sw_version = _normalize_olt_software_version((snapshot.get('sw_version') or '').strip())
    if model and model.lower() != 'unknown' and model != (olt.hardware_version or ''):
        olt.hardware_version = model
        update_fields.append('hardware_version')
    if sw_version and sw_version.lower() != 'unknown' and sw_version != (olt.sw_version or ''):
        olt.sw_version = sw_version
        update_fields.append('sw_version')

    olt.save(update_fields=update_fields)
    return True, status_text


def _fetch_snmp_only_after_save(olt):
    snapshot = fetch_snmp_snapshot(olt, include_entity_metrics=False, operation_timeout=3.0)
    status_text = str(snapshot.get('status', '') or 'SNMP fetched')
    update_fields = ['snmp_last_status', 'snmp_last_synced_at']
    olt.snmp_last_status = status_text[:300]
    olt.snmp_last_synced_at = timezone.now()

    model = (snapshot.get('model') or '').strip()
    sw_version = _normalize_olt_software_version((snapshot.get('sw_version') or '').strip())
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


def _refresh_autofind_counts_worker(selected_olt_id=None):
    try:
        qs = _ready_olts().only("id")
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


def _store_autofind_rows_cache(olt_id, snapshot):
    payload = {
        "snapshot": dict(snapshot or {}),
        "stored_at": timezone.now(),
    }
    with _AUTOFIND_ROWS_CACHE_LOCK:
        _AUTOFIND_ROWS_CACHE[int(olt_id)] = payload
    return payload["snapshot"]


def _is_autofind_busy_status(status):
    text = str(status or "").strip().lower()
    return bool(text) and any(token in text for token in (
        "resource busy",
        "device busy",
        "olt is busy",
        "busy",
    ))


def _is_autofind_widget_unreachable(olt):
    if not olt:
        return False
    if getattr(olt, "snmp_down_since", None):
        return True
    return _is_recent_olt_snmp_unreachable(
        getattr(olt, "snmp_last_status", ""),
        getattr(olt, "snmp_last_synced_at", None),
        max_age_seconds=180,
    )


def _refresh_autofind_rows_worker(olt_id):
    try:
        olt = OLT.objects.only(
            "id", "name", "ip_address", "port", "username", "password",
            "snmp_last_status", "snmp_last_synced_at", "snmp_down_since",
        ).filter(pk=olt_id).first()
        if not olt:
            return
        while True:
            olt.refresh_from_db(fields=["snmp_last_status", "snmp_last_synced_at", "snmp_down_since"])
            if _is_autofind_widget_unreachable(olt):
                _store_autofind_rows_cache(olt_id, {"status": "OLT Unreachable", "rows": []})
                return
            snapshot = fetch_ont_autofind_snapshot(olt)
            if not _is_autofind_busy_status(snapshot.get("status")):
                _store_autofind_rows_cache(olt_id, snapshot)
                return
            time.sleep(3)
    finally:
        with _AUTOFIND_ROWS_CACHE_LOCK:
            _AUTOFIND_ROWS_REFRESHING.discard(int(olt_id))


def _schedule_autofind_rows_refresh(olt_id):
    olt_id = int(olt_id or 0)
    if olt_id <= 0:
        return False
    with _AUTOFIND_ROWS_CACHE_LOCK:
        if olt_id in _AUTOFIND_ROWS_REFRESHING:
            return False
        _AUTOFIND_ROWS_REFRESHING.add(olt_id)
    threading.Thread(
        target=_refresh_autofind_rows_worker,
        args=(olt_id,),
        name=f"autofind-rows-{olt_id}",
        daemon=True,
    ).start()
    return True


def _get_autofind_snapshot_for_view(olt):
    olt_id = int(getattr(olt, "id", 0) or 0)
    if olt_id <= 0:
        return fetch_ont_autofind_snapshot(olt)
    if _is_autofind_widget_unreachable(olt):
        return {"status": "OLT Unreachable", "rows": []}
    # ALWAYS run the live `display ont autofind all` on the OLT — autofind must
    # reflect the device's current state, never a stale cache (the OLT itself
    # sometimes returns the list and sometimes not, so we re-query every time).
    snapshot = fetch_ont_autofind_snapshot(olt)
    if _is_autofind_busy_status(snapshot.get("status")):
        # The OLT has another Telnet session active right now, so the live query
        # could not run. Fall back to the last known rows (if any) and retry in
        # the background instead of showing a hard error.
        _schedule_autofind_rows_refresh(olt_id)
        with _AUTOFIND_ROWS_CACHE_LOCK:
            cached_entry = _AUTOFIND_ROWS_CACHE.get(olt_id)
        if cached_entry and (cached_entry.get("snapshot") or {}).get("rows"):
            fallback = dict(cached_entry["snapshot"])
            base_status = str(fallback.get("status") or "").strip()
            fallback["status"] = (f"{base_status} | OLT busy, showing last data".strip(" |"))
            return fallback
        return {"status": "Loading autofind rows for this OLT...", "rows": [], "pending": True}
    _store_autofind_rows_cache(olt_id, snapshot)
    return snapshot


def _get_live_autofind_snapshot_for_ajax(olt, *, max_attempts=3, retry_delay=2.0):
    """Fetch live Autofind rows without blocking the main Autofind page render."""
    olt_id = int(getattr(olt, "id", 0) or 0)
    if olt_id <= 0:
        return fetch_ont_autofind_snapshot(olt)
    if _is_autofind_widget_unreachable(olt):
        snapshot = {"status": "OLT Unreachable", "rows": []}
        _store_autofind_rows_cache(olt_id, snapshot)
        return snapshot

    with _AUTOFIND_ROWS_CACHE_LOCK:
        if olt_id in _AUTOFIND_LIVE_FETCHING:
            return {
                "status": "OLT is busy. Existing live autofind fetch is still running.",
                "rows": [],
                "pending": True,
            }
        _AUTOFIND_LIVE_FETCHING.add(olt_id)

    last_snapshot = {"status": "Live autofind fetch did not run.", "rows": []}
    try:
        for attempt in range(1, max(1, int(max_attempts or 1)) + 1):
            snapshot = fetch_ont_autofind_snapshot(olt)
            status_text = str(snapshot.get("status") or "").strip()
            lowered = status_text.lower()
            rows = snapshot.get("rows") or []
            success = status_text.startswith("Autofind ONUs fetched:")
            retryable = any(
                token in lowered
                for token in (
                    "busy",
                    "timeout",
                    "connection closed",
                    "connection reset",
                    "connection aborted",
                    "telnet error",
                    "could not be opened",
                    "login failed",
                )
            )
            if success:
                _store_autofind_rows_cache(olt_id, snapshot)
                return snapshot
            if rows and not retryable:
                _store_autofind_rows_cache(olt_id, snapshot)
                return snapshot

            if "busy" in lowered:
                status_text = f"OLT is busy. Retry {attempt}/{max_attempts}."
            elif retryable:
                status_text = f"{status_text or 'Telnet fetch failed.'} Retry {attempt}/{max_attempts}."
            last_snapshot = {**dict(snapshot or {}), "status": status_text, "rows": rows}
            if attempt < max_attempts and retryable:
                time.sleep(float(retry_delay or 0))
                continue
            break

        OLT.objects.filter(pk=olt_id).update(
            autofind_status=str(last_snapshot.get("status") or "")[:300],
            autofind_refreshed_at=timezone.now(),
        )
        return last_snapshot
    finally:
        with _AUTOFIND_ROWS_CACHE_LOCK:
            _AUTOFIND_LIVE_FETCHING.discard(olt_id)


def _build_unconfigured_group(
    request,
    olt,
    index,
    existing_by_serial,
    search_query,
    category_filter,
    onu_type_options,
    download_speed_options,
    upload_speed_options,
    snapshot_override=None,
):
    snapshot = snapshot_override if snapshot_override is not None else _get_autofind_snapshot_for_view(olt)
    status_text = snapshot.get("status") or "Autofind unavailable"
    lowered_status = str(status_text or "").strip().lower()
    is_busy = False
    is_unreachable = _is_autofind_widget_unreachable(olt)
    is_pending = (not is_unreachable) and (
        bool(snapshot.get("pending"))
        or not (snapshot.get("rows") or [])
        and str(status_text or "").strip().lower() != "autofind onus fetched: 0"
    )
    onu_type_lookup = {
        str(item.get("value") or "").strip().lower(): str(item.get("value") or "").strip()
        for item in (onu_type_options or [])
        if str(item.get("value") or "").strip()
    }
    vlan_options = []
    for vlan_row in list(getattr(olt, "vlan_cache", []) or []):
        vlan_id_text = str(vlan_row.get("vlan_id") or "").strip()
        if not vlan_id_text or vlan_row.get("is_management"):
            continue
        vlan_label = vlan_id_text
        vlan_desc = str(vlan_row.get("description") or "").strip()
        if vlan_desc and vlan_desc != "-":
            vlan_label = f"{vlan_id_text} - {vlan_desc}"
        vlan_options.append({"value": vlan_id_text, "label": vlan_label})
    vlan_options_with_untagged = list(vlan_options)
    if not any(str(item.get("value") or "").strip().lower() == "untagged" for item in vlan_options_with_untagged):
        vlan_options_with_untagged.append({"value": "untagged", "label": "untagged"})

    olt_rows = []
    total_new = 0
    total_resync = 0
    for row in snapshot.get("rows") or []:
        item = dict(row)
        item["olt_id"] = olt.id
        item["olt_name"] = olt.name
        serial_tokens = _normalize_onu_serial_token(item.get("sn"))
        existing_record = None
        for token in serial_tokens:
            existing_record = existing_by_serial.get(token)
            if existing_record:
                break
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
        item["previous_running"] = (
            f"{existing_record.olt.name} | 0/{int(existing_record.slot or 0)}/{int(existing_record.port or 0)} | ONT {int(existing_record.ont_id or 0)}"
            if existing_record
            else "-"
        )
        item["authorize_key"] = f"auth-{olt.id}-{int(item.get('board') or 0)}-{int(item.get('port') or 0)}-{re.sub(r'[^A-Za-z0-9]+', '-', str(item.get('sn') or '').strip())}"
        row_pon_type = str(item.get("pon_type") or "").strip().upper()
        if not row_pon_type or row_pon_type == "-":
            row_pon_type = _onu_tech_label(olt, item.get("board")).upper()
        item["authorize_pon_type"] = "EPON" if "EPON" in row_pon_type else "GPON"
        item["authorize_vlan_mapping_disabled"] = item["authorize_pon_type"] == "EPON"
        item["authorize_vlan_options"] = vlan_options_with_untagged
        item["authorize_svlan_options"] = vlan_options
        equipment_id = str(item.get("type") or "-").strip()
        item["equipment_id"] = equipment_id or "-"
        matched_onu_type = ""
        if equipment_id and equipment_id not in {"-", ""}:
            matched_onu_type = onu_type_lookup.get(equipment_id.lower(), "")
        item["authorize_onu_type"] = matched_onu_type
        item["authorize_onu_mode"] = str(getattr(existing_record, "onu_mode_cache", "") or "").strip() if existing_record else ""
        item["authorize_subscriber_name"] = str(getattr(existing_record, "description", "") or "").strip() if existing_record else ""
        existing_user_vlan_cache = str(getattr(existing_record, "user_vlan_cache", "") or "").strip() if existing_record else ""
        existing_service_vlan_cache = str(getattr(existing_record, "attached_vlans_cache", "") or "").strip() if existing_record else ""
        item["authorize_vlan"] = (existing_user_vlan_cache.split(",")[0].strip() if existing_user_vlan_cache else "")
        existing_service_vlan = existing_service_vlan_cache.split(",")[0].strip() if existing_service_vlan_cache else ""
        existing_user_vlan = item["authorize_vlan"]
        item["authorize_svlan"] = existing_service_vlan if existing_service_vlan and existing_service_vlan != existing_user_vlan else ""
        item["authorize_tag_transform"] = "default"
        item["authorize_mapping_mode"] = str(getattr(existing_record, "mapping_mode_cache", "") or "").strip().lower() if existing_record else ""
        if item["authorize_mapping_mode"] not in {"priority", "vlan"}:
            item["authorize_mapping_mode"] = "priority"
        if item["authorize_vlan_mapping_disabled"]:
            item["authorize_mapping_mode"] = "priority"
        item["authorize_download_speed"] = str(getattr(existing_record, "download_profile_index_cache", "") or "").strip() if existing_record else ""
        item["authorize_upload_speed"] = str(getattr(existing_record, "upload_profile_index_cache", "") or "").strip() if existing_record else ""
        if existing_record:
            total_resync += 1
        else:
            total_new += 1
        if category_filter and category != category_filter:
            continue
        if search_query:
            haystack = " ".join([
                str(item.get("olt_name") or ""),
                str(item.get("pon_type") or ""),
                str(item.get("board") or ""),
                str(item.get("port") or ""),
                str(item.get("sn") or ""),
                str(item.get("equipment_id") or ""),
                str(item.get("category_label") or ""),
                str(item.get("previous_running") or ""),
                str(item.get("autofind_time") or ""),
            ]).lower()
            if search_query not in haystack:
                continue
        olt_rows.append(item)
    olt_rows.sort(key=lambda row: (int(row.get("board") or 0), int(row.get("port") or 0), str(row.get("sn") or "")))
    group = {
        "index": index,
        "olt_id": olt.id,
        "olt_name": olt.name,
        "rows": olt_rows,
        "count": len(olt_rows),
        "status": status_text,
        "is_busy": is_busy,
        "is_pending": is_pending,
        "is_unreachable": is_unreachable,
    }
    html = render_to_string(
        "oltmanager/_unconfigured_group.html",
        {
            "group": group,
            "unconfigured_onu_type_options": onu_type_options,
            "unconfigured_download_speed_options": download_speed_options,
            "unconfigured_upload_speed_options": upload_speed_options,
            "unconfigured_return_query": str(request.GET.get("return_query") or request.GET.urlencode()).strip(),
        },
        request=request,
    )
    return {
        "group": group,
        "status": status_text,
        "html": html,
        "new_total": total_new,
        "resync_total": total_resync,
        "visible_total": len(olt_rows),
    }


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


def _format_profile_speed_label_from_mbps(value):
    try:
        mbps = float(value)
    except (TypeError, ValueError):
        return ""
    if mbps <= 0:
        return ""
    if mbps >= 1000:
        gbps = mbps / 1000.0
        return f"{gbps:g}G"
    return f"{mbps:g} Mbps"


def _short_speed_profile_label(profile_name, fallback_index="", speed_label_by_index=None):
    text = str(profile_name or "").strip()
    if text and text != "-":
        cleaned = re.sub(r"(?i)(?:[-_ ]+)?(?:down|up)$", "", text).strip(" -_")
        gig_match = re.search(r"(?i)(\d+(?:\.\d+)?)\s*(?:g|gb|gbps|gig)\b", cleaned)
        if gig_match:
            try:
                return f"{float(gig_match.group(1)):g}G"
            except (TypeError, ValueError):
                pass
        mbps_match = re.search(r"(?i)(\d+(?:\.\d+)?)\s*(?:m|mb|mbps)\b", cleaned)
        if mbps_match:
            try:
                mbps = float(mbps_match.group(1))
            except (TypeError, ValueError):
                mbps = 0
            label = _format_profile_speed_label_from_mbps(mbps)
            if label:
                return label
        return text

    index_value = str(fallback_index or "").strip()
    if index_value and speed_label_by_index:
        return speed_label_by_index.get(index_value) or index_value
    return "-"


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


def _normalize_olt_software_version(value):
    text = str(value or "").strip().upper()
    match = re.search(r"\bR\d{3}\b", text)
    return match.group(0) if match else text
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
    for olt in _ready_olts().only("id", "dashboard_snapshot_refreshed_at").all():
        if _dashboard_snapshot_due(olt):
            _schedule_snapshot_refresh(olt.pk)


def _refresh_missing_dashboard_snapshots_inline(limit=1):
    """Fill brand-new blank OLT dashboard rows without waiting for async cache.

    This is intentionally tiny: at most one OLT per AJAX poll, and only rows with
    missing uptime/temp. Normal dashboard refresh still uses background threads.
    """
    if limit <= 0:
        return
    try:
        candidates = list(
            _ready_olts()
            .filter(Q(dashboard_uptime="") | Q(dashboard_temperature=""))
            .only(
                "id",
                "ip_address",
                "snmp_port",
                "snmp_community",
                "dashboard_uptime",
                "dashboard_temperature",
                "dashboard_snapshot_refreshed_at",
            )
            .order_by("dashboard_snapshot_refreshed_at", "id")[: int(limit)]
        )
    except OperationalError:
        return
    for olt in candidates:
        # Avoid stacking with an existing async refresh for this OLT.
        with _SNAPSHOT_CACHE_LOCK:
            if olt.pk in _SNAPSHOT_REFRESHING:
                continue
        last = getattr(olt, "dashboard_snapshot_refreshed_at", None)
        if last and (timezone.now() - last).total_seconds() < 30:
            continue
        snapshot = fetch_snmp_snapshot(olt, include_entity_metrics=True, operation_timeout=3.0)
        fetched_uptime = str(snapshot.get("uptime") or "").strip()
        fetched_temp = str(snapshot.get("temperature") or "").strip()
        update_fields = []
        if fetched_uptime and fetched_uptime != "--" and fetched_uptime != (olt.dashboard_uptime or ""):
            olt.dashboard_uptime = fetched_uptime
            update_fields.append("dashboard_uptime")
        if fetched_temp and fetched_temp != "--" and fetched_temp != (olt.dashboard_temperature or ""):
            olt.dashboard_temperature = fetched_temp
            update_fields.append("dashboard_temperature")
        if update_fields:
            olt.dashboard_snapshot_refreshed_at = timezone.now()
            update_fields.append("dashboard_snapshot_refreshed_at")
            olt.save(update_fields=update_fields)


def _collect_dashboard_olt_uptimes(selected_olt_id=None):
    rows = []
    try:
        query = _ready_olts().only(
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
        for olt in _ready_olts().only("id", "name").order_by("name"):
            rows.append({
                "id": olt.id,
                "name": olt.name,
                "uptime": "--",
                "uptime_ok": False,
                "temperature": "--",
                "temperature_alert": False,
                "selected": bool(selected_olt_id and olt.id == selected_olt_id),
            })
    rows.sort(key=lambda row: row["name"].lower())
    return rows


def _collect_dashboard_snmp_down_olts():
    rows = []
    down_tokens = (
        "timeout",
        "no response",
        "timed out",
        "snmp timeout",
        "snmp fetch failed",
        "snmp data unavailable",
        "unavailable",
        "failed",
        "unreachable",
        "icmp is fine",
        "olt is down",
        "network is unreachable",
        "host unreachable",
    )
    try:
        query = _ready_olts().only("id", "name", "snmp_last_status", "snmp_last_synced_at").order_by("name")
        for olt in query:
            status = str(getattr(olt, "snmp_last_status", "") or "").strip()
            if not _is_recent_olt_snmp_unreachable(status, getattr(olt, "snmp_last_synced_at", None), max_age_seconds=90):
                continue
            rows.append({
                "id": olt.id,
                "name": olt.name,
                "status": status or "SNMP no response on UDP 161",
            })
    except OperationalError:
        return []
    return rows


def _build_dashboard_olt_health_rows(selected_olt_id=None):
    uptime_rows = _collect_dashboard_olt_uptimes(selected_olt_id)
    down_rows = _collect_dashboard_snmp_down_olts()
    down_map = {int(row["id"]): row for row in down_rows if row.get("id")}
    merged = []
    for row in uptime_rows:
        item = dict(row)
        down_item = down_map.get(int(row["id"]))
        temperature_text = str(item.get("temperature") or "--").strip() or "--"
        temperature_c = _parse_temperature_celsius(temperature_text)
        is_hot = bool(temperature_c is not None and temperature_c >= 50)
        is_down = bool(down_item)
        if is_down:
            item["health"] = "red"
            item["subtitle"] = _recent_olt_alert_label(
                down_item.get("status"),
                timezone.now(),
                max_age_seconds=999999,
            ) or "SNMP Down"
        elif is_hot:
            item["health"] = "orange"
            item["subtitle"] = f"Temperature {temperature_text}"
        else:
            item["health"] = "green"
            item["subtitle"] = f"Temperature {temperature_text}"
        merged.append(item)
    merged.sort(key=lambda row: str(row.get("name") or "").lower())
    return {
        "rows": merged,
        "counts": {
            "green": sum(1 for row in merged if row.get("health") == "green"),
            "orange": sum(1 for row in merged if row.get("health") == "orange"),
            "red": sum(1 for row in merged if row.get("health") == "red"),
        },
        "down_rows": down_rows,
    }


def _is_olt_snmp_unreachable(status):
    text = str(status or "").strip().lower()
    if not text:
        return False
    down_tokens = (
        "timeout",
        "timed out",
        "no response",
        "snmp fetch failed",
        "snmp data unavailable",
        "unavailable",
        "failed",
        "unreachable",
        "icmp is fine",
        "olt is down",
        "network is unreachable",
        "host unreachable",
    )
    return any(token in text for token in down_tokens)


def _is_recent_olt_snmp_unreachable(status, synced_at, max_age_seconds=90):
    if not _is_olt_snmp_unreachable(status):
        return False
    if not synced_at:
        return False
    try:
        age_seconds = (timezone.now() - synced_at).total_seconds()
    except Exception:
        return False
    return age_seconds <= max_age_seconds


def _recent_olt_alert_label(status, synced_at, max_age_seconds=90):
    if not _is_recent_olt_snmp_unreachable(status, synced_at, max_age_seconds=max_age_seconds):
        return ""
    lowered = str(status or "").strip().lower()
    if "olt unreachable" in lowered or "olt is down" in lowered:
        return "OLT Unreachable"
    return "SNMP Down"


def _dashboard_snmp_down_olt_ids():
    return {int(row["id"]) for row in _collect_dashboard_snmp_down_olts() if row.get("id")}


def _parse_signal_number(value):
    match = re.search(r"-?\d+(?:\.\d+)?", str(value or ""))
    if not match:
        return None
    try:
        return float(match.group(0))
    except (TypeError, ValueError):
        return None


def _collect_dashboard_pon_signal_alerts(selected_olt=None, limit=10):
    olts = [selected_olt] if selected_olt else list(_ready_olts().only("id", "name", "pon_ports_cache").order_by("name"))
    red_rows = []
    orange_rows = []
    for olt in olts:
        if not olt:
            continue
        for group in list(getattr(olt, "pon_ports_cache", []) or []):
            slot = str(group.get("slot") or "0").strip() or "0"
            for port in list(group.get("ports") or []):
                avg_signal = str(port.get("average_signal") or "").strip()
                bucket = str(port.get("average_signal_bucket") or "").strip().lower()
                numeric = _parse_signal_number(avg_signal)
                if numeric is None or bucket not in {"bad", "warn"}:
                    continue
                port_number = str(port.get("port") or "0")
                row = {
                    "olt_id": int(olt.pk),
                    "olt_name": olt.name,
                    "slot": slot,
                    "port": port_number,
                    "average_signal": avg_signal,
                    "bucket": bucket,
                    "url": f"{reverse('configured_onus')}?olt={olt.pk}&board={slot}&port={port_number}",
                    "_sort": numeric,
                }
                if bucket == "bad":
                    red_rows.append(row)
                else:
                    orange_rows.append(row)
    red_rows.sort(key=lambda item: item["_sort"])
    orange_rows.sort(key=lambda item: item["_sort"])
    rows = (red_rows + orange_rows)[: max(1, int(limit or 10))]
    for row in rows:
        row.pop("_sort", None)
    return rows


def _collect_dashboard_alert_widgets(selected_olt=None, limit=60):
    """Build the dashboard's live alert widgets from active AlertEvents:
    signal-degradation and possible-fiber-cut lists (scrollable).

    Active AlertEvent rows remain the primary source. If the alert worker has
    not populated that table yet, fall back to current cached ONU state so the
    dashboard does not show empty widgets while signal/status data exists.
    """
    from .models import AlertConfig, AlertEvent, ConfiguredONU

    cache_key = (int(getattr(selected_olt, "pk", 0) or 0), int(limit or 60))
    now = timezone.now()
    with _DASHBOARD_ALERT_WIDGET_CACHE_LOCK:
        cached = _DASHBOARD_ALERT_WIDGET_CACHE.get(cache_key)
        if cached:
            cached_at = cached.get("cached_at")
            if cached_at and (now - cached_at).total_seconds() < DASHBOARD_ALERT_WIDGET_CACHE_SECONDS:
                return cached.get("data") or {"degrade": [], "fiber": []}

    qs = AlertEvent.objects.filter(
        is_active=True, alert_type__in=["signal_degrade", "fiber_cut"]
    ).select_related("olt")
    if selected_olt:
        qs = qs.filter(olt=selected_olt)

    degrade, fiber = [], []
    for a in qs.order_by("-created_at")[: max(1, int(limit or 60)) * 2]:
        d = a.details or {}
        olt_name = a.olt.name if a.olt_id else "—"
        slot = d.get("slot")
        port = d.get("port")
        if a.alert_type == "signal_degrade":
            ont = d.get("ont_id")
            recent = d.get("recent_dbm")
            drop = d.get("drop_db")
            url = ""
            if a.olt_id and slot is not None and port is not None and ont is not None:
                url = reverse("configured_onu_detail", args=[a.olt_id, slot, port, ont])
            degrade.append({
                "olt_name": olt_name,
                "loc": f"0/{slot}/{port}:{ont}",
                "value": (f"{float(recent):.1f} dBm" if isinstance(recent, (int, float)) else "--"),
                "drop": (f"-{float(drop):.1f} dB" if isinstance(drop, (int, float)) else ""),
                "url": url,
            })
        else:  # fiber_cut
            recent_down = d.get("recent_down")
            if recent_down is None:
                recent_down = d.get("down")
            total = d.get("total")
            pct = d.get("pct")
            url = ""
            if a.olt_id and slot is not None and port is not None:
                url = f"{reverse('configured_onus')}?olt={a.olt_id}&board={slot}&port={port}"
            fiber.append({
                "olt_name": olt_name,
                "loc": f"0/{slot}/{port}",
                "value": (f"{recent_down}/{total} down" if total else f"{recent_down} down"),
                "pct": (f"{pct}%" if pct is not None else ""),
                "url": url,
            })

    if len(degrade) < limit:
        existing_keys = {
            (item.get("olt_name"), item.get("loc"))
            for item in degrade
        }
        fallback_qs = (
            ConfiguredONU.objects
            .select_related("olt")
            .filter(signal_bucket__in=["bad", "warn"])
            .exclude(olt_rx="")
            .exclude(olt_rx="--")
            .only("olt_id", "olt__name", "slot", "port", "ont_id", "olt_rx", "signal_bucket")
        )
        if selected_olt:
            fallback_qs = fallback_qs.filter(olt=selected_olt)
        rows = []
        for onu in fallback_qs[: max(1, int(limit or 60)) * 8]:
            olt_name = onu.olt.name if onu.olt_id else "-"
            loc = f"0/{onu.slot}/{onu.port}:{onu.ont_id}"
            if (olt_name, loc) in existing_keys:
                continue
            dbm = _parse_dbm_value(onu.olt_rx)
            rows.append({
                "olt_name": olt_name,
                "loc": loc,
                "value": str(onu.olt_rx or "--"),
                "drop": "critical" if str(onu.signal_bucket or "").lower() == "bad" else "warning",
                "olt_id": onu.olt_id,
                "slot": onu.slot,
                "port": onu.port,
                "ont_id": onu.ont_id,
                "_sort": dbm if dbm is not None else 99.0,
            })
        rows.sort(key=lambda item: item["_sort"])
        for row in rows[: max(0, int(limit or 60) - len(degrade))]:
            row.pop("_sort", None)
            olt_id = row.pop("olt_id", None)
            slot = row.pop("slot", None)
            port = row.pop("port", None)
            ont_id = row.pop("ont_id", None)
            row["url"] = (
                reverse("configured_onu_detail", args=[olt_id, slot, port, ont_id])
                if olt_id is not None and slot is not None and port is not None and ont_id is not None
                else ""
            )
            degrade.append(row)

    if len(fiber) < limit:
        cfg = AlertConfig.get()
        min_onus = max(2, int(getattr(cfg, "fiber_cut_min_onus", 4) or 4))
        ratio_pct = min(100, max(1, int(getattr(cfg, "fiber_cut_ratio", 60) or 60)))
        recent_cutoff = timezone.now() - timezone.timedelta(minutes=30)
        fiber_qs = (
            ConfiguredONU.objects
            .exclude(derived_status="admin_disabled")
        )
        if selected_olt:
            fiber_qs = fiber_qs.filter(olt=selected_olt)
        groups = (
            fiber_qs
            .values("olt_id", "olt__name", "slot", "port")
            .annotate(
                total=Count("id"),
                down=Count("id", filter=Q(derived_status__in=["offline", "loss_of_signal", "power_failure"])),
                recent_down=Count(
                    "id",
                    filter=(
                        Q(derived_status__in=["offline", "loss_of_signal", "power_failure"])
                        & ~Q(status_source="snmp_down")
                        & Q(status_first_seen_at__gte=recent_cutoff)
                    ),
                ),
            )
        )
        rows = []
        existing_fiber_keys = {(item.get("olt_name"), item.get("loc")) for item in fiber}
        for group in groups:
            olt_id = group.get("olt_id")
            olt_name = group.get("olt__name") or "-"
            slot = group.get("slot")
            port = group.get("port")
            total = int(group.get("total") or 0)
            recent_down = int(group.get("recent_down") or 0)
            if total < min_onus:
                continue
            pct = (recent_down * 100 // total) if total else 0
            loc = f"0/{slot}/{port}"
            if recent_down >= min_onus and pct >= ratio_pct and (olt_name, loc) not in existing_fiber_keys:
                rows.append({
                    "olt_name": olt_name,
                    "loc": loc,
                    "value": f"{recent_down}/{total} down",
                    "pct": f"{pct}%",
                    "url": f"{reverse('configured_onus')}?olt={olt_id}&board={slot}&port={port}" if olt_id else "",
                    "_sort": (-recent_down, -pct, olt_name, str(slot), str(port)),
                })
        rows.sort(key=lambda item: item["_sort"])
        for row in rows[: max(0, int(limit or 60) - len(fiber))]:
            row.pop("_sort", None)
            fiber.append(row)

    data = {"degrade": degrade[:limit], "fiber": fiber[:limit]}
    with _DASHBOARD_ALERT_WIDGET_CACHE_LOCK:
        _DASHBOARD_ALERT_WIDGET_CACHE[cache_key] = {
            "cached_at": now,
            "data": data,
        }
    return data


def _dashboard_summary_from_latest_sample(olt_id=None):
    sample = ensure_dashboard_status_samples_for_scope(olt_id=olt_id)
    if not sample:
        return None
    return {
        'total_onus': int(getattr(sample, 'total_onus', 0) or 0),
        'online_onus': int(getattr(sample, 'online_onus', 0) or 0),
        'wait_for_authorize_total': int(getattr(sample, 'wait_for_authorize_total', 0) or 0),
        'wait_for_authorize_new_total': int(getattr(sample, 'wait_for_authorize_new_total', 0) or 0),
        'wait_for_authorize_resync_total': int(getattr(sample, 'wait_for_authorize_resync_total', 0) or 0),
        'admin_disabled': int(getattr(sample, 'admin_disabled', 0) or 0),
        'power_failure': int(getattr(sample, 'power_failure', 0) or 0),
        'loss_of_signal': int(getattr(sample, 'loss_of_signal', 0) or 0),
        'signal_warn': int(getattr(sample, 'signal_warn', 0) or 0),
        'signal_bad': int(getattr(sample, 'signal_bad', 0) or 0),
    }


def _dashboard_summary_counts(onu_qs, olt_id=None):
    # Cards should reflect the current database state. The background worker is
    # responsible for updating ConfiguredONU every 10 minutes; graph history still
    # comes from DashboardStatusSample.
    return _dashboard_status_counts_from_queryset(onu_qs)


def _apply_dashboard_down_olt_override(counts, down_olt_ids, selected_olt_id=None):
    """Show ONUs under currently down OLTs as zero online without touching samples."""
    payload = dict(counts or {})
    down_ids = {int(value) for value in (down_olt_ids or []) if value is not None}
    if not down_ids:
        return payload
    if selected_olt_id is not None:
        try:
            selected_olt_id = int(selected_olt_id)
        except (TypeError, ValueError):
            selected_olt_id = None
        if selected_olt_id not in down_ids:
            return payload
        payload["online_onus"] = 0
        payload["signal_warn"] = 0
        payload["signal_bad"] = 0
        return payload

    subtract_online = 0
    subtract_warn = 0
    subtract_bad = 0
    for olt_id in down_ids:
        scoped = _dashboard_status_counts_from_queryset(
            ConfiguredONU.objects.filter(olt_id=olt_id)
        )
        subtract_online += int(scoped.get("online_onus") or 0)
        subtract_warn += int(scoped.get("signal_warn") or 0)
        subtract_bad += int(scoped.get("signal_bad") or 0)
    payload["online_onus"] = max(0, int(payload.get("online_onus") or 0) - subtract_online)
    payload["signal_warn"] = max(0, int(payload.get("signal_warn") or 0) - subtract_warn)
    payload["signal_bad"] = max(0, int(payload.get("signal_bad") or 0) - subtract_bad)
    return payload


def _dashboard_graph_config(range_key="24h"):
    range_key = str(range_key or "24h").lower()
    now = timezone.now()
    if range_key == "live":
        return {
            "key": "live",
            "label": "Live",
            "since": now - timezone.timedelta(minutes=10),
            "bucket_minutes": 1,
            "label_format": "%H:%M",
        }
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


def _get_dashboard_status_graph_cached(olt_id=None, range_key="24h"):
    """Cache graph payloads until the next dashboard sample is written."""
    normalized_range = _dashboard_graph_config(range_key)["key"]
    marker_qs = DashboardStatusSample.objects.all()
    if olt_id:
        marker_qs = marker_qs.filter(olt_id=olt_id)
    else:
        marker_qs = marker_qs.filter(olt__isnull=True)
    marker = marker_qs.order_by("-sampled_at").values_list("id", flat=True).first() or 0
    cache_key = f"dashboard-status-graph:v2:{olt_id or 'all'}:{normalized_range}:{marker}"
    payload = cache.get(cache_key)
    if payload is None:
        payload = _build_dashboard_status_graph(olt_id, normalized_range)
        cache.set(cache_key, payload, 300)
    return payload


def _build_dashboard_pon_traffic_graph(olt_id=None, range_key="24h"):
    config = _dashboard_graph_config(range_key)
    qs = PONTrafficSample.objects.filter(sampled_at__gte=config["since"])
    if olt_id:
        qs = qs.filter(olt_id=olt_id)
    else:
        qs = qs.filter(olt__isnull=True)

    rows = list(
        qs.order_by("sampled_at").values(
            "sampled_at",
            "in_octets",
            "out_octets",
            "in_packets",
            "out_packets",
        )
    )
    if len(rows) < 2:
        return {
            "range_key": config["key"],
            "range_label": config["label"],
            "points": [],
            "latest": {
                "upload_mbps": 0,
                "download_mbps": 0,
                "upload_pps": 0,
                "download_pps": 0,
                "upload_avg_size": 0,
                "download_avg_size": 0,
                "upload_max_mbps": 0,
                "download_max_mbps": 0,
            },
        }

    grouped = {}
    previous = None
    for row in rows:
        sampled_at = row.get("sampled_at")
        if not sampled_at:
            previous = row
            continue
        if previous is None:
            previous = row
            continue
        elapsed = (sampled_at - previous["sampled_at"]).total_seconds() if previous.get("sampled_at") else 0
        if elapsed <= 0:
            previous = row
            continue

        delta_in_octets = int(row.get("in_octets") or 0) - int(previous.get("in_octets") or 0)
        delta_out_octets = int(row.get("out_octets") or 0) - int(previous.get("out_octets") or 0)
        delta_in_packets = int(row.get("in_packets") or 0) - int(previous.get("in_packets") or 0)
        delta_out_packets = int(row.get("out_packets") or 0) - int(previous.get("out_packets") or 0)
        previous = row

        if min(delta_in_octets, delta_out_octets, delta_in_packets, delta_out_packets) < 0:
            continue

        local_dt = timezone.localtime(sampled_at, ZoneInfo("Asia/Karachi"))
        bucket = _bucket_dashboard_datetime(local_dt, config)
        bucket_key = bucket.isoformat()
        bucket_row = grouped.setdefault(
            bucket_key,
            {
                "bucket": bucket,
                "count": 0,
                "upload_mbps": 0.0,
                "download_mbps": 0.0,
                "upload_pps": 0.0,
                "download_pps": 0.0,
                "upload_avg_size": 0.0,
                "download_avg_size": 0.0,
            },
        )
        upload_mbps = ((delta_out_octets * 8) / elapsed) / 1_000_000
        download_mbps = ((delta_in_octets * 8) / elapsed) / 1_000_000
        upload_pps = (delta_out_packets / elapsed) if delta_out_packets > 0 else 0.0
        download_pps = (delta_in_packets / elapsed) if delta_in_packets > 0 else 0.0
        upload_avg_size = (delta_out_octets / delta_out_packets) if delta_out_packets > 0 else 0.0
        download_avg_size = (delta_in_octets / delta_in_packets) if delta_in_packets > 0 else 0.0

        bucket_row["count"] += 1
        bucket_row["upload_mbps"] += upload_mbps
        bucket_row["download_mbps"] += download_mbps
        bucket_row["upload_pps"] += upload_pps
        bucket_row["download_pps"] += download_pps
        bucket_row["upload_avg_size"] += upload_avg_size
        bucket_row["download_avg_size"] += download_avg_size

    points = []
    for bucket_key in sorted(grouped.keys()):
        row = grouped[bucket_key]
        count = max(1, int(row["count"]))
        points.append({
            "x": row["bucket"].isoformat(),
            "label": row["bucket"].strftime(config["label_format"]),
            "upload_mbps": round(row["upload_mbps"] / count, 2),
            "download_mbps": round(row["download_mbps"] / count, 2),
            "upload_pps": int(round(row["upload_pps"] / count)),
            "download_pps": int(round(row["download_pps"] / count)),
            "upload_avg_size": int(round(row["upload_avg_size"] / count)),
            "download_avg_size": int(round(row["download_avg_size"] / count)),
        })

    if points:
        normalized_points = []
        point_map = {point["x"]: point for point in points}
        start_bucket = _bucket_dashboard_datetime(timezone.localtime(config["since"], ZoneInfo("Asia/Karachi")), config)
        end_bucket = _bucket_dashboard_datetime(timezone.localtime(timezone.now(), ZoneInfo("Asia/Karachi")), config)
        cursor = start_bucket
        while cursor <= end_bucket:
            key = cursor.isoformat()
            point = point_map.get(key)
            if point is None:
                point = {
                    "x": key,
                    "label": cursor.strftime(config["label_format"]),
                    "upload_mbps": 0,
                    "download_mbps": 0,
                    "upload_pps": 0,
                    "download_pps": 0,
                    "upload_avg_size": 0,
                    "download_avg_size": 0,
                }
            normalized_points.append(point)
            cursor = _advance_dashboard_bucket(cursor, config)
        points = normalized_points

    raw_points = list(points)
    upload_max = max((float(point["upload_mbps"]) for point in raw_points), default=0.0)
    download_max = max((float(point["download_mbps"]) for point in raw_points), default=0.0)
    latest = raw_points[-1] if raw_points else {
        "upload_mbps": 0,
        "download_mbps": 0,
        "upload_pps": 0,
        "download_pps": 0,
        "upload_avg_size": 0,
        "download_avg_size": 0,
    }
    latest = {
        **latest,
        "upload_max_mbps": round(upload_max, 2),
        "download_max_mbps": round(download_max, 2),
    }
    return {
        "range_key": config["key"],
        "range_label": config["label"],
        "points": points,
        "latest": latest,
    }


def _build_olt_pon_port_traffic_graph(olt_id, range_key="24h", slot=None, port=None):
    config = _dashboard_graph_config(range_key)
    qs = PONPortTrafficSample.objects.filter(olt_id=olt_id, sampled_at__gte=config["since"])
    if slot is not None:
        qs = qs.filter(slot=slot)
    if port is not None:
        qs = qs.filter(port=port)

    rows = list(
        qs.order_by("sampled_at").values(
            "sampled_at",
            "in_octets",
            "out_octets",
            "in_packets",
            "out_packets",
        )
    )
    if len(rows) < 2:
        fallback_qs = PONPortTrafficSample.objects.filter(olt_id=olt_id)
        if slot is not None:
            fallback_qs = fallback_qs.filter(slot=slot)
        if port is not None:
            fallback_qs = fallback_qs.filter(port=port)
        rows = list(
            fallback_qs.order_by("-sampled_at").values(
                "sampled_at",
                "in_octets",
                "out_octets",
                "in_packets",
                "out_packets",
            )[:4]
        )
        rows.reverse()
    if len(rows) < 2:
        return {
            "range_key": config["key"],
            "range_label": config["label"],
            "points": [],
            "latest": {
                "upload_mbps": 0,
                "download_mbps": 0,
                "upload_pps": 0,
                "download_pps": 0,
                "upload_avg_size": 0,
                "download_avg_size": 0,
                "upload_max_mbps": 0,
                "download_max_mbps": 0,
            },
        }

    def _counter_delta(current_value, previous_value):
        current_int = int(current_value or 0)
        previous_int = int(previous_value or 0)
        delta = current_int - previous_int
        if delta >= 0:
            return delta
        max_32 = 4294967295
        if 0 <= previous_int <= max_32 and 0 <= current_int <= max_32:
            return (max_32 - previous_int) + current_int + 1
        return None

    grouped = {}
    previous = None
    for row in rows:
        sampled_at = row.get("sampled_at")
        if not sampled_at:
            previous = row
            continue
        if previous is None:
            previous = row
            continue
        elapsed = (sampled_at - previous["sampled_at"]).total_seconds() if previous.get("sampled_at") else 0
        if elapsed <= 0:
            previous = row
            continue
        delta_in_octets = _counter_delta(row.get("in_octets"), previous.get("in_octets"))
        delta_out_octets = _counter_delta(row.get("out_octets"), previous.get("out_octets"))
        delta_in_packets = _counter_delta(row.get("in_packets"), previous.get("in_packets"))
        delta_out_packets = _counter_delta(row.get("out_packets"), previous.get("out_packets"))
        previous = row
        if None in {delta_in_octets, delta_out_octets, delta_in_packets, delta_out_packets}:
            continue
        local_dt = timezone.localtime(sampled_at, ZoneInfo("Asia/Karachi"))
        bucket = _bucket_dashboard_datetime(local_dt, config)
        bucket_key = bucket.isoformat()
        bucket_row = grouped.setdefault(
            bucket_key,
            {
                "bucket": bucket,
                "count": 0,
                "upload_mbps": 0.0,
                "download_mbps": 0.0,
                "upload_pps": 0.0,
                "download_pps": 0.0,
                "upload_avg_size": 0.0,
                "download_avg_size": 0.0,
            },
        )
        upload_mbps = ((delta_out_octets * 8) / elapsed) / 1_000_000
        download_mbps = ((delta_in_octets * 8) / elapsed) / 1_000_000
        upload_pps = (delta_out_packets / elapsed) if delta_out_packets > 0 else 0.0
        download_pps = (delta_in_packets / elapsed) if delta_in_packets > 0 else 0.0
        upload_avg_size = (delta_out_octets / delta_out_packets) if delta_out_packets > 0 else 0.0
        download_avg_size = (delta_in_octets / delta_in_packets) if delta_in_packets > 0 else 0.0
        bucket_row["count"] += 1
        bucket_row["upload_mbps"] += upload_mbps
        bucket_row["download_mbps"] += download_mbps
        bucket_row["upload_pps"] += upload_pps
        bucket_row["download_pps"] += download_pps
        bucket_row["upload_avg_size"] += upload_avg_size
        bucket_row["download_avg_size"] += download_avg_size

    points = []
    for bucket_key in sorted(grouped.keys()):
        row = grouped[bucket_key]
        count = max(1, int(row["count"]))
        points.append({
            "x": row["bucket"].isoformat(),
            "label": row["bucket"].strftime(config["label_format"]),
            "upload_mbps": round(row["upload_mbps"] / count, 2),
            "download_mbps": round(row["download_mbps"] / count, 2),
            "upload_pps": int(round(row["upload_pps"] / count)),
            "download_pps": int(round(row["download_pps"] / count)),
            "upload_avg_size": int(round(row["upload_avg_size"] / count)),
            "download_avg_size": int(round(row["download_avg_size"] / count)),
        })

    if points:
        normalized_points = []
        point_map = {point["x"]: point for point in points}
        start_bucket = _bucket_dashboard_datetime(timezone.localtime(config["since"], ZoneInfo("Asia/Karachi")), config)
        end_bucket = _bucket_dashboard_datetime(timezone.localtime(timezone.now(), ZoneInfo("Asia/Karachi")), config)
        cursor = start_bucket
        while cursor <= end_bucket:
            key = cursor.isoformat()
            point = point_map.get(key)
            if point is None:
                point = {
                    "x": key,
                    "label": cursor.strftime(config["label_format"]),
                    "upload_mbps": 0,
                    "download_mbps": 0,
                    "upload_pps": 0,
                    "download_pps": 0,
                    "upload_avg_size": 0,
                    "download_avg_size": 0,
                }
            normalized_points.append(point)
            cursor = _advance_dashboard_bucket(cursor, config)
        points = normalized_points

    upload_max = max((float(point["upload_mbps"]) for point in points), default=0.0)
    download_max = max((float(point["download_mbps"]) for point in points), default=0.0)
    latest = points[-1] if points else {
        "upload_mbps": 0,
        "download_mbps": 0,
        "upload_pps": 0,
        "download_pps": 0,
        "upload_avg_size": 0,
        "download_avg_size": 0,
    }
    latest = {
        **latest,
        "upload_max_mbps": round(upload_max, 2),
        "download_max_mbps": round(download_max, 2),
    }
    return {
        "range_key": config["key"],
        "range_label": config["label"],
        "mode": "single",
        "points": points,
        "latest": latest,
    }


def _flatten_pon_port_choices(groups, only_up=False, include_all=False):
    choices = []
    seen = set()
    if include_all:
        choices.append({
            "value": "",
            "label": "All Up Ports",
            "slot": None,
            "port": None,
        })
    for grp in groups or []:
        slot = int(grp.get("slot") or 0)
        for row in grp.get("ports") or []:
            if only_up:
                status_text = str(row.get("status") or row.get("oper_status") or "").strip().lower()
                if "up" not in status_text:
                    continue
            port = int(row.get("port") or 0)
            key = (slot, port)
            if key in seen:
                continue
            seen.add(key)
            tech = _pon_tech_from_board_type(row.get("type") or grp.get("board_type"))
            choices.append({
                "value": f"{slot}:{port}",
                "label": f"{tech} 0/{slot}/{port}",
                "slot": slot,
                "port": port,
            })
    return choices


def _build_latest_pon_port_traffic_map(olt_id):
    rows = list(
        PONPortTrafficSample.objects.filter(olt_id=olt_id)
        .order_by("slot", "port", "-sampled_at")
        .values("slot", "port", "sampled_at", "in_octets", "out_octets", "in_packets", "out_packets")
    )
    if not rows:
        return {}

    def _counter_delta(current_value, previous_value):
        current_int = int(current_value or 0)
        previous_int = int(previous_value or 0)
        delta = current_int - previous_int
        if delta >= 0:
            return delta
        max_32 = 4294967295
        if 0 <= previous_int <= max_32 and 0 <= current_int <= max_32:
            return (max_32 - previous_int) + current_int + 1
        return None

    latest_map = {}
    grouped = {}
    for row in rows:
        key = (int(row.get("slot") or 0), int(row.get("port") or 0))
        grouped.setdefault(key, []).append(row)
    for key, port_rows in grouped.items():
        if len(port_rows) < 2:
            continue
        current = port_rows[0]
        previous = port_rows[1]
        current_at = current.get("sampled_at")
        previous_at = previous.get("sampled_at")
        if not current_at or not previous_at:
            continue
        elapsed = (current_at - previous_at).total_seconds()
        if elapsed <= 0:
            continue
        delta_in_octets = _counter_delta(current.get("in_octets"), previous.get("in_octets"))
        delta_out_octets = _counter_delta(current.get("out_octets"), previous.get("out_octets"))
        if delta_in_octets is None or delta_out_octets is None:
            continue
        latest_map[key] = {
            "download_mbps": round(((delta_in_octets * 8) / elapsed) / 1_000_000, 2),
            "upload_mbps": round(((delta_out_octets * 8) / elapsed) / 1_000_000, 2),
            "sampled_at": timezone.localtime(current_at, ZoneInfo("Asia/Karachi")).strftime("%Y-%m-%d %I:%M:%S %p"),
        }
    return latest_map


def _build_latest_uplink_traffic_map(olt_id):
    rows = list(
        UplinkPortTrafficSample.objects.filter(olt_id=olt_id)
        .order_by("port_name", "-sampled_at")
        .values("port_name", "sampled_at", "in_octets", "out_octets")
    )
    if not rows:
        return {}

    def _counter_delta(current_value, previous_value):
        current_int = int(current_value or 0)
        previous_int = int(previous_value or 0)
        delta = current_int - previous_int
        if delta >= 0:
            return delta
        max_32 = 4294967295
        if 0 <= previous_int <= max_32 and 0 <= current_int <= max_32:
            return (max_32 - previous_int) + current_int + 1
        return None

    latest_map = {}
    grouped = {}
    for row in rows:
        key = str(row.get("port_name") or "").strip()
        if not key:
            continue
        grouped.setdefault(key, []).append(row)
    for key, port_rows in grouped.items():
        if len(port_rows) < 2:
            continue
        current = port_rows[0]
        previous = port_rows[1]
        current_at = current.get("sampled_at")
        previous_at = previous.get("sampled_at")
        if not current_at or not previous_at:
            continue
        elapsed = (current_at - previous_at).total_seconds()
        if elapsed <= 0:
            continue
        delta_in_octets = _counter_delta(current.get("in_octets"), previous.get("in_octets"))
        delta_out_octets = _counter_delta(current.get("out_octets"), previous.get("out_octets"))
        if delta_in_octets is None or delta_out_octets is None:
            continue
        latest_map[key] = {
            "download_mbps": round(((delta_in_octets * 8) / elapsed) / 1_000_000, 2),
            "upload_mbps": round(((delta_out_octets * 8) / elapsed) / 1_000_000, 2),
            "sampled_at": timezone.localtime(current_at, ZoneInfo("Asia/Karachi")).strftime("%Y-%m-%d %I:%M:%S %p"),
        }
    return latest_map


def _get_cached_port_traffic_payload(cache_key, builder, ttl=None):
    now_ts = time.time()
    effective_ttl = PORT_TRAFFIC_GRAPH_CACHE_TTL if ttl is None else ttl
    with _PORT_TRAFFIC_GRAPH_CACHE_LOCK:
        cached = _PORT_TRAFFIC_GRAPH_CACHE.get(cache_key)
        if cached and (now_ts - cached["ts"]) <= effective_ttl:
            return cached["payload"]
    payload = builder()
    with _PORT_TRAFFIC_GRAPH_CACHE_LOCK:
        _PORT_TRAFFIC_GRAPH_CACHE[cache_key] = {"ts": now_ts, "payload": payload}
    return payload


def _schedule_live_port_traffic_refresh(olt_id, traffic_kind):
    key = (str(traffic_kind or "").strip().lower(), int(olt_id))
    with _LIVE_PORT_TRAFFIC_REFRESH_LOCK:
        if key in _LIVE_PORT_TRAFFIC_REFRESHING:
            return
        _LIVE_PORT_TRAFFIC_REFRESHING.add(key)

    def _worker():
        try:
            olt = OLT.objects.filter(pk=olt_id).only(
                "id",
                "ip_address",
                "snmp_port",
                "snmp_community",
            ).first()
            if not olt:
                return
            if traffic_kind == "pon":
                record_pon_port_traffic_sample_for_olt(olt, force=False, min_interval_seconds=15)
            elif traffic_kind == "uplink":
                record_uplink_port_traffic_sample_for_olt(olt, force=False, min_interval_seconds=15)
        finally:
            with _LIVE_PORT_TRAFFIC_REFRESH_LOCK:
                _LIVE_PORT_TRAFFIC_REFRESHING.discard(key)

    threading.Thread(target=_worker, daemon=True).start()


def _flatten_uplink_port_choices(rows):
    choices = []
    seen = set()
    include_all = False
    only_up = False
    if isinstance(rows, dict):
        include_all = bool(rows.get("include_all"))
        only_up = bool(rows.get("only_up"))
        rows = rows.get("rows") or []
    if include_all:
        choices.append({
            "value": "",
            "label": "All Up Ports",
        })
    for row in rows or []:
        port_name = str(row.get("port") or "").strip()
        if not port_name or port_name in seen:
            continue
        if only_up:
            status_text = str(row.get("status") or row.get("oper_status") or "").strip().lower()
            if "up" not in status_text:
                continue
        seen.add(port_name)
        choices.append({
            "value": port_name,
            "label": port_name,
        })
    return choices


def _build_olt_uplink_traffic_graph(olt_id, range_key="24h", port_name=""):
    config = _dashboard_graph_config(range_key)
    qs = UplinkPortTrafficSample.objects.filter(olt_id=olt_id, sampled_at__gte=config["since"])
    if port_name:
        qs = qs.filter(port_name=port_name)

    rows = list(qs.order_by("sampled_at").values("sampled_at", "in_octets", "out_octets"))
    if len(rows) < 2:
        fallback_qs = UplinkPortTrafficSample.objects.filter(olt_id=olt_id)
        if port_name:
            fallback_qs = fallback_qs.filter(port_name=port_name)
        rows = list(fallback_qs.order_by("-sampled_at").values("sampled_at", "in_octets", "out_octets")[:4])
        rows.reverse()
    if len(rows) < 2:
        return {
            "range_key": config["key"],
            "range_label": config["label"],
            "points": [],
            "latest": {
                "upload_mbps": 0,
                "download_mbps": 0,
                "upload_max_mbps": 0,
                "download_max_mbps": 0,
            },
        }

    def _counter_delta(current_value, previous_value):
        current_int = int(current_value or 0)
        previous_int = int(previous_value or 0)
        delta = current_int - previous_int
        if delta >= 0:
            return delta
        max_32 = 4294967295
        if 0 <= previous_int <= max_32 and 0 <= current_int <= max_32:
            return (max_32 - previous_int) + current_int + 1
        return None

    grouped = {}
    previous = None
    for row in rows:
        sampled_at = row.get("sampled_at")
        if not sampled_at:
            previous = row
            continue
        if previous is None:
            previous = row
            continue
        elapsed = (sampled_at - previous["sampled_at"]).total_seconds() if previous.get("sampled_at") else 0
        if elapsed <= 0:
            previous = row
            continue
        delta_in_octets = _counter_delta(row.get("in_octets"), previous.get("in_octets"))
        delta_out_octets = _counter_delta(row.get("out_octets"), previous.get("out_octets"))
        previous = row
        if delta_in_octets is None or delta_out_octets is None:
            continue
        local_dt = timezone.localtime(sampled_at, ZoneInfo("Asia/Karachi"))
        bucket = _bucket_dashboard_datetime(local_dt, config)
        bucket_key = bucket.isoformat()
        bucket_row = grouped.setdefault(bucket_key, {
            "bucket": bucket,
            "count": 0,
            "upload_mbps": 0.0,
            "download_mbps": 0.0,
        })
        bucket_row["count"] += 1
        bucket_row["upload_mbps"] += ((delta_out_octets * 8) / elapsed) / 1_000_000
        bucket_row["download_mbps"] += ((delta_in_octets * 8) / elapsed) / 1_000_000

    points = []
    for bucket_key in sorted(grouped.keys()):
        row = grouped[bucket_key]
        count = max(1, int(row["count"]))
        points.append({
            "x": row["bucket"].isoformat(),
            "label": row["bucket"].strftime(config["label_format"]),
            "upload_mbps": round(row["upload_mbps"] / count, 2),
            "download_mbps": round(row["download_mbps"] / count, 2),
        })

    if points:
        normalized_points = []
        point_map = {point["x"]: point for point in points}
        start_bucket = _bucket_dashboard_datetime(timezone.localtime(config["since"], ZoneInfo("Asia/Karachi")), config)
        end_bucket = _bucket_dashboard_datetime(timezone.localtime(timezone.now(), ZoneInfo("Asia/Karachi")), config)
        cursor = start_bucket
        while cursor <= end_bucket:
            key = cursor.isoformat()
            point = point_map.get(key)
            if point is None:
                point = {
                    "x": key,
                    "label": cursor.strftime(config["label_format"]),
                    "upload_mbps": 0,
                    "download_mbps": 0,
                }
            normalized_points.append(point)
            cursor = _advance_dashboard_bucket(cursor, config)
        points = normalized_points

    raw_points = list(points)
    upload_max = max((float(point["upload_mbps"]) for point in raw_points), default=0.0)
    download_max = max((float(point["download_mbps"]) for point in raw_points), default=0.0)
    latest = raw_points[-1] if raw_points else {"upload_mbps": 0, "download_mbps": 0}
    latest = {
        **latest,
        "upload_max_mbps": round(upload_max, 2),
        "download_max_mbps": round(download_max, 2),
    }
    return {
        "range_key": config["key"],
        "range_label": config["label"],
        "mode": "single",
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


def _debounced_onu_snmp_status(record, raw_status):
    raw_status = str(raw_status or "").strip().lower()
    offline_statuses = {"offline", "admin_disabled", "power_failure", "loss_of_signal"}
    if record is None or raw_status not in {"online", *offline_statuses}:
        return "", "", False

    current_status = _normalize_configured_status(record.derived_status, run_state=record.run_state)
    if raw_status == "offline" and current_status in {"admin_disabled", "power_failure", "loss_of_signal"}:
        return current_status, record.status_source or "snmp_refresh", True
    if current_status == "admin_disabled":
        return current_status, record.status_source or "inventory", False
    return raw_status, "snmp_refresh", True


def _refresh_single_onu_power_from_snmp(olt, record, slot, port, ont_id):
    if record is None or _is_olt_snmp_unreachable(getattr(olt, "snmp_last_status", "")):
        return {}
    signal = fetch_single_onu_snmp_signal(olt, int(slot), int(port), int(ont_id))
    payload = _signal_payload_from_values(signal.get("onu_rx"), signal.get("olt_rx"))
    if not payload.get("signal_visible"):
        return signal
    now = timezone.now()
    record.onu_rx = payload["onu_rx"] if payload["onu_rx"] != "--" else ""
    record.olt_rx = payload["olt_rx"] if payload["olt_rx"] != "--" else ""
    record.tx_power = (signal.get("tx_power") or "") if ((signal.get("tx_power") or "") != "--") else record.tx_power
    record.run_state = "online"
    record.derived_status = "online"
    record.status_source = "snmp_refresh"
    record.signal_bucket = payload.get("signal_class") or ""
    if not record.status_first_seen_at:
        record.status_first_seen_at = now
    record.status_updated_at = now
    record.save(update_fields=[
        "onu_rx",
        "olt_rx",
        "tx_power",
        "run_state",
        "derived_status",
        "status_source",
        "signal_bucket",
        "status_first_seen_at",
        "status_updated_at",
    ])
    if should_record_onu_optical_sample(olt, slot, port, ont_id, now=now):
        try:
            ONUOpticalSample.objects.create(
                olt=olt,
                slot=int(slot),
                port=int(port),
                ont_id=int(ont_id),
                onu_rx=record.onu_rx,
                olt_rx=record.olt_rx,
                tx_power=record.tx_power if record.tx_power != "--" else "",
                sample_source=ONUOpticalSample.SOURCE_SINGLE_RETRY,
            )
        except Exception:
            pass
    return signal


def _hide_offline_onu_power(row):
    status = _normalize_configured_status(row.get("derived_status"), run_state=row.get("run_state"))
    if status != "online":
        row["onu_rx"] = "--"
        row["olt_rx"] = "--"
        row["tx_power"] = "--"
        row["signal_bucket"] = ""
    return row


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
        "loss_of_signal": "LOS",
    }
    return labels.get(normalized, "Offline")


def _configured_status_class(value, run_state=""):
    normalized = _normalize_configured_status(value, run_state=run_state)
    if normalized == "online":
        return "good"
    if normalized in {"admin_disabled", "loss_of_signal"}:
        return "warn"
    return "bad"


def _ui_telnet_error_message(message):
    text = str(message or "").strip()
    lowered = text.lower()
    reload_tokens = (
        "cannot schedule new futures after interpreter shutdown",
        "interpreter shutdown",
    )
    if any(token in lowered for token in reload_tokens):
        return "Server is reloading. Please try again in a few seconds."
    busy_tokens = (
        "resource busy",
        "device busy",
        "configuration console exit",
        "please retry to log on",
        "session limit",
        "too many users",
        "connection reset",
        "connection closed",
        "forcibly closed",
        "10053",
        "10054",
    )
    if any(token in lowered for token in busy_tokens):
        return "OLT is busy. Please try again in a few seconds."
    return text


def _format_status_age_text(dt):
    text = _format_relative_time_text(dt)
    return f"({text})" if text else ""


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
        value = max(1, total_seconds)
        return f"{value} sec ago"

    units = (
        ("year", 365 * 86400),
        ("month", 30 * 86400),
        ("day", 86400),
        ("hour", 3600),
        ("minute", 60),
    )
    for label, seconds in units:
        if total_seconds >= seconds:
            value = total_seconds // seconds
            suffix = "s" if value != 1 else ""
            return f"{value} {label}{suffix} ago"
    return "1 sec ago"


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
    cache_key = (int(olt.pk), int(slot), int(port), int(ont_id), int(hours))
    now = timezone.now()
    with _ONU_SIGNAL_HISTORY_CACHE_LOCK:
        cached = _ONU_SIGNAL_HISTORY_CACHE.get(cache_key)
        if cached and (now - cached["updated_at"]).total_seconds() <= ONU_SIGNAL_HISTORY_CACHE_SECONDS:
            return cached["history"]
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
        .values("sampled_at", "onu_rx", "olt_rx", "tx_power", "sample_source")
    )
    history = []
    for row in rows:
        history.append(
            {
                "sampled_at": timezone.localtime(row["sampled_at"]).isoformat(),
                "onu_rx": row.get("onu_rx") or "--",
                "olt_rx": row.get("olt_rx") or "--",
                "tx_power": row.get("tx_power") or "--",
                "sample_source": row.get("sample_source") or "fresh",
            }
        )
    if not history:
        current = (
            ConfiguredONU.objects.filter(olt=olt, slot=slot, port=port, ont_id=ont_id)
            .values("onu_rx", "olt_rx", "tx_power", "status_updated_at", "synced_at")
            .first()
        )
        if current:
            has_signal = any(str(current.get(key) or "").strip() not in {"", "--"} for key in ("onu_rx", "olt_rx"))
            if has_signal:
                sampled_at = timezone.now()
                history.append(
                    {
                        "sampled_at": timezone.localtime(sampled_at).isoformat(),
                        "onu_rx": current.get("onu_rx") or "--",
                        "olt_rx": current.get("olt_rx") or "--",
                        "tx_power": current.get("tx_power") or "--",
                        "sample_source": "carried",
                    }
                )
    with _ONU_SIGNAL_HISTORY_CACHE_LOCK:
        _ONU_SIGNAL_HISTORY_CACHE[cache_key] = {
            "updated_at": now,
            "history": history,
        }
    return history


def _onu_traffic_cap_bps(olt, slot, port, ont_id, direction):
    profile_field = "upload_profile_index_cache" if direction == "up" else "download_profile_index_cache"
    record = (
        ConfiguredONU.objects.filter(olt=olt, slot=slot, port=port, ont_id=ont_id)
        .values(profile_field)
        .first()
    )
    index_text = str((record or {}).get(profile_field) or "")
    match = re.search(r"\d+", index_text)
    if match:
        speed = (
            SpeedProfile.objects.filter(index_number=int(match.group(0)), is_active=True)
            .values_list("speed_mbps_value", flat=True)
            .first()
        )
        try:
            speed_mbps = float(speed or 0)
        except (TypeError, ValueError):
            speed_mbps = 0.0
        if speed_mbps > 0:
            return speed_mbps * 1_000_000 * 1.25
    return 1_250_000_000.0


def _sanitize_onu_traffic_bps(value, cap_bps):
    try:
        bps = float(value or 0)
    except (TypeError, ValueError):
        return 0.0
    if bps < 0 or bps > cap_bps:
        return 0.0
    return bps


def _record_onu_traffic_sample(olt, slot, port, ont_id):
    counters = fetch_single_onu_snmp_traffic_counters(olt, slot, port, ont_id)
    if not counters.get("ok"):
        return {"ok": False, "status": counters.get("status") or "SNMP ONU traffic unavailable"}

    now = timezone.now()
    previous = (
        ONUTrafficSample.objects.filter(olt=olt, slot=slot, port=port, ont_id=ont_id)
        .order_by("-sampled_at")
        .first()
    )
    up_bytes = int(counters.get("up_bytes") or 0)
    down_bytes = int(counters.get("down_bytes") or 0)
    up_packets = int(counters.get("up_packets") or 0)
    down_packets = int(counters.get("down_packets") or 0)
    up_bps = 0.0
    down_bps = 0.0
    if previous:
        seconds = max(1.0, (now - previous.sampled_at).total_seconds())
        if up_bytes >= previous.up_bytes:
            up_bps = ((up_bytes - previous.up_bytes) * 8) / seconds
        if down_bytes >= previous.down_bytes:
            down_bps = ((down_bytes - previous.down_bytes) * 8) / seconds
    up_bps = _sanitize_onu_traffic_bps(up_bps, _onu_traffic_cap_bps(olt, slot, port, ont_id, "up"))
    down_bps = _sanitize_onu_traffic_bps(down_bps, _onu_traffic_cap_bps(olt, slot, port, ont_id, "down"))

    sample = ONUTrafficSample.objects.create(
        olt=olt,
        slot=slot,
        port=port,
        ont_id=ont_id,
        up_bytes=up_bytes,
        down_bytes=down_bytes,
        up_packets=up_packets,
        down_packets=down_packets,
        up_bps=up_bps,
        down_bps=down_bps,
    )
    return {
        "ok": True,
        "sampled_at": timezone.localtime(sample.sampled_at, ZoneInfo("Asia/Karachi")).isoformat(),
        "up_bps": round(up_bps, 2),
        "down_bps": round(down_bps, 2),
        "up_bytes": up_bytes,
        "down_bytes": down_bytes,
        "status": counters.get("status") or "SNMP ONU traffic fetched",
    }


def _schedule_onu_traffic_samples(olt_id, onu_keys, min_interval_seconds=ONU_TRAFFIC_SAMPLE_SECONDS):
    normalized_keys = []
    seen = set()
    for key in onu_keys or []:
        try:
            normalized = (int(key[0]), int(key[1]), int(key[2]))
        except (TypeError, ValueError, IndexError):
            continue
        if normalized in seen:
            continue
        seen.add(normalized)
        normalized_keys.append(normalized)
    if not normalized_keys:
        return

    refresh_key = int(olt_id)
    with _ONU_TRAFFIC_REFRESH_LOCK:
        if refresh_key in _ONU_TRAFFIC_REFRESHING:
            return
        _ONU_TRAFFIC_REFRESHING.add(refresh_key)

    def _worker():
        try:
            close_old_connections()
            olt = OLT.objects.filter(pk=refresh_key).only(
                "id",
                "ip_address",
                "snmp_port",
                "snmp_community",
            ).first()
            if not olt:
                return
            now = timezone.now()
            latest_rows = (
                ONUTrafficSample.objects.filter(olt_id=refresh_key)
                .values("slot", "port", "ont_id")
                .annotate(latest=Max("sampled_at"))
            )
            latest_map = {
                (int(row["slot"]), int(row["port"]), int(row["ont_id"])): row["latest"]
                for row in latest_rows
            }
            for slot, port, ont_id in normalized_keys:
                latest = latest_map.get((slot, port, ont_id))
                if latest and (now - latest).total_seconds() < min_interval_seconds:
                    continue
                try:
                    _record_onu_traffic_sample(olt, slot, port, ont_id)
                except Exception:
                    continue
        finally:
            close_old_connections()
            with _ONU_TRAFFIC_REFRESH_LOCK:
                _ONU_TRAFFIC_REFRESHING.discard(refresh_key)

    threading.Thread(target=_worker, daemon=True).start()


def _get_onu_traffic_history(olt, slot, port, ont_id, hours=1):
    since = timezone.now() - timezone.timedelta(hours=hours)
    up_cap_bps = _onu_traffic_cap_bps(olt, slot, port, ont_id, "up")
    down_cap_bps = _onu_traffic_cap_bps(olt, slot, port, ont_id, "down")
    rows = (
        ONUTrafficSample.objects.filter(
            olt=olt,
            slot=slot,
            port=port,
            ont_id=ont_id,
            sampled_at__gte=since,
        )
        .order_by("sampled_at")
        .values("sampled_at", "up_bps", "down_bps", "up_bytes", "down_bytes")
    )
    history = []
    for row in rows:
        local_dt = timezone.localtime(row["sampled_at"], ZoneInfo("Asia/Karachi"))
        history.append(
            {
                "sampled_at": local_dt.isoformat(),
                "label": local_dt.strftime("%H:%M"),
                "up_bps": round(_sanitize_onu_traffic_bps(row.get("up_bps"), up_cap_bps), 2),
                "down_bps": round(_sanitize_onu_traffic_bps(row.get("down_bps"), down_cap_bps), 2),
                "up_bytes": int(row.get("up_bytes") or 0),
                "down_bytes": int(row.get("down_bytes") or 0),
            }
        )
    return history


def _onu_traffic_graph_hours(range_key):
    key = str(range_key or "1h").strip().lower()
    return {
        "1h": 1,
        "1d": 24,
        "1w": 24 * 7,
        "1m": 24 * 30,
        "1y": 24 * 365,
    }.get(key, 1)


def _onu_type_has_catv_port(onu_type_value):
    def _norm(value):
        return re.sub(r"[^A-Z0-9]+", "", str(value or "").replace("_SOLT", "").upper())

    catalog = _load_onu_type_catv_lookup()
    key = _norm(onu_type_value)
    item = catalog.get(key)
    if not item and key:
        item = next((row for row_key, row in catalog.items() if row_key and (row_key in key or key in row_key)), None)
    if not item:
        return False
    catv_value = str(item.get("catv") or "").strip()
    if catv_value.isdigit():
        return int(catv_value) > 0
    return catv_value not in {"", "0", "-"}


def _onu_has_catv_port(record):
    onu_type_value = getattr(record, "onu_type_cache", "") if record is not None else ""
    return _onu_type_has_catv_port(onu_type_value)


def _get_catv_supported_onu_type_values():
    cache_key = "configured_onu_catv_supported_type_values:v1"
    values = cache.get(cache_key)
    if values is not None:
        return values
    distinct_types = ConfiguredONU.objects.exclude(onu_type_cache="").values_list("onu_type_cache", flat=True).distinct()
    values = [value for value in distinct_types if _onu_type_has_catv_port(value)]
    cache.set(cache_key, values, 300)
    return values


def _catv_onu_type_query():
    query = Q(pk__in=[])
    for item in _load_onu_type_option_rows():
        catv_value = str(item.get("catv") or "").strip()
        has_catv = int(catv_value) > 0 if catv_value.isdigit() else catv_value not in {"", "0", "-"}
        if not has_catv:
            continue
        for value in (item.get("value"), item.get("label"), f"{item.get('value')}_SOLT"):
            text = str(value or "").strip()
            if text:
                query |= Q(onu_type_cache__iexact=text) | Q(onu_type_cache__icontains=text)
    return query


def _onu_signal_graph_config(range_key):
    key = str(range_key or "1h").strip().lower()
    configs = {
        "1h": {"key": "1h", "label": "Hour", "hours": 1, "bucket_seconds": 300, "tick_format": "%H:%M"},
        "1d": {"key": "1d", "label": "Day", "hours": 24, "bucket_seconds": 3600, "tick_format": "%H:%M"},
        "1w": {"key": "1w", "label": "Week", "hours": 24 * 7, "bucket_seconds": 86400, "tick_format": "%d %b"},
        "1m": {"key": "1m", "label": "Month", "hours": 24 * 30, "bucket_seconds": 86400, "tick_format": "%d %b"},
        "1y": {"key": "1y", "label": "Year", "hours": 24 * 365, "bucket_seconds": 86400 * 30, "tick_format": "%b %Y"},
    }
    return configs.get(key, configs["1h"])


def _build_onu_signal_graph_data(olt, slot, port, ont_id, range_key="1h"):
    config = _onu_signal_graph_config(range_key)
    since = timezone.now() - timezone.timedelta(hours=config["hours"])
    rows = list(
        ONUOpticalSample.objects.filter(
            olt=olt,
            slot=slot,
            port=port,
            ont_id=ont_id,
            sampled_at__gte=since,
        )
        .order_by("sampled_at")
        .values("sampled_at", "onu_rx", "olt_rx", "tx_power", "sample_source")
    )
    if not rows:
        latest_sample = (
            ONUOpticalSample.objects.filter(
                olt=olt,
                slot=slot,
                port=port,
                ont_id=ont_id,
            )
            .order_by("-sampled_at")
            .values("sampled_at", "onu_rx", "olt_rx", "tx_power", "sample_source")
            .first()
        )
        if latest_sample:
            rows = [{
                "sampled_at": latest_sample.get("sampled_at"),
                "onu_rx": latest_sample.get("onu_rx") or "",
                "olt_rx": latest_sample.get("olt_rx") or "",
                "tx_power": latest_sample.get("tx_power") or "",
                "sample_source": "stale",
            }]
    if not rows:
        current = (
            ConfiguredONU.objects.filter(olt=olt, slot=slot, port=port, ont_id=ont_id)
            .values("onu_rx", "olt_rx", "tx_power", "status_updated_at", "synced_at")
            .first()
        )
        if current:
            has_signal = any(str(current.get(key) or "").strip() not in {"", "--"} for key in ("onu_rx", "olt_rx"))
            if has_signal:
                sampled_at = timezone.now()
                rows = [{
                    "sampled_at": sampled_at,
                    "onu_rx": current.get("onu_rx") or "",
                    "olt_rx": current.get("olt_rx") or "",
                    "tx_power": current.get("tx_power") or "",
                    "sample_source": "carried",
                }]
    points = []
    latest_onu = None
    latest_olt = None
    peak_onu = None
    peak_olt = None
    for row in rows:
        sampled_at = row.get("sampled_at")
        if not sampled_at:
            continue
        local_dt = timezone.localtime(sampled_at, ZoneInfo("Asia/Karachi"))
        onu_value = _parse_dbm_value(row.get("onu_rx"))
        olt_value = _parse_dbm_value(row.get("olt_rx"))
        point_onu = round(float(onu_value), 2) if onu_value is not None else None
        point_olt = round(float(olt_value), 2) if olt_value is not None else None
        if point_onu is not None:
            latest_onu = point_onu
            peak_onu = point_onu if peak_onu is None else max(peak_onu, point_onu)
        if point_olt is not None:
            latest_olt = point_olt
            peak_olt = point_olt if peak_olt is None else max(peak_olt, point_olt)
        points.append(
            {
                "label": local_dt.strftime(config["tick_format"]),
                "sampled_at": local_dt.isoformat(),
                "onu_rx": point_onu,
                "olt_rx": point_olt,
                "sample_source": row.get("sample_source") or "fresh",
            }
        )

    return {
        "range_key": config["key"],
        "range_label": config["label"],
        "points": points,
        "latest": {
            "onu_rx": latest_onu,
            "olt_rx": latest_olt,
            "onu_peak": peak_onu,
            "olt_peak": peak_olt,
        },
    }


def _avg(values):
    clean = [float(value) for value in values if value is not None]
    return (sum(clean) / len(clean)) if clean else None


def _signal_score(avg_olt_rx):
    if avg_olt_rx is None:
        return 55
    if avg_olt_rx >= -27:
        return 100
    if avg_olt_rx >= -29:
        return 82
    if avg_olt_rx >= -31:
        return 62
    if avg_olt_rx >= -33:
        return 38
    return 18


def _empty_onu_stability_summary(report_date=None):
    return {
        "stability": 0,
        "down_risk": 0,
        "state": "warn",
        "label": "No report",
        "samples": 0,
        "flaps": 0,
        "onu_avg": "-",
        "pon_avg": "-",
        "report_date": report_date.isoformat() if report_date else "",
    }


def _calculate_onu_stability_summary(olt, slot, port, ont_id, report_date):
    start_at = timezone.make_aware(
        timezone.datetime.combine(report_date, timezone.datetime.min.time()),
        timezone.get_current_timezone(),
    )
    end_at = start_at + timezone.timedelta(days=1)
    status_rows = list(
        ONUStatusSample.objects.filter(
            olt=olt,
            slot=slot,
            port=port,
            ont_id=ont_id,
            sampled_at__gte=start_at,
            sampled_at__lt=end_at,
        )
        .order_by("sampled_at")
        .values_list("status", flat=True)
    )
    total_status = len(status_rows)
    online_count = sum(1 for item in status_rows if str(item or "").strip().lower() == "online")
    online_ratio = (online_count / total_status) if total_status else None
    transitions = 0
    previous = None
    for item in status_rows:
        current = str(item or "").strip().lower()
        if not current:
            continue
        if previous and current != previous:
            transitions += 1
        previous = current

    onu_values = [
        _parse_dbm_value(row["olt_rx"])
        for row in ONUOpticalSample.objects.filter(
            olt=olt,
            slot=slot,
            port=port,
            ont_id=ont_id,
            sampled_at__gte=start_at,
            sampled_at__lt=end_at,
        ).values("olt_rx")
    ]
    pon_values = [
        _parse_dbm_value(row["olt_rx"])
        for row in ONUOpticalSample.objects.filter(
            olt=olt,
            slot=slot,
            port=port,
            sampled_at__gte=start_at,
            sampled_at__lt=end_at,
        ).values("olt_rx")
    ]
    if not status_rows and not onu_values:
        return _empty_onu_stability_summary(report_date)
    onu_avg = _avg(onu_values)
    pon_avg = _avg(pon_values)
    signal_score = _signal_score(onu_avg)
    pon_penalty = 0
    if onu_avg is not None and pon_avg is not None and onu_avg < (pon_avg - 3):
        pon_penalty = min(22, int(abs(onu_avg - pon_avg) * 4))
    flap_score = max(0, 100 - (transitions * 8))
    online_score = int((online_ratio if online_ratio is not None else 0.75) * 100)
    stability = round(max(0, min(100, (online_score * 0.55) + (signal_score * 0.35) + (flap_score * 0.10) - pon_penalty)))
    down_risk = round(max(0, min(100, 100 - stability + (10 if signal_score < 40 else 0))))
    state = "good" if stability >= 80 else "warn" if stability >= 55 else "bad"
    label = "Stable" if state == "good" else "Unstable" if state == "warn" else "Critical"
    return {
        "stability": stability,
        "down_risk": down_risk,
        "state": state,
        "label": label,
        "samples": total_status,
        "flaps": transitions,
        "onu_avg": f"{onu_avg:.2f} dBm" if onu_avg is not None else "-",
        "pon_avg": f"{pon_avg:.2f} dBm" if pon_avg is not None else "-",
        "report_date": report_date.isoformat(),
    }


def _build_onu_stability_summary(olt, slot, port, ont_id, record=None):
    report_date = timezone.localdate()
    if record is None:
        record = ConfiguredONU.objects.filter(olt=olt, slot=slot, port=port, ont_id=ont_id).first()
    if record is None:
        return _empty_onu_stability_summary(report_date)
    cached_date = getattr(record, "stability_report_date", None)
    cached_payload = getattr(record, "stability_report_cache", None) or {}
    if cached_date == report_date and cached_payload:
        return cached_payload
    payload = _calculate_onu_stability_summary(olt, slot, port, ont_id, report_date)
    record.stability_report_date = report_date
    record.stability_report_cache = payload
    record.save(update_fields=["stability_report_date", "stability_report_cache"])
    return payload


def _get_cached_configured_onu_filter_options():
    now = timezone.now()
    with _CONFIGURED_ONU_FILTERS_CACHE_LOCK:
        updated_at = _CONFIGURED_ONU_FILTERS_CACHE.get("updated_at")
        if updated_at and (now - updated_at).total_seconds() <= CONFIGURED_ONU_FILTERS_CACHE_SECONDS:
            return (
                list(_CONFIGURED_ONU_FILTERS_CACHE.get("olts") or []),
                list(_CONFIGURED_ONU_FILTERS_CACHE.get("boards") or []),
                _CONFIGURED_ONU_FILTERS_CACHE.get("latest_sync"),
            )

    available_olts = [{"id": str(olt.pk), "name": olt.name} for olt in _ready_olts().only("id", "name").order_by("id")]
    available_boards = sorted(
        {str(slot) for slot in ConfiguredONU.objects.order_by().values_list("slot", flat=True).distinct()},
        key=lambda x: int(x),
    )
    latest_inventory_sync = ConfiguredONU.objects.aggregate(latest_sync=Max("synced_at")).get("latest_sync")
    with _CONFIGURED_ONU_FILTERS_CACHE_LOCK:
        _CONFIGURED_ONU_FILTERS_CACHE.update(
            {
                "updated_at": now,
                "olts": available_olts,
                "boards": available_boards,
                "latest_sync": latest_inventory_sync,
            }
        )
    return available_olts, available_boards, latest_inventory_sync


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
@never_cache
def olt_list(request):
    _schedule_missing_device_snapshots_if_due()
    olt_filter = (request.GET.get('olt') or '').strip()
    selected_olt = None
    onu_qs = ConfiguredONU.objects.all()
    if olt_filter:
        try:
            selected_olt = OLT.objects.only(
                "id",
                "name",
                "autofind_onu_count",
                "autofind_new_count",
                "autofind_resync_count",
                "pon_ports_cache",
                "pon_ports_status",
                "uplink_cache",
                "uplink_status",
            ).filter(pk=int(olt_filter)).first()
        except (TypeError, ValueError):
            selected_olt = None
        if selected_olt:
            onu_qs = onu_qs.filter(olt_id=selected_olt.pk)

    down_olt_ids = _dashboard_snmp_down_olt_ids()
    dashboard_counts = _dashboard_summary_counts(onu_qs, selected_olt.pk if selected_olt else None)
    dashboard_counts = _apply_dashboard_down_olt_override(
        dashboard_counts,
        down_olt_ids,
        selected_olt.pk if selected_olt else None,
    )
    total_all = int(dashboard_counts.get("total_onus") or 0)
    # Counts come from the 10-minute dashboard sample. Do not override them from
    # the 10-second OLT reachability state; that state is shown in the OLT widget.
    total_online = int(dashboard_counts.get("online_onus") or 0)
    total_offline = max(0, total_all - total_online)
    total_wait_for_authorize = 0
    total_wait_for_authorize_new = 0
    total_wait_for_authorize_resync = 0
    total_admin_disabled = int(dashboard_counts.get("admin_disabled") or 0)
    total_loss_of_signal = int(dashboard_counts.get("loss_of_signal") or 0)
    total_power_failure = int(dashboard_counts.get("power_failure") or 0)
    total_signal_warn = int(dashboard_counts.get("signal_warn") or 0)
    total_signal_bad = int(dashboard_counts.get("signal_bad") or 0)
    dashboard_pon_traffic_graph = None
    dashboard_pon_traffic_port_choices = []
    dashboard_pon_traffic_graph_url = ""
    dashboard_uplink_traffic_graph = None
    dashboard_uplink_traffic_port_choices = []
    dashboard_uplink_traffic_graph_url = ""
    dashboard_history_rows = []
    if selected_olt:
        dashboard_history_rows = list(
            OLTLoginHistory.objects.filter(olt_id=selected_olt.pk)
            .order_by('-logged_in_at')
            .values('logged_in_at', 'action', 'details')[:80]
        )
        dashboard_pon_groups = list(getattr(selected_olt, "pon_ports_cache", []) or [])
        dashboard_pon_traffic_port_choices = _flatten_pon_port_choices(dashboard_pon_groups, only_up=True, include_all=False)
        default_pon_choice = dashboard_pon_traffic_port_choices[0] if dashboard_pon_traffic_port_choices else None
        if default_pon_choice:
            dashboard_pon_traffic_graph_url = reverse("olt_pon_traffic_graph_data", kwargs={"pk": selected_olt.pk})

        dashboard_uplink_rows = list(getattr(selected_olt, "uplink_cache", []) or [])
        dashboard_uplink_traffic_port_choices = _flatten_uplink_port_choices({
            "rows": dashboard_uplink_rows,
            "only_up": True,
            "include_all": False,
        })
        default_uplink_choice = dashboard_uplink_traffic_port_choices[0]["value"] if dashboard_uplink_traffic_port_choices else ""
        if dashboard_uplink_traffic_port_choices:
            dashboard_uplink_traffic_graph_url = reverse("olt_uplink_traffic_graph_data", kwargs={"pk": selected_olt.pk})

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

    _dashboard_alert_widgets = _collect_dashboard_alert_widgets(selected_olt)

    _olt_health = _build_dashboard_olt_health_rows(selected_olt.pk if selected_olt else None)
    _olt_counts = _olt_health.get("counts", {})
    # Online OLT = reachable (green/orange health); offline = SNMP-down (red).
    _online_olts = int(_olt_counts.get("green", 0)) + int(_olt_counts.get("orange", 0))
    _total_olts = _online_olts + int(_olt_counts.get("red", 0))

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
        'dashboard_olt_health': _olt_health,
        'dashboard_total_olts': _total_olts,
        'dashboard_online_olts': _online_olts,
        'dashboard_offline_olts': _total_olts - _online_olts,
        'dashboard_signal_degrade_alerts': _dashboard_alert_widgets["degrade"],
        'dashboard_fiber_cut_alerts': _dashboard_alert_widgets["fiber"],
        'dashboard_selected_olt': selected_olt,
        'dashboard_scope_title': f"{selected_olt.name} snapshot" if selected_olt else "Live subscriber snapshot",
        'dashboard_scope_kicker': selected_olt.name if selected_olt else "ONU Overview",
        'dashboard_warning_url': f"{configured_signal_base}?{urlencode(warning_params)}",
        'dashboard_critical_url': f"{configured_signal_base}?{urlencode(critical_params)}",
        'dashboard_admin_disabled_url': f"{configured_signal_base}?{urlencode(admin_disabled_params)}",
        'dashboard_loss_of_signal_url': f"{configured_signal_base}?{urlencode(loss_of_signal_params)}",
        'dashboard_power_failure_url': f"{configured_signal_base}?{urlencode(power_failure_params)}",
        'dashboard_graph': _get_dashboard_status_graph_cached(selected_olt.pk if selected_olt else None, '1h'),
        'dashboard_pon_traffic_graph': dashboard_pon_traffic_graph,
        'dashboard_pon_traffic_port_choices': dashboard_pon_traffic_port_choices,
        'dashboard_pon_traffic_graph_url': dashboard_pon_traffic_graph_url,
        'dashboard_uplink_traffic_graph': dashboard_uplink_traffic_graph,
        'dashboard_uplink_traffic_port_choices': dashboard_uplink_traffic_port_choices,
        'dashboard_uplink_traffic_graph_url': dashboard_uplink_traffic_graph_url,
        'dashboard_history_rows': dashboard_history_rows,
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
        payload = _get_dashboard_status_graph_cached(olt_id, range_key)
    except OperationalError:
        payload = {
            "range_key": range_key,
            "range_label": "Unavailable",
            "points": [],
            "latest": {"online": 0, "offline": 0, "admin_disabled": 0, "power_failure": 0, "loss_of_signal": 0},
        }
    return JsonResponse({"ok": True, **payload})


@login_required
def dashboard_pon_traffic_graph(request):
    range_key = (request.GET.get("range") or "24h").strip().lower()
    olt_filter = (request.GET.get("olt") or "").strip()
    olt_id = int(olt_filter) if olt_filter.isdigit() else None
    try:
        if olt_id:
            olt = OLT.objects.only("id", "ip_address", "snmp_port", "snmp_community").filter(pk=olt_id).first()
            if olt:
                record_pon_traffic_sample_for_olt(olt)
        payload = _build_dashboard_pon_traffic_graph(olt_id, range_key)
    except OperationalError:
        payload = {
            "range_key": range_key,
            "range_label": "Unavailable",
            "points": [],
            "latest": {
                "upload_mbps": 0,
                "download_mbps": 0,
                "upload_pps": 0,
                "download_pps": 0,
                "upload_avg_size": 0,
                "download_avg_size": 0,
                "upload_max_mbps": 0,
                "download_max_mbps": 0,
            },
        }
    return JsonResponse({"ok": True, **payload})


@login_required
@never_cache
def dashboard_olt_uptimes(request):
    graph_range = (request.GET.get("graph_range") or "1h").strip().lower()
    _schedule_dashboard_snapshot_refreshes()
    _refresh_missing_dashboard_snapshots_inline(limit=1)
    selected_olt_filter = (request.GET.get("olt") or "").strip()
    onu_qs = ConfiguredONU.objects.all()
    selected_olt_id = None
    if selected_olt_filter.isdigit():
        selected_olt_id = int(selected_olt_filter)
        onu_qs = onu_qs.filter(olt_id=selected_olt_id)
    health_bundle = _build_dashboard_olt_health_rows(selected_olt_id)
    down_rows = health_bundle.get("down_rows") or []
    down_olt_ids = {int(row["id"]) for row in down_rows if row.get("id")}
    rows = health_bundle.get("rows") or []
    dashboard_counts = _dashboard_summary_counts(onu_qs, selected_olt_id)
    dashboard_counts = _apply_dashboard_down_olt_override(dashboard_counts, down_olt_ids, selected_olt_id)
    total_all = int(dashboard_counts.get("total_onus") or 0)
    # Keep summary cards on the 10-minute sample cadence, except that OLT-down
    # health from the 10-second monitor must immediately zero that OLT's online ONUs.
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
    total_wait_for_authorize = 0
    total_wait_for_authorize_new = 0
    total_wait_for_authorize_resync = 0
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
        "counts": health_bundle.get("counts") or {"green": 0, "orange": 0, "red": 0},
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
        "status_graph": _get_dashboard_status_graph_cached(selected_olt_id, graph_range),
        "pon_signal_alerts": _collect_dashboard_pon_signal_alerts(OLT.objects.filter(pk=selected_olt_id).first() if selected_olt_id else None),
        "updating": updating,
    })


@login_required
def configured_onus(request):
    search_query = (request.GET.get('q') or '').strip()
    olt_filter = (request.GET.get('olt') or '').strip()
    board_filter = (request.GET.get('board') or '').strip()
    port_filter = (request.GET.get('port') or '').strip()
    vlan_filter = (request.GET.get('vlan') or '').strip()
    status_filter = (request.GET.get('status') or '').strip().lower()
    signal_filter = (request.GET.get('signal') or '').strip().lower()
    tv_filter = (request.GET.get('tv') or '').strip().lower()
    onu_type_filter = (request.GET.get('onu_type') or '').strip()
    speed_profile_filter = (request.GET.get('speed_profile') or '').strip()
    sort_filter = (request.GET.get('sort') or '').strip().lower()
    if signal_filter == "warning":
        signal_filter = "warn"
    elif signal_filter == "critical":
        signal_filter = "bad"

    # OLTs that are currently unreachable — every ONU under them must be treated
    # as offline regardless of its last-cached status.
    try:
        down_olt_ids = _dashboard_snmp_down_olt_ids()
    except Exception:
        down_olt_ids = set()

    base_qs = ConfiguredONU.objects.all()
    if olt_filter:
        base_qs = base_qs.filter(olt_id=olt_filter)
    if board_filter:
        base_qs = base_qs.filter(slot=board_filter)
    if port_filter:
        base_qs = base_qs.filter(port=port_filter)
    _online_q = dashboard_online_status_q()
    if down_olt_ids:
        # An ONU only counts as online if its OLT is reachable.
        _online_q = _online_q & ~Q(olt_id__in=down_olt_ids)
    if status_filter == "online":
        base_qs = base_qs.filter(_online_q)
    elif status_filter == "offline":
        base_qs = base_qs.exclude(_online_q)
    elif status_filter in {"admin_disabled", "power_failure", "loss_of_signal"}:
        base_qs = base_qs.filter(derived_status=status_filter)
    if signal_filter:
        base_qs = base_qs.filter(signal_bucket=signal_filter)
    if vlan_filter:
        base_qs = base_qs.filter(attached_vlans_cache__regex=rf'(^|,\s*){re.escape(vlan_filter)}(\s*,|$)')
    if tv_filter in {"enabled", "disabled", "unsupported", "catv"}:
        catv_supported_types = _get_catv_supported_onu_type_values()
        if tv_filter == "enabled":
            base_qs = base_qs.filter(onu_type_cache__in=catv_supported_types).exclude(catv_operational_cache__iexact="disabled")
        elif tv_filter == "disabled":
            base_qs = base_qs.filter(onu_type_cache__in=catv_supported_types, catv_operational_cache__iexact="disabled")
        elif tv_filter == "unsupported":
            base_qs = base_qs.exclude(onu_type_cache__in=catv_supported_types)
        else:
            base_qs = base_qs.filter(onu_type_cache__in=catv_supported_types)
    if onu_type_filter:
        # Exact match so e.g. "EG8143A5" does not also pull in "EG8143A5-CATV".
        base_qs = base_qs.filter(onu_type_cache__iexact=onu_type_filter)
    if speed_profile_filter:
        # Show only ONUs that use this speed profile (matched by its cached name).
        sp_base = re.sub(r'(?i)[-_](UP|DOWN)$', '', speed_profile_filter.strip()).strip()
        base_qs = base_qs.filter(
            Q(download_profile_name_cache__icontains=f"{sp_base}-DOWN")
            | Q(download_profile_name_cache__icontains=f"{sp_base}-UP")
            | Q(upload_profile_name_cache__icontains=f"{sp_base}-DOWN")
            | Q(upload_profile_name_cache__icontains=f"{sp_base}-UP")
        )

    detail_fields = (
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
        "address",
        "contact",
        "onu_rx",
        "olt_rx",
        "tx_power",
        "signal_bucket",
        "attached_vlans_cache",
        "onu_type_cache",
        "derived_status",
        "status_source",
        "status_first_seen_at",
        "status_updated_at",
        "raw_line",
    )

    records_qs = base_qs.select_related("olt").only(
        "id",
        *detail_fields,
        "olt__id",
        "olt__name",
    ).order_by("olt_id", "slot", "port", "ont_id")
    if search_query:
        records_qs = records_qs.filter(_build_configured_onu_search_q(search_query))

    db_sort_map = {
        "name": ("description", "sn", "olt__name", "slot", "port", "ont_id"),
        "sn": ("sn", "olt__name", "slot", "port", "ont_id"),
        "onu": ("olt__name", "slot", "port", "ont_id"),
    }
    if sort_filter in db_sort_map:
        records_qs = records_qs.order_by(*db_sort_map[sort_filter])
    elif sort_filter == "vlan":
        records_qs = records_qs.annotate(
            sort_empty=Case(
                When(attached_vlans_cache="", then=Value(1)),
                default=Value(0),
                output_field=IntegerField(),
            )
        ).order_by("sort_empty", "attached_vlans_cache", "olt__name", "slot", "port", "ont_id")
    elif sort_filter == "onu_type":
        records_qs = records_qs.annotate(
            sort_empty=Case(
                When(onu_type_cache="", then=Value(1)),
                default=Value(0),
                output_field=IntegerField(),
            )
        ).order_by("sort_empty", "onu_type_cache", "olt__name", "slot", "port", "ont_id")
    elif sort_filter == "status":
        records_qs = records_qs.annotate(
            status_rank=Case(
                When(derived_status__iexact="online", then=Value(0)),
                When(run_state__iexact="online", then=Value(0)),
                When(derived_status__iexact="admin_disabled", then=Value(1)),
                When(derived_status__iexact="power_failure", then=Value(2)),
                When(derived_status__iexact="loss_of_signal", then=Value(3)),
                default=Value(4),
                output_field=IntegerField(),
            )
        ).order_by("status_rank", "olt__name", "slot", "port", "ont_id")
    elif sort_filter == "tv":
        records_qs = sorted(records_qs, key=lambda record: (0 if _onu_has_catv_port(record) else 1, record.olt.name, int(record.slot), int(record.port), int(record.ont_id)))
    elif sort_filter == "signal":
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

    preserved_sort_params = {
        key: value
        for key, value in {
            "status": status_filter,
            "signal": signal_filter,
            "tv": tv_filter,
            "q": search_query,
            "olt": olt_filter,
            "board": board_filter,
            "port": port_filter,
            "vlan": vlan_filter,
            "onu_type": onu_type_filter,
            "speed_profile": speed_profile_filter,
        }.items()
        if value
    }
    sort_urls = {
        key: f"{reverse('configured_onus')}?{urlencode({**preserved_sort_params, 'sort': key})}"
        for key in ("status", "name", "sn", "onu", "vlan", "onu_type", "tv", "signal")
    }

    paginator = Paginator(records_qs, 100)
    page_number = request.GET.get('page') or 1
    page_obj = paginator.get_page(page_number)

    page_records = list(page_obj.object_list) if not isinstance(page_obj.object_list, list) else page_obj.object_list
    filter_olts_for_map = list(_ready_olts().only("id", "pon_ports_cache", "olt_cards_cache").all())
    filter_olt_by_id = {int(olt.pk): olt for olt in filter_olts_for_map}

    rows = []
    for record in page_records:
        tech_source_olt = filter_olt_by_id.get(int(record.olt_id or 0)) or record.olt
        tech_label = _onu_tech_label(tech_source_olt, record.slot)
        row = _configured_onu_record_to_row(record, tech_label=tech_label)
        enriched = dict(row)
        enriched["olt_name"] = record.olt.name
        enriched["olt_id"] = record.olt_id
        enriched["sn"] = _format_onu_serial_display(row.get("sn"))
        enriched["display_name"] = _format_onu_display_name(
            (row.get("description") or "").strip(),
            enriched["sn"] or f"{record.olt.name}-{row.get('ont_id')}",
        )
        if record.olt_id in down_olt_ids:
            # OLT unreachable → force offline so the list never shows a stale "online".
            enriched["status_value"] = "offline"
            enriched["status_label"] = _configured_status_label("offline", run_state="offline")
            enriched["status_class"] = _configured_status_class("offline", run_state="offline")
        else:
            enriched["status_value"] = _normalize_configured_status(row.get("derived_status"), run_state=row.get("run_state"))
            enriched["status_label"] = _configured_status_label(row.get("derived_status"), run_state=row.get("run_state"))
            enriched["status_class"] = _configured_status_class(row.get("derived_status"), run_state=row.get("run_state"))
        _tech = tech_label
        enriched["onu_label"] = f"{record.olt.name} {_tech}-onu_{row.get('fsp')}:{row.get('ont_id')}"
        enriched["signal_class"] = (row.get("signal_bucket") or "").strip() or _classify_onu_signal(row.get("olt_rx"))
        enriched["has_catv"] = _onu_has_catv_port(record)
        enriched["catv_disabled"] = str(getattr(record, "catv_operational_cache", "") or "").strip().lower() == "disabled"
        rows.append(enriched)

    available_olts, available_boards, latest_inventory_sync = _get_cached_configured_onu_filter_options()
    latest_status_sync = DashboardStatusSample.objects.order_by("-sampled_at").values_list("sampled_at", flat=True).first()
    available_ports = [str(i) for i in range(16)]

    # Per-OLT board/port map so the Board and Port dropdowns can be rebuilt
    # client-side from the selected OLT's actual PON inventory only.
    # Board = slots that have PON cards (real_type is GPON/EPON/etc.).
    # Port  = actual PON port numbers from pon_ports_cache; if that is empty,
    #         fall back to range(card["ports"]) from olt_cards_cache.
    olt_board_port_map = {}
    for _flt_olt in filter_olts_for_map:
        # Build ports_by_slot from pon_ports_cache (authoritative when available).
        ports_by_slot = {}
        for group in (getattr(_flt_olt, "pon_ports_cache", []) or []):
            slot = str((group or {}).get("slot", "")).strip()
            if slot == "":
                continue
            ports = []
            for port_row in ((group or {}).get("ports") or []):
                pv = str((port_row or {}).get("port", "")).strip()
                if pv != "" and pv not in ports:
                    ports.append(pv)
            try:
                ports = sorted(ports, key=lambda x: int(x))
            except (TypeError, ValueError):
                pass
            if ports:
                ports_by_slot[slot] = ports

        # Only include slots whose card is a PON board.
        boards = []
        for card in (getattr(_flt_olt, "olt_cards_cache", []) or []):
            slot = str((card or {}).get("slot", "")).strip()
            if slot == "":
                continue
            real_type = str(
                (card or {}).get("real_type") or (card or {}).get("model_type") or (card or {}).get("type") or ""
            )
            from oltmanager.utils import _is_pon_board_model
            if not _is_pon_board_model(real_type):
                continue
            if slot not in boards:
                boards.append(slot)
            # Fallback: if pon_ports_cache had no entry for this slot, build from count.
            if slot not in ports_by_slot:
                try:
                    port_count = int((card or {}).get("ports") or 0)
                except (TypeError, ValueError):
                    port_count = 0
                if port_count > 0:
                    ports_by_slot[slot] = [str(p) for p in range(port_count)]

        try:
            boards = sorted(boards, key=lambda x: int(x))
        except (TypeError, ValueError):
            pass
        if boards:
            olt_board_port_map[str(_flt_olt.pk)] = {"boards": boards, "ports": ports_by_slot}
    start_index = page_obj.start_index() if paginator.count else 0
    end_index = page_obj.end_index() if paginator.count else 0
    latest_inventory_sync_display = ""
    sync_display_at = latest_status_sync or latest_inventory_sync
    if sync_display_at:
        sync_display_at = timezone.localtime(sync_display_at, ZoneInfo("Asia/Karachi"))
        latest_inventory_sync_display = sync_display_at.strftime("%Y-%m-%d %I:%M:%S %p")

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
        "configured_onu_tv_filter": tv_filter,
        "configured_onu_sort_filter": sort_filter,
        "configured_onu_search_query": search_query,
        "configured_onu_olt_filter": olt_filter,
        "configured_onu_board_filter": board_filter,
        "configured_onu_port_filter": port_filter,
        "configured_onu_vlan_filter": vlan_filter,
        "configured_onu_onu_type_filter": onu_type_filter,
        "configured_onu_speed_profile_filter": speed_profile_filter,
        "configured_onu_sort_urls": sort_urls,
        "configured_onu_filter_olts": available_olts,
        "configured_onu_filter_boards": available_boards,
        "configured_onu_filter_ports": available_ports,
        "configured_onu_board_port_map": olt_board_port_map,
        "configured_onu_last_sync_at": sync_display_at,
        "configured_onu_last_sync_display": latest_inventory_sync_display,
        "configured_onu_signal_refresh_url": reverse("configured_onu_signals_refresh"),
        "configured_onu_status_sync_progress_url": reverse("configured_onu_status_sync_progress"),
    }
    return render(request, "oltmanager/configured_onus.html", context)


@login_required
def unconfigured_onus(request):
    selected_olts = []
    seen_selected_olts = set()
    for value in request.GET.getlist("olts"):
        value = str(value)
        if not value.isdigit() or value in seen_selected_olts:
            continue
        selected_olts.append(value)
        seen_selected_olts.add(value)
        if len(selected_olts) >= 6:
            break
    search_query = (request.GET.get("q") or "").strip().lower()
    category_filter = str(request.GET.get("category") or "").strip().lower()
    if category_filter not in {"new", "resync"}:
        category_filter = ""

    all_olts = list(_ready_olts().only("id", "name", "ip_address").order_by("name"))

    grouped_rows = []
    group_targets = []
    statuses = []
    total_new = 0
    total_resync = 0
    if selected_olts:
        selected_details = {
            str(olt.id): olt
            for olt in _ready_olts().filter(id__in=[int(value) for value in selected_olts])
            .only(
                "id", "name", "ip_address", "vlan_cache",
                "autofind_onu_count", "autofind_new_count", "autofind_resync_count",
                "snmp_last_status", "snmp_last_synced_at", "snmp_down_since",
            )
        }
        selected_map = {str(olt.id): selected_details.get(str(olt.id)) or olt for olt in all_olts if str(olt.id) in set(selected_olts)}
        selected_ordered = []
        for olt_id in selected_olts:
            olt = selected_map.get(str(olt_id))
            if not olt:
                continue
            selected_ordered.append(olt)

        total_rows = sum(int(getattr(olt, "autofind_onu_count", 0) or 0) for olt in selected_ordered)
        total_new = sum(int(getattr(olt, "autofind_new_count", 0) or 0) for olt in selected_ordered)
        total_resync = sum(int(getattr(olt, "autofind_resync_count", 0) or 0) for olt in selected_ordered)

        selected_ordered.sort(
            key=lambda olt: (
                0 if int(getattr(olt, "autofind_onu_count", 0) or 0) > 0 else 1,
                str(getattr(olt, "name", "") or "").lower(),
            )
        )

        for index, olt in enumerate(selected_ordered, start=1):
            group_targets.append({
                "index": index,
                "olt_id": olt.id,
                "olt_name": olt.name,
            })
        if group_targets:
            statuses.append("Selected OLTs loading live autofind data progressively...")
    else:
        total_rows = sum(group["count"] for group in grouped_rows)
    authorize_debug = request.session.pop("authorize_debug_payload", None)
    context = {
        "unconfigured_groups": grouped_rows,
        "unconfigured_group_targets": group_targets,
        "unconfigured_selected_olts": selected_olts,
        "unconfigured_filter_olts": [{"id": str(olt.id), "name": olt.name, "ip": olt.ip_address} for olt in all_olts],
        "unconfigured_search_query": request.GET.get("q", "").strip(),
        "unconfigured_category_filter": category_filter,
        "unconfigured_status": " | ".join(statuses),
        "unconfigured_total": total_rows,
        "unconfigured_new_total": total_new,
        "unconfigured_resync_total": total_resync,
        "unconfigured_onu_type_options": [],
        "unconfigured_download_speed_options": [],
        "unconfigured_upload_speed_options": [],
        "unconfigured_return_query": request.GET.urlencode(),
        "authorize_debug": authorize_debug,
    }
    return render(request, "oltmanager/unconfigured_onus.html", context)


@login_required
def unconfigured_onus_group_data(request, olt_id):
    try:
        olt_id = int(olt_id)
    except (TypeError, ValueError):
        return JsonResponse({"ok": False, "error": "Invalid OLT id."}, status=400)
    search_query = (request.GET.get("q") or "").strip().lower()
    category_filter = str(request.GET.get("category") or "").strip().lower()
    if category_filter not in {"new", "resync"}:
        category_filter = ""
    index = int(request.GET.get("index") or 1)

    olt = OLT.objects.only(
        "id", "name", "ip_address", "vlan_cache",
        "snmp_last_status", "snmp_last_synced_at", "snmp_down_since",
    ).filter(pk=olt_id).first()
    if not olt:
        return JsonResponse({"ok": False, "error": "OLT not found."}, status=404)

    existing_by_serial = {}
    existing_onus = list(
        ConfiguredONU.objects.select_related("olt")
        .only("olt_id", "olt__name", "slot", "port", "ont_id", "sn")
        .exclude(sn="")
    )
    for record in existing_onus:
        for token in _normalize_onu_serial_token(record.sn):
            if token and token not in existing_by_serial:
                existing_by_serial[token] = record

    onu_type_options = _load_onu_type_option_rows()
    speed_profile_templates = list(SpeedProfile.objects.filter(is_active=True).order_by("speed_mbps_value", "name"))
    download_speed_options = []
    upload_speed_options = []
    for profile in speed_profile_templates:
        base_name = (profile.name or "").strip()
        base_name = re.sub(r"(?i)(?:-|_)?(up|down)$", "", base_name).strip(" -_") or (profile.name or "")
        speed_display = (profile.speed_display or "").strip() or (
            f"{profile.speed_mbps_value} Mbps" if profile.speed_mbps_value else "-"
        )
        download_speed_options.append(
            {
                "value": str(int(profile.index_number or 0)),
                "label": (profile.download_name or f"{base_name}-DOWN").strip(),
                "speed": speed_display,
            }
        )
        upload_speed_options.append(
            {
                "value": str(int((profile.index_number or 0) + 1)),
                "label": (profile.upload_name or f"{base_name}-UP").strip(),
                "speed": speed_display,
            }
        )

    snapshot = _get_live_autofind_snapshot_for_ajax(olt)
    payload = _build_unconfigured_group(
        request=request,
        olt=olt,
        index=index,
        existing_by_serial=existing_by_serial,
        search_query=search_query,
        category_filter=category_filter,
        onu_type_options=onu_type_options,
        download_speed_options=download_speed_options,
        upload_speed_options=upload_speed_options,
        snapshot_override=snapshot,
    )
    return JsonResponse({"ok": True, "pending": bool(payload.get("group", {}).get("is_pending")), **payload})


def _run_authorize_bg_task(task_id, olt, authorize_kwargs, user_pk, slot, port, frame, ont_id_hint):
    """Background thread: runs authorize_autofind_onu and stores result in _AUTHORIZE_TASKS."""
    close_old_connections()

    def on_progress(step, label):
        with _AUTHORIZE_TASKS_LOCK:
            if task_id in _AUTHORIZE_TASKS:
                _AUTHORIZE_TASKS[task_id]["step"] = step
                _AUTHORIZE_TASKS[task_id]["label"] = label

    try:
        payload = authorize_autofind_onu(**authorize_kwargs, on_progress=on_progress)
        ok = bool(payload.get("ok"))
        ont_id = payload.get("ont_id")
        redirect_url = ""

        if ok:
            _schedule_autofind_rows_refresh(int(olt.pk))
            _schedule_autofind_counts_refresh(int(olt.pk))
            try:
                User = get_user_model()
                user = User.objects.filter(pk=user_pk).first()
                if user:
                    _record_olt_login(
                        olt, user, "authorize_onu",
                        f"ONU authorized: 0/{int(frame)}/{int(slot)}/{int(port)} ont {int(ont_id or 0)}",
                        onu=f"0/{int(frame)}/{int(slot)}/{int(port)}:{int(ont_id or 0)}",
                    )
            except Exception:
                pass
            if ont_id is not None:
                try:
                    record = ConfiguredONU.objects.filter(
                        olt=olt, slot=int(slot), port=int(port), ont_id=int(ont_id),
                    ).first()
                    if record is not None:
                        _refresh_single_onu_power_from_snmp(olt, record, int(slot), int(port), int(ont_id))
                except Exception:
                    pass
                redirect_url = "{}?auth_debug=1".format(
                    reverse("configured_onu_detail", kwargs={
                        "olt_pk": int(olt.pk),
                        "slot": int(slot),
                        "port": int(port),
                        "ont_id": int(ont_id),
                    })
                )

        with _AUTHORIZE_TASKS_LOCK:
            if task_id in _AUTHORIZE_TASKS:
                _AUTHORIZE_TASKS[task_id].update({
                    "done": True,
                    "ok": ok,
                    "step": 4 if ok else _AUTHORIZE_TASKS[task_id].get("step", 0),
                    "label": "Done" if ok else _AUTHORIZE_TASKS[task_id].get("label", ""),
                    "message": str(payload.get("message") or ""),
                    "redirect_url": redirect_url,
                    "ont_id": ont_id,
                    "service_port_ids": payload.get("service_port_ids") or [],
                    "service_profile_id": payload.get("service_profile_id"),
                    "line_profile_id": payload.get("line_profile_id"),
                })
    except Exception as exc:
        with _AUTHORIZE_TASKS_LOCK:
            if task_id in _AUTHORIZE_TASKS:
                _AUTHORIZE_TASKS[task_id].update({
                    "done": True,
                    "ok": False,
                    "message": f"Authorize task encountered an unexpected error: {exc}",
                    "redirect_url": "",
                })


@login_required
@require_POST
@admin_required
def unconfigured_onu_authorize(request):
    is_ajax = request.headers.get("X-Requested-With") == "XMLHttpRequest"
    return_query = str(request.POST.get("return_query") or "").strip()
    redirect_url = reverse("unconfigured_onus")
    if return_query:
        redirect_url = f"{redirect_url}?{return_query}"

    def _finish_error(message_text):
        messages.error(request, message_text)
        if is_ajax:
            return JsonResponse({"ok": False, "redirect_url": redirect_url, "message": message_text})
        return redirect(redirect_url)

    olt_id = request.POST.get("olt_id")
    frame = request.POST.get("frame", "0")
    slot = request.POST.get("slot", "0")
    port = request.POST.get("port", "0")
    sn = str(request.POST.get("sn") or "").strip()
    pon_type_value = str(request.POST.get("pon_type") or "").strip().upper()
    onu_type_value = str(request.POST.get("onu_type") or "").strip()
    onu_mode = str(request.POST.get("onu_mode") or "").strip().lower()
    vlan_value = str(request.POST.get("vlan") or "").strip()
    use_svlan = bool(request.POST.get("use_svlan"))
    service_vlan_value = str(request.POST.get("service_vlan") or "").strip() if use_svlan else ""
    tag_transform_value = str(request.POST.get("tag_transform") or "default").strip().lower() if use_svlan else ""
    mapping_mode = str(request.POST.get("mapping_mode") or "priority").strip().lower()
    if mapping_mode == "vlan":
        use_svlan = False
        service_vlan_value = ""
        tag_transform_value = ""
    download_profile_index = str(request.POST.get("download_speed") or "").strip()
    upload_profile_index = str(request.POST.get("upload_speed") or "").strip()
    subscriber_name = str(request.POST.get("subscriber_name") or "").strip()

    if not str(olt_id or "").isdigit():
        return _finish_error("Authorize failed: invalid OLT.")
    if not sn:
        return _finish_error("Authorize failed: serial is missing.")
    if pon_type_value not in {"GPON", "EPON"}:
        pon_type_value = "GPON"
    if not onu_type_value:
        return _finish_error("Authorize failed: select an ONU Type.")
    if onu_mode not in {"routing", "bridging"}:
        return _finish_error("Authorize failed: select an ONU Mode.")
    if not vlan_value:
        return _finish_error("Authorize failed: select a VLAN.")
    if use_svlan and not service_vlan_value:
        return _finish_error("Authorize failed: select an SVLAN.")
    if use_svlan and vlan_value.lower() == "untagged":
        tag_transform_value = "default"
    if use_svlan and tag_transform_value not in {"default", "translate"}:
        return _finish_error("Authorize failed: select a valid tag-transform.")
    if mapping_mode not in {"priority", "vlan"}:
        return _finish_error("Authorize failed: select a valid mapping mode.")
    if not download_profile_index or not upload_profile_index:
        return _finish_error("Authorize failed: select both download and upload speed profiles.")
    if not subscriber_name:
        return _finish_error("Authorize failed: client name is required.")

    olt = OLT.objects.filter(pk=int(olt_id)).only(
        "id", "name", "ip_address", "username", "password", "port",
        "pricing_mode", "pricing_expires_at", "pricing_locked", "pricing_locked_reason",
    ).first()
    if not olt:
        return _finish_error("Authorize failed: OLT not found.")
    if olt.pricing_access_locked:
        return _finish_error(olt.pricing_lock_message or "Authorize failed: subscription expired.")
    if mapping_mode == "vlan" and _onu_tech_label(olt, slot) == "epon":
        return _finish_error("Authorize failed: VLAN Mapping is currently disabled for EPON ONUs.")

    onu_type_map = {
        str(row.get("value") or "").strip().lower(): row
        for row in _load_onu_type_option_rows()
    }
    onu_type_entry = onu_type_map.get(onu_type_value.lower())
    if not onu_type_entry:
        return _finish_error(f"Authorize failed: ONU Type `{onu_type_value}` was not found in the catalog.")

    speed_profile_lookup = {}
    for profile in SpeedProfile.objects.filter(is_active=True):
        base_name = (profile.name or "").strip()
        base_name = re.sub(r"(?i)(?:-|_)?(up|down)$", "", base_name).strip(" -_") or (profile.name or "")
        speed_profile_lookup[str(int(profile.index_number or 0))] = {
            "name": (profile.download_name or f"{base_name}-DOWN").strip(),
        }
        speed_profile_lookup[str(int((profile.index_number or 0) + 1))] = {
            "name": (profile.upload_name or f"{base_name}-UP").strip(),
        }

    download_profile_name = str((speed_profile_lookup.get(download_profile_index) or {}).get("name") or "").strip()
    upload_profile_name = str((speed_profile_lookup.get(upload_profile_index) or {}).get("name") or "").strip()
    line_profile_vlan_ids = [service_vlan_value] if mapping_mode == "vlan" and service_vlan_value else [vlan_value]

    authorize_kwargs = dict(
        olt=olt,
        frame=int(frame or 0),
        slot=int(slot or 0),
        port=int(port or 0),
        sn=sn,
        pon_type=pon_type_value,
        onu_type_name=onu_type_value,
        vlan_ids=[vlan_value],
        download_profile_index=download_profile_index,
        download_profile_name=download_profile_name,
        upload_profile_index=upload_profile_index,
        upload_profile_name=upload_profile_name,
        subscriber_name=subscriber_name,
        onu_mode=onu_mode,
        service_vlan=service_vlan_value,
        tag_transform=tag_transform_value,
        mapping_mode=mapping_mode,
        line_profile_vlan_ids=line_profile_vlan_ids,
        onu_type_serial=int(onu_type_entry.get("serial_no") or 300),
        pots_ports=str(onu_type_entry.get("voip_ports") or "0").strip() or "0",
        eth_ports=str(onu_type_entry.get("ethernet_ports") or "0").strip() or "0",
    )

    if is_ajax:
        # Async path: return task_id immediately, frontend polls for progress
        import uuid
        task_id = uuid.uuid4().hex[:20]
        now_ts = time.time()
        # Prune stale tasks (> 10 min old) to prevent unbounded growth
        with _AUTHORIZE_TASKS_LOCK:
            stale = [tid for tid, t in _AUTHORIZE_TASKS.items() if now_ts - t.get("created_at", now_ts) > 600]
            for tid in stale:
                _AUTHORIZE_TASKS.pop(tid, None)
            _AUTHORIZE_TASKS[task_id] = {
                "done": False, "ok": False, "step": 0,
                "label": "Opening Telnet session...",
                "message": "", "redirect_url": "",
                "created_at": now_ts,
            }
        threading.Thread(
            target=_run_authorize_bg_task,
            args=(task_id, olt, authorize_kwargs, request.user.pk,
                  int(slot or 0), int(port or 0), int(frame or 0), None),
            name=f"authorize-{task_id}",
            daemon=True,
        ).start()
        return JsonResponse({"ok": True, "task_id": task_id})

    # Synchronous fallback for non-AJAX submissions
    payload = authorize_autofind_onu(**authorize_kwargs)
    if payload.get("ok"):
        request.session["authorize_debug_payload"] = {
            "title": f"Authorize Debug | {olt.name} | 0/{int(slot or 0)}/{int(port or 0)}",
            "transcript": str(payload.get("transcript") or ""),
            "location": f"{int(olt.id)}:{int(slot or 0)}:{int(port or 0)}:{int(payload.get('ont_id') or 0)}",
        }
        with _AUTOFIND_ROWS_CACHE_LOCK:
            _AUTOFIND_ROWS_CACHE.pop(int(olt.id), None)
        _schedule_autofind_rows_refresh(int(olt.id))
        _schedule_autofind_counts_refresh(int(olt.id))
        messages.success(request, (
            f"ONU authorized on {olt.name}. ONT-ID {payload.get('ont_id')} | "
            f"SRV Profile {payload.get('service_profile_id')} | "
            f"LINE Profile {payload.get('line_profile_id')} | "
            f"Service-port {', '.join(payload.get('service_port_ids') or []) or '-'}"
        )[:300])
        if payload.get("ont_id") is not None:
            record = ConfiguredONU.objects.filter(
                olt=olt, slot=int(slot or 0), port=int(port or 0),
                ont_id=int(payload.get("ont_id") or 0),
            ).first()
            if record is not None:
                _refresh_single_onu_power_from_snmp(olt, record, int(slot or 0), int(port or 0), int(payload.get("ont_id") or 0))
            detail_url = "{}?auth_debug=1".format(reverse("configured_onu_detail", kwargs={
                "olt_pk": int(olt.id), "slot": int(slot or 0),
                "port": int(port or 0), "ont_id": int(payload.get("ont_id") or 0),
            }))
            return redirect(detail_url)
    else:
        request.session["authorize_debug_payload"] = {
            "title": f"Authorize Debug | {olt.name} | 0/{int(slot or 0)}/{int(port or 0)}",
            "transcript": str(payload.get("transcript") or ""),
            "location": "",
        }
        messages.error(request, f"Authorize failed on {olt.name}: {payload.get('message') or 'Unknown error.'}")
    return redirect(redirect_url)


@login_required
def unconfigured_onu_authorize_progress(request, task_id):
    with _AUTHORIZE_TASKS_LOCK:
        task = dict(_AUTHORIZE_TASKS.get(str(task_id) or "", {}) or {})
    if not task:
        return JsonResponse({"done": True, "ok": False, "message": "Task not found or expired."}, status=404)
    task.pop("created_at", None)
    return JsonResponse(task)


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
        if not detail_refresh:
            records = {
                (int(record.slot), int(record.port), int(record.ont_id)): record
                for record in ConfiguredONU.objects.filter(
                    olt=olt,
                    slot__in=[slot for slot, _, _ in onu_keys],
                    port__in=[port for _, port, _ in onu_keys],
                    ont_id__in=[ont_id for _, _, ont_id in onu_keys],
                )
            }
            epon_live_budget = 4
            for slot, port, ont_id in onu_keys:
                record = records.get((slot, port, ont_id))
                if not record:
                    continue
                key = f"{olt_id}:{slot}:{port}:{ont_id}"
                status_value = _normalize_configured_status(record.derived_status, run_state=record.run_state)
                cached_signal = _signal_payload_from_values(record.onu_rx, record.olt_rx)
                is_epon = _onu_tech_label(olt, slot).upper() == "EPON"
                if (
                    epon_live_budget > 0
                    and is_epon
                    and status_value == "online"
                    and not cached_signal.get("signal_visible")
                    and not _is_olt_snmp_unreachable(getattr(olt, "snmp_last_status", ""))
                ):
                    live_signal = _refresh_single_onu_power_from_snmp(olt, record, slot, port, ont_id)
                    fresh_signal = _signal_payload_from_values(live_signal.get("onu_rx"), live_signal.get("olt_rx"))
                    if fresh_signal.get("signal_visible"):
                        cached_signal = fresh_signal
                    epon_live_budget -= 1
                response_items[key] = cached_signal
                response_items[key]["status_value"] = status_value
                response_items[key]["status_label"] = _configured_status_label(record.derived_status, run_state=record.run_state)
                response_items[key]["status_class"] = _configured_status_class(record.derived_status, run_state=record.run_state)
            continue
        detail_single_key = next(iter(onu_keys)) if detail_refresh and len(onu_keys) == 1 else None
        if detail_single_key:
            slot_key, port_key, ont_key = detail_single_key
            single_status = fetch_single_onu_snmp_status(olt, slot_key, port_key, ont_key)
            snmp_status_map = {detail_single_key: single_status.get("value")} if single_status.get("value") else {}
        else:
            snmp_status_map = fetch_olt_snmp_status_map(olt).get("items") or {}
        type_distance_map = None

        def _type_distance_from_snmp_map(slot, port, ont_id):
            nonlocal type_distance_map
            if type_distance_map is None:
                type_distance_map = fetch_olt_snmp_onu_type_distance_maps(olt)
            key_tuple = (int(slot), int(port), int(ont_id))
            return {
                "onu_type": str((type_distance_map.get("type_items") or {}).get(key_tuple) or "").strip()[:128],
                "distance": str((type_distance_map.get("distance_items") or {}).get(key_tuple) or "").strip()[:32],
            }

        optical_map = {}
        for signal_key in sorted(onu_keys):
            slot_key, port_key, ont_key = signal_key
            optical_map[signal_key] = fetch_single_onu_snmp_signal(olt, slot_key, port_key, ont_key)
        fetch_ok = any(
            str(item.get("onu_rx") or "--") != "--" or str(item.get("olt_rx") or "--") != "--"
            for item in optical_map.values()
        )
        successful_ports = {(slot_key, port_key) for (slot_key, port_key, _), item in optical_map.items() if str(item.get("onu_rx") or "--") != "--" or str(item.get("olt_rx") or "--") != "--"}

        db_updates = []
        samples = []
        status_samples = []
        traffic_sample_keys = set()
        recent_signal_sample_keys = recent_onu_optical_sample_keys(olt)
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
                previous_status = _normalize_configured_status(record.derived_status, run_state=record.run_state)
                snmp_status = str(snmp_status_map.get((slot, port, ont_id)) or "").strip().lower()
                next_status, next_source, status_observed = _debounced_onu_snmp_status(record, snmp_status)
                if status_observed:
                    now = timezone.now()
                    if next_status == "online":
                        record.run_state = "online"
                    elif next_status in {"offline", "admin_disabled", "power_failure", "loss_of_signal"}:
                        record.run_state = "offline"
                    if next_status != previous_status:
                        record.status_first_seen_at = now
                    elif not record.status_first_seen_at:
                        record.status_first_seen_at = now
                    record.derived_status = next_status
                    record.status_source = next_source
                    record.status_updated_at = now
                status_value = _normalize_configured_status(record.derived_status, run_state=record.run_state)
                response_items[key] = (
                    _signal_payload_from_values(record.onu_rx, record.olt_rx)
                    if status_value == "online"
                    else _signal_payload_from_values("--", "--")
                )
                response_items[key]["status_value"] = status_value
                response_items[key]["status_label"] = _configured_status_label(record.derived_status, run_state=record.run_state)
                response_items[key]["status_class"] = _configured_status_class(record.derived_status, run_state=record.run_state)
                response_items[key]["status_age_text"] = _format_status_age_text(
                    record.status_first_seen_at or record.status_updated_at
                )
                is_online_now = _normalize_configured_status(record.derived_status, run_state=record.run_state) == "online"
                became_online = previous_status != "online" and is_online_now
                should_check_type = False if detail_refresh else is_online_now and (became_online or not (record.onu_type_cache or "").strip())
                should_check_distance = False if detail_refresh else is_online_now and (became_online or not (record.ont_distance_m or "").strip())
                if should_check_type or should_check_distance:
                    snmp_detail = _type_distance_from_snmp_map(slot, port, ont_id)
                    snmp_type = snmp_detail.get("onu_type") or ""
                    if should_check_type and snmp_type and snmp_type != (record.onu_type_cache or ""):
                        record.onu_type_cache = snmp_type
                    snmp_distance = snmp_detail.get("distance") or ""
                    if should_check_distance and snmp_distance and snmp_distance != (record.ont_distance_m or ""):
                        record.ont_distance_m = snmp_distance
                    if snmp_type or snmp_distance:
                        record.capability_synced_at = timezone.now()
                db_updates.append(record)
                if detail_refresh and len(onu_keys) == 1:
                    response_items[key]["signal_distance_text"] = _format_onu_distance_text(
                        getattr(record, "ont_distance_m", "") if hasattr(record, "ont_distance_m") else ""
                    )
                    response_items[key]["attached_vlans_text"] = (getattr(record, "user_vlan_cache", "") or "").strip() or "-"
                status_samples.append(
                    ONUStatusSample(
                        olt=olt,
                        slot=slot,
                        port=port,
                        ont_id=ont_id,
                        status=_normalize_configured_status(record.derived_status, run_state=record.run_state),
                        source=(record.status_source or "")[:32],
                    )
                )
                if not detail_refresh and is_online_now:
                    stored_signal_row = _signal_payload_from_values(record.onu_rx, record.olt_rx)
                    if stored_signal_row["signal_visible"]:
                        traffic_sample_keys.add((slot, port, ont_id))
                continue

            if record:
                now = timezone.now()
                previous_status = _normalize_configured_status(record.derived_status, run_state=record.run_state)
                snmp_status = str(snmp_status_map.get((slot, port, ont_id)) or "").strip().lower()
                next_status, next_source, snmp_status_observed = _debounced_onu_snmp_status(record, snmp_status)
                if not snmp_status_observed:
                    next_status = _normalize_configured_status(record.derived_status, run_state=record.run_state)
                    next_source = record.status_source or "inventory"
                if next_status == "online":
                    record.run_state = "online"
                elif next_status in {"offline", "admin_disabled", "power_failure", "loss_of_signal"}:
                    record.run_state = "offline"
                signal = optical_map.get((slot, port, ont_id), {"onu_rx": "--", "olt_rx": "--", "tx_power": "--"})
                fresh_signal_row = _signal_payload_from_values(signal.get("onu_rx"), signal.get("olt_rx"))
                if (
                    fresh_signal_row["signal_visible"]
                    and not snmp_status
                    and _normalize_configured_status(record.derived_status, run_state=record.run_state) != "admin_disabled"
                ):
                    record.run_state = "online"
                    next_status = "online"
                    next_source = "snmp_refresh"
                stored_signal_row = _signal_payload_from_values(record.onu_rx, record.olt_rx)
                is_online_response = _normalize_configured_status(next_status, run_state=record.run_state) == "online"
                payload_row = (
                    fresh_signal_row
                    if fresh_signal_row["signal_visible"] and is_online_response
                    else stored_signal_row
                    if stored_signal_row["signal_visible"] and is_online_response
                    else _signal_payload_from_values("--", "--")
                )
                response_items[key] = dict(payload_row)
                if fresh_signal_row["signal_visible"]:
                    record.onu_rx = payload_row["onu_rx"] if payload_row["onu_rx"] != "--" else ""
                    record.olt_rx = payload_row["olt_rx"] if payload_row["olt_rx"] != "--" else ""
                    record.tx_power = (signal.get("tx_power") or "") if ((signal.get("tx_power") or "") != "--") else record.tx_power
                    record.signal_bucket = payload_row["signal_class"] or ""
                elif stored_signal_row["signal_visible"]:
                    payload_row = stored_signal_row
                    response_items[key] = dict(payload_row)
                elif is_online_response:
                    response_items[key] = dict(stored_signal_row)
                if next_status != previous_status:
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
                became_online = previous_status != "online" and _normalize_configured_status(next_status, run_state=record.run_state) == "online"
                is_online_now = _normalize_configured_status(next_status, run_state=record.run_state) == "online"
                should_check_type = False if detail_refresh else is_online_now and (became_online or not (record.onu_type_cache or "").strip())
                should_check_distance = False if detail_refresh else is_online_now and (became_online or not (record.ont_distance_m or "").strip())
                if should_check_type or should_check_distance:
                    snmp_detail = _type_distance_from_snmp_map(slot, port, ont_id)
                    snmp_type = snmp_detail.get("onu_type") or ""
                    if should_check_type and snmp_type and snmp_type != (record.onu_type_cache or ""):
                        record.onu_type_cache = snmp_type
                    snmp_distance = snmp_detail.get("distance") or ""
                    if should_check_distance and snmp_distance and snmp_distance != (record.ont_distance_m or ""):
                        record.ont_distance_m = snmp_distance
                    if snmp_type or snmp_distance:
                        record.capability_synced_at = now
                db_updates.append(record)
                if detail_refresh and len(onu_keys) == 1:
                    response_items[key]["signal_distance_text"] = _format_onu_distance_text(
                        getattr(record, "ont_distance_m", "") if hasattr(record, "ont_distance_m") else ""
                    )
                    response_items[key]["attached_vlans_text"] = (getattr(record, "user_vlan_cache", "") or "").strip() or "-"
                    response_items[key]["status_since_label"] = (
                        "Online Since" if _normalize_configured_status(response_items[key]["status_value"]) == "online" else "Status Since"
                    )
                    response_items[key]["status_since_text"] = _format_status_age_text(
                        record.status_first_seen_at or record.status_updated_at
                    )
                status_samples.append(
                    ONUStatusSample(
                        olt=olt,
                        slot=slot,
                        port=port,
                        ont_id=ont_id,
                        status=_normalize_configured_status(record.derived_status, run_state=record.run_state),
                        source=(record.status_source or "")[:32],
                    )
                )
                if not detail_refresh and is_online_response and (
                    fresh_signal_row["signal_visible"] or stored_signal_row["signal_visible"]
                ):
                    traffic_sample_keys.add((slot, port, ont_id))
            sample_key = (int(slot), int(port), int(ont_id))
            if fresh_signal_row["signal_visible"] and sample_key not in recent_signal_sample_keys:
                samples.append(
                    ONUOpticalSample(
                        olt=olt,
                        slot=slot,
                        port=port,
                        ont_id=ont_id,
                        onu_rx=fresh_signal_row["onu_rx"] if fresh_signal_row["onu_rx"] != "--" else "",
                        olt_rx=fresh_signal_row["olt_rx"] if fresh_signal_row["olt_rx"] != "--" else "",
                        tx_power=(signal.get("tx_power") or "") if ((signal.get("tx_power") or "") != "--") else "",
                        sample_source=ONUOpticalSample.SOURCE_FRESH,
                    )
                )
                recent_signal_sample_keys.add(sample_key)
        if db_updates:
            ConfiguredONU.objects.bulk_update(
                db_updates,
                ["onu_rx", "olt_rx", "tx_power", "onu_type_cache", "ont_distance_m", "capability_synced_at", "signal_bucket", "run_state", "derived_status", "status_source", "status_first_seen_at", "status_updated_at"],
                batch_size=200,
            )
            if not detail_refresh:
                try:
                    record_dashboard_status_samples(force=True)
                except OperationalError:
                    pass
        if samples and fetch_ok:
            ONUOpticalSample.objects.bulk_create(samples, batch_size=200)
        if status_samples:
            ONUStatusSample.objects.bulk_create(status_samples, batch_size=200)
        if traffic_sample_keys:
            _schedule_onu_traffic_samples(olt.pk, traffic_sample_keys)

    return JsonResponse({"ok": True, "items": response_items})


@login_required
def configured_onu_status_sync_progress(request):
    return JsonResponse({"ok": True, "progress": get_onu_status_sync_progress()})


@login_required
def configured_onu_signal_graph_data(request, olt_pk, slot, port, ont_id):
    olt = get_object_or_404(OLT, pk=olt_pk)
    range_key = str(request.GET.get("range") or "1h").strip().lower()
    payload = _build_onu_signal_graph_data(olt, int(slot), int(port), int(ont_id), range_key=range_key)
    return JsonResponse({"ok": True, **payload})


@login_required
def configured_onu_traffic_graph_data(request, olt_pk, slot, port, ont_id):
    olt = get_object_or_404(OLT, pk=olt_pk)
    range_key = str(request.GET.get("range") or "1h").strip().lower()
    sample = None
    if str(request.GET.get("sample") or "").strip() == "1":
        sample = _record_onu_traffic_sample(olt, int(slot), int(port), int(ont_id))
    config = _onu_signal_graph_config(range_key)
    return JsonResponse(
        {
            "ok": True,
            "range_key": config["key"],
            "range_label": config["label"],
            "sample": sample or {},
            "points": _get_onu_traffic_history(olt, int(slot), int(port), int(ont_id), hours=_onu_traffic_graph_hours(config["key"])),
        }
    )


@login_required
@require_POST
@admin_required
def configured_onu_catv_action(request, olt_pk, slot, port, ont_id):
    olt = get_object_or_404(OLT, pk=olt_pk)
    locked_response = _deny_olt_access_if_locked(request, olt)
    if locked_response:
        return locked_response
    record = ConfiguredONU.objects.filter(olt=olt, slot=slot, port=port, ont_id=ont_id).first()
    try:
        payload = json.loads(request.body.decode("utf-8") or "{}")
    except (TypeError, ValueError, json.JSONDecodeError):
        payload = {}
    enabled = bool(payload.get("enabled"))
    snapshot = execute_onu_catv_operational_state(
        olt,
        slot,
        port,
        ont_id,
        enabled,
        frame=(record.frame if record is not None else 0),
    )
    if snapshot.get("ok") and record is not None:
        record.catv_operational_cache = "enabled" if enabled else "disabled"
        record.save(update_fields=["catv_operational_cache"])
    status_code = 200 if snapshot.get("ok") else 400
    return JsonResponse(
        {
            "ok": bool(snapshot.get("ok")),
            "message": _ui_telnet_error_message(snapshot.get("message")),
            "enabled": enabled if snapshot.get("ok") else None,
            "transcript": str(snapshot.get("transcript") or ""),
        },
        status=status_code,
    )


@login_required
def configured_onu_detail(request, olt_pk, slot, port, ont_id):
    olt = get_object_or_404(OLT, pk=olt_pk)
    if olt.pricing_access_locked:
        return _render_olt_subscription_locked(request, olt)
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

    if request.method == "POST" and record is not None and _is_admin_user(request.user):
        action = (request.POST.get("action") or "").strip().lower()
        if action == "save_contact_info":
            address = _clean_onu_detail_text(request.POST.get("address"), 255)
            contact = _clean_onu_detail_text(request.POST.get("contact"), 64)
            record.address = address
            record.contact = contact
            record.save(update_fields=["address", "contact"])
            messages.success(request, "ONU contact details updated.")
            return redirect("configured_onu_detail", olt_pk=olt.pk, slot=slot, port=port, ont_id=ont_id)
        if action == "save_onu_name":
            record.description = _clean_onu_detail_text(request.POST.get("onu_name"), 255)
            record.save(update_fields=["description"])
            messages.success(request, "ONU name updated in OptiVerse.")
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
    _tech = _onu_tech_label(olt, slot)
    selected_onu["onu_label"] = f"{_tech}-onu_0/{slot}/{port}:{ont_id}"
    selected_onu["pon_tech_label"] = f"{str(_tech or 'gpon').upper()} ONU"
    # Imported ONUs (configured outside the app) get a "delete & reconfigure" hint.
    selected_onu["configured_via_app"] = bool(getattr(record, "configured_via_app", False)) if record is not None else True
    selected_mapping_mode = str(getattr(record, "mapping_mode_cache", "") if record is not None else "").strip().lower()
    if selected_mapping_mode == "vlan":
        selected_onu["mapping_label"] = "VLAN Mapping"
        selected_onu["is_vlan_mapping"] = True
    elif selected_mapping_mode == "priority" or not selected_onu["configured_via_app"]:
        selected_onu["mapping_label"] = "PRI Mapping"
        selected_onu["is_vlan_mapping"] = False
    else:
        selected_onu["mapping_label"] = ""
        selected_onu["is_vlan_mapping"] = False
    need_optical = False
    need_capability = False
    olt_unreachable = _is_olt_snmp_unreachable(getattr(olt, "snmp_last_status", ""))
    runtime_snapshot = _configured_onu_runtime_snapshot_from_record(record)
    capability_snapshot = {}
    live_signal = {}
    if record is not None and not olt_unreachable:
        needs_detail_sync = (
            not (getattr(record, "onu_type_cache", "") or "").strip()
            or not (getattr(record, "ont_distance_m", "") or "").strip()
            or not getattr(record, "capability_synced_at", None)
            or not getattr(record, "runtime_synced_at", None)
        )
        if needs_detail_sync:
            _schedule_onu_detail_sync(olt.pk, slot, port, ont_id)
        needs_vlan_config_sync = (
            not (getattr(record, "attached_vlans_cache", "") or "").strip()
            or not (getattr(record, "service_port_id_cache", "") or "").strip()
            or not (getattr(record, "user_vlan_cache", "") or "").strip()
            or not (getattr(record, "download_profile_name_cache", "") or "").strip()
            or not (getattr(record, "upload_profile_name_cache", "") or "").strip()
        )
        if needs_vlan_config_sync:
            _schedule_onu_attached_vlan_sync(olt.pk, slot, port, ont_id)
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
        (getattr(record, "onu_type_cache", "") if record is not None else "").strip()
        or "-"
    )
    selected_onu["onu_type_display"] = _display_onu_type_name(selected_onu["onu_type"]) or "-"
    selected_onu["attached_vlans"] = (
        (getattr(record, "user_vlan_cache", "") if record is not None else "").strip()
        or "-"
    )
    selected_onu_mode = (getattr(record, "onu_mode_cache", "") if record is not None else "").strip()
    if not selected_onu_mode and record is not None and not getattr(record, "configured_via_app", False):
        selected_onu_mode = "routing"
    selected_onu["onu_mode"] = selected_onu_mode or "-"
    selected_onu["last_down_cause"] = (runtime_snapshot.get("last_down_cause") or "").strip()
    selected_onu["battery_state"] = (runtime_snapshot.get("battery_state") or "").strip()
    selected_onu["ont_distance_m"] = (
        (getattr(record, "ont_distance_m", "") if record is not None else "").strip()
    )
    selected_onu["status_age_text"] = _status_age_text_from_onu_runtime(
        effective_status,
        runtime_snapshot,
    ) or _format_status_age_text(
        selected_onu.get("status_first_seen_at") or selected_onu.get("status_updated_at")
    )
    status_since_dt = _status_since_datetime_from_onu_runtime(effective_status, runtime_snapshot)
    selected_onu["status_since_label"] = "Online Since" if _normalize_configured_status(effective_status) == "online" else "Status Since"
    selected_onu["status_since_text"] = _format_relative_time_text(status_since_dt)
    if need_optical and live_signal:
        selected_onu["onu_rx"] = live_signal.get("onu_rx", "--")
        selected_onu["tx_power"] = live_signal.get("tx_power", "--")
        selected_onu["olt_rx"] = live_signal.get("olt_rx", "--")

    if record is not None:
        capability_update_fields = []
        if selected_onu["onu_type"] not in {"", "-"} and selected_onu["onu_type"] != (record.onu_type_cache or ""):
            record.onu_type_cache = selected_onu["onu_type"]
            capability_update_fields.append("onu_type_cache")
        if selected_onu["ont_distance_m"] != (record.ont_distance_m or ""):
            record.ont_distance_m = selected_onu["ont_distance_m"]
            capability_update_fields.append("ont_distance_m")
        if capability_update_fields:
            record.capability_synced_at = timezone.now()
            capability_update_fields.append("capability_synced_at")
            record.save(update_fields=capability_update_fields)
    selected_onu["signal_distance_text"] = _format_onu_distance_text(selected_onu.get("ont_distance_m"))
    selected_onu["signal_class"] = _classify_onu_signal(selected_onu.get("olt_rx"))
    if _normalize_configured_status(selected_onu.get("status_value"), run_state=selected_onu.get("run_state")) != "online":
        selected_onu["onu_rx"] = "--"
        selected_onu["olt_rx"] = "--"
        selected_onu["tx_power"] = "--"
        selected_onu["signal_class"] = ""

    def _split_positional(value):
        # Keep empty placeholders so the parallel caches stay position-aligned —
        # each row's speed profile then lands under the correct service-port/VLAN.
        text = str(value or "")
        if not text.strip():
            return []
        return [part.strip() for part in text.split(",")]

    raw_service_ports = getattr(record, "service_port_id_cache", "") if record is not None else ""
    raw_service_vlans = getattr(record, "attached_vlans_cache", "") if record is not None else ""
    raw_user_vlans = getattr(record, "user_vlan_cache", "") if record is not None else ""
    raw_download_indices = getattr(record, "download_profile_index_cache", "") if record is not None else ""
    raw_upload_indices = getattr(record, "upload_profile_index_cache", "") if record is not None else ""
    raw_download_names = getattr(record, "download_profile_name_cache", "") if record is not None else ""
    raw_upload_names = getattr(record, "upload_profile_name_cache", "") if record is not None else ""
    service_port_values = _split_positional(raw_service_ports)
    service_vlan_values = _split_positional(raw_service_vlans)
    user_vlan_values = _split_positional(raw_user_vlans)
    download_index_values = _split_positional(raw_download_indices)
    upload_index_values = _split_positional(raw_upload_indices)
    download_profile_values = _split_positional(raw_download_names)
    upload_profile_values = _split_positional(raw_upload_names)
    profile_speed_label_by_index = {}
    default_speed_profile_label = "1G"
    for profile in SpeedProfile.objects.filter(is_active=True).only("index_number", "name", "download_name", "upload_name", "speed_mbps_value"):
        base_index = int(profile.index_number or 0)
        if not base_index:
            continue
        speed_label = _format_profile_speed_label_from_mbps(profile.speed_mbps_value)
        if not speed_label:
            speed_label = _short_speed_profile_label(profile.download_name or profile.upload_name or profile.name)
        try:
            speed_mbps = float(profile.speed_mbps_value or 0)
        except (TypeError, ValueError):
            speed_mbps = 0
        if speed_label and (
            "1G" in str(profile.name or "").upper()
            or "1000" in str(profile.name or "")
            or speed_mbps >= 1000
        ):
            default_speed_profile_label = speed_label
        profile_speed_label_by_index[str(base_index)] = speed_label or str(base_index)
        profile_speed_label_by_index[str(base_index + 1)] = speed_label or str(base_index + 1)
    speed_profile_rows = []
    speed_profile_count = max(
        len(service_port_values),
        len(service_vlan_values),
        len(user_vlan_values),
        len(download_index_values),
        len(upload_index_values),
        len(download_profile_values),
        len(upload_profile_values),
        1,
    )

    def _align_short_profile_cache(values, raw_value):
        # Older cache writes could append a new VLAN's profile without inserting
        # blank placeholders for existing VLAN rows. When no comma placeholders
        # exist, keep that lone profile on the trailing/new row instead of row 1.
        if 0 < len(values) < speed_profile_count and "," not in str(raw_value or ""):
            return ([""] * (speed_profile_count - len(values))) + values
        return values

    download_index_values = _align_short_profile_cache(download_index_values, raw_download_indices)
    upload_index_values = _align_short_profile_cache(upload_index_values, raw_upload_indices)
    download_profile_values = _align_short_profile_cache(download_profile_values, raw_download_names)
    upload_profile_values = _align_short_profile_cache(upload_profile_values, raw_upload_names)

    def _row_value(values, index):
        return (values[index] if index < len(values) else "").strip() or "-"

    def _profile_row_value(name_values, index_values, index, default_label=""):
        name_value = (name_values[index] if index < len(name_values) else "").strip()
        index_value = (index_values[index] if index < len(index_values) else "").strip()
        label = _short_speed_profile_label(
            name_value,
            fallback_index=index_value,
            speed_label_by_index=profile_speed_label_by_index,
        )
        return label if label != "-" else (default_label or "-")

    for index in range(speed_profile_count):
        row_has_config = any(
            value != "-"
            for value in (
                _row_value(service_port_values, index),
                _row_value(service_vlan_values, index),
                _row_value(user_vlan_values, index),
            )
        )
        row_default_speed = default_speed_profile_label if row_has_config else ""
        speed_profile_rows.append(
            {
                "service_port_id": _row_value(service_port_values, index),
                "service_vlan": _row_value(service_vlan_values, index),
                "user_vlan": _row_value(user_vlan_values, index),
                "download": _profile_row_value(download_profile_values, download_index_values, index, row_default_speed),
                "upload": _profile_row_value(upload_profile_values, upload_index_values, index, row_default_speed),
                "configure_url": reverse(
                    "configured_onu_speed_profile_config",
                    kwargs={
                        "olt_pk": olt.pk,
                        "slot": slot,
                        "port": port,
                        "ont_id": ont_id,
                        "row_index": index,
                    },
                ),
            }
        )

    def _normalize_onu_type_lookup_key(value):
        text = str(value or "").strip().upper()
        if not text:
            return ""
        text = re.sub(r"(?i)[\s-]*_?SOLT$", "", text).strip(" _-")
        return text

    ethernet_port_rows = []
    ethernet_port_count = 0
    onu_type_lookup_value = _normalize_onu_type_lookup_key(selected_onu.get("onu_type"))
    if onu_type_lookup_value and onu_type_lookup_value != "-":
        for row in _load_onu_type_catalog_rows():
            catalog_key = _normalize_onu_type_lookup_key(row.get("onu_type"))
            if catalog_key == onu_type_lookup_value:
                try:
                    ethernet_port_count = int(str(row.get("ethernet_ports") or "0").strip() or "0")
                except (TypeError, ValueError):
                    ethernet_port_count = 0
                break
    if ethernet_port_count <= 0:
        try:
            ethernet_port_count = int(str(selected_onu.get("eth_ports") or "0").strip() or "0")
        except (TypeError, ValueError):
            ethernet_port_count = 0
    if ethernet_port_count <= 0:
        ethernet_port_count = 1
    access_vlan_text = user_vlan_values[0] if user_vlan_values else ((selected_onu.get("attached_vlans") or "-").split(",")[0].strip() if str(selected_onu.get("attached_vlans") or "").strip() else "-")
    ethernet_port_config_map = _load_ethernet_port_config_cache(record)
    for port_number in range(1, max(ethernet_port_count, 0) + 1):
        port_config = ethernet_port_config_map.get(str(port_number), {}) if isinstance(ethernet_port_config_map, dict) else {}
        cached_mode = str(port_config.get("mode") or "").strip().lower()
        cached_vlan = str(port_config.get("vlan") or "").strip()
        cached_status = str(port_config.get("status") or "").strip().lower()
        if cached_mode == "access" and cached_vlan:
            mode_text = f"Access VLAN {cached_vlan}"
        elif cached_mode == "trunk":
            mode_text = "Trunk"
        elif cached_mode == "transparent":
            mode_text = "Transparent"
        elif cached_mode == "lan":
            mode_text = "LAN"
        else:
            mode_text = "LAN"
        ethernet_port_rows.append(
            {
                "port_name": f"eth_0/{port_number}",
                "admin_state": "Port shutdown" if cached_status == "shutdown" else "Enabled",
                "mode": mode_text,
                "dhcp": "No control",
                "configure_url": reverse(
                    "configured_onu_ethernet_port_config",
                    kwargs={
                        "olt_pk": olt.pk,
                        "slot": slot,
                        "port": port,
                        "ont_id": ont_id,
                        "eth_port": port_number,
                    },
                ),
            }
        )

    signal_visible = any(str(selected_onu.get(key, "")).strip() not in {"", "--"} for key in ("onu_rx", "olt_rx"))
    signal_history = _get_onu_signal_history(olt, slot, port, ont_id, hours=1)
    traffic_history = _get_onu_traffic_history(olt, slot, port, ont_id, hours=1)
    stability_summary = _build_onu_stability_summary(olt, slot, port, ont_id, record=record)
    authorize_debug = None
    if str(request.GET.get("auth_debug") or "").strip():
        debug_payload = request.session.pop("authorize_debug_payload", None)
        expected_location = f"{int(olt.pk)}:{int(slot)}:{int(port)}:{int(ont_id)}"
        if debug_payload and str(debug_payload.get("location") or "").strip() == expected_location:
            authorize_debug = debug_payload
    context = {
        "olt": olt,
        "olt_unreachable": olt_unreachable,
        "olt_unreachable_message": "OLT is Unreachable",
        "slot": slot,
        "port": port,
        "ont_id": ont_id,
        "fsp": f"0/{slot}/{port}",
        "onu_label": f"{_tech}-onu_0/{slot}/{port}:{ont_id}",
        "onu": selected_onu,
        "onu_signal_visible": signal_visible,
        "onu_signal_history_json": json.dumps(signal_history),
        "onu_traffic_history_json": json.dumps(traffic_history),
        "onu_stability": stability_summary,
        "onu_has_catv": _onu_has_catv_port(record),
        "onu_catv_enabled": str(getattr(record, "catv_operational_cache", "") or "").strip().lower() != "disabled",
        "olt_filter_url": f"{reverse('configured_onus')}?olt={olt.pk}",
        "olt_uplink_url": f"{reverse('olt_view', kwargs={'pk': olt.pk})}?section=uplink",
        "board_filter_url": f"{reverse('configured_onus')}?olt={olt.pk}&board={slot}",
        "port_filter_url": f"{reverse('configured_onus')}?olt={olt.pk}&board={slot}&port={port}",
        "onu_signal_refresh_url": reverse("configured_onu_signals_refresh"),
        "onu_signal_graph_url": reverse("configured_onu_signal_graph_data", kwargs={
            "olt_pk": olt.pk,
            "slot": slot,
            "port": port,
            "ont_id": ont_id,
        }),
        "onu_traffic_graph_url": reverse("configured_onu_traffic_graph_data", kwargs={
            "olt_pk": olt.pk,
            "slot": slot,
            "port": port,
            "ont_id": ont_id,
        }),
        "onu_mac_address_url": reverse("configured_onu_mac_address", kwargs={
            "olt_pk": olt.pk,
            "slot": slot,
            "port": port,
            "ont_id": ont_id,
        }),
        "onu_running_config_url": reverse("configured_onu_running_config", kwargs={
            "olt_pk": olt.pk,
            "slot": slot,
            "port": port,
            "ont_id": ont_id,
        }),
        "onu_last_down_history_url": reverse("configured_onu_last_down_history", kwargs={
            "olt_pk": olt.pk,
            "slot": slot,
            "port": port,
            "ont_id": ont_id,
        }),
        "onu_fetch_config_url": reverse("configured_onu_fetch_config", kwargs={
            "olt_pk": olt.pk,
            "slot": slot,
            "port": port,
            "ont_id": ont_id,
        }),
        "onu_mapping_convert_url": reverse("configured_onu_mapping_convert", kwargs={
            "olt_pk": olt.pk,
            "slot": slot,
            "port": port,
            "ont_id": ont_id,
        }),
        "onu_disable_url": reverse("configured_onu_action", kwargs={
            "olt_pk": olt.pk,
            "slot": slot,
            "port": port,
            "ont_id": ont_id,
            "action": "disable",
        }),
        "onu_enable_url": reverse("configured_onu_action", kwargs={
            "olt_pk": olt.pk,
            "slot": slot,
            "port": port,
            "ont_id": ont_id,
            "action": "enable",
        }),
        "onu_restart_url": reverse("configured_onu_action", kwargs={
            "olt_pk": olt.pk,
            "slot": slot,
            "port": port,
            "ont_id": ont_id,
            "action": "restart",
        }),
        "onu_reset_url": reverse("configured_onu_action", kwargs={
            "olt_pk": olt.pk,
            "slot": slot,
            "port": port,
            "ont_id": ont_id,
            "action": "reset",
        }),
        "onu_delete_url": reverse("configured_onu_action", kwargs={
            "olt_pk": olt.pk,
            "slot": slot,
            "port": port,
            "ont_id": ont_id,
            "action": "delete",
        }),
        "onu_catv_url": reverse("configured_onu_catv_action", kwargs={
            "olt_pk": olt.pk,
            "slot": slot,
            "port": port,
            "ont_id": ont_id,
        }),
        "onu_speed_profile_rows": speed_profile_rows,
        "onu_add_vlan_url": reverse("configured_onu_add_vlan", kwargs={"olt_pk": olt.pk, "slot": slot, "port": port, "ont_id": ont_id}),
        "onu_ethernet_port_rows": ethernet_port_rows,
        "authorize_debug": authorize_debug,
    }
    return render(request, "oltmanager/configured_onu_detail.html", context)


def _execute_onu_mapping_conversion(olt, record, plan, user=None, *, on_progress=None):
    def _emit(step, label):
        if callable(on_progress):
            try:
                on_progress(step, label)
            except Exception:
                pass

    result = {"ok": False, "message": "Mapping conversion failed.", "redirect_url": "", "transcript": ""}
    old_frame = int(record.frame or 0)
    old_slot = int(record.slot or 0)
    old_port = int(record.port or 0)
    old_ont_id = int(record.ont_id or 0)
    sn_value = str(record.sn or "").strip()
    old_service_ports = [str(item).strip() for item in plan.get("service_ports") or [] if str(item).strip()]
    authorize_kwargs = dict(
        olt=olt,
        frame=old_frame,
        slot=old_slot,
        port=old_port,
        sn=sn_value,
        onu_type_name=plan["onu_type_name"],
        vlan_ids=plan["vlan_ids"],
        line_profile_vlan_ids=plan.get("line_profile_vlan_ids") or plan["vlan_ids"],
        download_profile_index=plan["download_profile_index"],
        download_profile_name=plan["download_profile_name"],
        upload_profile_index=plan["upload_profile_index"],
        upload_profile_name=plan["upload_profile_name"],
        subscriber_name=plan["subscriber_name"],
        onu_mode=plan["onu_mode"],
        onu_type_serial=plan["onu_type_serial"],
        pots_ports=plan["pots_ports"],
        eth_ports=plan["eth_ports"],
        service_vlan=plan.get("service_vlan") or "",
        tag_transform=plan.get("tag_transform") or "",
        mapping_mode=plan["target_mode"],
    )

    _emit(1, f"Deleting existing ONU and service-port(s): {', '.join(old_service_ports) or '-'}")
    delete_result = execute_onu_cli_delete_action(
        olt,
        old_slot,
        old_port,
        old_ont_id,
        frame=old_frame,
        service_port_ids=old_service_ports,
    )
    if not delete_result.get("ok"):
        result.update({
            "message": _ui_telnet_error_message(delete_result.get("message")) or "Existing ONU could not be deleted.",
            "transcript": str(delete_result.get("transcript") or ""),
        })
        return result

    record.delete()

    def _auth_progress(step, label):
        mapped_step = min(max(int(step or 0) + 2, 2), 6)
        _emit(mapped_step, label or "Authorizing ONU...")

    payload = authorize_autofind_onu(**authorize_kwargs, on_progress=_auth_progress)
    if not payload.get("ok"):
        result.update({
            "message": (
                f"ONU deleted, but {plan['target_label']} rebuild failed: "
                f"{_ui_telnet_error_message(payload.get('message')) or 'authorize failed'}"
            ),
            "transcript": str(payload.get("transcript") or ""),
            "redirect_url": reverse("unconfigured_onus"),
        })
        _schedule_autofind_rows_refresh(int(olt.pk))
        _schedule_autofind_counts_refresh(int(olt.pk))
        return result

    new_ont_id = int(payload.get("ont_id") or old_ont_id)
    new_record = ConfiguredONU.objects.filter(
        olt=olt, frame=old_frame, slot=old_slot, port=old_port, ont_id=new_ont_id,
    ).first()
    if new_record is not None:
        try:
            _refresh_single_onu_power_from_snmp(olt, new_record, old_slot, old_port, new_ont_id)
        except Exception:
            pass
    _schedule_autofind_rows_refresh(int(olt.pk))
    _schedule_autofind_counts_refresh(int(olt.pk))
    if user is not None:
        try:
            _record_olt_login(
                olt,
                user,
                "mapping_convert",
                f"ONU converted {plan['current_label']} -> {plan['target_label']}: 0/{old_slot}/{old_port} ont {old_ont_id}",
                onu=f"0/{old_slot}/{old_port}:{new_ont_id}",
            )
        except Exception:
            pass
    result.update({
        "ok": True,
        "message": f"ONU converted to {plan['target_label']}. New ONT-ID {new_ont_id}.",
        "redirect_url": reverse("configured_onu_detail", kwargs={
            "olt_pk": olt.pk,
            "slot": old_slot,
            "port": old_port,
            "ont_id": new_ont_id,
        }),
        "transcript": str(payload.get("transcript") or ""),
    })
    return result


def _run_mapping_convert_bg_task(task_id, olt_id, record_id, user_pk):
    close_old_connections()

    def _set_progress(step, label):
        with _MAPPING_CONVERT_TASKS_LOCK:
            if task_id in _MAPPING_CONVERT_TASKS:
                _MAPPING_CONVERT_TASKS[task_id]["step"] = int(step or 0)
                _MAPPING_CONVERT_TASKS[task_id]["label"] = str(label or "")

    try:
        _set_progress(0, "Preparing mapping conversion...")
        olt = OLT.objects.filter(pk=int(olt_id)).first()
        record = ConfiguredONU.objects.filter(pk=int(record_id), olt=olt).first() if olt else None
        user = get_user_model().objects.filter(pk=int(user_pk)).first() if user_pk else None
        if olt is None or record is None:
            result = {"ok": False, "message": "ONU record not found.", "redirect_url": "", "transcript": ""}
        else:
            plan = _build_onu_mapping_conversion_plan(record)
            if not plan.get("ok"):
                result = {"ok": False, "message": plan.get("message") or "Mapping conversion could not be prepared.", "redirect_url": "", "transcript": ""}
            elif plan.get("warnings"):
                result = {"ok": False, "message": "Mapping conversion blocked: " + " ".join(plan.get("warnings") or []), "redirect_url": "", "transcript": ""}
            else:
                result = _execute_onu_mapping_conversion(olt, record, plan, user=user, on_progress=_set_progress)
        with _MAPPING_CONVERT_TASKS_LOCK:
            if task_id in _MAPPING_CONVERT_TASKS:
                _MAPPING_CONVERT_TASKS[task_id].update({
                    "done": True,
                    "ok": bool(result.get("ok")),
                    "step": 6 if result.get("ok") else _MAPPING_CONVERT_TASKS[task_id].get("step", 0),
                    "label": "Done" if result.get("ok") else _MAPPING_CONVERT_TASKS[task_id].get("label", ""),
                    "message": str(result.get("message") or ""),
                    "transcript": str(result.get("transcript") or ""),
                    "redirect_url": str(result.get("redirect_url") or ""),
                })
    except Exception as exc:
        with _MAPPING_CONVERT_TASKS_LOCK:
            if task_id in _MAPPING_CONVERT_TASKS:
                _MAPPING_CONVERT_TASKS[task_id].update({
                    "done": True,
                    "ok": False,
                    "message": f"Mapping conversion encountered an unexpected error: {exc}",
                    "transcript": "",
                    "redirect_url": "",
                })
    finally:
        close_old_connections()


@login_required
@admin_required
def configured_onu_mapping_convert(request, olt_pk, slot, port, ont_id):
    olt = get_object_or_404(OLT, pk=olt_pk)
    locked_response = _deny_olt_access_if_locked(request, olt)
    if locked_response:
        return locked_response
    record = get_object_or_404(ConfiguredONU, olt=olt, slot=slot, port=port, ont_id=ont_id)
    plan = _build_onu_mapping_conversion_plan(record)
    detail_url = reverse("configured_onu_detail", kwargs={"olt_pk": olt.pk, "slot": slot, "port": port, "ont_id": ont_id})

    if not plan.get("ok"):
        messages.error(request, plan.get("message") or "Mapping conversion could not be prepared.")
        return redirect(detail_url)

    if request.method == "POST":
        if plan.get("warnings"):
            message = "Mapping conversion blocked: " + " ".join(plan.get("warnings") or [])
            if request.headers.get("X-Requested-With") == "XMLHttpRequest":
                return JsonResponse({"ok": False, "message": message}, status=400)
            messages.error(request, message)
            return redirect(detail_url)

        if request.headers.get("X-Requested-With") == "XMLHttpRequest":
            task_id = uuid.uuid4().hex[:20]
            now_ts = time.time()
            with _MAPPING_CONVERT_TASKS_LOCK:
                stale = [tid for tid, task in _MAPPING_CONVERT_TASKS.items() if now_ts - task.get("created_at", now_ts) > 900]
                for tid in stale:
                    _MAPPING_CONVERT_TASKS.pop(tid, None)
                _MAPPING_CONVERT_TASKS[task_id] = {
                    "done": False,
                    "ok": False,
                    "step": 0,
                    "label": "Preparing mapping conversion...",
                    "message": "",
                    "transcript": "",
                    "redirect_url": "",
                    "created_at": now_ts,
                }
            threading.Thread(
                target=_run_mapping_convert_bg_task,
                args=(task_id, olt.pk, record.pk, request.user.pk),
                name=f"mapping-convert-{task_id}",
                daemon=True,
            ).start()
            return JsonResponse({"ok": True, "task_id": task_id})

        result = _execute_onu_mapping_conversion(olt, record, plan, user=request.user)
        if result.get("ok"):
            messages.success(request, result.get("message") or f"ONU converted to {plan['target_label']}.")
            return redirect(result.get("redirect_url") or detail_url)
        messages.error(request, result.get("message") or "Mapping conversion failed.")
        if result.get("redirect_url"):
            return redirect(result["redirect_url"])
        return redirect(detail_url)

    return render(
        request,
        "oltmanager/configured_onu_mapping_convert.html",
        {
            "olt": olt,
            "record": record,
            "plan": plan,
            "back_url": detail_url,
        },
    )


@login_required
def configured_onu_mapping_convert_progress(request, task_id):
    with _MAPPING_CONVERT_TASKS_LOCK:
        task = dict(_MAPPING_CONVERT_TASKS.get(str(task_id) or "", {}) or {})
    if not task:
        return JsonResponse({"done": True, "ok": False, "message": "Task not found or expired."}, status=404)
    task.pop("created_at", None)
    return JsonResponse(task)


def _run_speed_profile_bg_task(task_id, olt, speed_kwargs, redirect_url):
    """Background thread: runs the speed-profile update and records live progress."""
    close_old_connections()

    def on_progress(step, label):
        with _SPEED_PROFILE_TASKS_LOCK:
            if task_id in _SPEED_PROFILE_TASKS:
                _SPEED_PROFILE_TASKS[task_id]["step"] = step
                _SPEED_PROFILE_TASKS[task_id]["label"] = label

    try:
        snapshot = execute_onu_speed_profile_config(olt, on_progress=on_progress, **speed_kwargs)
        ok = bool(snapshot.get("ok"))
        with _SPEED_PROFILE_TASKS_LOCK:
            if task_id in _SPEED_PROFILE_TASKS:
                _SPEED_PROFILE_TASKS[task_id].update({
                    "done": True,
                    "ok": ok,
                    "step": 5 if ok else _SPEED_PROFILE_TASKS[task_id].get("step", 0),
                    "label": "Done" if ok else _SPEED_PROFILE_TASKS[task_id].get("label", ""),
                    "message": _ui_telnet_error_message(snapshot.get("message")),
                    "transcript": str(snapshot.get("transcript") or ""),
                    "redirect_url": redirect_url if ok else "",
                })
    except Exception as exc:
        with _SPEED_PROFILE_TASKS_LOCK:
            if task_id in _SPEED_PROFILE_TASKS:
                _SPEED_PROFILE_TASKS[task_id].update({
                    "done": True,
                    "ok": False,
                    "message": f"Speed profile update encountered an unexpected error: {exc}",
                    "transcript": "",
                    "redirect_url": "",
                })
    finally:
        close_old_connections()


@login_required
def configured_onu_speed_profile_progress(request, task_id):
    with _SPEED_PROFILE_TASKS_LOCK:
        task = dict(_SPEED_PROFILE_TASKS.get(str(task_id) or "", {}) or {})
    if not task:
        return JsonResponse({"done": True, "ok": False, "message": "Task not found or expired."}, status=404)
    task.pop("created_at", None)
    return JsonResponse(task)


@login_required
@admin_required
def configured_onu_speed_profile_config(request, olt_pk, slot, port, ont_id, row_index):
    olt = get_object_or_404(OLT, pk=olt_pk)
    locked_response = _deny_olt_access_if_locked(request, olt)
    if locked_response:
        return locked_response
    record = get_object_or_404(ConfiguredONU, olt=olt, slot=slot, port=port, ont_id=ont_id)
    row_index = max(0, int(row_index))
    attached_vlans = [item.strip() for item in str(record.attached_vlans_cache or "").split(",") if item.strip()]
    olt_vlan_options = _olt_vlan_option_values(olt)
    # "untagged" must be selectable in BOTH the SVLAN and the User-VLAN (CVLAN)
    # dropdowns — Huawei accepts an untagged user-vlan on the service-port.
    if not any(str(v).lower() == "untagged" for v in olt_vlan_options):
        olt_vlan_options = olt_vlan_options + ["untagged"]
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
    speed_row_count = max(len(service_ports), len(service_vlans), len(user_vlans), len(download_indices), len(upload_indices), 1)

    def _align_short_index_cache(values, raw_value):
        if 0 < len(values) < speed_row_count and "," not in str(raw_value or ""):
            return ([""] * (speed_row_count - len(values))) + values
        return values

    download_indices = _align_short_index_cache(download_indices, record.download_profile_index_cache)
    upload_indices = _align_short_index_cache(upload_indices, record.upload_profile_index_cache)
    service_port_id = service_ports[row_index] if row_index < len(service_ports) else ""
    current_svlan = service_vlans[row_index] if row_index < len(service_vlans) else ""
    current_vlan = user_vlans[row_index] if row_index < len(user_vlans) else (attached_vlans[0] if attached_vlans else "")
    if current_svlan == current_vlan:
        current_svlan = ""
    current_download = download_indices[row_index] if row_index < len(download_indices) else ""
    current_upload = upload_indices[row_index] if row_index < len(upload_indices) else ""

    profiles = list(SpeedProfile.objects.filter(is_active=True).order_by("speed_mbps_value", "name"))
    download_options = []
    upload_options = []
    for profile in profiles:
        base_index = int(profile.index_number or 0)
        if base_index:
            download_options.append({
                "value": str(base_index),
                "label": profile.name,
                "selected": str(base_index) == str(current_download),
            })
            upload_options.append({
                "value": str(base_index + 1),
                "label": profile.name,
                "selected": str(base_index + 1) == str(current_upload),
            })

    response_message = ""
    transcript = ""
    is_ajax = request.headers.get("x-requested-with") == "XMLHttpRequest"
    if request.method == "POST":
        selected_vlan = str(request.POST.get("user_vlan") or "").strip()
        selected_svlan = str(request.POST.get("service_vlan") or "").strip() if request.POST.get("use_svlan") else ""
        selected_download = str(request.POST.get("download_speed") or "").strip()
        selected_upload = str(request.POST.get("upload_speed") or "").strip()
        detail_redirect = reverse("configured_onu_detail", kwargs={"olt_pk": olt.pk, "slot": slot, "port": port, "ont_id": ont_id})
        if not selected_vlan or not selected_download or not selected_upload:
            response_message = "Select VLAN and speed profiles."
            if is_ajax:
                return JsonResponse({"ok": False, "message": response_message, "transcript": ""}, status=400)
        else:
            speed_kwargs = dict(
                frame=0,
                slot=slot,
                port=port,
                ont_id=ont_id,
                service_port_id=service_port_id,
                user_vlan=selected_vlan,
                service_vlan=selected_svlan,
                download_profile_index=selected_download,
                upload_profile_index=selected_upload,
            )
            if is_ajax:
                # Async path: kick off a background worker and let the frontend
                # poll for real-time, step-by-step progress.
                import uuid
                task_id = uuid.uuid4().hex[:20]
                now_ts = time.time()
                with _SPEED_PROFILE_TASKS_LOCK:
                    stale = [tid for tid, t in _SPEED_PROFILE_TASKS.items() if now_ts - t.get("created_at", now_ts) > 600]
                    for tid in stale:
                        _SPEED_PROFILE_TASKS.pop(tid, None)
                    _SPEED_PROFILE_TASKS[task_id] = {
                        "done": False, "ok": False, "step": 0,
                        "label": "Opening OLT session...",
                        "message": "", "transcript": "", "redirect_url": "",
                        "created_at": now_ts,
                    }
                threading.Thread(
                    target=_run_speed_profile_bg_task,
                    args=(task_id, olt, speed_kwargs, detail_redirect),
                    name=f"speed-profile-{task_id}",
                    daemon=True,
                ).start()
                return JsonResponse({"ok": True, "task_id": task_id})

            # Synchronous fallback for non-AJAX submissions.
            snapshot = execute_onu_speed_profile_config(olt, **speed_kwargs)
            response_message = _ui_telnet_error_message(snapshot.get("message"))
            transcript = str(snapshot.get("transcript") or "")
            if snapshot.get("ok"):
                return redirect("configured_onu_detail", olt_pk=olt.pk, slot=slot, port=port, ont_id=ont_id)

    return render(
        request,
        "oltmanager/configured_onu_speed_profile_config.html",
        {
            "olt": olt,
            "record": record,
            "slot": slot,
            "port": port,
            "ont_id": ont_id,
            "row_index": row_index,
            "service_port_id": service_port_id,
            "current_svlan": current_svlan,
            "current_vlan": current_vlan,
            "olt_vlan_options": olt_vlan_options,
            "vlan_options": ([current_vlan] if current_vlan else (attached_vlans[:1] if attached_vlans else [])) + ["untagged"],
            "download_options": download_options,
            "upload_options": upload_options,
            "response_message": response_message,
            "transcript": transcript,
            "back_url": reverse("configured_onu_detail", kwargs={"olt_pk": olt.pk, "slot": slot, "port": port, "ont_id": ont_id}),
        },
    )


def _run_add_vlan_bg_task(task_id, olt, vlan_kwargs, redirect_url, duplicate_vlans):
    """Background thread: runs the ONU VLAN add and records live progress."""
    close_old_connections()

    def on_progress(step, label):
        with _SPEED_PROFILE_TASKS_LOCK:
            if task_id in _SPEED_PROFILE_TASKS:
                _SPEED_PROFILE_TASKS[task_id]["step"] = step
                _SPEED_PROFILE_TASKS[task_id]["label"] = label

    try:
        snapshot = execute_onu_add_service_vlan_config(
            olt,
            on_progress=on_progress,
            **vlan_kwargs,
        )
        ok = bool(snapshot.get("ok"))
        message = _ui_telnet_error_message(snapshot.get("message"))
        if ok and duplicate_vlans:
            message = f"{message} Skipped existing: {', '.join(duplicate_vlans)}"
        with _SPEED_PROFILE_TASKS_LOCK:
            if task_id in _SPEED_PROFILE_TASKS:
                _SPEED_PROFILE_TASKS[task_id].update({
                    "done": True,
                    "ok": ok,
                    "step": 5 if ok else _SPEED_PROFILE_TASKS[task_id].get("step", 0),
                    "label": "Done" if ok else _SPEED_PROFILE_TASKS[task_id].get("label", ""),
                    "message": message,
                    "transcript": str(snapshot.get("transcript") or ""),
                    "redirect_url": redirect_url if ok else "",
                })
    except Exception as exc:
        with _SPEED_PROFILE_TASKS_LOCK:
            if task_id in _SPEED_PROFILE_TASKS:
                _SPEED_PROFILE_TASKS[task_id].update({
                    "done": True,
                    "ok": False,
                    "message": f"VLAN add encountered an unexpected error: {exc}",
                    "transcript": "",
                    "redirect_url": "",
                })
    finally:
        close_old_connections()


def _remove_service_port_cache_row(record, service_port_id):
    if record is None:
        return False

    sp_id = str(service_port_id or "").strip()
    if not sp_id:
        return False

    cache_fields = [
        "service_port_id_cache",
        "attached_vlans_cache",
        "user_vlan_cache",
        "download_profile_index_cache",
        "upload_profile_index_cache",
        "download_profile_name_cache",
        "upload_profile_name_cache",
    ]

    def _split(value):
        text = str(value or "")
        if not text.strip():
            return []
        return [part.strip() for part in text.split(",")]

    values_by_field = {field: _split(getattr(record, field, "")) for field in cache_fields}
    service_ports = values_by_field["service_port_id_cache"]
    try:
        row_index = service_ports.index(sp_id)
    except ValueError:
        return False

    row_count = max([len(values) for values in values_by_field.values()] + [row_index + 1])
    for field, values in values_by_field.items():
        if len(values) < row_count:
            values.extend([""] * (row_count - len(values)))
        values.pop(row_index)

    while any(values_by_field.values()):
        last_index = max(len(values) for values in values_by_field.values()) - 1
        if last_index < 0:
            break
        if any((values[last_index] if last_index < len(values) else "").strip() for values in values_by_field.values()):
            break
        for values in values_by_field.values():
            if last_index < len(values):
                values.pop()

    for field, values in values_by_field.items():
        setattr(record, field, ",".join(values)[:255])
    record.save(update_fields=cache_fields)
    return True


@login_required
@admin_required
@require_POST
def configured_onu_service_port_delete(request, olt_pk, slot, port, ont_id):
    olt = get_object_or_404(OLT, pk=olt_pk)
    locked_response = _deny_olt_access_if_locked(request, olt)
    if locked_response:
        return locked_response
    record = ConfiguredONU.objects.filter(olt=olt, slot=slot, port=port, ont_id=ont_id).first()
    sp_id = str(request.POST.get("service_port_id") or "").strip()
    is_ajax = request.headers.get("x-requested-with") == "XMLHttpRequest"
    detail_redirect = reverse("configured_onu_detail", kwargs={"olt_pk": olt.pk, "slot": slot, "port": port, "ont_id": ont_id})

    cache_ids = [x.strip() for x in str(getattr(record, "service_port_id_cache", "") if record is not None else "").split(",") if x.strip()]
    if not sp_id.isdigit() or (cache_ids and sp_id not in cache_ids):
        msg = "Invalid service-port for this ONU."
        if is_ajax:
            return JsonResponse({"ok": False, "message": msg}, status=400)
        messages.error(request, msg)
        return redirect(detail_redirect)

    snapshot = execute_onu_delete_service_port(
        olt, slot, port, ont_id, sp_id, frame=(record.frame if record is not None else 0),
    )
    message = _ui_telnet_error_message(snapshot.get("message"))
    if snapshot.get("ok"):
        _remove_service_port_cache_row(record, sp_id)
        # Re-read the ONU so the service-port row and the attached-VLAN list both
        # drop accurately (the deleted VLAN disappears when nothing else uses it).
        if not snapshot.get("not_found"):
            try:
                sync_single_onu_attached_vlans(olt, slot, port, ont_id, record=record, allow_empty_overwrite=True)
            except Exception:
                pass
        _record_olt_login(
            olt, request.user, "delete_service_port",
            f"Service-port {sp_id} deleted: 0/{int(slot)}/{int(port)} ont {int(ont_id)}",
            request=request, onu=f"0/{int(slot)}/{int(port)}:{int(ont_id)}",
        )
        if is_ajax:
            return JsonResponse({"ok": True, "message": message, "redirect_url": detail_redirect})
        messages.success(request, message)
        return redirect(detail_redirect)

    if is_ajax:
        return JsonResponse({"ok": False, "message": message, "transcript": str(snapshot.get("transcript") or "")}, status=400)
    messages.error(request, message)
    return redirect(detail_redirect)


@login_required
@admin_required
def configured_onu_add_vlan(request, olt_pk, slot, port, ont_id):
    olt = get_object_or_404(OLT, pk=olt_pk)
    locked_response = _deny_olt_access_if_locked(request, olt)
    if locked_response:
        return locked_response
    record = get_object_or_404(ConfiguredONU, olt=olt, slot=slot, port=port, ont_id=ont_id)
    existing_vlans = [item.strip() for item in str(record.attached_vlans_cache or "").split(",") if item.strip()]
    existing_user_vlans = [item.strip() for item in str(record.user_vlan_cache or "").split(",") if item.strip()]
    existing_service_ports = [item.strip() for item in str(record.service_port_id_cache or "").split(",") if item.strip()]
    is_vlan_mapping = str(getattr(record, "mapping_mode_cache", "") or "").strip().lower() == "vlan"
    vlan_mapping_max_vlans = 8
    vlan_mapping_existing_count = max(len(existing_vlans), len(existing_user_vlans), len(existing_service_ports))
    vlan_mapping_remaining = max(vlan_mapping_max_vlans - vlan_mapping_existing_count, 0)
    vlan_options = _olt_vlan_option_values(olt)
    if not vlan_options:
        vlan_options = existing_vlans[:]

    profiles = list(SpeedProfile.objects.filter(is_active=True).order_by("speed_mbps_value", "name"))
    download_options = []
    upload_options = []
    for profile in profiles:
        base_index = int(profile.index_number or 0)
        if base_index:
            download_options.append({"value": str(base_index), "label": profile.name})
            upload_options.append({"value": str(base_index + 1), "label": profile.name})

    response_message = ""
    transcript = ""
    is_ajax = request.headers.get("x-requested-with") == "XMLHttpRequest"
    if request.method == "POST":
        requested_vlans = []
        for item in request.POST.getlist("vlan_ids"):
            text = str(item or "").strip()
            if text and text not in requested_vlans:
                requested_vlans.append(text)
        selected_vlans = requested_vlans[:]
        selected_download = str(request.POST.get("download_speed") or "").strip()
        selected_upload = str(request.POST.get("upload_speed") or "").strip()
        existing_compare_vlans = set(existing_vlans) | set(existing_user_vlans)
        duplicate_vlans = [item for item in selected_vlans if item in existing_compare_vlans]
        selected_vlans = [item for item in selected_vlans if item not in existing_compare_vlans]
        detail_redirect = reverse("configured_onu_detail", kwargs={"olt_pk": olt.pk, "slot": slot, "port": port, "ont_id": ont_id})
        if is_vlan_mapping and len(selected_vlans) > vlan_mapping_remaining:
            response_message = f"VLAN Mapping supports a maximum of {vlan_mapping_max_vlans} VLANs. You can add {vlan_mapping_remaining} more."
            if is_ajax:
                return JsonResponse({"ok": False, "message": response_message, "transcript": ""}, status=400)
            selected_vlans = []
        if (not selected_vlans and not (is_vlan_mapping and requested_vlans)) or not selected_download or not selected_upload:
            response_message = response_message or "Select VLAN and speed profiles."
            if is_ajax:
                return JsonResponse({"ok": False, "message": response_message, "transcript": ""}, status=400)
        else:
            vlan_kwargs = dict(
                frame=0,
                slot=slot,
                port=port,
                ont_id=ont_id,
                vlan_ids=selected_vlans,
                line_profile_vlan_ids=requested_vlans if is_vlan_mapping else selected_vlans,
                download_profile_index=selected_download,
                upload_profile_index=selected_upload,
            )
            if is_ajax:
                # Async path: background worker + real-time progress polling.
                import uuid
                task_id = uuid.uuid4().hex[:20]
                now_ts = time.time()
                with _SPEED_PROFILE_TASKS_LOCK:
                    stale = [tid for tid, t in _SPEED_PROFILE_TASKS.items() if now_ts - t.get("created_at", now_ts) > 600]
                    for tid in stale:
                        _SPEED_PROFILE_TASKS.pop(tid, None)
                    _SPEED_PROFILE_TASKS[task_id] = {
                        "done": False, "ok": False, "step": 0,
                        "label": "Opening OLT session...",
                        "message": "", "transcript": "", "redirect_url": "",
                        "created_at": now_ts,
                    }
                threading.Thread(
                    target=_run_add_vlan_bg_task,
                    args=(task_id, olt, vlan_kwargs, detail_redirect, duplicate_vlans),
                    name=f"add-vlan-{task_id}",
                    daemon=True,
                ).start()
                return JsonResponse({"ok": True, "task_id": task_id})

            # Synchronous fallback for non-AJAX submissions.
            snapshot = execute_onu_add_service_vlan_config(olt, **vlan_kwargs)
            response_message = _ui_telnet_error_message(snapshot.get("message"))
            if duplicate_vlans and snapshot.get("ok"):
                response_message = f"{response_message} Skipped existing: {', '.join(duplicate_vlans)}"
            transcript = str(snapshot.get("transcript") or "")
            if snapshot.get("ok"):
                return redirect(detail_redirect)

    return render(
        request,
        "oltmanager/configured_onu_add_vlan.html",
        {
            "olt": olt,
            "record": record,
            "slot": slot,
            "port": port,
            "ont_id": ont_id,
            "vlan_options": vlan_options,
            "download_options": download_options,
            "upload_options": upload_options,
            "is_vlan_mapping": is_vlan_mapping,
            "vlan_mapping_max_vlans": vlan_mapping_max_vlans,
            "vlan_mapping_existing_count": vlan_mapping_existing_count,
            "vlan_mapping_remaining": vlan_mapping_remaining,
            "response_message": response_message,
            "transcript": transcript,
            "back_url": reverse("configured_onu_detail", kwargs={"olt_pk": olt.pk, "slot": slot, "port": port, "ont_id": ont_id}),
        },
    )


def _olt_vlan_option_values(olt):
    values = []
    for row in list(getattr(olt, "vlan_cache", []) or []):
        vlan_id = str(row.get("vlan_id") or "").strip()
        if vlan_id and vlan_id.isdigit() and vlan_id not in values:
            values.append(vlan_id)
    return values


@login_required
@admin_required
def configured_onu_ethernet_port_config(request, olt_pk, slot, port, ont_id, eth_port):
    olt = get_object_or_404(OLT, pk=olt_pk)
    locked_response = _deny_olt_access_if_locked(request, olt)
    if locked_response:
        return locked_response
    record = get_object_or_404(ConfiguredONU, olt=olt, slot=slot, port=port, ont_id=ont_id)
    is_ajax = request.headers.get("x-requested-with") == "XMLHttpRequest"
    attached_vlans = [item.strip() for item in str(record.attached_vlans_cache or "").split(",") if item.strip()]
    port_config_map = _load_ethernet_port_config_cache(record)
    port_config = port_config_map.get(str(eth_port), {}) if isinstance(port_config_map, dict) else {}
    selected_status = str(port_config.get("status") or "").strip().lower() or "enabled"
    selected_mode = str(port_config.get("mode") or "").strip().lower() or "lan"
    selected_allowed_vlans = [item.strip() for item in str(port_config.get("allowed_vlans") or "").split(",") if item.strip()]
    current_vlan = str(port_config.get("vlan") or "").strip() or str(record.user_vlan_cache or "").strip() or (attached_vlans[0] if attached_vlans else "")
    vlan_options = attached_vlans[:] if attached_vlans else []
    if not vlan_options and current_vlan and current_vlan != "1":
        vlan_options = [current_vlan]
    if current_vlan and current_vlan not in vlan_options and current_vlan != "1":
        vlan_options.append(current_vlan)
    allowed_vlans = vlan_options[:]
    response_message = ""
    if selected_mode == "transparent" and current_vlan == "1":
        current_vlan = vlan_options[0] if vlan_options else ""
    if request.method == "POST":
        action_ok = False
        selected_status = str(request.POST.get("status") or "enabled").strip().lower() or "enabled"
        selected_mode = str(request.POST.get("mode") or "lan").strip().lower() or "lan"
        current_vlan = str(request.POST.get("vlan_id") or "").strip()
        selected_allowed_vlans = [item.strip() for item in request.POST.getlist("allowed_vlans") if item.strip()]
        prev_status = str(port_config.get("status") or "enabled").strip().lower()
        status_changed = selected_status != prev_status

        if selected_mode == "access":
            if not current_vlan:
                response_message = "Select VLAN-ID"
            else:
                snapshot = execute_onu_ethernet_port_access_config(olt, slot, port, ont_id, eth_port, current_vlan)
                response_message = _ui_telnet_error_message(snapshot.get("message"))
                if snapshot.get("ok"):
                    action_ok = True
                    port_config_map[str(eth_port)] = {
                        "status": selected_status,
                        "mode": "access",
                        "vlan": str(snapshot.get("verified_vlan") or current_vlan).strip(),
                        "allowed_vlans": "",
                    }
                    _save_ethernet_port_config_cache(record, port_config_map)
                    current_vlan = str(snapshot.get("verified_vlan") or current_vlan).strip()
        elif selected_mode == "transparent":
            snapshot = execute_onu_ethernet_port_transparent_config(olt, slot, port, ont_id, eth_port)
            response_message = _ui_telnet_error_message(snapshot.get("message"))
            if snapshot.get("ok"):
                action_ok = True
                port_config_map[str(eth_port)] = {
                    "status": selected_status,
                    "mode": "transparent",
                    "vlan": "1",
                    "allowed_vlans": "",
                }
                _save_ethernet_port_config_cache(record, port_config_map)
        elif selected_mode == "lan":
            snapshot = execute_onu_ethernet_port_lan_config(olt, slot, port, ont_id, eth_port)
            response_message = _ui_telnet_error_message(snapshot.get("message"))
            if snapshot.get("ok"):
                action_ok = True
                port_config_map[str(eth_port)] = {
                    "status": selected_status,
                    "mode": "lan",
                    "vlan": "",
                    "allowed_vlans": "",
                }
                _save_ethernet_port_config_cache(record, port_config_map)
        elif selected_mode == "trunk":
            if not selected_allowed_vlans:
                response_message = "Select at least one VLAN for trunk mode."
            else:
                snapshot = execute_onu_ethernet_port_trunk_config(
                    olt, slot, port, ont_id, eth_port, selected_allowed_vlans
                )
                response_message = _ui_telnet_error_message(snapshot.get("message"))
                if snapshot.get("ok"):
                    action_ok = True
                    port_config_map[str(eth_port)] = {
                        "status": selected_status,
                        "mode": "trunk",
                        "vlan": "",
                        "allowed_vlans": ",".join(selected_allowed_vlans),
                    }
                    _save_ethernet_port_config_cache(record, port_config_map)

        # Apply ethernet port admin state via CLI whenever status changed OR when
        # explicitly setting shutdown, regardless of whether mode config succeeded.
        if status_changed or selected_status == "shutdown":
            cli_state = "shutdown" if selected_status in ("shutdown", "disabled") else "enabled"
            cli_result = execute_onu_eth_port_cli_admin_state(
                olt, slot, port, ont_id, eth_port, cli_state
            )
            if cli_result.get("ok"):
                # Update cached status even if mode config didn't run
                existing = port_config_map.get(str(eth_port)) or {}
                existing["status"] = selected_status
                port_config_map[str(eth_port)] = existing
                _save_ethernet_port_config_cache(record, port_config_map)
                if not action_ok:
                    action_ok = True
                    response_message = cli_result.get("message") or ""
            elif not action_ok:
                response_message = _ui_telnet_error_message(cli_result.get("message")) or response_message

        if is_ajax:
            return JsonResponse(
                {
                    "ok": action_ok,
                    "message": response_message,
                    "redirect_url": reverse("configured_onu_detail", kwargs={"olt_pk": olt.pk, "slot": slot, "port": port, "ont_id": ont_id}) if action_ok else "",
                },
                status=200,
            )
    return render(
        request,
        "oltmanager/configured_onu_ethernet_port_config.html",
        {
            "olt": olt,
            "record": record,
            "slot": slot,
            "port": port,
            "ont_id": ont_id,
            "eth_port": eth_port,
            "current_vlan": current_vlan,
            "vlan_options": vlan_options,
            "allowed_vlans": allowed_vlans,
            "response_message": response_message,
            "selected_status": selected_status,
            "selected_mode": selected_mode,
            "selected_allowed_vlans": selected_allowed_vlans,
            "back_url": reverse("configured_onu_detail", kwargs={"olt_pk": olt.pk, "slot": slot, "port": port, "ont_id": ont_id}),
        },
    )


@login_required
@require_POST
def configured_onu_mac_address(request, olt_pk, slot, port, ont_id):
    olt = get_object_or_404(OLT, pk=olt_pk)
    locked_response = _deny_olt_access_if_locked(request, olt)
    if locked_response:
        return locked_response
    snapshot = fetch_single_ont_mac_addresses(olt, slot, port, ont_id)
    status_code = 200 if snapshot.get("ok") else 400
    message = _ui_telnet_error_message(snapshot.get("message"))
    return JsonResponse(
        {
            "ok": bool(snapshot.get("ok")),
            "output": str(snapshot.get("output") or ""),
            "message": message,
            "command": str(snapshot.get("command") or ""),
        },
        status=status_code,
    )


@login_required
@require_POST
def configured_onu_live_status(request, olt_pk, slot, port, ont_id):
    olt = get_object_or_404(OLT, pk=olt_pk)
    locked_response = _deny_olt_access_if_locked(request, olt)
    if locked_response:
        return locked_response
    snapshot = fetch_single_ont_live_status(olt, slot, port, ont_id)
    status_code = 200 if snapshot.get("ok") else 400
    message = _ui_telnet_error_message(snapshot.get("message"))
    return JsonResponse(
        {
            "ok": bool(snapshot.get("ok")),
            "output": str(snapshot.get("output") or ""),
            "message": message,
            "command": str(snapshot.get("command") or ""),
        },
        status=status_code,
    )


@login_required
@require_POST
def configured_onu_running_config(request, olt_pk, slot, port, ont_id):
    olt = get_object_or_404(OLT, pk=olt_pk)
    locked_response = _deny_olt_access_if_locked(request, olt)
    if locked_response:
        return locked_response
    record = ConfiguredONU.objects.filter(olt=olt, slot=slot, port=port, ont_id=ont_id).first()
    snapshot = fetch_single_ont_running_config(
        olt,
        slot,
        port,
        ont_id,
        expected_sn=(getattr(record, "sn", "") if record is not None else ""),
    )
    status_code = 200 if snapshot.get("ok") else 400
    message = _ui_telnet_error_message(snapshot.get("message"))
    return JsonResponse(
        {
            "ok": bool(snapshot.get("ok")),
            "output": str(snapshot.get("output") or ""),
            "message": message,
            "command": str(snapshot.get("command") or ""),
        },
        status=status_code,
    )


@login_required
@require_POST
def configured_onu_last_down_history(request, olt_pk, slot, port, ont_id):
    olt = get_object_or_404(OLT, pk=olt_pk)
    locked_response = _deny_olt_access_if_locked(request, olt)
    if locked_response:
        return locked_response
    record = ConfiguredONU.objects.filter(olt=olt, slot=slot, port=port, ont_id=ont_id).first()
    snapshot = fetch_single_ont_last_down_history(
        olt,
        slot,
        port,
        ont_id,
        frame=(getattr(record, "frame", 0) if record is not None else 0),
    )
    status_code = 200 if snapshot.get("ok") else 400
    message = _ui_telnet_error_message(snapshot.get("message"))
    return JsonResponse(
        {
            "ok": bool(snapshot.get("ok")),
            "output": str(snapshot.get("output") or ""),
            "message": message,
            "command": str(snapshot.get("command") or ""),
        },
        status=status_code,
    )


@login_required
@require_POST
def configured_onu_fetch_config(request, olt_pk, slot, port, ont_id):
    """Read this ONU's live service-port/VLAN/profile config from the OLT and update the DB.

    Runs the exact ONU service-port lookup via `sync_single_onu_attached_vlans`,
    then parses VLANs, service-port IDs and speed profiles into cache fields.
    Returns whether anything changed so the UI can say "updated" vs "already in sync".
    """
    olt = get_object_or_404(OLT, pk=olt_pk)
    locked_response = _deny_olt_access_if_locked(request, olt)
    if locked_response:
        return locked_response
    result = sync_single_onu_attached_vlans(olt, slot, port, ont_id)
    ok = bool(result.get("ok"))
    updated = bool(result.get("updated"))
    details = result.get("details") or {}
    vlan_summary = str(result.get("vlan_value") or "").strip()
    service_ports = ", ".join(str(sp) for sp in (details.get("service_port_ids") or []) if str(sp).strip())
    download_profiles = ", ".join(str(name) for name in (details.get("download_profile_names") or []) if str(name).strip())
    upload_profiles = ", ".join(str(name) for name in (details.get("upload_profile_names") or []) if str(name).strip())
    if ok:
        message = "Config updated from OLT." if updated else "Config already in sync - no change."
    else:
        message = _ui_telnet_error_message(result.get("status")) or "Could not fetch current config."
    return JsonResponse(
        {
            "ok": ok,
            "updated": updated,
            "message": message,
            "attached_vlans": vlan_summary,
            "service_ports": service_ports,
            "download_profiles": download_profiles,
            "upload_profiles": upload_profiles,
        },
        status=200 if ok else 400,
    )


@login_required
@require_POST
@admin_required
def configured_onu_action(request, olt_pk, slot, port, ont_id, action):
    olt = get_object_or_404(OLT, pk=olt_pk)
    locked_response = _deny_olt_access_if_locked(request, olt)
    if locked_response:
        return locked_response
    record = ConfiguredONU.objects.filter(olt=olt, slot=slot, port=port, ont_id=ont_id).first()
    action_key = str(action or "").strip().lower()
    redirect_url = ""

    if action_key == "delete":
        service_port_ids = []
        if record is not None:
            service_port_ids = [part.strip() for part in str(record.service_port_id_cache or "").split(",") if part.strip()]

        frame_value = record.frame if record is not None else 0

        snapshot = execute_onu_cli_delete_action(
            olt,
            slot,
            port,
            ont_id,
            frame=frame_value,
            service_port_ids=service_port_ids,
        )

        if snapshot.get("ok"):
            if record is not None:
                record.delete()
            _schedule_autofind_rows_refresh(int(olt.pk))
            _schedule_autofind_counts_refresh(int(olt.pk))
            _record_olt_login(
                olt,
                request.user,
                "delete_onu",
                f"ONU deleted via CLI: 0/{int(slot)}/{int(port)} ont {int(ont_id)}",
                request=request,
                onu=f"0/{int(slot)}/{int(port)}:{int(ont_id)}",
            )
            redirect_url = reverse("unconfigured_onus")
        status_code = 200 if snapshot.get("ok") else 400
        return JsonResponse(
            {
                "ok": bool(snapshot.get("ok")),
                "message": _ui_telnet_error_message(snapshot.get("message")),
                "action": action_key,
                "redirect_url": redirect_url,
                "transcript": str(snapshot.get("transcript") or ""),
                "status_value": "",
                "status_label": "",
                "status_class": "",
            },
            status=status_code,
        )

    snapshot = execute_onu_snmp_control_action(olt, slot, port, ont_id, action)
    if snapshot.get("ok") and record is not None:
        now = timezone.now()
        if action_key == "disable":
            record.control_flag = "disabled"
            record.run_state = "offline"
            record.derived_status = "admin_disabled"
            record.status_source = "snmp_write"
        elif action_key == "enable":
            record.control_flag = ""
            record.run_state = "offline"
            record.derived_status = "offline"
            record.status_source = "snmp_write"
        elif action_key in {"restart", "reset"}:
            record.run_state = "offline"
            if str(record.derived_status or "").strip().lower() != "admin_disabled":
                record.derived_status = "offline"
            record.status_source = "snmp_write"
        record.status_first_seen_at = now
        record.status_updated_at = now
        record.save(update_fields=["control_flag", "run_state", "derived_status", "status_source", "status_first_seen_at", "status_updated_at"])
    status_code = 200 if snapshot.get("ok") else 400
    return JsonResponse(
        {
            "ok": bool(snapshot.get("ok")),
            "message": _ui_telnet_error_message(snapshot.get("message")),
            "oid": str(snapshot.get("oid") or ""),
            "value": str(snapshot.get("value") or ""),
            "action": str(action or ""),
            "status_value": (record.derived_status if record is not None else ""),
            "status_label": (_configured_status_label(record.derived_status, run_state=record.run_state) if record is not None else ""),
            "status_class": (_configured_status_class(record.derived_status, run_state=record.run_state) if record is not None else ""),
        },
        status=status_code,
    )


@login_required
def settings_home(request):
    return render(request, "oltmanager/settings_home.html")


@login_required
@admin_required
def settings_billing(request):
    now = timezone.now()
    rows = []
    olts = (
        OLT.objects.only(
            "id",
            "name",
            "ip_address",
            "pricing_mode",
            "pricing_expires_at",
            "pricing_locked",
            "pricing_locked_reason",
        )
        .order_by("name")
    )
    for olt in olts:
        expires_at = olt.pricing_expires_at
        if not expires_at:
            days_label = "No expiry"
            days_class = "neutral"
        elif expires_at <= now:
            days_label = "Expired"
            days_class = "bad"
        else:
            seconds_left = max(0, int((expires_at - now).total_seconds()))
            days_left = max(1, (seconds_left + 86399) // 86400)
            days_label = f"{days_left} day{'s' if days_left != 1 else ''}"
            days_class = "warn" if days_left <= 2 else "good"

        rows.append(
            {
                "olt": olt,
                "package": olt.get_pricing_mode_display(),
                "package_class": str(olt.pricing_mode or "").strip().lower() or "standard",
                "expires_at": expires_at,
                "days_label": days_label,
                "days_class": days_class,
                "status": olt.pricing_status_label,
                "locked": olt.pricing_access_locked,
            }
        )

    return render(
        request,
        "oltmanager/settings_billing.html",
        {
            "rows": rows,
            "generated_at": now,
        },
    )


def _report_parse_dbm(value):
    text = str(value or "").strip()
    if not text or text in {"--", "-"}:
        return None
    match = re.search(r"(-?\d+(?:\.\d+)?)", text)
    if not match:
        return None
    try:
        return float(match.group(1))
    except (TypeError, ValueError):
        return None


@login_required
def health_report(request):
    """Daily network health report: per-OLT and overall snapshot of ONU status,
    signal quality, new activations, reachability and active alerts."""
    from .models import AlertEvent

    now = timezone.now()
    today = timezone.localdate()
    day_ago = now - timezone.timedelta(hours=24)

    olts = list(OLT.objects.filter(is_ready=True).order_by("name"))
    olt_ids = [o.id for o in olts]

    # Pull every ONU once, bucket in Python (avoids N per-OLT queries).
    onus = list(
        ConfiguredONU.objects.filter(olt_id__in=olt_ids).only(
            "olt_id", "slot", "port", "ont_id", "derived_status", "signal_bucket",
            "onu_rx", "description", "configured_via_app", "created_at",
        )
    )

    def _blank_stat():
        return {
            "total": 0, "online": 0, "offline": 0, "admin_disabled": 0,
            "power_failure": 0, "loss_of_signal": 0,
            "sig_good": 0, "sig_warn": 0, "sig_bad": 0,
            "new_today": 0,
        }

    per_olt = {oid: _blank_stat() for oid in olt_ids}
    totals = _blank_stat()
    worst_signals = []  # (dbm, olt_name, slot, port, ont_id, desc)

    olt_name_by_id = {o.id: o.name for o in olts}

    for onu in onus:
        for bucket in (per_olt.get(onu.olt_id), totals):
            if bucket is None:
                continue
            bucket["total"] += 1
            ds = str(onu.derived_status or "").strip().lower() or "offline"
            if ds == "online":
                bucket["online"] += 1
            elif ds == "admin_disabled":
                bucket["admin_disabled"] += 1
            else:
                bucket["offline"] += 1
                if ds == "power_failure":
                    bucket["power_failure"] += 1
                elif ds == "loss_of_signal":
                    bucket["loss_of_signal"] += 1
            sb = str(onu.signal_bucket or "").strip().lower()
            if sb == "good":
                bucket["sig_good"] += 1
            elif sb == "warn":
                bucket["sig_warn"] += 1
            elif sb == "bad":
                bucket["sig_bad"] += 1
            if onu.configured_via_app and onu.created_at and timezone.localtime(onu.created_at).date() == today:
                bucket["new_today"] += 1

        # Worst-signal candidates: online ONUs with a readable Rx power.
        if str(onu.derived_status or "").lower() == "online":
            dbm = _report_parse_dbm(onu.onu_rx)
            if dbm is not None:
                worst_signals.append({
                    "dbm": dbm,
                    "olt": olt_name_by_id.get(onu.olt_id, "-"),
                    "loc": f"0/{onu.slot}/{onu.port}:{onu.ont_id}",
                    "desc": onu.description or "",
                })

    worst_signals.sort(key=lambda r: r["dbm"])
    worst_signals = worst_signals[:10]

    # Per-OLT reachability from the latest SNMP probe status.
    olt_rows = []
    reachable_count = 0
    for o in olts:
        status = str(o.snmp_last_status or "").lower()
        unreachable = ("down" in status) or ("unreachable" in status)
        if not unreachable:
            reachable_count += 1
        stat = per_olt.get(o.id, _blank_stat())
        health_pct = int(round(stat["online"] * 100 / stat["total"])) if stat["total"] else 0
        olt_rows.append({
            "name": o.name,
            "ip": o.ip_address,
            "reachable": not unreachable,
            "status_text": o.snmp_last_status or "—",
            "temp": o.dashboard_temperature or "—",
            "uptime": o.dashboard_uptime or "—",
            "health_pct": health_pct,
            **stat,
        })

    # Alerts.
    active_alerts = list(
        AlertEvent.objects.filter(is_active=True).select_related("olt").order_by("-created_at")[:50]
    )
    sev_counts = {"critical": 0, "warning": 0, "info": 0}
    for a in active_alerts:
        sev_counts[a.severity] = sev_counts.get(a.severity, 0) + 1
    alerts_24h = AlertEvent.objects.filter(created_at__gte=day_ago).count()
    fiber_cut_active = [a for a in active_alerts if a.alert_type == "fiber_cut"]
    degrade_active = [a for a in active_alerts if a.alert_type == "signal_degrade"]

    context = {
        "generated_at": now,
        "today": today,
        "totals": totals,
        "olt_rows": olt_rows,
        "olt_count": len(olts),
        "reachable_count": reachable_count,
        "unreachable_count": len(olts) - reachable_count,
        "worst_signals": worst_signals,
        "active_alerts": active_alerts,
        "active_alert_count": len(active_alerts),
        "sev_counts": sev_counts,
        "alerts_24h": alerts_24h,
        "fiber_cut_active": fiber_cut_active,
        "degrade_active": degrade_active,
        "overall_health_pct": int(round(totals["online"] * 100 / totals["total"])) if totals["total"] else 0,
    }
    return render(request, "oltmanager/health_report.html", context)


@login_required
@admin_required
def settings_alerts(request):
    from .models import AlertConfig, AlertEvent

    cfg = AlertConfig.get()
    if request.method == "POST":
        action = (request.POST.get("action") or "").strip()
        if action == "clear_resolved":
            AlertEvent.objects.filter(is_active=False).delete()
            messages.success(request, "Resolved alerts cleared.")
            return redirect(f"{reverse('settings_alerts')}?show={request.POST.get('show') or 'active'}")

        cfg.notify_olt_down = bool(request.POST.get("notify_olt_down"))
        cfg.notify_olt_recovered = bool(request.POST.get("notify_olt_recovered"))
        cfg.notify_high_temp = bool(request.POST.get("notify_high_temp"))
        cfg.notify_fiber_cut = bool(request.POST.get("notify_fiber_cut"))
        cfg.notify_signal_degrade = bool(request.POST.get("notify_signal_degrade"))

        def _to_int(name, default, lo=1, hi=None):
            try:
                value = max(lo, int(request.POST.get(name) or default))
            except (TypeError, ValueError):
                return default
            return min(hi, value) if hi is not None else value

        cfg.temp_threshold_c = _to_int("temp_threshold_c", 60)
        cfg.fiber_cut_min_onus = _to_int("fiber_cut_min_onus", 4, lo=2)
        cfg.fiber_cut_ratio = _to_int("fiber_cut_ratio", 60, lo=1, hi=100)
        cfg.signal_degrade_drop_db = _to_int("signal_degrade_drop_db", 3, lo=1)
        cfg.save()
        messages.success(request, "Alert settings saved.")
        return redirect("settings_alerts")

    show = (request.GET.get("show") or "active").strip().lower()
    alerts_qs = AlertEvent.objects.select_related("olt").order_by("-created_at")
    if show == "active":
        alerts_qs = alerts_qs.filter(is_active=True)
    alerts = list(alerts_qs[:100])
    return render(
        request,
        "oltmanager/settings_alerts.html",
        {
            "cfg": cfg,
            "alerts": alerts,
            "show": show,
            "active_alert_count": AlertEvent.objects.filter(is_active=True).count(),
        },
    )


@login_required
@admin_required
def settings_users(request):
    User = get_user_model()
    account_types = {"admin": "Admin", "standard": "Standard"}
    form_data = {}
    errors = []

    if request.method == "POST":
        form_data = {
            "name": (request.POST.get("name") or "").strip(),
            "userid": (request.POST.get("userid") or "").strip(),
            "account_type": (request.POST.get("account_type") or "").strip().lower(),
        }
        password = request.POST.get("password") or ""

        if not form_data["name"]:
            errors.append("Name is required.")
        if not form_data["userid"]:
            errors.append("User ID is required.")
        if not password:
            errors.append("Password is required.")
        if form_data["account_type"] not in account_types:
            errors.append("Account type is required.")
        if form_data["userid"] and User.objects.filter(username__iexact=form_data["userid"]).exists():
            errors.append("This user ID already exists.")

        if not errors:
            is_admin_account = form_data["account_type"] == "admin"
            user = User.objects.create_user(
                username=form_data["userid"],
                password=password,
                first_name=form_data["name"],
                is_staff=is_admin_account,
                is_superuser=False,
            )
            messages.success(request, f"{account_types[form_data['account_type']]} user {user.username} created.")
            return redirect("settings_users")

    users = User.objects.order_by("-is_superuser", "-is_staff", "username")
    return render(
        request,
        "oltmanager/settings_users.html",
        {
            "users": users,
            "form_data": form_data,
            "errors": errors,
            "account_types": account_types,
        },
    )


@lru_cache(maxsize=1)
def _load_onu_type_catalog_rows():
    catalog_path = Path(__file__).resolve().parent / "onu_types_catalog.tsv"
    rows = []
    if not catalog_path.exists():
        return rows
    with catalog_path.open("r", encoding="utf-8", errors="ignore") as handle:
        reader = csv.DictReader(handle, delimiter="\t")
        for index, row in enumerate(reader, start=300):
            if not row:
                continue
            rows.append(
                {
                    "serial_no": index,
                    "pon_type": (row.get("PON type") or "").strip(),
                    "channels": (row.get("Channels") or "").strip(),
                    "onu_type": (row.get("ONU type") or "").strip(),
                    "ethernet_ports": (row.get("Ethernet ports") or "").strip(),
                    "wifi": (row.get("WiFi") or "").strip(),
                    "voip_ports": (row.get("VoIP ports") or "").strip(),
                    "catv": (row.get("CATV") or "").strip(),
                    "allow_custom_profiles": (row.get("Allow custom profiles") or "").strip(),
                    "capability": (row.get("Capability") or "").strip(),
                }
            )
    return tuple(rows)


@lru_cache(maxsize=1)
def _load_onu_type_option_rows():
    options = []
    for row in _load_onu_type_catalog_rows():
        onu_type_value = str(row.get("onu_type") or "").strip()
        if not onu_type_value:
            continue
        options.append(
            {
                "value": onu_type_value,
                "label": _format_solt_onu_type_name(onu_type_value),
                "serial_no": int(row.get("serial_no") or 0),
                "ethernet_ports": str(row.get("ethernet_ports") or "").strip(),
                "voip_ports": str(row.get("voip_ports") or "").strip(),
                "catv": str(row.get("catv") or "").strip(),
                "capability": str(row.get("capability") or "").strip(),
            }
        )
    return tuple(options)


@lru_cache(maxsize=1)
def _load_onu_type_catv_lookup():
    def _norm(value):
        return re.sub(r"[^A-Z0-9]+", "", str(value or "").replace("_SOLT", "").upper())

    catalog = {}
    for item in _load_onu_type_option_rows():
        for key_source in (item.get("value"), item.get("label")):
            key = _norm(key_source)
            if key:
                catalog[key] = item
    return catalog


@login_required
@admin_required
def settings_onu_types(request):
    rows = _load_onu_type_catalog_rows()
    counts = {}
    for item in ConfiguredONU.objects.exclude(onu_type_cache="").values("onu_type_cache").order_by():
        key = str(item.get("onu_type_cache") or "").strip().upper()
        if key:
            counts[key] = counts.get(key, 0) + 1
    prepared_rows = []
    for row in rows:
        item = dict(row)
        onu_type_value = str(item.get("onu_type") or "").strip()
        count = counts.get(onu_type_value.upper(), 0)
        item["onus_count"] = count
        item["onus_url"] = f"{reverse('configured_onus')}?onu_type={quote_plus(onu_type_value)}" if count else ""
        prepared_rows.append(item)
    return render(
        request,
        "oltmanager/settings_onu_types.html",
        {
            "onu_types": prepared_rows,
        },
    )


@login_required
@admin_required
def settings_speed_profiles(request):
    tab = (request.GET.get("tab") or "download").strip().lower()
    if tab not in {"download", "upload"}:
        tab = "download"

    if request.method == "POST" and request.POST.get("action") == "delete_profile":
        del_key = str(request.POST.get("profile_key") or "").strip()
        try:
            del_outcome = delete_speed_profile_from_file(del_key)
        except Exception as exc:
            del_outcome = {"ok": False, "message": f"Could not delete profile: {exc}"}
        if del_outcome.get("ok"):
            messages.success(request, del_outcome.get("message") or "Speed profile deleted.")
        else:
            messages.error(request, del_outcome.get("message") or "Could not delete speed profile.")
        return redirect(f"{reverse('settings_speed_profiles')}?tab={tab}")

    create_error = ""
    create_name = ""
    create_download = True
    create_upload = True
    if request.method == "POST" and request.POST.get("action") == "create_profile":
        create_name = str(request.POST.get("profile_name") or "").strip()
        create_download = bool(request.POST.get("want_download"))
        create_upload = bool(request.POST.get("want_upload"))
        try:
            outcome = create_speed_profile_in_file(
                create_name,
                want_download=create_download,
                want_upload=create_upload,
            )
        except Exception as exc:
            outcome = {"ok": False, "message": f"Could not create profile: {exc}"}
        if outcome.get("ok"):
            messages.success(request, outcome.get("message") or "Speed profile created.")
            return redirect(f"{reverse('settings_speed_profiles')}?tab={tab}")
        create_error = outcome.get("message") or "Could not create speed profile."

    base_profiles = list(SpeedProfile.objects.filter(is_active=True).order_by("speed_mbps_value", "name"))
    sync_warning = ""
    if not base_profiles:
        try:
            sync_speed_profiles_from_file()
            base_profiles = list(SpeedProfile.objects.filter(is_active=True).order_by("speed_mbps_value", "name"))
        except OperationalError:
            sync_warning = "Speed profile sync is busy. Showing the last saved data."
    try:
        usage_counts = speed_profile_onu_usage_counts()
    except Exception:
        usage_counts = {}

    builtin_profiles = []
    custom_profiles = []
    for profile in base_profiles:
        base_name = (profile.name or "").strip()
        base_name = re.sub(r"(?i)(?:-|_)?(up|down)$", "", base_name).strip(" -_") or (profile.name or "")
        speed_display = profile.speed_display or (f"{profile.speed_mbps_value} Mbps" if profile.speed_mbps_value else "-")
        onu_count = int(usage_counts.get(str(profile.key or "").strip().upper(), 0))
        onus_url = f"{reverse('configured_onus')}?speed_profile={quote_plus(profile.key)}" if onu_count else ""
        if tab == "download":
            entry = {
                "index_number": profile.index_number,
                "name": f"{base_name}-DOWN",
                "speed_display": speed_display,
                "key": profile.key,
                "onu_count": onu_count,
                "onus_url": onus_url,
            }
        else:
            entry = {
                "index_number": profile.index_number + 1,
                "name": f"{base_name}-UP",
                "speed_display": speed_display,
                "key": profile.key,
                "onu_count": onu_count,
                "onus_url": onus_url,
            }
        (custom_profiles if profile.is_custom else builtin_profiles).append(entry)
    return render(
        request,
        "oltmanager/settings_speed_profiles.html",
        {
            "builtin_profiles": builtin_profiles,
            "custom_profiles": custom_profiles,
            "active_tab": tab,
            "sync_warning": sync_warning,
            "create_error": create_error,
            "create_name": create_name,
            "create_download": create_download,
            "create_upload": create_upload,
        },
    )


@login_required
def olt_settings_olt(request):
    _schedule_missing_device_snapshots_if_due()
    olts = list(_ready_olts().order_by("name"))
    down_ids = _dashboard_snmp_down_olt_ids()
    for olt in olts:
        olt.status_state = "down" if olt.id in down_ids else "up"
    return render(
        request,
        'oltmanager/olt_settings_olt.html',
        {
            'olts': olts,
        },
    )


@login_required
@admin_required
def olt_add(request):
    if request.method == 'POST':
        form = OLTForm(request.POST)
        if form.is_valid():
            active_onboarding = _active_olt_onboarding()
            if active_onboarding:
                active_name = str(getattr(active_onboarding, "name", "") or "another OLT")
                form.add_error(
                    None,
                    f"OLT onboarding is already running for {active_name}. Please wait until that process completes before adding another OLT.",
                )
                return render(
                    request,
                    'oltmanager/olt_form.html',
                    {
                        'form': form,
                        'form_title': 'Add New OLT',
                        'form_subtle': 'Enter device information for Telnet-based access.',
                        'back_fallback_url': reverse('olt_settings_olt'),
                        'cancel_url': reverse('olt_settings_olt'),
                        'show_import_onus': True,
                    },
                )
            olt = form.save(commit=False)
            snmp_mode = form.cleaned_data.get('snmp_mode') or 'manual'
            # "Import ONUs as well?" — when unchecked, onboarding fetches only the
            # OLT details/cards/PON/uplink/VLAN and skips the ONU import.
            olt.import_onus = request.POST.get('import_onus') == 'on'
            olt.is_ready = False
            olt.onboarding_status = "queued"
            olt.onboarding_progress = 0
            olt.onboarding_message = "OLT saved. Waiting to start..."
            olt.onboarding_log = "OLT saved. Waiting to start..."
            olt.onboarding_started_at = timezone.now()
            olt.onboarding_finished_at = None
            olt.save()
            _schedule_olt_onboarding(olt.pk, snmp_mode)
            return redirect('olt_add_progress', pk=olt.pk)
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
            'show_import_onus': True,
        },
    )


@login_required
@admin_required
def olt_edit(request, pk):
    olt = get_object_or_404(OLT, pk=pk)
    if request.method == 'POST':
        form = OLTForm(request.POST, instance=olt)
        if form.is_valid():
            olt = form.save(commit=False)
            olt.save()
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
@admin_required
def olt_delete(request, pk):
    olt = get_object_or_404(OLT, pk=pk)
    if request.method == 'POST':
        olt.delete()
        return redirect('olt_settings_olt')
    return render(request, 'oltmanager/olt_confirm_delete.html', {'olt': olt})


@login_required
@admin_required
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
@admin_required
def olt_save_config(request, pk):
    olt = get_object_or_404(OLT, pk=pk)
    locked_response = _deny_olt_access_if_locked(request, olt)
    if locked_response:
        return locked_response
    if request.method != 'POST':
        return redirect('olt_view', pk=olt.pk)
    from .utils import execute_olt_save_now
    ok, message = execute_olt_save_now(olt)
    _record_olt_login(
        olt, request.user, 'save_config',
        f"Manual save from OLT view: {message}"[:300], request=request,
    )
    if ok:
        messages.success(request, f"Save: {message}")
    else:
        messages.error(request, f"Save failed: {message}")
    return redirect('olt_view', pk=olt.pk)


@login_required
@admin_required
def olt_config_backup(request, pk):
    olt = get_object_or_404(OLT, pk=pk)
    locked_response = _deny_olt_access_if_locked(request, olt)
    if locked_response:
        return locked_response
    if request.method != 'POST':
        return redirect('olt_view', pk=olt.pk)
    from .utils import fetch_olt_full_running_config
    ok, text, message = fetch_olt_full_running_config(olt)
    if not ok:
        _record_olt_login(
            olt, request.user, 'backup_failed',
            f"Manual backup failed: {message}"[:300], request=request,
        )
        messages.error(request, f"Backup failed: {message}")
        return redirect('olt_view', pk=olt.pk)

    _record_olt_login(
        olt, request.user, 'backup_config',
        'Manual configuration backup downloaded.', request=request,
    )
    safe_name = re.sub(r'[^A-Za-z0-9._-]+', '_', str(olt.name or f'olt-{olt.pk}')).strip('_') or f'olt-{olt.pk}'
    stamp = timezone.localtime().strftime('%Y%m%d-%H%M%S')
    filename = f"{safe_name}_config_{stamp}.txt"
    header = (
        "! OLT configuration backup\r\n"
        f"! Name : {olt.name}\r\n"
        f"! IP   : {olt.ip_address}\r\n"
        f"! Taken: {timezone.localtime().strftime('%Y-%m-%d %H:%M:%S')}\r\n"
        "! ----------------------------------------------------------\r\n\r\n"
    )
    body = header + str(text or '').replace('\r\n', '\n').replace('\n', '\r\n')
    response = HttpResponse(body, content_type='text/plain; charset=utf-8')
    response['Content-Disposition'] = f'attachment; filename="{filename}"'
    return response


def _sync_config_new_onu_report_rows(olt, new_onu_rows):
    key_q = Q()
    for row in new_onu_rows or []:
        try:
            key_q |= Q(
                frame=int(row.get("frame") or 0),
                slot=int(row.get("slot")),
                port=int(row.get("port")),
                ont_id=int(row.get("ont_id")),
            )
        except (TypeError, ValueError, AttributeError):
            continue
    if not key_q:
        return new_onu_rows or []
    records = ConfiguredONU.objects.filter(olt=olt).filter(key_q).order_by("slot", "port", "ont_id")
    return [
        {
            "frame": int(record.frame or 0),
            "slot": int(record.slot),
            "port": int(record.port),
            "ont_id": int(record.ont_id),
            "sn": record.sn or "",
            "name": record.description or "",
            "status": record.derived_status or record.run_state or "",
            "signal": record.olt_rx or record.onu_rx or "",
            "onu_type": record.onu_type_cache or "",
            "vlans": record.attached_vlans_cache or "",
            "distance": record.ont_distance_m or "",
            "download": record.download_profile_name_cache or "",
            "upload": record.upload_profile_name_cache or "",
        }
        for record in records
    ]


@login_required
@admin_required
@require_POST
def olt_sync_config(request, pk):
    olt = get_object_or_404(OLT, pk=pk)
    locked_response = _deny_olt_access_if_locked(request, olt)
    if locked_response:
        return locked_response
    started_at = time.time()
    wants_json = (
        request.headers.get("x-requested-with") == "XMLHttpRequest"
        or "application/json" in request.headers.get("accept", "")
    )
    try:
        result = sync_configured_onus_inventory(olt)
        new_onu_rows = result.get("new_onus") or []
        detail_fill = {}
        vlan_fill = {}
        if not result.get("incomplete") and new_onu_rows:
            detail_fill = sync_onu_detail_fields_for_olt(olt, target_keys=new_onu_rows)
            vlan_fill = sync_onu_attached_vlans_for_olt(
                olt,
                fallback_missing=True,
                only_missing=True,
                imported_only=True,
                target_keys=new_onu_rows,
            )
            new_onu_rows = _sync_config_new_onu_report_rows(olt, new_onu_rows)
        duration_seconds = round(time.time() - started_at, 1)
        if result.get("incomplete"):
            message = (
                f"Config sync incomplete on {olt.name}: fetched "
                f"{result.get('actual_count') or 0} of {result.get('expected_count') or 0} ONUs."
            )
            if wants_json:
                return JsonResponse({
                    "ok": False,
                    "type": "Incomplete",
                    "message": message,
                    "duration_seconds": duration_seconds,
                    "actual_count": int(result.get("actual_count") or 0),
                    "expected_count": int(result.get("expected_count") or 0),
                    "status": result.get("status") or "",
                }, status=409)
            messages.warning(request, message)
        else:
            count = int(result.get("count") or 0)
            message = f"Config sync completed on {olt.name}: {count} ONUs synced."
            if wants_json:
                return JsonResponse({
                    "ok": True,
                    "type": "Completed",
                    "message": message,
                    "duration_seconds": duration_seconds,
                    "count": count,
                    "new_count": int(result.get("new_count") or 0),
                    "new_onus": new_onu_rows,
                    "detail_fill_status": detail_fill.get("status") or "",
                    "vlan_fill_status": vlan_fill.get("status") or "",
                    "status": result.get("status") or "",
                })
            messages.success(request, message)
    except Exception as exc:
        duration_seconds = round(time.time() - started_at, 1)
        message = f"Config sync failed on {olt.name}: {_ui_telnet_error_message(str(exc))}"
        if wants_json:
            return JsonResponse({
                "ok": False,
                "type": "Failed",
                "message": message,
                "duration_seconds": duration_seconds,
            }, status=500)
        messages.error(request, message)
    return redirect(f"{reverse('olt_view', kwargs={'pk': olt.pk})}?section=advanced")


@login_required
@admin_required
@require_POST
def olt_sync_single_onu(request, pk):
    olt = get_object_or_404(OLT, pk=pk)
    locked_response = _deny_olt_access_if_locked(request, olt)
    if locked_response:
        return locked_response

    started_at = time.time()
    sn = str(request.POST.get("serial") or request.POST.get("sn") or "").strip()
    wants_json = (
        request.headers.get("x-requested-with") == "XMLHttpRequest"
        or "application/json" in request.headers.get("accept", "")
    )

    def _single_response(payload, status=200):
        if wants_json:
            return JsonResponse(payload, status=status)
        message = payload.get("message") or payload.get("status") or ""
        if payload.get("ok"):
            messages.success(request, message)
        else:
            messages.error(request, message)
        return redirect(f"{reverse('olt_view', kwargs={'pk': olt.pk})}?section=advanced")

    if not sn:
        return _single_response({
            "ok": False,
            "type": "Failed",
            "report_title": "Per ONU Sync Report - Attention Required",
            "message": "Enter an ONU serial number.",
            "duration_seconds": round(time.time() - started_at, 1),
        }, status=400)

    try:
        location = find_onu_location_by_sn_cli(olt, sn)
        if not location.get("ok"):
            return _single_response({
                "ok": False,
                "type": "Not Found",
                "report_title": "Per ONU Sync Report - Attention Required",
                "message": f"ONU serial was not found on {olt.name}: {_ui_telnet_error_message(location.get('message'))}",
                "duration_seconds": round(time.time() - started_at, 1),
            }, status=404)

        key = {
            "frame": int(location.get("frame") or 0),
            "slot": int(location.get("slot") or 0),
            "port": int(location.get("port") or 0),
            "ont_id": int(location.get("ont_id") or 0),
        }
        target_keys = [key]
        inventory = sync_detected_onu_keys_inventory(
            olt,
            [(key["frame"], key["slot"], key["port"], key["ont_id"])],
        )
        if int(inventory.get("count") or 0) <= 0:
            return _single_response({
                "ok": False,
                "type": "Failed",
                "report_title": "Per ONU Sync Report - Attention Required",
                "message": f"ONU located at {key['frame']}/{key['slot']}/{key['port']} ONT {key['ont_id']}, but details were not imported: {_ui_telnet_error_message(inventory.get('status'))}",
                "duration_seconds": round(time.time() - started_at, 1),
                "status": inventory.get("status") or "",
            }, status=502)

        detail_fill = sync_onu_detail_fields_for_olt(olt, target_keys=target_keys)
        vlan_fill = sync_onu_attached_vlans_for_olt(
            olt,
            fallback_missing=True,
            only_missing=False,
            imported_only=False,
            target_keys=target_keys,
        )
        onu_rows = _sync_config_new_onu_report_rows(olt, target_keys)
        detail_url = ""
        if onu_rows:
            first = onu_rows[0]
            detail_url = reverse("configured_onu_detail", kwargs={
                "olt_pk": olt.pk,
                "slot": int(first.get("slot") or key["slot"]),
                "port": int(first.get("port") or key["port"]),
                "ont_id": int(first.get("ont_id") or key["ont_id"]),
            })
            first["detail_url"] = detail_url

        duration_seconds = round(time.time() - started_at, 1)
        message = (
            f"Per ONU sync completed on {olt.name}: "
            f"{key['frame']}/{key['slot']}/{key['port']} ONT {key['ont_id']} updated."
        )
        return _single_response({
            "ok": True,
            "type": "Completed",
            "report_title": "Per ONU Sync Report",
            "onu_list_title": "Synced ONU Detail",
            "message": message,
            "duration_seconds": duration_seconds,
            "count": len(onu_rows) or int(inventory.get("count") or 0),
            "new_count": int(inventory.get("new_count") or 0),
            "new_onus": onu_rows,
            "detail_url": detail_url,
            "detail_fill_status": detail_fill.get("status") or "",
            "vlan_fill_status": vlan_fill.get("status") or "",
            "status": " | ".join(part for part in (
                inventory.get("status") or "",
                detail_fill.get("status") or "",
                vlan_fill.get("status") or "",
            ) if part),
        })
    except Exception as exc:
        return _single_response({
            "ok": False,
            "type": "Failed",
            "report_title": "Per ONU Sync Report - Attention Required",
            "message": f"Per ONU sync failed on {olt.name}: {_ui_telnet_error_message(str(exc))}",
            "duration_seconds": round(time.time() - started_at, 1),
        }, status=500)


@login_required
def olt_view(request, pk):
    available_sections = {
        'olt-details',
        'olt-cards',
        'history',
        'pon-ports',
        'uplink',
        'vlans',
        'advanced',
    }
    selected_section = getattr(request, "_olt_view_section", None) or request.GET.get('section', 'olt-details')
    if selected_section not in available_sections:
        selected_section = 'olt-details'
    olt = _get_olt_for_view(pk, selected_section)
    if olt.pricing_access_locked:
        return _render_olt_subscription_locked(request, olt)
    _reset_olt_view_vlan_autorefresh_on_new_visit(request, olt.pk)
    auto_vlan_refresh = None
    if _should_auto_refresh_olt_vlan_section(request, olt, selected_section):
        auto_vlan_refresh = {
            "section": selected_section,
            "url": reverse("olt_refresh_uplink_vlans" if selected_section == "uplink" else "olt_refresh_vlans", kwargs={"pk": olt.pk}),
            "title": "Refreshing uplink VLANs" if selected_section == "uplink" else "Refreshing VLAN list",
            "message": "Reading uplink VLAN membership from the OLT..." if selected_section == "uplink" else "Reading the OLT VLAN table and updating the database...",
        }

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
    vlan_notice_ok = None
    vlan_notice_url = ""
    vlan_override = getattr(request, "_vlan_override", None)
    history_rows = []
    if selected_section == 'history':
        history_rows = list(olt.login_history.select_related('olt').all()[:100])

    if selected_section == 'olt-cards':
        if olt.olt_cards_cache:
            olt_cards = olt.olt_cards_cache
            olt_cards_status = _clean_ui_status(olt.olt_cards_status, 'Loaded from database', has_data=bool(olt_cards))
        else:
            olt_cards = []
            olt_cards_status = 'No OLT cards snapshot in database. Use Refresh Ports.'

    if selected_section == 'pon-ports':
        saved_groups = list(getattr(olt, "pon_ports_cache", []) or [])
        if saved_groups:
            pon_port_groups = saved_groups
            pon_ports_status = _clean_ui_status(olt.pon_ports_status, 'Loaded from database', has_data=bool(saved_groups))
            _set_cached_pon_ports(olt.pk, pon_port_groups, pon_ports_status)
        else:
            pon_port_groups = []
            pon_ports_status = 'No PON ports snapshot in database. Use Refresh PON Ports.'
        pon_traffic_port_choices = _flatten_pon_port_choices(pon_port_groups)
        default_choice = pon_traffic_port_choices[0] if pon_traffic_port_choices else None
        selected_pon_traffic_slot = default_choice["slot"] if default_choice else None
        selected_pon_traffic_port = default_choice["port"] if default_choice else None
        pon_traffic_graph = _build_olt_pon_port_traffic_graph(olt.pk, '1h', selected_pon_traffic_slot, selected_pon_traffic_port) if default_choice else {
            "range_key": "1h",
            "range_label": "Hourly",
            "points": [],
            "latest": {"upload_mbps": 0, "download_mbps": 0, "upload_pps": 0, "download_pps": 0, "upload_avg_size": 0, "download_avg_size": 0, "upload_max_mbps": 0, "download_max_mbps": 0},
        }
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
            uplink_data = {'status': 'No uplink snapshot in database. Use Refresh Ports.', 'rows': []}
        uplink_traffic_port_choices = _flatten_uplink_port_choices(uplink_data.get("rows") or [])
        default_uplink_choice = uplink_traffic_port_choices[0]["value"] if uplink_traffic_port_choices else ""
        uplink_traffic_graph = (
            _get_cached_port_traffic_payload(
                ("uplink", olt.pk, "1h", default_uplink_choice),
                lambda: _build_olt_uplink_traffic_graph(olt.pk, '1h', default_uplink_choice),
            )
            if default_uplink_choice else {
                "range_key": "1h",
                "range_label": "Hourly",
                "points": [],
                "latest": {"upload_mbps": 0, "download_mbps": 0, "upload_max_mbps": 0, "download_max_mbps": 0},
            }
        )

    if selected_section == 'vlans':
        saved_vlan_rows = list(getattr(olt, "vlan_cache", []) or [])
        vlan_onu_counts = {}
        mgmt_vlan_id = None
        vlan_status_raw = getattr(olt, "vlan_status", "") or ""
        mgmt_status_match = re.search(r"(?i)\bMgmt\s+VLAN\s*:\s*(\d+)\b", vlan_status_raw)
        if mgmt_status_match:
            mgmt_vlan_id = mgmt_status_match.group(1).strip()
        for cache_value in ConfiguredONU.objects.filter(olt=olt).exclude(attached_vlans_cache="").values_list("attached_vlans_cache", flat=True):
            for vlan_id in [part.strip() for part in str(cache_value or "").split(",") if part.strip()]:
                vlan_onu_counts[vlan_id] = vlan_onu_counts.get(vlan_id, 0) + 1
        if saved_vlan_rows:
            prepared_vlan_rows = []
            configured_onus_url = reverse("configured_onus")
            total_vlan_count = len(saved_vlan_rows)
            for row in saved_vlan_rows:
                prepared_row = dict(row)
                vlan_id_text = str(prepared_row.get("vlan_id") or "").strip()
                if prepared_row.get("is_management") or (mgmt_vlan_id and vlan_id_text == mgmt_vlan_id):
                    mgmt_vlan_id = vlan_id_text or mgmt_vlan_id
                    continue
                prepared_row["onu_count"] = vlan_onu_counts.get(vlan_id_text, 0)
                prepared_row["onu_link"] = f"{configured_onus_url}?olt={olt.pk}&vlan={quote_plus(vlan_id_text)}" if vlan_id_text else ""
                prepared_vlan_rows.append(prepared_row)
            vlan_data = {
                'status': _clean_ui_status(vlan_status_raw, 'Loaded from database', has_data=True),
                'rows': prepared_vlan_rows,
                'mgmt_vlan_id': mgmt_vlan_id,
                'total_count': total_vlan_count,
            }
        else:
            vlan_data = {
                'status': _clean_ui_status(
                    vlan_status_raw,
                    'No VLAN snapshot in database. Use Refresh VLANs.',
                    has_data=False,
                ),
                'rows': [],
                'mgmt_vlan_id': None,
                'total_count': 0,
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
            vlan_notice_ok = vlan_override.get("notice_ok")
            vlan_notice_url = vlan_override.get("notice_url") or ""
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
            _restored_notice = _restore_vlan_notice(request, olt.pk)
            vlan_notice = _restored_notice["text"]
            vlan_notice_ok = _restored_notice["ok"]
            vlan_notice_url = _restored_notice["url"]

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
    vlan_uplink_vlan_options = [
        {
            "vlan_id": str(row.get("vlan_id") or "").strip(),
            "description": str(row.get("description") or "").strip(),
        }
        for row in (vlan_data.get("rows") or [])
        if str(row.get("vlan_id") or "").strip()
    ]
    vlan_uplink_source_rows = list(getattr(olt, "uplink_cache", []) or [])
    vlan_uplink_port_options = []
    for row in vlan_uplink_source_rows:
        port_name = str(row.get("port") or "").strip()
        if not port_name:
            continue
        agg = row.get("aggregate") or {}
        lag_label = ""
        if agg.get("master"):
            lag_label = "LAG master" if agg.get("is_master") else f"LAG member → add on {agg.get('master')}"
        vlan_uplink_port_options.append({
            "port": port_name,
            "status": str(row.get("oper_status") or row.get("status") or "").strip(),
            "lag_label": lag_label,
            "is_lag_master": bool(agg.get("is_master")),
            "in_lag": bool(agg.get("master")),
        })
    olt_alert_label = _recent_olt_alert_label(
        getattr(olt, "snmp_last_status", ""),
        getattr(olt, "snmp_last_synced_at", None),
        max_age_seconds=90,
    )
    olt_config_last_sync_display = ""
    if selected_section == "advanced":
        latest_config_sync = ConfiguredONU.objects.filter(olt=olt).aggregate(latest_sync=Max("synced_at")).get("latest_sync")
        if latest_config_sync:
            latest_config_sync = timezone.localtime(latest_config_sync, ZoneInfo("Asia/Karachi"))
            olt_config_last_sync_display = latest_config_sync.strftime("%Y-%m-%d %I:%M:%S %p")
    context = {
        'olt': olt,
        'olt_unreachable': bool(olt_alert_label),
        'olt_unreachable_message': olt_alert_label or 'OLT is Unreachable',
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
        'uplink_refresh_data_url': reverse('olt_uplink_refresh_data', kwargs={'pk': olt.pk}),
        'pon_traffic_graph': pon_traffic_graph if selected_section == 'pon-ports' else None,
        'pon_traffic_port_choices': pon_traffic_port_choices if selected_section == 'pon-ports' else [],
        'pon_traffic_graph_url': reverse('olt_pon_traffic_graph_data', kwargs={'pk': olt.pk}) if selected_section == 'pon-ports' else '',
        'snmp_snapshot': snmp_snapshot,
        'uplink_data': uplink_data,
        'uplink_status_display': uplink_status_display,
        'uplink_traffic_graph': uplink_traffic_graph if selected_section == 'uplink' else None,
        'uplink_traffic_port_choices': uplink_traffic_port_choices if selected_section == 'uplink' else [],
        'uplink_traffic_graph_url': reverse('olt_uplink_traffic_graph_data', kwargs={'pk': olt.pk}) if selected_section == 'uplink' else '',
        'vlan_data': vlan_data,
        'vlan_status_display': vlan_status_display,
        'vlan_add_form': vlan_add_form,
        'vlan_bulk_form': vlan_bulk_form,
        'vlan_transcript': vlan_transcript,
        'vlan_bulk_transcript': vlan_bulk_transcript,
        'vlan_notice': vlan_notice,
        'vlan_notice_ok': vlan_notice_ok,
        'vlan_notice_url': vlan_notice_url,
        'vlan_uplink_vlan_options': vlan_uplink_vlan_options,
        'vlan_uplink_port_options': vlan_uplink_port_options,
        'history_rows': history_rows,
        'olt_details_refresh_url': reverse('olt_details_refresh', kwargs={'pk': olt.pk}),
        'olt_config_last_sync_display': olt_config_last_sync_display,
        'auto_vlan_refresh': auto_vlan_refresh,
    }
    return render(request, 'oltmanager/olt_view.html', context)


@login_required
@admin_required
def olt_add_progress(request, pk):
    olt = get_object_or_404(OLT, pk=pk)
    return render(
        request,
        'oltmanager/olt_add_progress.html',
        {
            'olt': olt,
            'poll_url': reverse('olt_add_progress_status', kwargs={'pk': pk}),
            'action_url': reverse('olt_add_progress_action', kwargs={'pk': pk}),
            'review_data_url': reverse('olt_add_review_data', kwargs={'pk': pk}),
            'settings_url': reverse('olt_settings_olt'),
            'review_counts': _olt_onboarding_review_counts(olt),
        },
    )


@login_required
@admin_required
def olt_add_progress_status(request, pk):
    olt = get_object_or_404(OLT, pk=pk)
    olt = _fail_stale_olt_onboarding_if_needed(olt)
    log_lines = [line for line in str(olt.onboarding_log or "").splitlines() if line.strip()]
    return JsonResponse(
        {
            "ok": True,
            "status": str(olt.onboarding_status or ""),
            "progress": int(olt.onboarding_progress or 0),
            "message": str(olt.onboarding_message or ""),
            "is_ready": bool(olt.is_ready),
            "redirect_url": reverse('olt_view', kwargs={'pk': pk}) if olt.is_ready else "",
            "log_lines": log_lines,
            "review_counts": _olt_onboarding_review_counts(olt),
            **_onu_onboarding_counts(olt),
        }
    )


@login_required
@admin_required
def olt_add_review_data(request, pk):
    olt = get_object_or_404(OLT, pk=pk)

    cards = list(olt.olt_cards_cache or [])

    pon_groups = list(olt.pon_ports_cache or [])

    uplink = olt.uplink_cache or {}
    uplink_rows = list((uplink.get("rows") or []) if isinstance(uplink, dict) else [])

    vlan = olt.vlan_cache or {}
    vlan_rows = list((vlan.get("rows") or []) if isinstance(vlan, dict) else [])

    onus = []
    for onu in ConfiguredONU.objects.filter(olt=olt).order_by("slot", "port", "ont_id"):
        onus.append({
            "port_id": f"0/{onu.slot}/{onu.port}",
            "ont_id": onu.ont_id,
            "sn": onu.sn or "",
            "description": onu.description or "",
            "onu_type": onu.onu_type_cache or "",
            "distance_m": onu.ont_distance_m or "",
            "vlans": onu.attached_vlans_cache or "",
            "download_profile": onu.download_profile_name_cache or "",
            "upload_profile": onu.upload_profile_name_cache or "",
            "service_port_id": onu.service_port_id_cache or "",
            "run_state": onu.run_state or "",
            "status": onu.derived_status or onu.run_state or "",
        })

    return JsonResponse({
        "ok": True,
        "cards": cards,
        "pon_port_groups": pon_groups,
        "uplink_rows": uplink_rows,
        "vlan_rows": vlan_rows,
        "onus": onus,
        "review_counts": _olt_onboarding_review_counts(olt),
    })


@login_required
@require_POST
@admin_required
def olt_add_progress_action(request, pk):
    olt = get_object_or_404(OLT, pk=pk)
    action = str(request.POST.get("action") or "").strip().lower()
    if action == "add":
        olt.is_ready = True
        olt.onboarding_status = "completed"
        olt.onboarding_message = "OLT added to the app."
        olt.onboarding_log = _append_olt_onboarding_log(olt.onboarding_log, "OLT added to the app.")
        olt.onboarding_finished_at = timezone.now()
        olt.save(update_fields=["is_ready", "onboarding_status", "onboarding_message", "onboarding_log", "onboarding_finished_at"])
        messages.success(request, f"{olt.name} added successfully.")
        return redirect("olt_view", pk=olt.pk)
    if action == "rollback":
        name = olt.name
        olt.delete()
        messages.success(request, f"{name} onboarding rolled back.")
        return redirect("olt_settings_olt")
    if action == "abort":
        name = olt.name
        _request_olt_onboarding_abort(olt.pk)
        olt.delete()
        messages.success(request, f"{name} onboarding aborted and rolled back.")
        return redirect("olt_settings_olt")
    if action == "retry":
        _reset_olt_onboarding_data(olt)
        _schedule_olt_onboarding(olt.pk, "manual")
        messages.info(request, f"{olt.name} onboarding retry started.")
        return redirect("olt_add_progress", pk=olt.pk)
    messages.warning(request, "Invalid onboarding action.")
    return redirect("olt_add_progress", pk=olt.pk)


@login_required
def olt_details_refresh(request, pk):
    olt = get_object_or_404(OLT, pk=pk)
    locked_response = _deny_olt_access_if_locked(request, olt)
    if locked_response:
        return locked_response
    live_lock = _try_acquire_olt_live_lock(olt.pk)
    if live_lock is None:
        payload = _serialize_olt_details_snapshot(olt, _build_saved_device_snapshot(olt))
        return JsonResponse({
            'ok': False,
            'busy': True,
            'message': 'Device busy. Showing saved data.',
            'olt_unreachable': bool(_recent_olt_alert_label(
                getattr(olt, "snmp_last_status", ""),
                getattr(olt, "snmp_last_synced_at", None),
                max_age_seconds=90,
            )),
            'olt_unreachable_message': _recent_olt_alert_label(
                getattr(olt, "snmp_last_status", ""),
                getattr(olt, "snmp_last_synced_at", None),
                max_age_seconds=90,
            ) or 'OLT is Unreachable',
            **payload,
        })

    try:
        snapshot = fetch_snmp_snapshot(olt)
        need_telnet_details = _should_fetch_telnet_version_details(olt, snapshot)
        need_telnet_uptime = _should_fetch_telnet_uptime(snapshot)
        if need_telnet_details or need_telnet_uptime:
            telnet_snapshot = fetch_telnet_version_snapshot(olt)
            telnet_sw = _normalize_olt_software_version(str(telnet_snapshot.get('sw_version') or '').strip())
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
        fetched_sw = _normalize_olt_software_version((snapshot.get('sw_version') or '').strip())
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
        return JsonResponse({
            'ok': True,
            'olt_unreachable': bool(_recent_olt_alert_label(snapshot.get('status'), timezone.now(), max_age_seconds=90)),
            'olt_unreachable_message': _recent_olt_alert_label(snapshot.get('status'), timezone.now(), max_age_seconds=90) or 'OLT is Unreachable',
            **payload,
        })
    finally:
        live_lock.release()


@login_required
@admin_required
def olt_cli_window(request, pk):
    olt = get_object_or_404(OLT, pk=pk)
    locked_response = _deny_olt_access_if_locked(request, olt)
    if locked_response:
        return locked_response
    return render(request, 'oltmanager/olt_cli_window.html', {'olt': olt})


@login_required
@require_POST
@admin_required
def olt_cli_open(request, pk):
    olt = get_object_or_404(OLT, pk=pk)
    locked_response = _deny_olt_access_if_locked(request, olt)
    if locked_response:
        return locked_response
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
@admin_required
def olt_cli_run(request, pk):
    olt = get_object_or_404(OLT, pk=pk)
    locked_response = _deny_olt_access_if_locked(request, olt)
    if locked_response:
        return locked_response
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
            if raw_input == "\t" or raw_input == "?":
                output = adapter.read_session_output(tn, wait=0.15, rounds=14)
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
@admin_required
def olt_cli_close(request, pk):
    olt = get_object_or_404(OLT, pk=pk)
    locked_response = _deny_olt_access_if_locked(request, olt)
    if locked_response:
        return locked_response
    _close_user_cli_session(request.user.id, olt.pk)
    _record_olt_login(olt, request.user, 'cli_close', 'Interactive CLI session closed', request=request)
    return JsonResponse({'ok': True, 'message': 'CLI session closed.'})


@login_required
def olt_refresh_ports(request, pk):
    olt = get_object_or_404(OLT, pk=pk)
    locked_response = _deny_olt_access_if_locked(request, olt)
    if locked_response:
        return locked_response
    if request.method != 'POST':
        return redirect('olt_view', pk=pk)
    _schedule_cards_refresh(olt.pk)
    _record_olt_login(olt, request.user, 'refresh_cards', 'OLT cards refresh started', request=request)
    return redirect(f"{redirect('olt_view', pk=pk).url}?section=olt-cards")


@login_required
@require_POST
def olt_refresh_pon_ports(request, pk):
    olt = get_object_or_404(OLT, pk=pk)
    locked_response = _deny_olt_access_if_locked(request, olt)
    if locked_response:
        return locked_response
    _schedule_pon_refresh(olt.pk)
    _record_olt_login(olt, request.user, 'refresh_pon', 'PON ports refresh started', request=request)
    return redirect(f"{redirect('olt_view', pk=pk).url}?section=pon-ports")


@login_required
@require_POST
def olt_refresh_pon_sfp_tx(request, pk):
    olt = get_object_or_404(OLT, pk=pk)
    locked_response = _deny_olt_access_if_locked(request, olt)
    if locked_response:
        return locked_response
    live_lock = _acquire_olt_live_lock_with_retry(olt.pk)
    if live_lock is None:
        messages.warning(request, "Another live OLT task is already running. Please try again in a few seconds.")
        return redirect(f"{redirect('olt_view', pk=pk).url}?section=pon-ports")
    try:
        result = refresh_pon_sfp_tx_snapshot(olt)
        status_text = str(result.get("status") or "")
        if result.get("ok"):
            _set_cached_pon_ports(olt.pk, result.get("groups") or [], status_text)
            messages.success(request, status_text or "SFP Tx refreshed.")
            _record_olt_login(olt, request.user, 'refresh_pon_sfp_tx', status_text or 'SFP Tx refresh completed', request=request)
        else:
            messages.warning(request, status_text or "SFP Tx refresh failed.")
    finally:
        live_lock.release()
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
def olt_uplink_refresh_data(request, pk):
    olt = get_object_or_404(OLT, pk=pk)
    rows = list(getattr(olt, "uplink_cache", []) or [])
    status_text = _clean_ui_status(
        getattr(olt, "uplink_status", ""),
        "No uplink data found.",
        has_data=bool(rows),
    )
    refreshed_at = getattr(olt, "uplink_refreshed_at", None)
    refreshed_display = (
        timezone.localtime(refreshed_at, ZoneInfo("Asia/Karachi")).strftime("%Y-%m-%d %I:%M:%S %p")
        if refreshed_at
        else ""
    )
    return JsonResponse({
        "ok": True,
        "rows": rows,
        "status": status_text,
        "refreshed_at": refreshed_display,
    })


@login_required
def olt_uplink_mac_data(request, pk):
    olt = get_object_or_404(OLT, pk=pk)
    port_name = str(request.GET.get("port") or "").strip()
    rows = list(getattr(olt, "uplink_cache", []) or [])
    valid_ports = {str((row or {}).get("port") or "").strip() for row in rows}
    if not port_name or port_name not in valid_ports:
        return JsonResponse({
            "ok": False,
            "port": port_name,
            "status": "Select a valid uplink port.",
            "output": "",
            "total": 0,
        }, status=400)

    result = fetch_uplink_mac_addresses(olt, port_name, timeout_seconds=120)
    return JsonResponse(result)


@login_required
def olt_uplink_sfp_ddm_data(request, pk):
    olt = get_object_or_404(OLT, pk=pk)
    port_name = str(request.GET.get("port") or "").strip()
    rows = [dict(row or {}) for row in (getattr(olt, "uplink_cache", []) or [])]
    valid_ports = {str((row or {}).get("port") or "").strip() for row in rows}
    if not port_name or port_name not in valid_ports:
        return JsonResponse({
            "ok": False,
            "port": port_name,
            "status": "Select a valid uplink port.",
            "temperature": "-",
            "tx_power": "-",
            "rx_power": "-",
        }, status=400)

    result = fetch_uplink_sfp_ddm(olt, port_name, timeout_seconds=120)
    now_display = timezone.localtime(timezone.now(), ZoneInfo("Asia/Karachi")).strftime("%Y-%m-%d %I:%M:%S %p")
    for row in rows:
        if str((row or {}).get("port") or "").strip() != port_name:
            continue
        row["sfp_temperature"] = result.get("temperature") or "-"
        row["sfp_tx_power"] = result.get("tx_power") or "-"
        row["sfp_rx_power"] = result.get("rx_power") or "-"
        row["sfp_ddm_status"] = result.get("status") or ""
        row["sfp_media"] = result.get("sfp_media") or ""
        row["sfp_type"] = result.get("sfp_type") or ""
        row["sfp_ddm_updated_at"] = now_display
        break
    olt.uplink_cache = rows
    olt.uplink_refreshed_at = timezone.now()
    olt.save(update_fields=["uplink_cache", "uplink_refreshed_at"])
    result["updated_at"] = now_display
    return JsonResponse(result)


@login_required
def olt_pon_traffic_graph_data(request, pk):
    olt = get_object_or_404(OLT, pk=pk)
    range_key = (request.GET.get("range") or "1h").strip().lower()
    port_value = (request.GET.get("pon_port") or "").strip()
    slot = None
    port = None
    if ":" in port_value:
        left, right = port_value.split(":", 1)
        if left.isdigit() and right.isdigit():
            slot = int(left)
            port = int(right)

    if slot is None or port is None:
        first_choice = next(
            iter(_flatten_pon_port_choices(list(getattr(olt, "pon_ports_cache", []) or []), only_up=True, include_all=False)),
            None,
        )
        if first_choice:
            slot = first_choice["slot"]
            port = first_choice["port"]
    cache_key = ("pon", olt.pk, range_key, f"{slot}:{port}")
    if range_key == "live":
        _schedule_live_port_traffic_refresh(olt.pk, "pon")
        payload = _get_cached_port_traffic_payload(
            cache_key,
            lambda: _build_olt_pon_port_traffic_graph(olt.pk, range_key, slot, port),
            ttl=LIVE_PORT_TRAFFIC_GRAPH_CACHE_TTL,
        )
        return JsonResponse({"ok": True, **payload})

    payload = _get_cached_port_traffic_payload(
        cache_key,
        lambda: _build_olt_pon_port_traffic_graph(olt.pk, range_key, slot, port),
    )
    if slot is not None and port is not None and not (payload.get("points") or []):
        try:
            had_history = PONPortTrafficSample.objects.filter(olt_id=olt.pk, slot=slot, port=port).exists()
            record_pon_port_traffic_sample_for_olt(olt, force=True)
            if not had_history:
                time.sleep(0.8)
                record_pon_port_traffic_sample_for_olt(olt, force=True, min_interval_seconds=0)
        except OperationalError:
            pass
        else:
            with _PORT_TRAFFIC_GRAPH_CACHE_LOCK:
                _PORT_TRAFFIC_GRAPH_CACHE.pop(cache_key, None)
            payload = _get_cached_port_traffic_payload(
                cache_key,
                lambda: _build_olt_pon_port_traffic_graph(olt.pk, range_key, slot, port),
            )
    return JsonResponse({"ok": True, **payload})


@login_required
def olt_uplink_traffic_graph_data(request, pk):
    olt = get_object_or_404(OLT, pk=pk)
    range_key = (request.GET.get("range") or "1h").strip().lower()
    port_name = (request.GET.get("uplink_port") or "").strip()
    if not port_name:
        first_choice = next(
            iter(_flatten_uplink_port_choices({
                "rows": list(getattr(olt, "uplink_cache", []) or []),
                "only_up": True,
                "include_all": False,
            })),
            None,
        )
        port_name = (first_choice or {}).get("value", "")
    cache_key = ("uplink", olt.pk, range_key, port_name)
    if range_key == "live":
        _schedule_live_port_traffic_refresh(olt.pk, "uplink")
        payload = _get_cached_port_traffic_payload(
            cache_key,
            lambda: _build_olt_uplink_traffic_graph(olt.pk, range_key, port_name),
            ttl=LIVE_PORT_TRAFFIC_GRAPH_CACHE_TTL,
        )
        return JsonResponse({"ok": True, **payload})

    payload = _get_cached_port_traffic_payload(
        cache_key,
        lambda: _build_olt_uplink_traffic_graph(olt.pk, range_key, port_name),
    )
    if port_name and not (payload.get("points") or []):
        try:
            had_history = UplinkPortTrafficSample.objects.filter(olt_id=olt.pk, port_name=port_name).exists()
            record_uplink_port_traffic_sample_for_olt(olt, force=True)
            if not had_history:
                time.sleep(0.8)
                record_uplink_port_traffic_sample_for_olt(olt, force=True, min_interval_seconds=0)
        except OperationalError:
            pass
        else:
            with _PORT_TRAFFIC_GRAPH_CACHE_LOCK:
                _PORT_TRAFFIC_GRAPH_CACHE.pop(cache_key, None)
            payload = _get_cached_port_traffic_payload(
                cache_key,
                lambda: _build_olt_uplink_traffic_graph(olt.pk, range_key, port_name),
            )
    return JsonResponse({"ok": True, **payload})


@login_required
@require_POST
def olt_refresh_uplink(request, pk):
    olt = get_object_or_404(OLT, pk=pk)
    locked_response = _deny_olt_access_if_locked(request, olt)
    if locked_response:
        return locked_response
    _schedule_uplink_refresh(olt.pk)
    _record_olt_login(olt, request.user, 'refresh_uplink', 'Uplink refresh started', request=request)
    return redirect(f"{redirect('olt_view', pk=pk).url}?section=uplink")


@login_required
@require_POST
def olt_refresh_uplink_vlans(request, pk):
    olt = get_object_or_404(OLT, pk=pk)
    locked_response = _deny_olt_access_if_locked(request, olt)
    if locked_response:
        return locked_response
    is_ajax = request.headers.get("x-requested-with") == "XMLHttpRequest"
    live_lock = _acquire_olt_live_lock_with_retry(olt.pk)
    if live_lock is None:
        if is_ajax:
            return JsonResponse({
                "ok": False,
                "busy": True,
                "message": "Another live OLT task is already running. Please try again in a few seconds.",
            }, status=409)
        messages.warning(request, "Another live OLT task is already running. Please try again in a few seconds.")
        return redirect(f"{redirect('olt_view', pk=pk).url}?section=uplink")
    try:
        result = refresh_uplink_vlan_snapshot(olt)
        status_text = str(result.get("status") or "")
        if result.get("ok") and not is_ajax:
            messages.success(request, status_text or "Uplink VLANs refreshed.")
            _record_olt_login(olt, request.user, 'refresh_uplink_vlans', status_text or 'Uplink VLAN refresh completed', request=request)
        elif not result.get("ok") and not is_ajax:
            messages.warning(request, status_text or "Uplink VLAN refresh failed.")
        _safe_session_set(request, _olt_view_vlan_autorefresh_key(olt.pk, "uplink"), True)
        if is_ajax:
            return JsonResponse({
                "ok": bool(result.get("ok")),
                "message": status_text or ("Uplink VLANs refreshed." if result.get("ok") else "Uplink VLAN refresh failed."),
                "updated": int(result.get("updated") or 0),
                "redirect_url": f"{redirect('olt_view', pk=pk).url}?section=uplink",
            })
    finally:
        live_lock.release()
    return redirect(f"{redirect('olt_view', pk=pk).url}?section=uplink")


@login_required
@require_POST
def olt_refresh_vlans(request, pk):
    olt = get_object_or_404(OLT, pk=pk)
    locked_response = _deny_olt_access_if_locked(request, olt)
    if locked_response:
        return locked_response
    is_ajax = request.headers.get("x-requested-with") == "XMLHttpRequest"
    live_lock = _acquire_olt_live_lock_with_retry(olt.pk)
    if live_lock is None:
        if is_ajax:
            return JsonResponse({
                "ok": False,
                "busy": True,
                "message": "Another live OLT task is already running. Please try again in a few seconds.",
            }, status=409)
        messages.warning(request, "Another live OLT task is already running. Please try again in a few seconds.")
        return redirect(f"{redirect('olt_view', pk=pk).url}?section=vlans")
    try:
        vlan_data = _fetch_vlan_snapshot_with_retry(olt)
        save_vlan_snapshot(olt, vlan_data)
        _record_olt_login(olt, request.user, 'refresh_vlans', 'VLAN refresh completed', request=request)
        status_text = str((vlan_data or {}).get("status") or "")
        row_count = len((vlan_data or {}).get("rows") or [])
        if row_count and not is_ajax:
            messages.success(request, status_text or f"VLANs fetched: {row_count}")
        elif status_text and not is_ajax:
            messages.warning(request, status_text)
        _safe_session_set(request, _olt_view_vlan_autorefresh_key(olt.pk, "vlans"), True)
        if is_ajax:
            return JsonResponse({
                "ok": True,
                "message": status_text or f"VLANs fetched: {row_count}",
                "rows": row_count,
                "redirect_url": f"{redirect('olt_view', pk=pk).url}?section=vlans",
            })
    finally:
        live_lock.release()
    return redirect(f"{redirect('olt_view', pk=pk).url}?section=vlans")


@login_required
@admin_required
def olt_add_vlan(request, pk):
    olt = get_object_or_404(OLT, pk=pk)
    locked_response = _deny_olt_access_if_locked(request, olt)
    if locked_response:
        return locked_response
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
            transcript_text = "\n\n".join(
                part for part in [
                    str(add_result.get("transcript") or "").strip(),
                    str(verify_result.get("message") or "").strip(),
                ] if part
            ).strip()
            if not verify_result.get("ok"):
                notice_text = f"VLAN {cleaned['vlan_id']} Not created"
                _store_vlan_notice(request, olt.pk, notice_text)
                if not _store_vlan_form_state(request, olt.pk, form, transcript=transcript_text):
                    return _render_olt_vlans_response(request, pk, form=form, transcript=transcript_text, notice=notice_text)
                return redirect(f"{redirect('olt_view', pk=pk).url}?section=vlans")

            fetched_rows = list(saved_reference_rows)
            fetched_row = {
                "vlan_id": int(cleaned["vlan_id"]),
                "service_port_num": "-",
                "description": str(cleaned["description"] or "").strip() or "-",
            }
            fetched_rows = [row for row in fetched_rows if int(row.get("vlan_id", -1) or -1) != int(cleaned["vlan_id"])]
            fetched_rows.append(fetched_row)
            fetched_rows.sort(key=lambda row: int(row.get("vlan_id", 0) or 0))
            save_vlan_snapshot(olt, {
                "rows": fetched_rows,
                "status": f"VLANs fetched: {len(fetched_rows)}",
            })
            _record_olt_login(
                olt,
                request.user,
                "add_vlan",
                f'VLAN added: id={cleaned["vlan_id"]}, description={cleaned["description"] or "-"}',
                request=request,
            )
            messages.success(request, "VLAN Created")
            notice_text = "VLAN Created"
            _store_vlan_notice(request, olt.pk, notice_text)
            success_form = VLANAddForm(
                reserved_ids={int(row.get("vlan_id")) for row in fetched_rows if str(row.get("vlan_id", "")).isdigit()},
            )
            if not _store_vlan_form_state(request, olt.pk, success_form, transcript=transcript_text):
                return _render_olt_vlans_response(request, pk, form=success_form, transcript=transcript_text, notice=notice_text)
        else:
            notice_text = f"VLAN {cleaned['vlan_id']} Not created"
            transcript_text = str(add_result.get("transcript") or add_result.get("message") or "").strip()
            _store_vlan_notice(request, olt.pk, notice_text)
            if not _store_vlan_form_state(request, olt.pk, form, transcript=transcript_text):
                return _render_olt_vlans_response(request, pk, form=form, transcript=transcript_text, notice=notice_text)
            return redirect(f"{redirect('olt_view', pk=pk).url}?section=vlans")
    finally:
        live_lock.release()

    return redirect(f"{redirect('olt_view', pk=pk).url}?section=vlans")


@login_required
@admin_required
def olt_add_vlan_bulk(request, pk):
    olt = get_object_or_404(OLT, pk=pk)
    locked_response = _deny_olt_access_if_locked(request, olt)
    if locked_response:
        return locked_response
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
            _record_olt_login(
                olt,
                request.user,
                "add_vlan_bulk",
                f"VLAN range added: {start_vlan}-{end_vlan}",
                request=request,
            )
            messages.success(request, "VLAN Created")
            notice_text = "VLAN Created"
            _store_vlan_notice(request, olt.pk, notice_text)
            success_form = VLANBulkAddForm(
                reserved_ids={int(row.get("vlan_id")) for row in fetched_rows if str(row.get("vlan_id", "")).isdigit()},
            )
            bulk_transcript_text = str(add_result.get("transcript") or "").strip()
            if not _store_vlan_bulk_form_state(request, olt.pk, success_form, transcript=bulk_transcript_text):
                return _render_olt_vlans_response(request, pk, bulk_form=success_form, bulk_transcript=bulk_transcript_text, notice=notice_text)
        else:
            notice_text = f"VLAN {start_vlan}-{end_vlan} Not created"
            bulk_transcript_text = str(add_result.get("transcript") or add_result.get("message") or "").strip()
            _store_vlan_notice(request, olt.pk, notice_text)
            if not _store_vlan_bulk_form_state(request, olt.pk, form, transcript=bulk_transcript_text):
                return _render_olt_vlans_response(request, pk, bulk_form=form, bulk_transcript=bulk_transcript_text, notice=notice_text)
            return redirect(f"{redirect('olt_view', pk=pk).url}?section=vlans")
    finally:
        live_lock.release()

    return redirect(f"{redirect('olt_view', pk=pk).url}?section=vlans")


def _update_cached_uplink_vlan(olt, vlan_id, uplink_port, *, remove=False, create_vlan=False, description=""):
    vlan_text = str(vlan_id or "").strip()
    port_text = str(uplink_port or "").strip()
    changed = False
    rows = list(getattr(olt, "uplink_cache", []) or [])
    for row in rows:
        if str((row or {}).get("port") or "").strip() != port_text:
            continue
        current = str((row or {}).get("tagged_vlans") or "").strip()
        parts = [part.strip() for part in current.split(",") if part.strip() and part.strip() != "-"]
        if remove:
            next_parts = [part for part in parts if part != vlan_text]
        else:
            next_parts = parts[:]
            if vlan_text not in next_parts:
                next_parts.append(vlan_text)
        try:
            next_parts.sort(key=lambda value: int(str(value).strip()))
        except (TypeError, ValueError):
            pass
        row["tagged_vlans"] = ", ".join(next_parts) if next_parts else "-"
        changed = True
        break

    vlan_rows = list(getattr(olt, "vlan_cache", []) or [])
    if create_vlan and not remove and vlan_text and not any(str((row or {}).get("vlan_id") or "").strip() == vlan_text for row in vlan_rows):
        vlan_rows.append({"vlan_id": vlan_text, "description": str(description or "").strip()[:20]})
        try:
            vlan_rows.sort(key=lambda row: int(str((row or {}).get("vlan_id") or 0).strip() or 0))
        except (TypeError, ValueError):
            pass
        olt.vlan_cache = vlan_rows
        changed = True

    if changed:
        olt.uplink_cache = rows
        olt.save(update_fields=["uplink_cache", "vlan_cache"])


@login_required
@require_POST
@admin_required
def olt_add_vlan_uplink(request, pk):
    olt = get_object_or_404(OLT, pk=pk)
    locked_response = _deny_olt_access_if_locked(request, olt)
    if locked_response:
        return locked_response
    new_vlan_raw = str(request.POST.get("new_vlan_id") or request.POST.get("vlan_id") or "").strip()
    description = str(request.POST.get("description") or "").strip()
    selected_vlan_raw = str(request.POST.get("existing_vlan_id") or "").strip()
    uplink_port = str(request.POST.get("uplink_port") or "").strip()
    vlan_id_raw = new_vlan_raw or selected_vlan_raw
    create_vlan = bool(new_vlan_raw)

    if not vlan_id_raw or not uplink_port:
        _store_vlan_notice(request, olt.pk, "Select VLAN and uplink port first.")
        return redirect(f"{redirect('olt_view', pk=pk).url}?section=vlans")

    if create_vlan:
        reserved_ids = {
            int(row.get("vlan_id"))
            for row in list(getattr(olt, "vlan_cache", []) or [])
            if str(row.get("vlan_id", "")).isdigit()
        }
        form = VLANAddForm({"vlan_id": new_vlan_raw, "description": description}, reserved_ids=reserved_ids)
        if not form.is_valid():
            if not _store_vlan_form_state(request, olt.pk, form):
                return _render_olt_vlans_response(request, pk, form=form)
            return redirect(f"{redirect('olt_view', pk=pk).url}?section=vlans")
        vlan_id_raw = str(form.cleaned_data["vlan_id"])
        description = form.cleaned_data.get("description") or ""

    live_lock = _acquire_olt_live_lock_with_retry(olt.pk)
    if live_lock is None:
        _store_vlan_notice(request, olt.pk, "Another live OLT task is already running. Please try again in a few seconds.")
        return redirect(f"{redirect('olt_view', pk=pk).url}?section=vlans")

    try:
        result = configure_vlan_uplink_port(olt, vlan_id_raw, uplink_port, create_vlan=create_vlan, remove=False)
        notice_text = result.get("message") or ""
        _store_vlan_notice(request, olt.pk, notice_text, ok=bool(result.get("ok")))
        if result.get("ok"):
            _update_cached_uplink_vlan(olt, vlan_id_raw, uplink_port, remove=False, create_vlan=create_vlan, description=description)
            messages.success(request, notice_text)
            _record_olt_login(olt, request.user, "add_vlan_uplink", notice_text, request=request)
        else:
            messages.warning(request, notice_text)
    finally:
        live_lock.release()

    redirect_section = "uplink" if result.get("ok") else "vlans"
    return redirect(f"{redirect('olt_view', pk=pk).url}?section={redirect_section}")


@login_required
@require_POST
@admin_required
def olt_remove_vlan_uplink(request, pk):
    olt = get_object_or_404(OLT, pk=pk)
    locked_response = _deny_olt_access_if_locked(request, olt)
    if locked_response:
        return locked_response
    vlan_id_raw = str(request.POST.get("vlan_id") or "").strip()
    uplink_port = str(request.POST.get("uplink_port") or "").strip()

    if not vlan_id_raw or not uplink_port:
        _store_vlan_notice(request, olt.pk, "Select VLAN and uplink port first.")
        return redirect(f"{redirect('olt_view', pk=pk).url}?section=vlans")

    live_lock = _acquire_olt_live_lock_with_retry(olt.pk)
    if live_lock is None:
        _store_vlan_notice(request, olt.pk, "Another live OLT task is already running. Please try again in a few seconds.")
        return redirect(f"{redirect('olt_view', pk=pk).url}?section=vlans")

    try:
        result = configure_vlan_uplink_port(olt, vlan_id_raw, uplink_port, create_vlan=False, remove=True)
        notice_text = result.get("message") or ""
        _store_vlan_notice(request, olt.pk, notice_text, ok=bool(result.get("ok")))
        if result.get("ok"):
            _update_cached_uplink_vlan(olt, vlan_id_raw, uplink_port, remove=True)
            messages.success(request, notice_text)
            _record_olt_login(olt, request.user, "remove_vlan_uplink", notice_text, request=request)
        else:
            messages.warning(request, notice_text)
    finally:
        live_lock.release()

    return redirect(f"{redirect('olt_view', pk=pk).url}?section=vlans")


@login_required
@require_POST
@admin_required
def olt_delete_vlan(request, pk):
    olt = get_object_or_404(OLT, pk=pk)
    locked_response = _deny_olt_access_if_locked(request, olt)
    if locked_response:
        return locked_response
    vlan_id_raw = request.POST.get("vlan_id")
    try:
        vlan_id = int(vlan_id_raw)
    except (TypeError, ValueError):
        messages.warning(request, "Invalid VLAN ID.")
        return redirect(f"{redirect('olt_view', pk=pk).url}?section=vlans")

    vlan_id_text = str(vlan_id)
    onu_count = 0
    for cache_value in ConfiguredONU.objects.filter(olt=olt).exclude(attached_vlans_cache="").values_list("attached_vlans_cache", flat=True):
        parts = [part.strip() for part in str(cache_value or "").split(",") if part.strip()]
        if vlan_id_text in parts:
            onu_count += 1
    if onu_count:
        onu_link = f"{reverse('configured_onus')}?olt={olt.pk}&vlan={quote_plus(vlan_id_text)}"
        _store_vlan_notice(
            request,
            olt.pk,
            f"Remove {onu_count} ONU(s) from VLAN {vlan_id} first",
            url=onu_link,
        )
        messages.warning(
            request,
            format_html(
                'Remove <a href="{}">{} ONU(s)</a> from VLAN {} first',
                onu_link,
                onu_count,
                vlan_id,
            ),
        )
        return redirect(f"{redirect('olt_view', pk=pk).url}?section=vlans")

    previous_rows = list(getattr(olt, "vlan_cache", []) or [])
    next_rows = [
        row for row in previous_rows
        if str((row or {}).get("vlan_id") or "").strip() != vlan_id_text
    ]
    if len(next_rows) == len(previous_rows):
        notice_text = f"VLAN {vlan_id} was not found in the database."
        _store_vlan_notice(request, olt.pk, notice_text, ok=False)
        messages.warning(request, notice_text)
        return redirect(f"{redirect('olt_view', pk=pk).url}?section=vlans")

    olt.vlan_cache = next_rows
    olt.vlan_status = f"VLAN {vlan_id} removed from database."
    olt.save(update_fields=["vlan_cache", "vlan_status"])

    notice_text = f"VLAN {vlan_id} removed from database."
    _store_vlan_notice(request, olt.pk, notice_text, ok=True)
    messages.success(request, notice_text)

    return redirect(f"{redirect('olt_view', pk=pk).url}?section=vlans")


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
    for olt in _ready_olts().order_by('id'):
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
