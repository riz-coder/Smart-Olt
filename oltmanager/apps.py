import os
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from django.apps import AppConfig
from django.db import close_old_connections
from django.utils import timezone


_ONU_INVENTORY_SYNC_THREAD = None
_ONU_INVENTORY_SYNC_GUARD = threading.Lock()
_SNMP_MONITOR_THREAD = None
_SNMP_MONITOR_GUARD = threading.Lock()
ONU_INVENTORY_SYNC_SECONDS = 600
SNMP_MONITOR_SECONDS = 10
SNMP_DOWN_THRESHOLD_SECONDS = 60
_RUNTIME_SYNC_CURSOR = {}
_CAPABILITY_SYNC_CURSOR = {}
RUNTIME_SYNC_BATCH_SIZE = 80
CAPABILITY_SYNC_BATCH_SIZE = 40
ONU_SYNC_MAX_WORKERS = 3
_SNMP_DOWN_SINCE = {}
_SNMP_OFFLINE_APPLIED = set()


def _sleep_until_next_sync_boundary():
    now_ts = time.time()
    next_ts = ((int(now_ts) // ONU_INVENTORY_SYNC_SECONDS) + 1) * ONU_INVENTORY_SYNC_SECONDS
    sleep_for = max(1, next_ts - now_ts)
    time.sleep(sleep_for)


def _onu_inventory_sync_loop():
    from .models import OLT
    from .utils import (
        record_pon_traffic_samples,
        record_pon_port_traffic_samples,
        record_uplink_port_traffic_samples,
        record_dashboard_status_samples,
    )

    def _sync_single_olt_cycle(olt_id):
        from .models import OLT
        from .utils import (
            reconcile_offline_onus_with_signal,
            sync_olt_autofind_count,
            sync_onu_capabilities_for_olt,
            sync_configured_onus_inventory,
            sync_runtime_statuses_for_olt,
        )

        close_old_connections()
        try:
            olt = OLT.objects.filter(pk=olt_id).only("id", "name").first()
            if not olt:
                return

            try:
                sync_configured_onus_inventory(olt)
            except Exception:
                close_old_connections()

            try:
                sync_olt_autofind_count(olt)
            except Exception:
                close_old_connections()

            try:
                cursor_pk = _RUNTIME_SYNC_CURSOR.get(olt.id) or 0
                runtime_result = sync_runtime_statuses_for_olt(
                    olt,
                    only_non_online=True,
                    limit=RUNTIME_SYNC_BATCH_SIZE,
                    start_pk=cursor_pk,
                )
                _RUNTIME_SYNC_CURSOR[olt.id] = runtime_result.get("last_pk") or 0
            except Exception:
                close_old_connections()

            try:
                capability_cursor_pk = _CAPABILITY_SYNC_CURSOR.get(olt.id) or 0
                capability_result = sync_onu_capabilities_for_olt(
                    olt,
                    limit=CAPABILITY_SYNC_BATCH_SIZE,
                    start_pk=capability_cursor_pk,
                )
                _CAPABILITY_SYNC_CURSOR[olt.id] = capability_result.get("last_pk") or 0
            except Exception:
                close_old_connections()

            try:
                reconcile_offline_onus_with_signal(olt=olt, limit=120)
            except Exception:
                close_old_connections()
        finally:
            close_old_connections()

    while True:
        try:
            close_old_connections()
            olt_ids = list(OLT.objects.order_by("id").values_list("id", flat=True))
            if olt_ids:
                with ThreadPoolExecutor(max_workers=ONU_SYNC_MAX_WORKERS, thread_name_prefix="onu-sync") as executor:
                    futures = [executor.submit(_sync_single_olt_cycle, olt_id) for olt_id in olt_ids]
                    for future in as_completed(futures):
                        try:
                            future.result()
                        except Exception:
                            close_old_connections()
            try:
                record_pon_traffic_samples()
            except Exception:
                pass
            try:
                record_pon_port_traffic_samples()
            except Exception:
                pass
            try:
                record_uplink_port_traffic_samples()
            except Exception:
                pass
            try:
                record_dashboard_status_samples()
            except Exception:
                pass
        except Exception:
            pass
        finally:
            close_old_connections()
        _sleep_until_next_sync_boundary()


def _snmp_monitor_loop():
    from .models import OLT
    from .utils import mark_olt_onus_offline_due_to_snmp, probe_snmp_reachability, record_dashboard_status_samples

    def _probe_single_olt(olt_id):
        from .models import OLT

        close_old_connections()
        try:
            olt = OLT.objects.filter(pk=olt_id).only("id", "name", "ip_address", "snmp_port", "snmp_community").first()
            if not olt:
                return olt_id, False, "OLT not found"
            probe = probe_snmp_reachability(olt)
            return olt_id, bool(probe.get("ok")), str(probe.get("status") or "").strip()
        finally:
            close_old_connections()

    while True:
        try:
            close_old_connections()
            now_ts = time.time()
            olt_ids = list(OLT.objects.order_by("id").values_list("id", flat=True))
            if olt_ids:
                with ThreadPoolExecutor(max_workers=min(4, max(1, len(olt_ids))), thread_name_prefix="snmp-monitor") as executor:
                    futures = [executor.submit(_probe_single_olt, olt_id) for olt_id in olt_ids]
                    for future in as_completed(futures):
                        try:
                            olt_id, ok, status_text = future.result()
                        except Exception:
                            continue
                        if ok:
                            _SNMP_DOWN_SINCE.pop(olt_id, None)
                            if olt_id in _SNMP_OFFLINE_APPLIED:
                                olt = OLT.objects.filter(pk=olt_id).only("id", "snmp_last_status", "snmp_last_synced_at").first()
                                if olt:
                                    olt.snmp_last_status = "Live SNMP data fetched"
                                    olt.snmp_last_synced_at = timezone.now()
                                    olt.save(update_fields=["snmp_last_status", "snmp_last_synced_at"])
                                _SNMP_OFFLINE_APPLIED.discard(olt_id)
                                try:
                                    record_dashboard_status_samples(force=True)
                                except Exception:
                                    close_old_connections()
                            continue

                        first_down_ts = _SNMP_DOWN_SINCE.get(olt_id)
                        if first_down_ts is None:
                            _SNMP_DOWN_SINCE[olt_id] = now_ts
                            continue
                        if (now_ts - first_down_ts) < SNMP_DOWN_THRESHOLD_SECONDS:
                            continue
                        if olt_id in _SNMP_OFFLINE_APPLIED:
                            continue

                        olt = OLT.objects.filter(pk=olt_id).first()
                        if not olt:
                            continue
                        try:
                            mark_olt_onus_offline_due_to_snmp(olt, status_text=status_text)
                            _SNMP_OFFLINE_APPLIED.add(olt_id)
                            record_dashboard_status_samples(force=True)
                        except Exception:
                            close_old_connections()
        except Exception:
            pass
        finally:
            close_old_connections()
        time.sleep(SNMP_MONITOR_SECONDS)


class OltmanagerConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'oltmanager'

    def ready(self):
        global _ONU_INVENTORY_SYNC_THREAD, _SNMP_MONITOR_THREAD

        embedded_sync_disabled = os.environ.get("OLT_DISABLE_EMBEDDED_SYNC", "").strip().lower() in {"1", "true", "yes"}
        if embedded_sync_disabled:
            return

        embedded_sync_enabled = os.environ.get("OLT_ENABLE_EMBEDDED_SYNC", "").strip().lower() in {"1", "true", "yes"}
        is_server_process = "runserver" in sys.argv or embedded_sync_enabled
        if not is_server_process:
            return
        if os.environ.get("RUN_MAIN") not in {None, "true"}:
            return

        with _ONU_INVENTORY_SYNC_GUARD:
            if _ONU_INVENTORY_SYNC_THREAD and _ONU_INVENTORY_SYNC_THREAD.is_alive():
                return
            _ONU_INVENTORY_SYNC_THREAD = threading.Thread(
                target=_onu_inventory_sync_loop,
                name="onu-inventory-sync",
                daemon=True,
            )
            _ONU_INVENTORY_SYNC_THREAD.start()

        with _SNMP_MONITOR_GUARD:
            if _SNMP_MONITOR_THREAD and _SNMP_MONITOR_THREAD.is_alive():
                return
            _SNMP_MONITOR_THREAD = threading.Thread(
                target=_snmp_monitor_loop,
                name="snmp-monitor-sync",
                daemon=True,
            )
            _SNMP_MONITOR_THREAD.start()
