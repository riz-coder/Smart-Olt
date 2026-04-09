import os
import sys
import threading
import time

from django.apps import AppConfig
from django.db import close_old_connections


_ONU_INVENTORY_SYNC_THREAD = None
_ONU_INVENTORY_SYNC_GUARD = threading.Lock()
ONU_INVENTORY_SYNC_SECONDS = 600
_RUNTIME_SYNC_CURSOR = {}
RUNTIME_SYNC_BATCH_SIZE = 150


def _sleep_until_next_sync_boundary():
    now_ts = time.time()
    next_ts = ((int(now_ts) // ONU_INVENTORY_SYNC_SECONDS) + 1) * ONU_INVENTORY_SYNC_SECONDS
    sleep_for = max(1, next_ts - now_ts)
    time.sleep(sleep_for)


def _onu_inventory_sync_loop():
    from .models import OLT
    from .utils import (
        record_dashboard_status_samples,
        reconcile_offline_onus_with_signal,
        sync_olt_autofind_count,
        sync_configured_onus_inventory,
        sync_runtime_statuses_for_olt,
    )

    while True:
        try:
            close_old_connections()
            for olt in OLT.objects.all().only("id", "name"):
                try:
                    sync_configured_onus_inventory(olt)
                    sync_olt_autofind_count(olt)
                    cursor_pk = _RUNTIME_SYNC_CURSOR.get(olt.id) or 0
                    runtime_result = sync_runtime_statuses_for_olt(
                        olt,
                        only_non_online=False,
                        limit=RUNTIME_SYNC_BATCH_SIZE,
                        start_pk=cursor_pk,
                    )
                    _RUNTIME_SYNC_CURSOR[olt.id] = runtime_result.get("last_pk") or 0
                    reconcile_offline_onus_with_signal(olt=olt, limit=250)
                except Exception:
                    close_old_connections()
                    continue
            try:
                record_dashboard_status_samples()
            except Exception:
                pass
        except Exception:
            pass
        finally:
            close_old_connections()
        _sleep_until_next_sync_boundary()


class OltmanagerConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'oltmanager'

    def ready(self):
        global _ONU_INVENTORY_SYNC_THREAD

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
