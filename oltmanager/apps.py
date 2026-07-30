import logging
import os
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from django.apps import AppConfig
from django.conf import settings
from django.db import close_old_connections
from django.utils import timezone

logger = logging.getLogger("oltmanager.sync")


_ONU_INVENTORY_SYNC_THREAD = None
_ONU_INVENTORY_SYNC_GUARD = threading.Lock()
_SNMP_MONITOR_THREAD = None
_SNMP_MONITOR_GUARD = threading.Lock()
_ONU_STATUS_SYNC_THREAD = None
_ONU_STATUS_SYNC_GUARD = threading.Lock()
_ONU_SIGNAL_SAMPLE_THREAD = None
_ONU_SIGNAL_SAMPLE_GUARD = threading.Lock()
_DASHBOARD_SAMPLE_THREAD = None
_DASHBOARD_SAMPLE_GUARD = threading.Lock()
ONU_INVENTORY_SYNC_SECONDS = 600
SNMP_MONITOR_SECONDS = 10
# ONU dashboard counts/status snapshots follow the 10-minute dashboard cycle.
# The independent SNMP monitor below remains at 10 seconds for OLT reachability.
ONU_STATUS_SYNC_SECONDS = 600
ONU_SIGNAL_SAMPLE_SECONDS = int(getattr(settings, "OLT_ONU_SIGNAL_SAMPLE_SECONDS", os.environ.get("OLT_ONU_SIGNAL_SAMPLE_SECONDS", 3600)) or 3600)
# The monitor already runs every 10 seconds, so apply a failed SNMP probe on the
# same cycle instead of waiting for a second/third failure.
SNMP_DOWN_THRESHOLD_SECONDS = 0
# Reconcile on the first successful SNMP probe after an outage. The recovery path
# reads real per-ONU SNMP state, so it does not blindly mark every ONU online.
SNMP_UP_RECOVERY_STREAK = 1
_SNMP_UP_STREAK = {}
_CAPABILITY_SYNC_CURSOR = {}
_SIGNAL_SYNC_CURSOR = {}
CAPABILITY_SYNC_BATCH_SIZE = 40
SIGNAL_SYNC_BATCH_SIZE = 160
SIGNAL_SYNC_MAX_WORKERS = max(1, int(getattr(settings, "OLT_SIGNAL_SYNC_MAX_WORKERS", os.environ.get("OLT_SIGNAL_SYNC_MAX_WORKERS", 1)) or 1))
SIGNAL_TELNET_FALLBACK_ENABLED = str(
    getattr(settings, "OLT_SIGNAL_TELNET_FALLBACK_ENABLED", os.environ.get("OLT_SIGNAL_TELNET_FALLBACK_ENABLED", "false"))
).strip().lower() in {"1", "true", "yes", "on"}
ONU_SYNC_MAX_WORKERS = 3
_SNMP_DOWN_SINCE = {}
_SNMP_PENDING_STATUS = {}
_SNMP_OFFLINE_APPLIED = set()
# Restart-safe self-heal: per-OLT throttle for reconciling ONUs that are stuck in
# the snmp_down outage state once the OLT answers SNMP again. This does NOT depend
# on _SNMP_OFFLINE_APPLIED (which is lost on restart), so recovered ONUs can never
# stay offline forever.
_LAST_RECONCILE_AT = {}
RECONCILE_THROTTLE_SECONDS = 30
# Per-OLT timestamp of last SNMP-based new-ONU detection check.
_LAST_NEW_ONU_CHECK_AT = {}
NEW_ONU_CHECK_SECONDS = 60
AUTO_INVENTORY_SYNC_FROM_SNMP = str(
    getattr(settings, "OLT_AUTO_INVENTORY_SYNC_FROM_SNMP", os.environ.get("OLT_AUTO_INVENTORY_SYNC_FROM_SNMP", "false"))
).strip().lower() in {"1", "true", "yes", "on"}
# Tracks OLT IDs for which an immediate inventory sync thread is already running
# so we never stack concurrent Telnet syncs for the same OLT.
_IMMEDIATE_SYNC_RUNNING = set()
_IMMEDIATE_SYNC_LOCK = threading.Lock()
_IMMEDIATE_SYNC_LAST_AT = {}
IMMEDIATE_SYNC_COOLDOWN_SECONDS = int(getattr(settings, "OLT_IMMEDIATE_INVENTORY_SYNC_COOLDOWN_SECONDS", 900) or 900)
IMMEDIATE_SYNC_MAX_GLOBAL = max(1, int(getattr(settings, "OLT_IMMEDIATE_INVENTORY_SYNC_MAX_GLOBAL", 1) or 1))
_IMMEDIATE_SYNC_SEMAPHORE = threading.BoundedSemaphore(IMMEDIATE_SYNC_MAX_GLOBAL)
_SAMPLE_RETENTION_CLEANUP_LAST_TS = 0.0
_SAMPLE_RETENTION_CLEANUP_LOCK = threading.Lock()


def _run_sample_retention_cleanup_if_due():
    global _SAMPLE_RETENTION_CLEANUP_LAST_TS
    interval = int(getattr(settings, "OLT_SAMPLE_RETENTION_CLEANUP_SECONDS", 3600) or 3600)
    now_ts = time.time()
    if (now_ts - _SAMPLE_RETENTION_CLEANUP_LAST_TS) < interval:
        return
    if not _SAMPLE_RETENTION_CLEANUP_LOCK.acquire(blocking=False):
        return
    try:
        now_ts = time.time()
        if (now_ts - _SAMPLE_RETENTION_CLEANUP_LAST_TS) < interval:
            return
        from .utils import prune_sample_history

        deleted = prune_sample_history()
        _SAMPLE_RETENTION_CLEANUP_LAST_TS = now_ts
        if any(int(value or 0) for value in deleted.values()):
            logger.info("Sample retention cleanup pruned rows: %s", deleted)
    except Exception as exc:
        logger.warning("Sample retention cleanup failed: %s", exc)
    finally:
        _SAMPLE_RETENTION_CLEANUP_LOCK.release()


def _run_immediate_inventory_sync(olt_id):
    """Background thread: run a full inventory sync for one OLT right now."""
    from .models import OLT
    from .utils import sync_configured_onus_inventory

    close_old_connections()
    try:
        olt = OLT.objects.filter(pk=olt_id).first()
        if not olt:
            return
        result = sync_configured_onus_inventory(olt)
        if result.get("incomplete"):
            logger.warning(
                "OLT %s immediate sync incomplete: %s/%s ONUs fetched.",
                olt.name,
                result.get("actual_count"),
                result.get("expected_count"),
            )
        else:
            logger.info("OLT %s immediate sync done: %s", olt.name, result.get("status", ""))
    except Exception as exc:
        logger.exception("OLT %s immediate sync error: %s", olt_id, exc)
    finally:
        close_old_connections()
        with _IMMEDIATE_SYNC_LOCK:
            _IMMEDIATE_SYNC_RUNNING.discard(olt_id)
        try:
            _IMMEDIATE_SYNC_SEMAPHORE.release()
        except ValueError:
            pass


def _schedule_immediate_inventory_sync(olt_id):
    """Start an immediate inventory sync thread for olt_id (no-op if one is already running)."""
    now_ts = time.time()
    with _IMMEDIATE_SYNC_LOCK:
        if olt_id in _IMMEDIATE_SYNC_RUNNING:
            return False
        last_ts = float(_IMMEDIATE_SYNC_LAST_AT.get(olt_id) or 0.0)
        if (now_ts - last_ts) < IMMEDIATE_SYNC_COOLDOWN_SECONDS:
            return False
        if not _IMMEDIATE_SYNC_SEMAPHORE.acquire(blocking=False):
            return False
        _IMMEDIATE_SYNC_RUNNING.add(olt_id)
        _IMMEDIATE_SYNC_LAST_AT[olt_id] = now_ts
    threading.Thread(
        target=_run_immediate_inventory_sync,
        args=(olt_id,),
        name=f"onu-immediate-sync-{olt_id}",
        daemon=True,
    ).start()
    return True


def _sleep_until_next_sync_boundary():
    now_ts = time.time()
    next_ts = ((int(now_ts) // ONU_INVENTORY_SYNC_SECONDS) + 1) * ONU_INVENTORY_SYNC_SECONDS
    sleep_for = max(1, next_ts - now_ts)
    time.sleep(sleep_for)


def _sleep_until_next_signal_boundary():
    now_ts = time.time()
    interval = max(60, int(ONU_SIGNAL_SAMPLE_SECONDS or 3600))
    next_ts = ((int(now_ts) // interval) + 1) * interval
    time.sleep(max(1, next_ts - now_ts))


def _onu_inventory_sync_loop():
    from .models import OLT
    from .utils import (
        record_pon_traffic_samples,
        record_pon_port_traffic_samples,
        record_uplink_port_traffic_samples,
        record_dashboard_status_samples,
    )

    # Avoid a thundering herd immediately after ASGI/service restart. The
    # lightweight dashboard sampler runs separately, so full inventory can wait
    # for the normal 10-minute boundary.
    _sleep_until_next_sync_boundary()

    def _sync_single_olt_cycle(olt_id):
        from .models import OLT
        from .utils import (
            reconcile_offline_onus_with_signal,
            reconcile_onu_status_via_snmp,
            sync_olt_autofind_count,
            sync_onu_capabilities_for_olt,
            sync_missing_online_onu_power_for_olt,
        )

        close_old_connections()
        try:
            olt = OLT.objects.filter(pk=olt_id).only("id", "name", "snmp_last_status").first()
            if not olt:
                return

            # Self-heal: if the OLT is reachable, bulk-correct any ONU left stuck
            # in the "snmp_down" state from an earlier outage (survives restarts).
            try:
                reconcile_onu_status_via_snmp(olt)
            except Exception:
                close_old_connections()

            try:
                sync_olt_autofind_count(olt)
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
                sync_missing_online_onu_power_for_olt(olt, limit=120)
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
            olt_ids = list(
                OLT.objects
                .exclude(onboarding_status__in=["queued", "running", "aborting"])
                .order_by("id")
                .values_list("id", flat=True)
            )
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
            try:
                _run_sample_retention_cleanup_if_due()
            except Exception:
                pass
        except Exception:
            pass
        finally:
            close_old_connections()
        _sleep_until_next_sync_boundary()


def _snmp_monitor_loop():
    from .models import OLT
    from .utils import (
        mark_olt_onus_offline_due_to_snmp,
        probe_icmp_reachability,
        probe_snmp_reachability,
        reconcile_onu_status_via_snmp,
    )

    def _save_snmp_probe_status(olt_id, status_text):
        status_text = str(status_text or "").strip()[:300]
        if not status_text:
            return
        current = OLT.objects.filter(pk=olt_id).only("snmp_last_status", "snmp_last_synced_at").first()
        now = timezone.now()
        if current:
            same_status = str(getattr(current, "snmp_last_status", "") or "").strip() == status_text
            synced_at = getattr(current, "snmp_last_synced_at", None)
            if same_status and synced_at and (now - synced_at).total_seconds() < 30:
                return
        OLT.objects.filter(pk=olt_id).update(
            snmp_last_status=status_text,
            snmp_last_synced_at=now,
        )

    def _probe_single_olt(olt_id):
        from .models import OLT

        close_old_connections()
        try:
            olt = OLT.objects.filter(pk=olt_id).only("id", "name", "ip_address", "snmp_port", "snmp_community").first()
            if not olt:
                return olt_id, False, "OLT not found", False, "ICMP ping failed"
            snmp_probe = probe_snmp_reachability(olt)
            icmp_probe = probe_icmp_reachability(olt)
            return (
                olt_id,
                bool(snmp_probe.get("ok")),
                str(snmp_probe.get("status") or "").strip(),
                bool(icmp_probe.get("ok")),
                str(icmp_probe.get("status") or "").strip(),
            )
        finally:
            close_old_connections()

    while True:
        try:
            close_old_connections()
            now_ts = time.time()
            olt_ids = list(
                OLT.objects
                .exclude(onboarding_status__in=["queued", "running", "aborting"])
                .order_by("id")
                .values_list("id", flat=True)
            )
            if olt_ids:
                with ThreadPoolExecutor(max_workers=min(4, max(1, len(olt_ids))), thread_name_prefix="snmp-monitor") as executor:
                    futures = [executor.submit(_probe_single_olt, olt_id) for olt_id in olt_ids]
                    for future in as_completed(futures):
                        try:
                            olt_id, snmp_ok, snmp_status_text, icmp_ok, icmp_status_text = future.result()
                        except Exception:
                            continue
                        if snmp_ok:
                            _SNMP_DOWN_SINCE.pop(olt_id, None)
                            _SNMP_PENDING_STATUS.pop(olt_id, None)
                            up_streak = _SNMP_UP_STREAK.get(olt_id, 0) + 1
                            _SNMP_UP_STREAK[olt_id] = up_streak
                            olt = OLT.objects.filter(pk=olt_id).first()
                            if olt:
                                # SNMP answered -> the OLT is reachable RIGHT NOW.
                                # Always refresh the OLT status to reachable (both in
                                # the DB and on this in-memory copy, so the reconcile
                                # gate below sees a non-down status).
                                fresh_status = snmp_status_text or "Live SNMP data fetched"
                                _save_snmp_probe_status(olt_id, fresh_status)
                                olt.snmp_last_status = fresh_status
                                _SNMP_OFFLINE_APPLIED.discard(olt_id)

                                # ROBUST, restart-safe self-heal: once SNMP is
                                # sustained-up, reconcile every ONU still stuck in the
                                # snmp_down outage state directly from a real SNMP
                                # status walk. This does NOT depend on any in-memory
                                # flag, so an OLT that recovered while the app was
                                # restarted (or that was never flagged in-process) can
                                # never leave its ONUs stuck offline. Cheap quick-exit
                                # when nothing is stuck; throttled so the SNMP walk
                                # runs at most once per RECONCILE_THROTTLE_SECONDS.
                                if up_streak >= SNMP_UP_RECOVERY_STREAK:
                                    last_heal = _LAST_RECONCILE_AT.get(olt_id, 0.0)
                                    if (now_ts - last_heal) >= RECONCILE_THROTTLE_SECONDS:
                                        _LAST_RECONCILE_AT[olt_id] = now_ts
                                        try:
                                            outcome = reconcile_onu_status_via_snmp(olt)
                                            # ONU dashboard totals remain on the
                                            # 10-minute sample boundary.
                                        except Exception:
                                            close_old_connections()
                                        # Auto-resolve any active "OLT Down" alert now
                                        # that the device is reachable again (idempotent:
                                        # a no-op when no alert is active).
                                        try:
                                            from .alerts import resolve_alert
                                            resolve_alert(
                                                f"olt_down:{olt_id}",
                                                send_recovery=True,
                                                recovery_type="olt_recovered",
                                                title=f"OLT Recovered: {olt.name}",
                                                message=f"{olt.name} ({olt.ip_address}) is back online.",
                                                olt=olt,
                                            )
                                        except Exception:
                                            close_old_connections()

                                # Optional auto-discovery bridge: this is disabled by
                                # default because a SNMP-visible new ONU can trigger a
                                # full Telnet inventory sync. On busy installations that
                                # becomes expensive; use OLT > Advanced > Sync Config
                                # for the normal/manual import path.
                                last_new_check = _LAST_NEW_ONU_CHECK_AT.get(olt_id, 0.0)
                                if AUTO_INVENTORY_SYNC_FROM_SNMP and (now_ts - last_new_check) >= NEW_ONU_CHECK_SECONDS:
                                    _LAST_NEW_ONU_CHECK_AT[olt_id] = now_ts
                                    try:
                                        from .utils import detect_new_onus_from_snmp
                                        detection = detect_new_onus_from_snmp(olt)
                                        if detection.get("new_keys"):
                                            logger.info(
                                                "OLT %s: %d new ONU(s) detected via SNMP â€” "
                                                "triggering immediate inventory sync. (%s)",
                                                olt.name,
                                                len(detection["new_keys"]),
                                                detection.get("status", ""),
                                            )
                                            _schedule_immediate_inventory_sync(olt_id)
                                    except Exception:
                                        close_old_connections()
                            continue

                        olt = OLT.objects.filter(pk=olt_id).first()
                        if not olt:
                            continue
                        # A failed probe breaks any recovery streak.
                        _SNMP_UP_STREAK.pop(olt_id, None)
                        status_text = "SNMP Down" if icmp_ok else "OLT Unreachable"
                        pending_status = _SNMP_PENDING_STATUS.get(olt_id)
                        down_since = _SNMP_DOWN_SINCE.get(olt_id)
                        if pending_status != status_text or down_since is None:
                            _SNMP_PENDING_STATUS[olt_id] = status_text
                            _SNMP_DOWN_SINCE[olt_id] = now_ts
                            down_since = now_ts
                        if (now_ts - down_since) < SNMP_DOWN_THRESHOLD_SECONDS:
                            continue

                        _save_snmp_probe_status(olt_id, status_text)
                        if olt_id in _SNMP_OFFLINE_APPLIED:
                            continue
                        try:
                            mark_olt_onus_offline_due_to_snmp(olt, status_text=status_text)
                            _SNMP_OFFLINE_APPLIED.add(olt_id)
                        except Exception:
                            close_old_connections()
            # Keep dashboard ONU counts on the normal 10-minute sample boundary.
            # OLT reachability itself is still updated immediately by the 10-second
            # SNMP monitor and is rendered independently on the dashboard.
            # Alert engine: periodic temperature, fiber-cut and signal checks (in-app only).
            try:
                from .alerts import run_periodic_alert_checks
                run_periodic_alert_checks()
            except Exception:
                close_old_connections()
        except Exception:
            pass
        finally:
            close_old_connections()
        time.sleep(SNMP_MONITOR_SECONDS)


def _onu_status_sync_loop():
    from .models import OLT
    from .utils import sync_runtime_statuses_for_olt

    time.sleep(90)

    def _sync_single_olt_status(olt_id):
        from .models import OLT

        close_old_connections()
        try:
            olt = OLT.objects.filter(pk=olt_id).only("id", "name", "snmp_last_status").first()
            if not olt:
                return
            return sync_runtime_statuses_for_olt(
                olt,
                only_non_online=False,
                limit=None,
                write_samples=False,
            )
        finally:
            close_old_connections()

    while True:
        try:
            close_old_connections()
            olt_ids = list(OLT.objects.order_by("id").values_list("id", flat=True))
            if olt_ids:
                with ThreadPoolExecutor(max_workers=min(3, max(1, len(olt_ids))), thread_name_prefix="onu-status") as executor:
                    futures = [executor.submit(_sync_single_olt_status, olt_id) for olt_id in olt_ids]
                    for future in as_completed(futures):
                        try:
                            result = future.result() or {}
                        except Exception:
                            close_old_connections()
            # Do not force a dashboard count sample for a transient OLT outage or
            # recovery. Counts remain on the configured 10-minute boundary.
        except Exception:
            pass
        finally:
            close_old_connections()
        time.sleep(ONU_STATUS_SYNC_SECONDS)


def _onu_signal_sample_loop():
    from .models import OLT
    from .utils import sync_online_onu_power_for_olt, sync_onu_signals_from_snmp

    _sleep_until_next_signal_boundary()

    def _sample_single_olt(olt_id):
        from .models import OLT

        close_old_connections()
        try:
            olt = OLT.objects.filter(pk=olt_id).only("id", "name").first()
            if not olt:
                return

            # â”€â”€ 1. SNMP bulk fetch â€” up to 3 attempts before Telnet â”€â”€â”€â”€â”€â”€â”€â”€
            _SNMP_SIGNAL_RETRIES = 3
            _SNMP_SIGNAL_RETRY_DELAY = 4  # seconds between retries
            snmp_filled = 0
            for _attempt in range(_SNMP_SIGNAL_RETRIES):
                try:
                    snmp_result = sync_onu_signals_from_snmp(olt, overwrite=True)
                    snmp_filled = int(snmp_result.get("filled") or 0)
                    if snmp_filled > 0:
                        break
                except Exception:
                    close_old_connections()
                if _attempt < _SNMP_SIGNAL_RETRIES - 1:
                    time.sleep(_SNMP_SIGNAL_RETRY_DELAY)

            # â”€â”€ 2. Telnet fallback â€” only if all SNMP attempts returned nothing â”€â”€
            if snmp_filled == 0 and SIGNAL_TELNET_FALLBACK_ENABLED:
                try:
                    cursor_pk = _SIGNAL_SYNC_CURSOR.get(olt.id) or 0
                    result = sync_online_onu_power_for_olt(olt, limit=SIGNAL_SYNC_BATCH_SIZE, start_pk=cursor_pk)
                    _SIGNAL_SYNC_CURSOR[olt.id] = int(result.get("last_pk") or 0)
                except Exception:
                    close_old_connections()

        finally:
            close_old_connections()

    while True:
        try:
            close_old_connections()
            olt_ids = list(OLT.objects.order_by("id").values_list("id", flat=True))
            if olt_ids:
                with ThreadPoolExecutor(max_workers=min(SIGNAL_SYNC_MAX_WORKERS, max(1, len(olt_ids))), thread_name_prefix="onu-signal") as executor:
                    futures = [executor.submit(_sample_single_olt, olt_id) for olt_id in olt_ids]
                    for future in as_completed(futures):
                        try:
                            future.result()
                        except Exception:
                            close_old_connections()
        except Exception:
            pass
        finally:
            close_old_connections()
        time.sleep(ONU_SIGNAL_SAMPLE_SECONDS)


def _dashboard_sample_loop():
    from .utils import record_dashboard_status_samples

    while True:
        try:
            close_old_connections()
            record_dashboard_status_samples(force=False, refresh_onu_statuses=False)
        except Exception:
            close_old_connections()
        finally:
            close_old_connections()
        _sleep_until_next_sync_boundary()


class OltmanagerConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'oltmanager'

    def ready(self):
        global _ONU_INVENTORY_SYNC_THREAD, _SNMP_MONITOR_THREAD, _ONU_STATUS_SYNC_THREAD, _ONU_SIGNAL_SAMPLE_THREAD, _DASHBOARD_SAMPLE_THREAD

        embedded_sync_disabled = os.environ.get("OLT_DISABLE_EMBEDDED_SYNC", "").strip().lower() in {"1", "true", "yes"}
        if embedded_sync_disabled:
            return

        embedded_sync_enabled = os.environ.get("OLT_ENABLE_EMBEDDED_SYNC", "").strip().lower() in {"1", "true", "yes"}
        argv_text = " ".join(str(arg or "") for arg in sys.argv).lower()
        server_tokens = ("runserver", "daphne", "uvicorn", "gunicorn")
        is_server_process = embedded_sync_enabled or any(token in argv_text for token in server_tokens)
        if not is_server_process:
            return
        if os.environ.get("RUN_MAIN") not in {None, "true"}:
            return

        with _ONU_INVENTORY_SYNC_GUARD:
            if not (_ONU_INVENTORY_SYNC_THREAD and _ONU_INVENTORY_SYNC_THREAD.is_alive()):
                _ONU_INVENTORY_SYNC_THREAD = threading.Thread(
                    target=_onu_inventory_sync_loop,
                    name="onu-inventory-sync",
                    daemon=True,
                )
                _ONU_INVENTORY_SYNC_THREAD.start()

        with _SNMP_MONITOR_GUARD:
            if not (_SNMP_MONITOR_THREAD and _SNMP_MONITOR_THREAD.is_alive()):
                _SNMP_MONITOR_THREAD = threading.Thread(
                    target=_snmp_monitor_loop,
                    name="snmp-monitor-sync",
                    daemon=True,
                )
                _SNMP_MONITOR_THREAD.start()

        with _ONU_STATUS_SYNC_GUARD:
            if not (_ONU_STATUS_SYNC_THREAD and _ONU_STATUS_SYNC_THREAD.is_alive()):
                _ONU_STATUS_SYNC_THREAD = threading.Thread(
                    target=_onu_status_sync_loop,
                    name="onu-status-sync",
                    daemon=True,
                )
                _ONU_STATUS_SYNC_THREAD.start()

        with _ONU_SIGNAL_SAMPLE_GUARD:
            if not (_ONU_SIGNAL_SAMPLE_THREAD and _ONU_SIGNAL_SAMPLE_THREAD.is_alive()):
                _ONU_SIGNAL_SAMPLE_THREAD = threading.Thread(
                    target=_onu_signal_sample_loop,
                    name="onu-signal-sample-sync",
                    daemon=True,
                )
                _ONU_SIGNAL_SAMPLE_THREAD.start()

        with _DASHBOARD_SAMPLE_GUARD:
            if not (_DASHBOARD_SAMPLE_THREAD and _DASHBOARD_SAMPLE_THREAD.is_alive()):
                _DASHBOARD_SAMPLE_THREAD = threading.Thread(
                    target=_dashboard_sample_loop,
                    name="dashboard-sample-sync",
                    daemon=True,
                )
                _DASHBOARD_SAMPLE_THREAD.start()
