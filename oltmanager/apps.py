import logging
import datetime
import os
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from django.apps import AppConfig
from django.conf import settings
from django.db import close_old_connections
from django.db.backends.signals import connection_created
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
ONU_INVENTORY_SYNC_SECONDS = 600
SNMP_MONITOR_SECONDS = 10
SNMP_MONITOR_MAX_WORKERS = max(1, int(getattr(settings, "SNMP_MONITOR_MAX_WORKERS", 2) or 2))
# ONU dashboard counts/status snapshots follow the 10-minute dashboard cycle.
# The independent SNMP monitor below remains at 10 seconds for OLT reachability.
ONU_STATUS_SYNC_SECONDS = 600
ONU_SIGNAL_SAMPLE_SECONDS = max(300, int(getattr(settings, "ONU_SIGNAL_SAMPLE_SECONDS", 3600) or 3600))
ONU_STATUS_SYNC_MAX_WORKERS = max(1, int(getattr(settings, "ONU_STATUS_SYNC_MAX_WORKERS", 1) or 1))
ONU_SIGNAL_SAMPLE_MAX_WORKERS = max(1, int(getattr(settings, "ONU_SIGNAL_SAMPLE_MAX_WORKERS", 1) or 1))
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
ONU_SYNC_MAX_WORKERS = max(1, int(getattr(settings, "ONU_SYNC_MAX_WORKERS", 1) or 1))
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
AUTO_IMMEDIATE_INVENTORY_SYNC = False
# Tracks OLT IDs for which an immediate inventory sync thread is already running
# so we never stack concurrent Telnet syncs for the same OLT.
_IMMEDIATE_SYNC_RUNNING = set()
_IMMEDIATE_SYNC_LOCK = threading.Lock()
_SAMPLE_RETENTION_CLEANUP_LAST_TS = 0.0
_SAMPLE_RETENTION_CLEANUP_LOCK = threading.Lock()


def _configure_sqlite_connection(sender, connection, **kwargs):
    if connection.vendor != "sqlite":
        return
    with connection.cursor() as cursor:
        cursor.execute("PRAGMA busy_timeout=30000")
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA synchronous=NORMAL")


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
    from .utils import olt_background_enabled_q, sync_configured_onus_inventory

    close_old_connections()
    try:
        olt = OLT.objects.filter(pk=olt_id).filter(olt_background_enabled_q()).first()
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


def _schedule_immediate_inventory_sync(olt_id):
    """Start an immediate inventory sync thread for olt_id (no-op if one is already running)."""
    with _IMMEDIATE_SYNC_LOCK:
        if olt_id in _IMMEDIATE_SYNC_RUNNING:
            return False
        _IMMEDIATE_SYNC_RUNNING.add(olt_id)
    threading.Thread(
        target=_run_immediate_inventory_sync,
        args=(olt_id,),
        name=f"onu-immediate-sync-{olt_id}",
        daemon=True,
    ).start()
    return True


def _sleep_until_interval_boundary(interval_seconds):
    next_dt = _next_interval_boundary_datetime(interval_seconds)
    sleep_for = max(1, next_dt.timestamp() - time.time())
    time.sleep(sleep_for)


def _next_interval_boundary_datetime(interval_seconds):
    now_ts = time.time()
    interval_seconds = max(1, int(interval_seconds or 1))
    next_ts = ((int(now_ts) // interval_seconds) + 1) * interval_seconds
    return datetime.datetime.fromtimestamp(next_ts, tz=datetime.timezone.utc)


def _sleep_until_next_sync_boundary():
    _sleep_until_interval_boundary(ONU_INVENTORY_SYNC_SECONDS)


def _onu_inventory_sync_loop():
    from .models import OLT
    from .utils import (
        record_pon_traffic_samples,
        record_pon_port_traffic_samples,
        record_uplink_port_traffic_samples,
    )

    def _sync_single_olt_cycle(olt_id):
        from .models import OLT
        from .utils import (
            reconcile_offline_onus_with_signal,
            reconcile_onu_status_via_snmp,
            olt_background_enabled_q,
            sync_olt_autofind_count,
        )

        close_old_connections()
        try:
            olt = OLT.objects.filter(pk=olt_id).filter(olt_background_enabled_q()).only("id", "name", "snmp_last_status").first()
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
                reconcile_offline_onus_with_signal(olt=olt, limit=120)
            except Exception:
                close_old_connections()
        finally:
            close_old_connections()

    # Do not stampede Telnet/SNMP work immediately after Daphne/runserver starts.
    _sleep_until_interval_boundary(ONU_INVENTORY_SYNC_SECONDS)

    while True:
        try:
            close_old_connections()
            olt_ids = list(
                OLT.objects
                .filter(olt_background_enabled_q())
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
                _run_sample_retention_cleanup_if_due()
            except Exception:
                logger.exception("Sample retention cleanup cycle failed.")
        except Exception:
            logger.exception("ONU inventory/traffic sync cycle failed.")
        finally:
            close_old_connections()
        _sleep_until_next_sync_boundary()


def _snmp_monitor_loop():
    from .models import OLT
    from .utils import (
        mark_olt_onus_offline_due_to_snmp,
        olt_background_enabled_q,
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
            olt = OLT.objects.filter(pk=olt_id).filter(olt_background_enabled_q()).only("id", "name", "ip_address", "snmp_port", "snmp_community").first()
            if not olt:
                return olt_id, False, "OLT not found", False, "ICMP ping failed"
            snmp_probe = probe_snmp_reachability(olt)
            if snmp_probe.get("ok"):
                return (
                    olt_id,
                    True,
                    str(snmp_probe.get("status") or "").strip(),
                    True,
                    "ICMP skipped after SNMP success",
                )
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
                .filter(olt_background_enabled_q())
                .exclude(onboarding_status__in=["queued", "running", "aborting"])
                .order_by("id")
                .values_list("id", flat=True)
            )
            if olt_ids:
                with ThreadPoolExecutor(max_workers=min(SNMP_MONITOR_MAX_WORKERS, max(1, len(olt_ids))), thread_name_prefix="snmp-monitor") as executor:
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
                            olt = OLT.objects.filter(pk=olt_id).filter(olt_background_enabled_q()).first()
                            if olt:
                                # SNMP answered -> the OLT is reachable RIGHT NOW.
                                # Always refresh the OLT status to reachable (both in
                                # the DB and on this in-memory copy, so the reconcile
                                # gate below sees a non-down status).
                                fresh_status = snmp_status_text or "Live SNMP data fetched"
                                _save_snmp_probe_status(olt_id, fresh_status)
                                olt.snmp_last_status = fresh_status
                                _SNMP_OFFLINE_APPLIED.discard(olt_id)

                                # If a previous SNMP-down probe bulk-marked ONUs
                                # offline, immediately heal those rows once the
                                # OLT answers again. The helper exits before any
                                # SNMP walk when no snmp_down rows exist.
                                last_reconcile = _LAST_RECONCILE_AT.get(olt_id, 0.0)
                                if (now_ts - last_reconcile) >= RECONCILE_THROTTLE_SECONDS:
                                    _LAST_RECONCILE_AT[olt_id] = now_ts
                                    try:
                                        outcome = reconcile_onu_status_via_snmp(olt, only_snmp_down=True)
                                        if int(outcome.get("updated") or 0):
                                            logger.info(
                                                "OLT %s recovered stuck ONU status rows: %s",
                                                olt.name,
                                                outcome.get("status", ""),
                                            )
                                    except Exception:
                                        logger.exception("OLT %s recovery ONU status reconcile failed.", olt.name)
                                        close_old_connections()

                                # Keep the 10-second monitor lightweight. Full ONU
                                # status walks run in the 10-minute ONU status sync.
                                # Auto-resolve any active "OLT Down" alert now that
                                # the device is reachable again.
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

                                # New ONU detection can be used to trigger an immediate
                                # Telnet inventory sync, but that is intentionally disabled
                                # by default. Config inventory sync is now manual from the
                                # OLT Advanced -> Sync Config button to avoid surprise Telnet
                                # load while users are browsing.
                                last_new_check = _LAST_NEW_ONU_CHECK_AT.get(olt_id, 0.0)
                                if AUTO_IMMEDIATE_INVENTORY_SYNC and (now_ts - last_new_check) >= NEW_ONU_CHECK_SECONDS:
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

                        olt = OLT.objects.filter(pk=olt_id).filter(olt_background_enabled_q()).first()
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
    from .utils import (
        finish_onu_status_sync_progress,
        olt_background_enabled_q,
        record_dashboard_status_samples,
        schedule_onu_status_sync_progress,
        start_onu_status_sync_progress,
        sync_runtime_statuses_for_olt,
        update_onu_status_sync_progress,
    )

    def _sync_single_olt_status(olt_id):
        from .models import OLT

        close_old_connections()
        try:
            olt = OLT.objects.filter(pk=olt_id).filter(olt_background_enabled_q()).only("id", "name", "snmp_last_status").first()
            if not olt:
                return
            update_onu_status_sync_progress(
                olt.id,
                olt=olt.name,
                running=True,
                done=False,
                failed=False,
                message="Starting ONU status sync...",
            )

            def _progress(payload):
                update_onu_status_sync_progress(olt.id, olt=olt.name, **(payload or {}))

            return sync_runtime_statuses_for_olt(
                olt,
                only_non_online=False,
                limit=None,
                write_samples=False,
                on_progress=_progress,
            )
        finally:
            close_old_connections()

    # Keep initial page loads responsive after service restart.
    schedule_onu_status_sync_progress(_next_interval_boundary_datetime(ONU_STATUS_SYNC_SECONDS))
    _sleep_until_interval_boundary(ONU_STATUS_SYNC_SECONDS)

    while True:
        cycle_started = False
        olt_rows = []
        try:
            close_old_connections()
            for attempt in range(1, 4):
                try:
                    olt_rows = list(
                        OLT.objects
                        .filter(olt_background_enabled_q())
                        .exclude(onboarding_status__in=["queued", "running", "aborting"])
                        .order_by("id")
                        .values("id", "name")
                    )
                    break
                except Exception:
                    close_old_connections()
                    if attempt >= 3:
                        raise
                    time.sleep(2)
            olt_ids = [row["id"] for row in olt_rows]
            if olt_ids:
                start_onu_status_sync_progress(olt_rows)
                cycle_started = True
                for olt_id in olt_ids:
                    try:
                        result = _sync_single_olt_status(olt_id)
                        if result:
                            logger.info(
                                "OLT %s ONU status sync: checked=%s updated=%s status=%s",
                                result.get("olt") or olt_id,
                                result.get("checked"),
                                result.get("updated"),
                                result.get("status"),
                            )
                    except Exception as exc:
                        logger.exception("OLT %s ONU status sync failed.", olt_id)
                        try:
                            update_onu_status_sync_progress(
                                olt_id,
                                running=False,
                                done=True,
                                failed=True,
                                message=f"ONU status sync failed: {exc}",
                            )
                        except Exception:
                            pass
                        close_old_connections()
                try:
                    record_dashboard_status_samples(force=True, bypass_force_throttle=True)
                except Exception:
                    logger.exception("Dashboard status sample write failed after ONU status sync.")
                    close_old_connections()
                finish_onu_status_sync_progress(timezone.now() + datetime.timedelta(seconds=ONU_STATUS_SYNC_SECONDS))
                cycle_started = False
            else:
                schedule_onu_status_sync_progress(timezone.now() + datetime.timedelta(seconds=ONU_STATUS_SYNC_SECONDS))
        except Exception:
            logger.exception("ONU status sync cycle failed.")
            if cycle_started:
                try:
                    finish_onu_status_sync_progress(timezone.now() + datetime.timedelta(seconds=ONU_STATUS_SYNC_SECONDS))
                except Exception:
                    pass
        finally:
            close_old_connections()
        next_run_at = timezone.now() + datetime.timedelta(seconds=ONU_STATUS_SYNC_SECONDS)
        try:
            schedule_onu_status_sync_progress(next_run_at)
        except Exception:
            pass
        time.sleep(ONU_STATUS_SYNC_SECONDS)


def _onu_signal_sample_loop():
    from .models import OLT
    from .utils import olt_background_enabled_q, sync_onu_signals_from_snmp

    def _sample_single_olt(olt_id):
        from .models import OLT

        close_old_connections()
        try:
            olt = OLT.objects.filter(pk=olt_id).filter(olt_background_enabled_q()).only("id", "name").first()
            if not olt:
                return

            # Background signal samples must stay SNMP-only. Telnet fallback is
            # reserved for explicit user actions so browsing stays responsive.
            _SNMP_SIGNAL_RETRIES = 3
            _SNMP_SIGNAL_RETRY_DELAY = 4  # seconds between retries
            for _attempt in range(_SNMP_SIGNAL_RETRIES):
                try:
                    snmp_result = sync_onu_signals_from_snmp(olt, overwrite=True)
                    if int(snmp_result.get("filled") or 0) > 0:
                        break
                except Exception:
                    close_old_connections()
                if _attempt < _SNMP_SIGNAL_RETRIES - 1:
                    time.sleep(_SNMP_SIGNAL_RETRY_DELAY)

        finally:
            close_old_connections()

    # Signal sampling is useful, but it should never compete with first page load.
    _sleep_until_interval_boundary(ONU_SIGNAL_SAMPLE_SECONDS)

    while True:
        try:
            close_old_connections()
            olt_ids = list(OLT.objects.filter(olt_background_enabled_q()).order_by("id").values_list("id", flat=True))
            if olt_ids:
                with ThreadPoolExecutor(max_workers=min(ONU_SIGNAL_SAMPLE_MAX_WORKERS, max(1, len(olt_ids))), thread_name_prefix="onu-signal") as executor:
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


class OltmanagerConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'oltmanager'

    def ready(self):

        connection_created.connect(
            _configure_sqlite_connection,
            dispatch_uid="oltmanager.configure_sqlite_connection",
        )

        embedded_sync_disabled = os.environ.get("OLT_DISABLE_EMBEDDED_SYNC", "").strip().lower() in {"1", "true", "yes"}
        if embedded_sync_disabled:
            return

        embedded_sync_enabled = os.environ.get("OLT_ENABLE_EMBEDDED_SYNC", "").strip().lower() in {"1", "true", "yes"}
        is_server_process = "runserver" in sys.argv or embedded_sync_enabled
        if not is_server_process:
            return
        if os.environ.get("RUN_MAIN") not in {None, "true"}:
            return

        ensure_background_sync_threads()


def ensure_background_sync_threads():
    """Start any missing background sync thread.

    The production worker stays alive for days. After a code deploy or a rare
    thread crash, this lets the management command re-check and recover the
    actual polling threads instead of silently sleeping forever.
    """
    global _ONU_INVENTORY_SYNC_THREAD, _SNMP_MONITOR_THREAD, _ONU_STATUS_SYNC_THREAD, _ONU_SIGNAL_SAMPLE_THREAD

    started = []

    with _ONU_INVENTORY_SYNC_GUARD:
        if not (_ONU_INVENTORY_SYNC_THREAD and _ONU_INVENTORY_SYNC_THREAD.is_alive()):
            _ONU_INVENTORY_SYNC_THREAD = threading.Thread(
                target=_onu_inventory_sync_loop,
                name="onu-inventory-sync",
                daemon=True,
            )
            _ONU_INVENTORY_SYNC_THREAD.start()
            started.append("onu-inventory-sync")

    with _SNMP_MONITOR_GUARD:
        if not (_SNMP_MONITOR_THREAD and _SNMP_MONITOR_THREAD.is_alive()):
            _SNMP_MONITOR_THREAD = threading.Thread(
                target=_snmp_monitor_loop,
                name="snmp-monitor-sync",
                daemon=True,
            )
            _SNMP_MONITOR_THREAD.start()
            started.append("snmp-monitor-sync")

    with _ONU_STATUS_SYNC_GUARD:
        if not (_ONU_STATUS_SYNC_THREAD and _ONU_STATUS_SYNC_THREAD.is_alive()):
            _ONU_STATUS_SYNC_THREAD = threading.Thread(
                target=_onu_status_sync_loop,
                name="onu-status-sync",
                daemon=True,
            )
            _ONU_STATUS_SYNC_THREAD.start()
            started.append("onu-status-sync")

    with _ONU_SIGNAL_SAMPLE_GUARD:
        if not (_ONU_SIGNAL_SAMPLE_THREAD and _ONU_SIGNAL_SAMPLE_THREAD.is_alive()):
            _ONU_SIGNAL_SAMPLE_THREAD = threading.Thread(
                target=_onu_signal_sample_loop,
                name="onu-signal-sample-sync",
                daemon=True,
            )
            _ONU_SIGNAL_SAMPLE_THREAD.start()
            started.append("onu-signal-sample-sync")

    if started:
        logger.info("Background sync thread(s) started: %s", ", ".join(started))
    return started
