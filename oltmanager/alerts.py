"""Alert engine — detects and records alert events that are shown in-app.

No e-mail / external delivery: alerts are simply recorded as AlertEvent rows and
displayed on the Settings > Alerts page.
"""
import re
import time

from django.utils import timezone


# Which AlertConfig toggle gates each alert type (turn a type off = not recorded).
_TYPE_FLAG = {
    "olt_down": "notify_olt_down",
    "olt_recovered": "notify_olt_recovered",
    "olt_high_temp": "notify_high_temp",
    "fiber_cut": "notify_fiber_cut",
    "signal_degrade": "notify_signal_degrade",
}

# Derived ONU statuses that count as "down" for fiber-cut detection. admin_disabled
# is intentionally excluded (operator turned it off), and snmp_down is handled
# separately (whole-OLT outage, not a localized fiber cut).
_DOWN_STATUSES = {"offline", "loss_of_signal", "power_failure"}


def _alert_type_enabled(cfg, alert_type):
    flag = _TYPE_FLAG.get(alert_type)
    if flag is None:
        return True
    return bool(getattr(cfg, flag, True))


def _parse_temp_celsius(value):
    match = re.search(r"(-?\d+(?:\.\d+)?)", str(value or ""))
    if not match:
        return None
    try:
        return float(match.group(1))
    except (TypeError, ValueError):
        return None


def raise_alert(*, alert_type, key, severity, title, message, olt=None, details=None):
    """Create (or refresh) an active alert. Returns the AlertEvent or None."""
    from .models import AlertConfig, AlertEvent

    if not _alert_type_enabled(AlertConfig.get(), alert_type):
        return None

    existing = AlertEvent.objects.filter(is_active=True, dedup_key=key).first()
    if existing:
        changed = False
        if existing.title != title:
            existing.title = title
            changed = True
        if existing.message != message:
            existing.message = message
            changed = True
        if details is not None and existing.details != details:
            existing.details = details
            changed = True
        if changed:
            existing.save(update_fields=["title", "message", "details", "updated_at"])
        return existing
    return AlertEvent.objects.create(
        alert_type=alert_type,
        severity=severity,
        olt=olt,
        dedup_key=key,
        title=title,
        message=message,
        details=details or {},
        is_active=True,
    )


def resolve_alert(key, *, send_recovery=False, recovery_type="olt_recovered", title="", message="", olt=None):
    """Close an active alert; optionally record a 'recovered' info alert."""
    from .models import AlertConfig, AlertEvent

    now = timezone.now()
    event = AlertEvent.objects.filter(is_active=True, dedup_key=key).first()
    if not event:
        return None
    event.is_active = False
    event.resolved_at = now
    event.save(update_fields=["is_active", "resolved_at", "updated_at"])

    if send_recovery and _alert_type_enabled(AlertConfig.get(), recovery_type):
        AlertEvent.objects.create(
            alert_type=recovery_type,
            severity="info",
            olt=olt or event.olt,
            dedup_key=f"{key}:recovered:{int(now.timestamp())}",
            title=title or f"Recovered: {event.title}",
            message=message or "",
            is_active=False,
            resolved_at=now,
        )
    return event


def check_olt_temperature_alerts():
    from .models import AlertConfig, OLT

    cfg = AlertConfig.get()
    threshold = int(cfg.temp_threshold_c or 60)
    for olt in OLT.objects.only("id", "name", "ip_address", "dashboard_temperature"):
        temp_c = _parse_temp_celsius(getattr(olt, "dashboard_temperature", ""))
        key = f"olt_high_temp:{olt.id}"
        if temp_c is not None and temp_c >= threshold:
            raise_alert(
                alert_type="olt_high_temp",
                key=key,
                severity="warning",
                title=f"High temperature: {olt.name}",
                message=f"{olt.name} temperature is {temp_c:g}°C (threshold {threshold}°C).",
                olt=olt,
                details={"temp_c": temp_c, "threshold": threshold},
            )
        else:
            resolve_alert(key)


def _parse_dbm(value):
    """Extract a dBm float from a stored signal string like '-24.32 dBm'."""
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


# A fiber cut is a *correlated, recent* event: many ONUs on one PON port drop
# together within a short window. ONUs that have been offline for a long time
# (dead/decommissioned customers never deleted) are NOT a fiber cut, so we only
# count ONUs whose current down-status began inside this recent window.
FIBER_CUT_RECENT_WINDOW_MIN = 30


def check_fiber_cut_alerts():
    """Raise one 'possible fiber cut' alert per PON port where many ONUs dropped
    together recently — instead of N separate per-ONU offline events, and without
    firing on chronically-offline inventory.

    A whole-OLT outage (SNMP unreachable) is skipped here so it does not fire on
    every port; that is covered by the separate OLT-down alert.
    """
    from .models import AlertConfig, AlertEvent, ConfiguredONU, OLT

    cfg = AlertConfig.get()
    if not _alert_type_enabled(cfg, "fiber_cut"):
        return
    min_onus = max(2, int(cfg.fiber_cut_min_onus or 4))
    ratio_pct = min(100, max(1, int(cfg.fiber_cut_ratio or 60)))
    recent_cutoff = timezone.now() - timezone.timedelta(minutes=FIBER_CUT_RECENT_WINDOW_MIN)

    for olt in OLT.objects.only("id", "name", "snmp_last_status"):
        status = str(getattr(olt, "snmp_last_status", "") or "").lower()
        olt_unreachable = ("down" in status) or ("unreachable" in status)

        groups = {}  # (slot, port) -> {"total", "recent_down", "down"}
        for r in ConfiguredONU.objects.filter(olt=olt).only(
            "slot", "port", "derived_status", "status_source", "status_first_seen_at"
        ):
            ds = str(r.derived_status or "").strip().lower()
            if ds == "admin_disabled":
                continue
            g = groups.setdefault((r.slot, r.port), {"total": 0, "recent_down": 0, "down": 0})
            g["total"] += 1
            if ds in _DOWN_STATUSES:
                g["down"] += 1
                # Recent + not part of a whole-OLT SNMP outage = correlated drop.
                if (
                    str(r.status_source or "") != "snmp_down"
                    and r.status_first_seen_at is not None
                    and r.status_first_seen_at >= recent_cutoff
                ):
                    g["recent_down"] += 1

        active_keys = set()
        for (slot, port), g in groups.items():
            total, recent_down, down = g["total"], g["recent_down"], g["down"]
            if total < min_onus:
                continue
            pct = (recent_down * 100 // total) if total else 0
            key = f"pon_outage:{olt.id}:{slot}:{port}"
            if (not olt_unreachable) and recent_down >= min_onus and pct >= ratio_pct:
                raise_alert(
                    alert_type="fiber_cut",
                    key=key,
                    severity="critical",
                    title=f"Possible fiber cut — {olt.name} PON 0/{slot}/{port}",
                    message=(
                        f"{recent_down}/{total} ONUs on 0/{slot}/{port} dropped together "
                        f"in the last {FIBER_CUT_RECENT_WINDOW_MIN} min ({pct}%). "
                        f"Likely fiber / splitter / PON-port issue."
                    ),
                    olt=olt,
                    details={
                        "slot": slot, "port": port, "recent_down": recent_down,
                        "down": down, "total": total, "pct": pct,
                    },
                )
                active_keys.add(key)

        # Auto-resolve any fiber-cut alert on this OLT that is no longer triggering.
        for ev in AlertEvent.objects.filter(is_active=True, alert_type="fiber_cut", olt=olt).only("dedup_key"):
            if ev.dedup_key not in active_keys:
                resolve_alert(ev.dedup_key)


def check_signal_degradation_alerts():
    """Early-warning: flag online ONUs whose Rx power has steadily dropped toward
    the danger zone, using the optical sample history (predictive maintenance)."""
    from .models import AlertConfig, AlertEvent, ConfiguredONU, OLT, ONUOpticalSample

    cfg = AlertConfig.get()
    if not _alert_type_enabled(cfg, "signal_degrade"):
        return
    drop_db = max(1.0, float(cfg.signal_degrade_drop_db or 3))
    # Recent reading must be at least this weak to qualify (approaching the
    # ~-27 dBm GPON cliff) so we don't alert on healthy ONUs that merely wobble.
    danger_dbm = -24.0
    window_start = timezone.now() - timezone.timedelta(days=7)

    for olt in OLT.objects.only("id", "name"):
        online = {}
        for c in ConfiguredONU.objects.filter(olt=olt, derived_status="online").only(
            "slot", "port", "ont_id", "description"
        ):
            online[(c.slot, c.port, c.ont_id)] = c.description or ""
        if not online:
            # still clear stale alerts for this OLT below
            pass

        series = {}  # key -> list of dBm in time order
        if online:
            for s in ONUOpticalSample.objects.filter(
                olt=olt, sampled_at__gte=window_start
            ).only("slot", "port", "ont_id", "onu_rx").order_by("sampled_at"):
                key = (s.slot, s.port, s.ont_id)
                if key not in online:
                    continue
                v = _parse_dbm(s.onu_rx)
                if v is not None:
                    series.setdefault(key, []).append(v)

        active_keys = set()
        for key, pts in series.items():
            if len(pts) < 6:
                continue
            third = max(1, len(pts) // 3)
            baseline = sum(pts[:third]) / third
            recent = sum(pts[-third:]) / third
            drop = baseline - recent  # positive => signal got weaker (more negative)
            if drop >= drop_db and recent <= danger_dbm:
                slot, port, ont_id = key
                dedup = f"signal_degrade:{olt.id}:{slot}:{port}:{ont_id}"
                desc = online.get(key) or ""
                who = f" ({desc})" if desc else ""
                raise_alert(
                    alert_type="signal_degrade",
                    key=dedup,
                    severity="warning",
                    title=f"Signal degrading — {olt.name} ONU 0/{slot}/{port}:{ont_id}",
                    message=(
                        f"ONU 0/{slot}/{port}:{ont_id}{who} Rx dropped "
                        f"{drop:.1f} dB ({baseline:.1f} → {recent:.1f} dBm). "
                        f"Check fiber bend / splice before it fails."
                    ),
                    olt=olt,
                    details={
                        "slot": slot, "port": port, "ont_id": ont_id,
                        "baseline_dbm": round(baseline, 2), "recent_dbm": round(recent, 2),
                        "drop_db": round(drop, 2),
                    },
                )
                active_keys.add(dedup)

        for ev in AlertEvent.objects.filter(is_active=True, alert_type="signal_degrade", olt=olt).only("dedup_key"):
            if ev.dedup_key not in active_keys:
                resolve_alert(ev.dedup_key)


_LAST_TEMP_CHECK = 0.0
_LAST_FIBER_CHECK = 0.0
_LAST_DEGRADE_CHECK = 0.0
TEMP_CHECK_INTERVAL = 300       # 5 min
FIBER_CHECK_INTERVAL = 60       # 1 min — mass outage should surface fast
DEGRADE_CHECK_INTERVAL = 1800   # 30 min — trend analysis, no need to be frequent


def run_periodic_alert_checks():
    """Throttled temperature / fiber-cut / signal-degradation
    checks; call from a polling loop."""
    global _LAST_TEMP_CHECK, _LAST_FIBER_CHECK, _LAST_DEGRADE_CHECK
    now = time.time()
    if now - _LAST_TEMP_CHECK >= TEMP_CHECK_INTERVAL:
        _LAST_TEMP_CHECK = now
        try:
            check_olt_temperature_alerts()
        except Exception:
            pass
    if now - _LAST_FIBER_CHECK >= FIBER_CHECK_INTERVAL:
        _LAST_FIBER_CHECK = now
        try:
            check_fiber_cut_alerts()
        except Exception:
            pass
    if now - _LAST_DEGRADE_CHECK >= DEGRADE_CHECK_INTERVAL:
        _LAST_DEGRADE_CHECK = now
        try:
            check_signal_degradation_alerts()
        except Exception:
            pass



