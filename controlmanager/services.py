from decimal import Decimal
from pathlib import Path
import sqlite3

from django.utils import timezone

from .models import TenantOLTSnapshot, TenantSnapshot


class TenantSnapshotError(Exception):
    pass


def _table_exists(cursor, name):
    cursor.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", [name])
    return cursor.fetchone() is not None


def refresh_tenant_database_snapshot(tenant):
    """Read a tenant SQLite DB and copy lightweight resource counts only.

    This function is intentionally DB-only. It does not import tenant app code and
    does not run SNMP, Telnet, HTTP polling, migrations, or background jobs.
    """
    db_path = Path(str(tenant.database_path or "").strip())
    if not db_path:
        raise TenantSnapshotError("Tenant database path is empty.")
    if not db_path.exists():
        raise TenantSnapshotError(f"Tenant database not found: {db_path}")

    uri = f"file:{db_path.as_posix()}?mode=ro"
    try:
        conn = sqlite3.connect(uri, uri=True, timeout=5)
    except sqlite3.Error as exc:
        raise TenantSnapshotError(f"Could not open tenant DB read-only: {exc}") from exc

    try:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        if not _table_exists(cursor, "oltmanager_olt"):
            raise TenantSnapshotError("Tenant DB does not contain oltmanager_olt table.")
        if not _table_exists(cursor, "oltmanager_configuredonu"):
            raise TenantSnapshotError("Tenant DB does not contain oltmanager_configuredonu table.")

        cursor.execute(
            """
            SELECT id, name, ip_address, hardware_version, sw_version, snmp_last_status
            FROM oltmanager_olt
            ORDER BY name COLLATE NOCASE
            """
        )
        olt_rows = [dict(row) for row in cursor.fetchall()]

        cursor.execute(
            """
            SELECT
                olt_id,
                COUNT(*) AS onu_count,
                SUM(CASE WHEN LOWER(COALESCE(derived_status, '')) = 'online' THEN 1 ELSE 0 END) AS online_count
            FROM oltmanager_configuredonu
            GROUP BY olt_id
            """
        )
        counts_by_olt = {int(row["olt_id"]): dict(row) for row in cursor.fetchall()}
    finally:
        conn.close()

    seen = set()
    total_onus = 0
    total_online = 0
    for row in olt_rows:
        tenant_olt_id = int(row.get("id") or 0)
        counts = counts_by_olt.get(tenant_olt_id, {})
        onu_count = int(counts.get("onu_count") or 0)
        online_count = int(counts.get("online_count") or 0)
        offline_count = max(0, onu_count - online_count)
        total_onus += onu_count
        total_online += online_count
        seen.add(tenant_olt_id)
        TenantOLTSnapshot.objects.update_or_create(
            tenant=tenant,
            tenant_olt_id=tenant_olt_id,
            defaults={
                "name": str(row.get("name") or "")[:160],
                "ip_address": str(row.get("ip_address") or "")[:64],
                "hardware_version": str(row.get("hardware_version") or "")[:100],
                "sw_version": str(row.get("sw_version") or "")[:100],
                "snmp_last_status": str(row.get("snmp_last_status") or "")[:300],
                "onu_count": onu_count,
                "online_count": online_count,
                "offline_count": offline_count,
            },
        )

    TenantOLTSnapshot.objects.filter(tenant=tenant).exclude(tenant_olt_id__in=seen).delete()

    db_size_mb = Decimal(str(round(db_path.stat().st_size / (1024 * 1024), 2)))
    snapshot = TenantSnapshot.objects.create(
        tenant=tenant,
        olt_count=len(olt_rows),
        onu_count=total_onus,
        db_size_mb=db_size_mb,
        status_note=f"DB-only refresh. Online ONUs: {total_online}. Offline ONUs: {max(0, total_onus - total_online)}.",
    )
    tenant.last_known_olt_count = len(olt_rows)
    tenant.last_known_onu_count = total_onus
    tenant.last_known_db_size_mb = db_size_mb
    tenant.last_reported_at = timezone.now()
    tenant.save(update_fields=[
        "last_known_olt_count", "last_known_onu_count", "last_known_db_size_mb",
        "last_reported_at", "updated_at",
    ])
    return {
        "snapshot": snapshot,
        "olt_count": len(olt_rows),
        "onu_count": total_onus,
        "online_count": total_online,
        "offline_count": max(0, total_onus - total_online),
        "db_size_mb": db_size_mb,
    }
