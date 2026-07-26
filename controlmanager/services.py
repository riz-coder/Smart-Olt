from decimal import Decimal
from pathlib import Path
import os
import sqlite3
import subprocess

from django.conf import settings
from django.core.management.utils import get_random_secret_key
from django.utils import timezone

from .models import TenantOLTSnapshot, TenantSnapshot


class TenantSnapshotError(Exception):
    pass


class TenantProvisionError(Exception):
    pass


def _table_exists(cursor, name):
    cursor.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", [name])
    return cursor.fetchone() is not None


def _tenant_base_dir():
    return Path(os.environ.get("CONTROL_TENANT_BASE_DIR", "/opt/optiverse/tenants" if os.name != "nt" else str(settings.BASE_DIR / "control_tenants")))


def _tenant_codebase_path():
    return Path(os.environ.get("CONTROL_TENANT_CODEBASE_PATH", str(settings.BASE_DIR)))


def _tenant_panel_host():
    return os.environ.get("CONTROL_TENANT_PANEL_HOST", "10.101.11.22")


def _tenant_bind_host():
    return os.environ.get("CONTROL_TENANT_BIND_HOST", "0.0.0.0")


def _tenant_start_port():
    return int(os.environ.get("CONTROL_TENANT_START_PORT", "8001"))


def _tenant_env(tenant, *, disable_embedded_sync=False):
    env = os.environ.copy()
    env.update({
        "DJANGO_SECRET_KEY": get_random_secret_key(),
        "DJANGO_DEBUG": "False",
        "DJANGO_ALLOWED_HOSTS": f"{tenant.panel_host},127.0.0.1,localhost",
        "DJANGO_CSRF_TRUSTED_ORIGINS": f"http://{tenant.panel_host},http://{tenant.panel_host}:{tenant.panel_port}",
        "SQLITE_DB_PATH": tenant.database_path,
        "SQLITE_TIMEOUT_SECONDS": "60",
        "DJANGO_TIME_ZONE": os.environ.get("CONTROL_DJANGO_TIME_ZONE", "Asia/Karachi"),
        "DJANGO_LANGUAGE_CODE": "en-us",
        "OLT_ENABLE_EMBEDDED_SYNC": "true",
    })
    if disable_embedded_sync:
        env["OLT_DISABLE_EMBEDDED_SYNC"] = "1"
        env.pop("OLT_ENABLE_EMBEDDED_SYNC", None)
    return env


def _write_tenant_env_file(tenant):
    secret = get_random_secret_key()
    text = f"""DJANGO_SECRET_KEY={secret}
DJANGO_DEBUG=False
DJANGO_ALLOWED_HOSTS={tenant.panel_host},127.0.0.1,localhost
DJANGO_CSRF_TRUSTED_ORIGINS=http://{tenant.panel_host},http://{tenant.panel_host}:{tenant.panel_port}
DJANGO_SECURE_SSL_REDIRECT=False
DJANGO_SESSION_COOKIE_SECURE=False
DJANGO_CSRF_COOKIE_SECURE=False
DJANGO_TIME_ZONE=Asia/Karachi
DJANGO_LANGUAGE_CODE=en-us
SQLITE_DB_PATH={tenant.database_path}
SQLITE_TIMEOUT_SECONDS=60
OLT_ENABLE_EMBEDDED_SYNC=true
OLT_ONU_OPTICAL_SAMPLE_INTERVAL_SECONDS=3600
OLT_ONU_OPTICAL_RETENTION_DAYS=15
OLT_ONU_STATUS_RETENTION_DAYS=30
OLT_ONU_TRAFFIC_RETENTION_DAYS=30
OLT_PON_TRAFFIC_RETENTION_DAYS=30
OLT_PON_PORT_TRAFFIC_RETENTION_DAYS=30
OLT_UPLINK_PORT_TRAFFIC_RETENTION_DAYS=30
OLT_DASHBOARD_STATUS_RETENTION_DAYS=180
OLT_SAMPLE_RETENTION_CLEANUP_SECONDS=3600
"""
    env_path = Path(tenant.env_path)
    env_path.parent.mkdir(parents=True, exist_ok=True)
    env_path.write_text(text, encoding="utf-8")


def _run_tenant_manage(tenant, args, *, input_text=None, timeout=300):
    codebase = Path(tenant.codebase_path)
    python_bin = codebase / ".venv" / "bin" / "python"
    if os.name == "nt":
        python_bin = codebase / ".venv" / "Scripts" / "python.exe"
        if not python_bin.exists():
            python_bin = Path(os.environ.get("PYTHON", "python"))
    elif not python_bin.exists():
        python_bin = Path(os.environ.get("PYTHON", "python3"))
    cmd = [str(python_bin), "manage.py", *args]
    env = _tenant_env(tenant, disable_embedded_sync=True)
    result = subprocess.run(
        cmd,
        cwd=str(codebase),
        env=env,
        input=input_text,
        text=True,
        capture_output=True,
        timeout=timeout,
    )
    if result.returncode != 0:
        output = (result.stderr or result.stdout or "").strip()
        raise TenantProvisionError(output[:1000] or f"Tenant manage.py command failed: {' '.join(args)}")
    return result.stdout.strip()


def _systemd_available():
    return os.name != "nt" and Path("/run/systemd/system").exists() and Path("/etc/systemd/system").exists()


def _write_systemd_service(tenant):
    if not _systemd_available():
        return "systemd not available; service file skipped"
    codebase = Path(tenant.codebase_path)
    service_name = tenant.service_name
    service_text = f"""[Unit]
Description=OptiVerse Tenant Portal - {tenant.name}
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
Group=root
WorkingDirectory={codebase}
EnvironmentFile={tenant.env_path}
ExecStart={codebase}/.venv/bin/python -m daphne -b {_tenant_bind_host()} -p {tenant.panel_port} oltportal.asgi:application
Restart=always
RestartSec=5
TimeoutStopSec=30
KillSignal=SIGINT
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
"""
    path = Path("/etc/systemd/system") / f"{service_name}.service"
    path.write_text(service_text, encoding="utf-8")
    subprocess.run(["systemctl", "daemon-reload"], check=True, capture_output=True, text=True)
    subprocess.run(["systemctl", "disable", service_name], check=False, capture_output=True, text=True)
    subprocess.run(["systemctl", "restart", service_name], check=True, capture_output=True, text=True)
    return f"{service_name}.service started"


def prepare_tenant_defaults(tenant):
    tenant.save()
    slug = tenant.slug
    base = _tenant_base_dir() / slug
    highest_port = tenant.__class__.objects.exclude(pk=tenant.pk).order_by("-panel_port").values_list("panel_port", flat=True).first()
    if not tenant.panel_port or int(tenant.panel_port) < _tenant_start_port():
        tenant.panel_port = max(_tenant_start_port(), int(highest_port or (_tenant_start_port() - 1)) + 1)
    tenant.panel_scheme = tenant.panel_scheme or "http"
    tenant.panel_host = tenant.panel_host or _tenant_panel_host()
    tenant.codebase_path = tenant.codebase_path or str(_tenant_codebase_path())
    tenant.database_path = tenant.database_path or str(base / "db.sqlite3")
    tenant.env_path = tenant.env_path or str(base / ".env")
    tenant.service_name = tenant.service_name or f"optiverse-{slug}"
    tenant.isp_name = tenant.isp_name or tenant.name
    tenant.owner_name = tenant.owner_name or tenant.name
    tenant.save(update_fields=[
        "panel_port", "panel_scheme", "panel_host", "codebase_path", "database_path",
        "env_path", "service_name", "isp_name", "owner_name", "updated_at",
    ])
    return tenant


def provision_tenant_instance(tenant):
    tenant = prepare_tenant_defaults(tenant)
    Path(tenant.database_path).parent.mkdir(parents=True, exist_ok=True)
    _write_tenant_env_file(tenant)
    _run_tenant_manage(tenant, ["migrate", "--noinput"], timeout=600)
    username = tenant.panel_admin_username or "admin"
    password = tenant.panel_admin_initial_password
    email = tenant.owner_email or ""
    code = (
        "from django.contrib.auth import get_user_model; "
        "U=get_user_model(); "
        f"u,_=U.objects.get_or_create(username={username!r}, defaults={{'email': {email!r}, 'is_staff': True, 'is_superuser': True}}); "
        "u.is_staff=True; u.is_superuser=True; "
        f"u.email={email!r}; u.set_password({password!r}); u.save(); print('tenant superuser ready')"
    )
    _run_tenant_manage(tenant, ["shell", "-c", code], timeout=180)
    service_status = _write_systemd_service(tenant)
    tenant.status = tenant.STATUS_ACTIVE
    tenant.save(update_fields=["status", "updated_at"])
    try:
        refresh_tenant_database_snapshot(tenant)
    except TenantSnapshotError:
        pass
    return {"service_status": service_status, "panel_url": tenant.panel_url}


def _connect_tenant_db(tenant, *, read_only=True):
    db_path = Path(str(tenant.database_path or "").strip())
    if not db_path.exists():
        raise TenantSnapshotError(f"Tenant database not found: {db_path}")
    if read_only:
        conn = sqlite3.connect(f"file:{db_path.as_posix()}?mode=ro", uri=True, timeout=5)
    else:
        conn = sqlite3.connect(str(db_path), timeout=20)
    conn.row_factory = sqlite3.Row
    return conn


def get_tenant_olts(tenant):
    conn = _connect_tenant_db(tenant, read_only=True)
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT o.id, o.name, o.ip_address, o.hardware_version, o.sw_version, o.snmp_last_status,
                   COUNT(c.id) AS onu_count,
                   SUM(CASE WHEN LOWER(COALESCE(c.derived_status, '')) = 'online' THEN 1 ELSE 0 END) AS online_count
            FROM oltmanager_olt o
            LEFT JOIN oltmanager_configuredonu c ON c.olt_id = o.id
            GROUP BY o.id
            ORDER BY o.name COLLATE NOCASE
            """
        )
        rows = []
        for row in cursor.fetchall():
            item = dict(row)
            item["online_count"] = int(item.get("online_count") or 0)
            item["onu_count"] = int(item.get("onu_count") or 0)
            item["offline_count"] = max(0, item["onu_count"] - item["online_count"])
            rows.append(item)
        return rows
    finally:
        conn.close()


def get_tenant_olt_onus(tenant, tenant_olt_id):
    conn = _connect_tenant_db(tenant, read_only=True)
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT id, name, ip_address, hardware_version, sw_version, snmp_last_status FROM oltmanager_olt WHERE id=?", [int(tenant_olt_id)])
        olt = cursor.fetchone()
        if not olt:
            raise TenantSnapshotError("OLT not found in tenant database.")
        cursor.execute(
            """
            SELECT id, slot, port, ont_id, sn, description, derived_status, attached_vlans_cache, onu_rx, olt_rx, ont_distance_m
            FROM oltmanager_configuredonu
            WHERE olt_id=?
            ORDER BY slot, port, ont_id
            """,
            [int(tenant_olt_id)],
        )
        return dict(olt), [dict(row) for row in cursor.fetchall()]
    finally:
        conn.close()


def delete_tenant_olt(tenant, tenant_olt_id):
    code = (
        "from oltmanager.models import OLT; "
        f"qs=OLT.objects.filter(pk={int(tenant_olt_id)}); "
        "name=qs.first().name if qs.exists() else ''; "
        "deleted=qs.delete()[0]; print(f'deleted={deleted} name={name}')"
    )
    output = _run_tenant_manage(tenant, ["shell", "-c", code], timeout=180)
    refresh_tenant_database_snapshot(tenant)
    return output


def delete_tenant_onu(tenant, onu_id):
    code = (
        "from oltmanager.models import ConfiguredONU; "
        f"qs=ConfiguredONU.objects.filter(pk={int(onu_id)}); "
        "label=str(qs.first()) if qs.exists() else ''; "
        "deleted=qs.delete()[0]; print(f'deleted={deleted} onu={label}')"
    )
    output = _run_tenant_manage(tenant, ["shell", "-c", code], timeout=180)
    refresh_tenant_database_snapshot(tenant)
    return output


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

    conn = _connect_tenant_db(tenant, read_only=True)

    try:
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
