from decimal import Decimal
from datetime import datetime, timedelta
from pathlib import Path
import base64
import os
import re
import secrets
import shutil
import socket
import subprocess
import time
import http.client

from django.conf import settings
from django.core.management.utils import get_random_secret_key
from django.utils import timezone

from .models import Tenant, TenantOLTSnapshot, TenantSnapshot
from . import deployment
from . import tenant_database


class TenantSnapshotError(Exception):
    pass


class TenantProvisionError(Exception):
    pass


def _table_exists(cursor, name):
    return tenant_database.table_exists(cursor, name)


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


def _tenant_next_available_port(tenant):
    used_ports = set(
        int(port)
        for port in tenant.__class__.objects.exclude(pk=tenant.pk).values_list("panel_port", flat=True)
        if port
    )
    port = max(_tenant_start_port(), int(tenant.panel_port or 0) or _tenant_start_port())
    while port in used_ports or not _tenant_port_is_available(port):
        port += 1
        if port > 65535:
            raise TenantProvisionError("No free tenant TCP port is available.")
    return port


def _tenant_port_is_available(port):
    """Check the real bind address so non-OptiVerse services are not overwritten."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            probe.bind((_tenant_bind_host(), int(port)))
        return True
    except (OSError, OverflowError, ValueError):
        return False


def _control_bool(name, default=False):
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _tenant_auto_provision_enabled():
    return _control_bool("CONTROL_TENANT_AUTO_PROVISION", _control_bool("OPTIVERSE_TENANT_AUTO_PROVISION", False))


def _wireguard_keypair():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import x25519

    private_key = x25519.X25519PrivateKey.generate()
    public_key = private_key.public_key()
    private_raw = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return base64.b64encode(private_raw).decode("ascii"), base64.b64encode(public_raw).decode("ascii")


def _tenant_default_wg_address(tenant):
    pk = int(getattr(tenant, "pk", 1) or 1)
    return f"10.200.{10 + ((pk - 1) % 240)}.{2 + ((pk - 1) // 240)}/32"


def _safe_slug(tenant):
    return re.sub(r"[^a-z0-9-]+", "-", str(tenant.slug or tenant.name or "").lower()).strip("-") or f"tenant-{tenant.pk}"


def _tenant_cookie_prefix(tenant):
    return re.sub(r"[^a-z0-9_]+", "_", _safe_slug(tenant).replace("-", "_")).strip("_") or f"tenant_{tenant.pk}"


def _read_env_file_value(path, key):
    try:
        text = Path(path).read_text(encoding="utf-8")
    except (OSError, TypeError, ValueError):
        return ""
    prefix = f"{key}="
    for line in text.splitlines():
        if line.startswith(prefix):
            return line[len(prefix):].strip()
    return ""


def _tenant_secret_key(tenant):
    return (
        _read_env_file_value(tenant.env_path, "DJANGO_SECRET_KEY")
        or os.environ.get("CONTROL_TENANT_DJANGO_SECRET_KEY", "").strip()
        or get_random_secret_key()
    )


def _tenant_env(tenant, *, disable_embedded_sync=False):
    tenant_dir = Path(tenant.env_path).parent
    env = os.environ.copy()
    env.update(_tenant_database_env(tenant))
    env.update({
        "DJANGO_SETTINGS_MODULE": "oltportal.settings",
        "DJANGO_SECRET_KEY": _tenant_secret_key(tenant),
        "DJANGO_DEBUG": "False",
        "DJANGO_ALLOWED_HOSTS": f"{tenant.public_hostname or tenant.panel_host},127.0.0.1,localhost",
        "DJANGO_CSRF_TRUSTED_ORIGINS": tenant.panel_url if tenant.public_hostname else f"http://{tenant.panel_host},http://{tenant.panel_host}:{tenant.panel_port}",
        "DJANGO_SESSION_COOKIE_SECURE": str(bool(tenant.public_hostname)),
        "DJANGO_CSRF_COOKIE_SECURE": str(bool(tenant.public_hostname)),
        "DJANGO_SECURE_SSL_REDIRECT": str(bool(tenant.public_hostname)),
        "DJANGO_SESSION_COOKIE_NAME": f"optiverse_{_tenant_cookie_prefix(tenant)}_sessionid",
        "DJANGO_CSRF_COOKIE_NAME": f"optiverse_{_tenant_cookie_prefix(tenant)}_csrftoken",
        "OPTIVERSE_RUNTIME_DIR": str(tenant_dir),
        "ONU_STATUS_SYNC_PROGRESS_FILE": str(tenant_dir / "onu_status_sync_progress.json"),
        "DJANGO_TIME_ZONE": os.environ.get("CONTROL_DJANGO_TIME_ZONE", "Asia/Karachi"),
        "DJANGO_LANGUAGE_CODE": "en-us",
        "OLT_ENABLE_EMBEDDED_SYNC": "true",
    })
    if tenant.olt_management_subnet:
        env["OPTIVERSE_OLT_MANAGEMENT_SUBNET"] = tenant.olt_management_subnet
    if tenant.agent_token:
        env["OPTIVERSE_AGENT_TOKEN"] = tenant.agent_token
    if disable_embedded_sync:
        env["OLT_DISABLE_EMBEDDED_SYNC"] = "1"
        env.pop("OLT_ENABLE_EMBEDDED_SYNC", None)
    return env


def _tenant_database_env(tenant):
    return {'DB_ENGINE': tenant.database_engine, 'DB_NAME': tenant.database_name,
            'DB_USER': tenant.database_user, 'DB_PASSWORD': tenant.database_password,
            'DB_HOST': tenant.database_host, 'DB_PORT': str(tenant.database_port)}


def _write_tenant_env_file(tenant):
    secret = _tenant_secret_key(tenant)
    tenant_dir = Path(tenant.env_path).parent
    text = f"""DJANGO_SECRET_KEY={secret}
DJANGO_DEBUG=False
DJANGO_ALLOWED_HOSTS={tenant.public_hostname or tenant.panel_host},127.0.0.1,localhost
DJANGO_CSRF_TRUSTED_ORIGINS={tenant.panel_url if tenant.public_hostname else f'http://{tenant.panel_host},http://{tenant.panel_host}:{tenant.panel_port}'}
DJANGO_SECURE_SSL_REDIRECT={bool(tenant.public_hostname)}
DJANGO_SESSION_COOKIE_SECURE={bool(tenant.public_hostname)}
DJANGO_CSRF_COOKIE_SECURE={bool(tenant.public_hostname)}
DJANGO_SESSION_COOKIE_NAME=optiverse_{_tenant_cookie_prefix(tenant)}_sessionid
DJANGO_CSRF_COOKIE_NAME=optiverse_{_tenant_cookie_prefix(tenant)}_csrftoken
DJANGO_TIME_ZONE=Asia/Karachi
DJANGO_LANGUAGE_CODE=en-us
OPTIVERSE_RUNTIME_DIR={tenant_dir}
DB_ENGINE={tenant.database_engine}
DB_NAME={tenant.database_name}
DB_USER={tenant.database_user}
DB_PASSWORD={tenant.database_password}
DB_HOST={tenant.database_host}
DB_PORT={tenant.database_port}
ONU_STATUS_SYNC_PROGRESS_FILE={tenant_dir / "onu_status_sync_progress.json"}
OLT_ENABLE_EMBEDDED_SYNC=true
OLT_BACKGROUND_SYNC_THREADS={os.environ.get("CONTROL_TENANT_BACKGROUND_SYNC_THREADS", "snmp_monitor,onu_status,signal_sample,inventory")}
NEW_ONU_CHECK_SECONDS={os.environ.get("CONTROL_TENANT_NEW_ONU_CHECK_SECONDS", "180")}
NEW_ONU_RECONCILE_SECONDS={os.environ.get("CONTROL_TENANT_NEW_ONU_RECONCILE_SECONDS", "900")}
SNMP_MONITOR_MAX_WORKERS={os.environ.get("CONTROL_TENANT_SNMP_MONITOR_MAX_WORKERS", "1")}
ONU_STATUS_SYNC_MAX_WORKERS={os.environ.get("CONTROL_TENANT_ONU_STATUS_SYNC_MAX_WORKERS", "1")}
ONU_SIGNAL_SAMPLE_MAX_WORKERS={os.environ.get("CONTROL_TENANT_ONU_SIGNAL_SAMPLE_MAX_WORKERS", "1")}
ONU_STATUS_SYNC_OLT_TIMEOUT_SECONDS={os.environ.get("CONTROL_TENANT_ONU_STATUS_SYNC_OLT_TIMEOUT_SECONDS", "180")}
ONU_STATUS_SYNC_OLT_BATCH_SIZE={os.environ.get("CONTROL_TENANT_ONU_STATUS_SYNC_OLT_BATCH_SIZE", "1000")}
ONU_STATUS_SYNC_PON_TIMEOUT_SECONDS={os.environ.get("CONTROL_TENANT_ONU_STATUS_SYNC_PON_TIMEOUT_SECONDS", "12")}
ONU_STATUS_SYNC_SNMP_CHUNK_SIZE={os.environ.get("CONTROL_TENANT_ONU_STATUS_SYNC_SNMP_CHUNK_SIZE", "40")}
ONU_SIGNAL_SAMPLE_SECONDS={os.environ.get("CONTROL_TENANT_ONU_SIGNAL_SAMPLE_SECONDS", "3600")}
OLT_ONU_OPTICAL_SAMPLE_INTERVAL_SECONDS=3600
OLT_ONU_OPTICAL_RETENTION_DAYS=15
OLT_ONU_STATUS_RETENTION_DAYS=30
OLT_ONU_TRAFFIC_RETENTION_DAYS=30
OLT_PON_TRAFFIC_RETENTION_DAYS=30
OLT_PON_PORT_TRAFFIC_RETENTION_DAYS=30
OLT_UPLINK_PORT_TRAFFIC_RETENTION_DAYS=30
OLT_DASHBOARD_STATUS_RETENTION_DAYS=180
OLT_SAMPLE_RETENTION_CLEANUP_SECONDS=3600
OPTIVERSE_OLT_MANAGEMENT_SUBNET={tenant.olt_management_subnet or tenant.client_local_subnet}
OPTIVERSE_AGENT_TOKEN={tenant.agent_token}
"""
    env_path = Path(tenant.env_path)
    env_path.parent.mkdir(parents=True, exist_ok=True)
    env_path.write_text(text, encoding="utf-8")
    try:
        os.chmod(env_path, 0o640)
    except OSError:
        pass
    required = {
        "DJANGO_SECRET_KEY",
        "DJANGO_SESSION_COOKIE_NAME",
        "DJANGO_CSRF_COOKIE_NAME",
        "DB_NAME", "DB_USER", "DB_PASSWORD",
        "ONU_STATUS_SYNC_PROGRESS_FILE",
        "OLT_BACKGROUND_SYNC_THREADS",
    }
    missing = [key for key in sorted(required) if not _read_env_file_value(env_path, key)]
    if missing:
        raise TenantProvisionError(f"Tenant env file is incomplete. Missing: {', '.join(missing)}")


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
    service_name = str(tenant.service_name or f"optiverse-{_safe_slug(tenant)}").removesuffix('.service')
    if not re.fullmatch(r'optiverse(?:-[a-z0-9-]+)?', service_name):
        raise TenantProvisionError('Invalid tenant system service name.')
    worker_cpu_quota = os.environ.get('CONTROL_TENANT_WORKER_CPU_QUOTA', '100%').strip()
    if not re.fullmatch(r'[1-9][0-9]{0,3}%', worker_cpu_quota):
        raise TenantProvisionError('CONTROL_TENANT_WORKER_CPU_QUOTA must be a percentage such as 100%.')
    sync_service_name = f"{service_name}-sync"
    service_text = f"""[Unit]
Description=OptiVerse Tenant Portal - {tenant.name}
After=network-online.target postgresql.service
Wants=network-online.target

[Service]
Type=simple
User=root
Group=root
WorkingDirectory={codebase}
EnvironmentFile={tenant.env_path}
Environment=OLT_DISABLE_EMBEDDED_SYNC=1
Environment=OLT_ENABLE_EMBEDDED_SYNC=false
Nice=-5
ExecStart={codebase}/.venv/bin/gunicorn oltportal.asgi:application --bind {_tenant_bind_host()}:{tenant.panel_port} --workers 2 --worker-class uvicorn.workers.UvicornWorker --timeout 180 --graceful-timeout 30 --keep-alive 5 --max-requests 2000 --max-requests-jitter 200 --access-logfile - --error-logfile -
Restart=always
RestartSec=5
TimeoutStopSec=30
KillSignal=SIGTERM
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
"""
    sync_service_text = f"""[Unit]
Description=OptiVerse Tenant Background Sync - {tenant.name}
After=network-online.target postgresql.service
Wants=network-online.target

[Service]
Type=simple
User=root
Group=root
WorkingDirectory={codebase}
EnvironmentFile={tenant.env_path}
Environment=OLT_DISABLE_EMBEDDED_SYNC=0
Environment=OLT_ENABLE_EMBEDDED_SYNC=true
Nice=10
IOSchedulingClass=idle
CPUQuota={worker_cpu_quota}
ExecStart={codebase}/.venv/bin/python manage.py run_background_sync
Restart=always
RestartSec=5
TimeoutStopSec=30
KillSignal=SIGTERM
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
"""
    path = Path("/etc/systemd/system") / f"{service_name}.service"
    sync_path = Path("/etc/systemd/system") / f"{sync_service_name}.service"
    path.write_text(service_text, encoding="utf-8")
    sync_path.write_text(sync_service_text, encoding="utf-8")
    subprocess.run(["systemctl", "daemon-reload"], check=True, capture_output=True, text=True)
    subprocess.run(["systemctl", "enable", "--now", service_name, sync_service_name], check=True, capture_output=True, text=True)
    subprocess.run(["systemctl", "restart", service_name, sync_service_name], check=True, capture_output=True, text=True)
    _apply_tenant_vpn(tenant)
    tenant.service_name = service_name
    tenant.save(update_fields=["service_name", "updated_at"])
    _wait_tenant_http(tenant)
    try:
        deployment.publish_proxy(tenant, _run_command)
    except ValueError as exc:
        raise TenantProvisionError(str(exc)) from exc
    return f"{service_name}.service and {sync_service_name}.service started"


def _tenant_vpn_interface_name(tenant):
    return f"optiverse-{int(tenant.pk)}"


def _apply_tenant_vpn(tenant):
    """Install one isolated WireGuard /30 interface and its customer routes."""
    if not _systemd_available():
        return
    interface = _tenant_vpn_interface_name(tenant)
    target = Path("/etc/wireguard") / f"{interface}.conf"
    if not tenant.vpn_enabled:
        _run_command(["systemctl", "disable", "--now", f"wg-quick@{interface}"], timeout=60)
        target.unlink(missing_ok=True)
        return
    source = Path(tenant.env_path).parent / "vpn" / "wg0.conf"
    if not source.is_file():
        raise TenantProvisionError("Tenant WireGuard server configuration was not generated.")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(source.read_text(encoding="utf-8"), encoding="utf-8")
    os.chmod(target, 0o600)
    ok, output = _run_command(["systemctl", "enable", f"wg-quick@{interface}"], timeout=60)
    if ok:
        ok, output = _run_command(["systemctl", "restart", f"wg-quick@{interface}"], timeout=60)
    if not ok:
        raise TenantProvisionError(output or f"Could not activate WireGuard interface {interface}.")


def _run_command(args, *, timeout=120, cwd=None):
    result = subprocess.run(args, cwd=cwd, capture_output=True, text=True, timeout=timeout, check=False)
    output = "\n".join(part.strip() for part in [result.stdout, result.stderr] if part and part.strip())
    return result.returncode == 0, output


def _remove_tenant_file(path, log_lines):
    if not path:
        return
    target = Path(str(path or "")).expanduser()
    if not str(target):
        return
    for candidate in [target]:
        try:
            if candidate.is_file():
                candidate.unlink()
                log_lines.append(f"Removed file: {candidate}")
        except OSError as exc:
            log_lines.append(f"Could not remove file {candidate}: {exc}")


def _remove_tenant_directory_if_safe(tenant, log_lines):
    base_dir = _tenant_base_dir().resolve()
    slug_dir = (base_dir / _safe_slug(tenant)).resolve()
    candidate_dirs = []
    for raw_path in (tenant.env_path, tenant.database_path, tenant.wg_config_path):
        if raw_path:
            try:
                candidate_dirs.append(Path(raw_path).expanduser().resolve().parent)
            except OSError:
                pass
    if slug_dir in candidate_dirs and slug_dir != base_dir and base_dir in slug_dir.parents and slug_dir.exists():
        try:
            shutil.rmtree(slug_dir)
            log_lines.append(f"Removed tenant directory: {slug_dir}")
        except OSError as exc:
            log_lines.append(f"Could not remove tenant directory {slug_dir}: {exc}")


def _tenant_related_service_names(tenant):
    """Return every systemd unit owned by a tenant deployment."""
    primary = str(tenant.service_name or f"optiverse-{_safe_slug(tenant)}").strip().removesuffix(".service")
    if not re.fullmatch(r"optiverse(?:-[a-z0-9-]+)?", primary):
        raise TenantProvisionError("Invalid tenant system service name.")
    return primary, f"{primary}-sync"


def _remove_tenant_systemd_services(tenant, log_lines):
    if not _systemd_available():
        return
    systemd_dir = Path("/etc/systemd/system")
    for service_name in _tenant_related_service_names(tenant):
        _run_command(["systemctl", "disable", "--now", service_name], timeout=60)
        (systemd_dir / f"{service_name}.service").unlink(missing_ok=True)
        drop_in_dir = systemd_dir / f"{service_name}.service.d"
        if drop_in_dir.is_dir():
            shutil.rmtree(drop_in_dir)
        log_lines.append(f"Removed tenant service: {service_name}.service")
    _run_command(["systemctl", "daemon-reload"], timeout=30)
    _run_command(["systemctl", "reset-failed"], timeout=30)


def delete_tenant_instance(tenant):
    """Delete tenant runtime, local files and registry record.

    For safety, only the tenant-owned directory under CONTROL_TENANT_BASE_DIR is
    removed recursively. Shared codebase folders are never recursively removed.
    """
    log_lines = []
    _remove_tenant_systemd_services(tenant, log_lines)
    if _systemd_available():
        interface = _tenant_vpn_interface_name(tenant)
        _run_command(["systemctl", "disable", "--now", f"wg-quick@{interface}"], timeout=60)
        vpn_path = Path("/etc/wireguard") / f"{interface}.conf"
        vpn_path.unlink(missing_ok=True)

    try:
        deployment.remove_proxy(tenant, _run_command)
    except ValueError as exc:
        raise TenantProvisionError(str(exc)) from exc
    _drop_postgres_tenant(tenant)
    log_lines.append(f'Removed PostgreSQL tenant database: {tenant.database_name}')
    _remove_tenant_file(tenant.env_path, log_lines)
    _remove_tenant_file(tenant.wg_config_path, log_lines)
    _remove_tenant_directory_if_safe(tenant, log_lines)

    name = tenant.name
    slug = tenant.slug
    tenant.delete()
    return {"name": name, "slug": slug, "log": "\n".join(log_lines).strip()}


def _wait_tenant_http(tenant):
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        connection = http.client.HTTPConnection('127.0.0.1', int(tenant.panel_port), timeout=2)
        try:
            connection.request('GET', '/', headers={'Host': tenant.public_hostname or tenant.panel_host})
            response = connection.getresponse()
            if 200 <= response.status < 400:
                return
        except OSError:
            pass
        finally:
            connection.close()
        time.sleep(1)
    raise TenantProvisionError('Tenant service started but the web app did not become ready. Check its journal.')


def prepare_tenant_defaults(tenant):
    tenant.save()
    slug = tenant.slug
    base = _tenant_base_dir() / slug
    port_conflicts = tenant.__class__.objects.exclude(pk=tenant.pk).filter(panel_port=tenant.panel_port).exists() if tenant.panel_port else False
    # Tenant.panel_port historically defaults to 8000, which is reserved for
    # the base portal. New/legacy tenants must start at the configured tenant
    # range, and allocation also skips ports occupied outside the control DB.
    if not tenant.panel_port or int(tenant.panel_port) < _tenant_start_port() or port_conflicts:
        tenant.panel_port = _tenant_next_available_port(tenant)
    tenant.panel_scheme = tenant.panel_scheme or "http"
    tenant.panel_host = tenant.panel_host or _tenant_panel_host()
    tenant.codebase_path = tenant.codebase_path or str(_tenant_codebase_path())
    tenant.database_path = ''
    tenant.env_path = tenant.env_path or str(base / ".env")
    tenant.database_engine = 'postgresql'
    if not tenant.database_name:
        tenant.database_engine = 'postgresql'
        tenant.database_name = ('optiverse_tenant_' + _safe_slug(tenant).replace('-', '_'))[:63]
        tenant.database_user = tenant.database_name
        tenant.database_password = secrets.token_urlsafe(36)
        tenant.database_host = os.environ.get('CONTROL_TENANT_DB_HOST', '127.0.0.1')
        tenant.database_port = int(os.environ.get('CONTROL_TENANT_DB_PORT', '5432'))
    expected_service_name = f"optiverse-{slug}"
    if not tenant.service_name or str(tenant.service_name).startswith("optiverse-tenant-"):
        tenant.service_name = expected_service_name
    tenant.isp_name = tenant.isp_name or tenant.name
    tenant.owner_name = tenant.owner_name or tenant.name
    tenant.agent_token = tenant.agent_token or secrets.token_urlsafe(36)
    if not tenant.wg_client_private_key or not tenant.wg_client_public_key:
        tenant.wg_client_private_key, tenant.wg_client_public_key = _wireguard_keypair()
    tenant.wg_client_address = tenant.wg_client_address or _tenant_default_wg_address(tenant)
    tenant.save(update_fields=[
        "panel_port", "panel_scheme", "panel_host", "codebase_path", "database_path",
        "env_path", "service_name", "isp_name", "owner_name", "agent_token",
        "database_engine", "database_name", "database_user", "database_password", "database_host", "database_port",
        "wg_client_private_key", "wg_client_public_key", "wg_client_address",
        "updated_at",
    ])
    return tenant


def _postgres_admin_query(statement):
    if os.name == 'nt':
        import psycopg
        password = os.environ.get('CONTROL_PG_ADMIN_PASSWORD', '')
        if not password:
            raise TenantProvisionError('Set CONTROL_PG_ADMIN_PASSWORD for local tenant provisioning.')
        try:
            with psycopg.connect(dbname='postgres', host='127.0.0.1',
                    port=int(os.environ.get('CONTROL_TENANT_DB_PORT', '5432')),
                    user=os.environ.get('CONTROL_PG_ADMIN_USER', 'postgres'), password=password,
                    autocommit=True, connect_timeout=10) as connection:
                cursor = connection.execute(statement)
                row = cursor.fetchone() if cursor.description else None
                return row[0] if row else None
        except psycopg.Error as exc:
            raise TenantProvisionError('PostgreSQL administration failed; check local administrator settings.') from exc
    result = subprocess.run(['runuser', '-u', 'postgres', '--', 'psql', '-X', '-v', 'ON_ERROR_STOP=1', '-At', '-d', 'postgres'],
        input=statement.as_string(), text=True, capture_output=True, timeout=60)
    if result.returncode:
        raise TenantProvisionError('PostgreSQL administration failed; check the control service permissions and PostgreSQL logs.')
    return result.stdout.strip()


def _ensure_postgres_tenant(tenant):
    """Local trusted control service creates a dedicated tenant role/database."""
    from psycopg import sql
    if not re.fullmatch(r'optiverse_tenant_[a-z0-9_]+', tenant.database_name) or tenant.database_user != tenant.database_name:
        raise TenantProvisionError('Tenant database/user names must use the managed optiverse_tenant_ prefix.')
    if tenant.database_host not in {'127.0.0.1', 'localhost'}:
        raise TenantProvisionError('Automatic database provisioning requires a local PostgreSQL server.')
    query = _postgres_admin_query
    if not query(sql.SQL('SELECT 1 FROM pg_roles WHERE rolname={}').format(sql.Literal(tenant.database_user))):
        query(sql.SQL('CREATE ROLE {} LOGIN PASSWORD {}').format(sql.Identifier(tenant.database_user), sql.Literal(tenant.database_password)))
    if not query(sql.SQL('SELECT 1 FROM pg_database WHERE datname={}').format(sql.Literal(tenant.database_name))):
        query(sql.SQL('CREATE DATABASE {} OWNER {} TEMPLATE template0').format(sql.Identifier(tenant.database_name), sql.Identifier(tenant.database_user)))


def _drop_postgres_tenant(tenant):
    from psycopg import sql
    if (not re.fullmatch(r'optiverse_tenant_[a-z0-9_]+', tenant.database_name)
            or tenant.database_user != tenant.database_name
            or tenant.database_host not in {'127.0.0.1', 'localhost'}):
        raise TenantProvisionError('Refusing to remove an unmanaged or remote PostgreSQL database.')
    # Separate statements: DROP DATABASE cannot run inside a transaction block.
    _postgres_admin_query(sql.SQL('DROP DATABASE IF EXISTS {} WITH (FORCE)').format(sql.Identifier(tenant.database_name)))
    _postgres_admin_query(sql.SQL('DROP ROLE IF EXISTS {}').format(sql.Identifier(tenant.database_user)))


def provision_tenant_instance(tenant):
    tenant = prepare_tenant_defaults(tenant)
    try:
        deployment.prepare_deployment(tenant, _wireguard_keypair)
    except ValueError as exc:
        raise TenantProvisionError(str(exc)) from exc
    if tenant.vpn_enabled:
        deployment.write_vpn_files(tenant)
    _ensure_postgres_tenant(tenant)
    _write_tenant_env_file(tenant)
    _run_tenant_manage(tenant, ["migrate", "--noinput"], timeout=600)
    username = tenant.panel_admin_username or "admin"
    password = tenant.panel_admin_initial_password
    email = tenant.owner_email or ""
    code = (
        "from django.contrib.auth import get_user_model; "
        "U=get_user_model(); "
        f"u,created=U.objects.get_or_create(username={username!r}, defaults={{'email': {email!r}, 'is_staff': True, 'is_superuser': True}}); "
        "u.is_staff=True; u.is_superuser=True; "
        f"u.email={email!r}; u.set_password({password!r}) if created else None; u.save(); print('tenant superuser ready')"
    )
    _run_tenant_manage(tenant, ["shell", "-c", code], timeout=180)
    service_status = _write_systemd_service(tenant)
    tenant.status = tenant.STATUS_ACTIVE
    tenant.save(update_fields=["status", "service_name", "updated_at"])
    try:
        refresh_tenant_database_snapshot(tenant)
    except TenantSnapshotError:
        pass
    return {"service_status": service_status, "panel_url": tenant.panel_url}


def _connect_tenant_db(tenant, *, read_only=True):
    try:
        return tenant_database.connect(tenant, read_only)
    except (FileNotFoundError, *tenant_database.DATABASE_ERRORS) as exc:
        raise TenantSnapshotError(str(exc)) from exc


def _quote_identifier(value):
    return '"' + str(value).replace('"', '""') + '"'


def _tenant_fk_references(cursor, target_table):
    return tenant_database.references(cursor, target_table)


TENANT_OLT_BILLING_COLUMNS = {
    "pricing_mode",
    "pricing_expires_at",
    "pricing_locked",
    "pricing_locked_reason",
}

TENANT_OLT_PRICING_LABELS = {
    "demo": "Demo Account",
    "standard": "Standard (1 month)",
    "custom": "Custom",
}


def _tenant_olt_columns(cursor):
    return tenant_database.columns(cursor, 'oltmanager_olt')


def _ensure_tenant_olt_billing_columns(cursor):
    columns = _tenant_olt_columns(cursor)
    missing = sorted(TENANT_OLT_BILLING_COLUMNS - columns)
    if missing:
        raise TenantSnapshotError(
            "Tenant database is missing pricing columns. Run tenant migrations first: "
            + ", ".join(missing)
        )


def _parse_database_datetime(value):
    text = str(value or "").strip()
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if timezone.is_naive(parsed):
        parsed = timezone.make_aware(parsed, timezone.get_current_timezone())
    return parsed


def _billing_status_from_row(row):
    mode = str(row.get("pricing_mode") or "standard").strip().lower() or "standard"
    expires_at = _parse_database_datetime(row.get("pricing_expires_at"))
    manually_locked = bool(int(row.get("pricing_locked") or 0))
    expired = bool(expires_at and expires_at <= timezone.now())
    if manually_locked:
        status = "Disabled"
    elif expired:
        status = "Expired"
    else:
        status = "Active"
    return {
        "pricing_mode": mode,
        "pricing_label": TENANT_OLT_PRICING_LABELS.get(mode, mode.title()),
        "pricing_expires_at": expires_at,
        "pricing_expires_display": timezone.localtime(expires_at).strftime("%Y-%m-%d %H:%M") if expires_at else "-",
        "pricing_locked": manually_locked,
        "pricing_status": status,
        "pricing_reason": str(row.get("pricing_locked_reason") or "").strip(),
    }


def _clear_fk_references(cursor, target_table, target_id, *, set_null_tables=None):
    set_null_tables = set(set_null_tables or [])
    for table_name, column_name in _tenant_fk_references(cursor, target_table):
        if not column_name:
            continue
        table_sql = _quote_identifier(table_name)
        column_sql = _quote_identifier(column_name)
        if table_name in set_null_tables:
            cursor.execute(f"UPDATE {table_sql} SET {column_sql}=NULL WHERE {column_sql}=%s", [target_id])
        else:
            cursor.execute(f"DELETE FROM {table_sql} WHERE {column_sql}=%s", [target_id])


def get_tenant_olts(tenant):
    conn = _connect_tenant_db(tenant, read_only=True)
    try:
        cursor = conn.cursor()
        if not _table_exists(cursor, "oltmanager_olt"):
            raise TenantSnapshotError("Tenant database is not initialized yet. Run tenant provisioning/migrations again.")
        if not _table_exists(cursor, "oltmanager_configuredonu"):
            raise TenantSnapshotError("Tenant database is missing ONU tables. Run tenant provisioning/migrations again.")
        has_billing_columns = TENANT_OLT_BILLING_COLUMNS.issubset(_tenant_olt_columns(cursor))
        billing_select = (
            "o.pricing_mode, o.pricing_expires_at, o.pricing_locked, o.pricing_locked_reason,"
            if has_billing_columns
            else "'standard' AS pricing_mode, NULL AS pricing_expires_at, 0 AS pricing_locked, '' AS pricing_locked_reason,"
        )
        cursor.execute(
            """
            SELECT o.id, o.name, o.ip_address, o.hardware_version, o.sw_version, o.snmp_last_status,
                   {billing_select}
                   COUNT(c.id) AS onu_count,
                   SUM(CASE WHEN LOWER(COALESCE(c.derived_status, '')) = 'online' THEN 1 ELSE 0 END) AS online_count
            FROM oltmanager_olt o
            LEFT JOIN oltmanager_configuredonu c ON c.olt_id = o.id
            GROUP BY o.id
            ORDER BY LOWER(o.name)
            """.format(billing_select=billing_select)
        )
        rows = []
        for row in cursor.fetchall():
            item = dict(row)
            item["online_count"] = int(item.get("online_count") or 0)
            item["onu_count"] = int(item.get("onu_count") or 0)
            item["offline_count"] = max(0, item["onu_count"] - item["online_count"])
            item.update(_billing_status_from_row(item))
            rows.append(item)
        return rows
    finally:
        conn.close()


def get_tenant_olt_onus(tenant, tenant_olt_id, search_query=""):
    conn = _connect_tenant_db(tenant, read_only=True)
    try:
        cursor = conn.cursor()
        if not _table_exists(cursor, "oltmanager_olt"):
            raise TenantSnapshotError("Tenant database is not initialized yet. Run tenant provisioning/migrations again.")
        if not _table_exists(cursor, "oltmanager_configuredonu"):
            raise TenantSnapshotError("Tenant database is missing ONU tables. Run tenant provisioning/migrations again.")
        has_billing_columns = TENANT_OLT_BILLING_COLUMNS.issubset(_tenant_olt_columns(cursor))
        billing_select = (
            ", pricing_mode, pricing_expires_at, pricing_locked, pricing_locked_reason"
            if has_billing_columns
            else ", 'standard' AS pricing_mode, NULL AS pricing_expires_at, 0 AS pricing_locked, '' AS pricing_locked_reason"
        )
        cursor.execute(f"SELECT id, name, ip_address, hardware_version, sw_version, snmp_last_status{billing_select} FROM oltmanager_olt WHERE id=%s", [int(tenant_olt_id)])
        olt = cursor.fetchone()
        if not olt:
            raise TenantSnapshotError("OLT not found in tenant database.")
        params = [int(tenant_olt_id)]
        where_extra = ""
        search_text = str(search_query or "").strip()
        if search_text:
            like_text = f"%{search_text.lower()}%"
            where_extra = """
              AND (
                LOWER(COALESCE(sn, '')) LIKE %s
                OR LOWER(COALESCE(description, '')) LIKE %s
                OR LOWER(COALESCE(attached_vlans_cache, '')) LIKE %s
                OR (CAST(slot AS TEXT) || '/' || CAST(port AS TEXT) || '/' || CAST(ont_id AS TEXT)) LIKE %s
              )
            """
            params.extend([like_text, like_text, like_text, f"%{search_text}%"])
        cursor.execute(
            f"""
            SELECT id, slot, port, ont_id, sn, description, derived_status, attached_vlans_cache, onu_rx, olt_rx, ont_distance_m
            FROM oltmanager_configuredonu
            WHERE olt_id=%s
            {where_extra}
            ORDER BY slot, port, ont_id
            """,
            params,
        )
        olt_item = dict(olt)
        olt_item.update(_billing_status_from_row(olt_item))
        return olt_item, [dict(row) for row in cursor.fetchall()]
    finally:
        conn.close()


def update_tenant_olt_pricing(tenant, tenant_olt_id, *, pricing_mode=None, expires_at=None, locked=None, reason=""):
    tenant_olt_id = int(tenant_olt_id)
    conn = _connect_tenant_db(tenant, read_only=False)
    try:
        cursor = conn.cursor()
        if not _table_exists(cursor, "oltmanager_olt"):
            raise TenantSnapshotError("Tenant database is not initialized yet. Run tenant provisioning/migrations again.")
        _ensure_tenant_olt_billing_columns(cursor)
        cursor.execute("SELECT id, name FROM oltmanager_olt WHERE id=%s", [tenant_olt_id])
        row = cursor.fetchone()
        if not row:
            raise TenantSnapshotError("OLT not found in tenant database.")

        update_parts = []
        params = []
        mode = str(pricing_mode or "").strip().lower()
        if mode:
            if mode not in TENANT_OLT_PRICING_LABELS:
                raise TenantSnapshotError("Invalid pricing mode.")
            if mode == "demo":
                expires_at = timezone.now() + timedelta(days=3)
            elif mode == "standard":
                expires_at = timezone.now() + timedelta(days=30)
            update_parts.extend(["pricing_mode=%s", "pricing_expires_at=%s"])
            params.extend([mode, expires_at])
        if locked is not None:
            update_parts.extend(["pricing_locked=%s", "pricing_locked_reason=%s"])
            params.extend([bool(locked), str(reason or "")[:255]])
        if not update_parts:
            return "No pricing changes submitted."
        params.append(tenant_olt_id)
        cursor.execute(f"UPDATE oltmanager_olt SET {', '.join(update_parts)} WHERE id=%s", params)
        conn.commit()
        name = str(row["name"] or "")
    except tenant_database.DATABASE_ERRORS as exc:
        conn.rollback()
        raise TenantSnapshotError(f"Could not update OLT pricing in tenant database: {exc}") from exc
    finally:
        conn.close()
    refresh_tenant_database_snapshot(tenant, record_snapshot=False)
    return f"{name} pricing updated."


def delete_tenant_olt(tenant, tenant_olt_id):
    tenant_olt_id = int(tenant_olt_id)
    conn = _connect_tenant_db(tenant, read_only=False)
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM oltmanager_olt WHERE id=%s", [tenant_olt_id])
        row = cursor.fetchone()
        if not row:
            raise TenantSnapshotError("OLT not found in tenant database.")
        name = str(row["name"] or "")
        _clear_fk_references(
            cursor,
            "oltmanager_olt",
            tenant_olt_id,
            set_null_tables={"oltmanager_alertevent"},
        )
        cursor.execute("DELETE FROM oltmanager_olt WHERE id=%s", [tenant_olt_id])
        deleted = cursor.rowcount
        conn.commit()
    except tenant_database.DATABASE_ERRORS as exc:
        conn.rollback()
        raise TenantSnapshotError(f"Could not delete OLT from tenant database: {exc}") from exc
    finally:
        conn.close()
    refresh_tenant_database_snapshot(tenant)
    return f"deleted={deleted} name={name}"


def delete_tenant_onu(tenant, onu_id):
    onu_id = int(onu_id)
    conn = _connect_tenant_db(tenant, read_only=False)
    try:
        cursor = conn.cursor()
        _clear_fk_references(cursor, "oltmanager_configuredonu", onu_id)
        cursor.execute(
            "SELECT slot, port, ont_id, sn FROM oltmanager_configuredonu WHERE id=%s",
            [onu_id],
        )
        row = cursor.fetchone()
        if not row:
            raise TenantSnapshotError("ONU not found in tenant database.")
        label = f"{row['slot']}/{row['port']}/{row['ont_id']} {row['sn'] or ''}".strip()
        cursor.execute("DELETE FROM oltmanager_configuredonu WHERE id=%s", [onu_id])
        deleted = cursor.rowcount
        conn.commit()
    except tenant_database.DATABASE_ERRORS as exc:
        conn.rollback()
        raise TenantSnapshotError(f"Could not delete ONU from tenant database: {exc}") from exc
    finally:
        conn.close()
    refresh_tenant_database_snapshot(tenant)
    return f"deleted={deleted} onu={label}"


def refresh_tenant_database_snapshot(tenant, *, record_snapshot=True):
    """Read a tenant PostgreSQL database and copy lightweight resource counts only.

    This function is intentionally DB-only. It does not import tenant app code and
    does not run SNMP, Telnet, HTTP polling, migrations, or background jobs.
    """
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
            ORDER BY LOWER(name)
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

    db_size_mb = Decimal(str(round(tenant_database.size_mb(tenant), 2)))
    snapshot = None
    if record_snapshot:
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
