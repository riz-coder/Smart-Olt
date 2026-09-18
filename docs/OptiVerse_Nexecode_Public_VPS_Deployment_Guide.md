# OptiVerse Public VPS Deployment Guide — nexecode.com

Updated: 18 September 2026

This guide deploys the current native Linux build with PostgreSQL, systemd, Nginx, Certbot and optional per-tenant WireGuard. Docker and Caddy are not used.

## 1. Final design

- Control panel: `https://optiverse.nexecode.com/`
- Tenant pattern: `https://TENANT-NAME.nexecode.com/`
- Example tenant: `https://connect.nexecode.com/`
- Control service: `127.0.0.1:9000`
- Tenant services: localhost ports starting at `8001`
- PostgreSQL: localhost only
- Public ports: TCP 22, 80 and 443; tenant WireGuard UDP ports only when VPN is enabled

## 2. Protect existing VPS services

Record the existing state before deployment. Do not stop, remove or overwrite unrelated services.

```bash
systemctl --failed
systemctl list-units --type=service --state=running --no-pager
ss -lntup
nginx -T > /root/nginx-before-optiverse.txt
sudo -u postgres psql -d postgres -c "SELECT datname FROM pg_database ORDER BY datname;"
```

```bash
install -d -m 700 /var/backups/optiverse
tar -czf /var/backups/optiverse/nginx-before-optiverse.tar.gz /etc/nginx
sudo -u postgres pg_dumpall --globals-only > /var/backups/optiverse/postgres-globals.sql
```

The application creates separate Nginx sites, systemd units and PostgreSQL databases. It must not reuse an existing site's domain, port, database or service name.

## 3. DNS

Create these records pointing to the VPS public IPv4:

| Type | Host | Value |
|---|---|---|
| A | `optiverse` | `<VPS_PUBLIC_IPV4>` |
| A | `*` | `<VPS_PUBLIC_IPV4>` |

The wildcard enables `connect.nexecode.com` and future tenants. Existing explicit DNS records take precedence and remain unchanged.

```bash
getent ahostsv4 optiverse.nexecode.com
getent ahostsv4 connect.nexecode.com
```

## 4. Required packages

```bash
apt update
apt install -y git curl python3 python3-venv python3-dev build-essential \
  libxml2-dev libxslt1-dev zlib1g-dev nginx postgresql postgresql-client \
  certbot wireguard-tools
systemctl enable --now nginx postgresql
```

Do not install or enable Caddy. If another proxy owns ports 80/443, stop and review the conflict instead of affecting it automatically.

## 5. Clone the application

```bash
install -d -m 755 /opt/optiverse
cd /opt/optiverse
git clone https://github.com/riz-coder/Smart-Olt.git
cd /opt/optiverse/Smart-Olt
git branch --show-current
git log -1 --oneline
```

Expected branch is `main`. Never commit production `.env` files.

## 6. Base `.env`

```bash
cp .env.example .env
chmod 600 .env
nano .env
```

Set at least these production values and retain relevant polling/email/retention options from `.env.example`:

```dotenv
DJANGO_SECRET_KEY=<GENERATED_BASE_SECRET>
DJANGO_DEBUG=False
DJANGO_ALLOWED_HOSTS=127.0.0.1,localhost
DJANGO_CSRF_TRUSTED_ORIGINS=https://optiverse.nexecode.com
DJANGO_SESSION_COOKIE_SECURE=True
DJANGO_CSRF_COOKIE_SECURE=True
DJANGO_TIME_ZONE=Asia/Karachi

DB_ENGINE=postgresql
DB_HOST=127.0.0.1
DB_PORT=5432
DB_NAME=optiverse_app
DB_USER=optiverse_app
DB_PASSWORD=<GENERATED_BASE_DB_PASSWORD>
DB_SSLMODE=prefer
DB_CONN_MAX_AGE=60

OLT_DISABLE_EMBEDDED_SYNC=1
OLT_ENABLE_EMBEDDED_SYNC=false
OLT_BACKGROUND_SYNC_THREADS=snmp_monitor,onu_status,signal_sample,inventory
NEW_ONU_CHECK_SECONDS=180
NEW_ONU_RECONCILE_SECONDS=900
NEW_ONU_RECONCILE_MAX_WORKERS=2
OPTIVERSE_WORKER_CPU_QUOTA=100%
```

## 7. Control-plane `.env.control`

```bash
cp .env.control.example .env.control
chmod 600 .env.control
nano .env.control
```

Replace every placeholder:

```dotenv
CONTROL_DB_ENGINE=postgresql
CONTROL_DB_HOST=127.0.0.1
CONTROL_DB_PORT=5432
CONTROL_DB_NAME=optiverse_control
CONTROL_DB_USER=optiverse_control
CONTROL_DB_PASSWORD=<GENERATED_CONTROL_DB_PASSWORD>
CONTROL_DB_CONN_MAX_AGE=60

CONTROL_DJANGO_SECRET_KEY=<GENERATED_CONTROL_SECRET>
CONTROL_DJANGO_DEBUG=False
CONTROL_DJANGO_ALLOWED_HOSTS=optiverse.nexecode.com,127.0.0.1,localhost
CONTROL_DJANGO_CSRF_TRUSTED_ORIGINS=https://optiverse.nexecode.com
CONTROL_DJANGO_TIME_ZONE=Asia/Karachi

CONTROL_TENANT_DB_ENGINE=postgresql
CONTROL_PG_ADMIN_USER=postgres
CONTROL_PG_ADMIN_PASSWORD=
CONTROL_TENANT_DB_HOST=127.0.0.1
CONTROL_TENANT_DB_PORT=5432
CONTROL_TENANT_CODEBASE_PATH=/opt/optiverse/Smart-Olt
CONTROL_TENANT_BASE_DIR=/opt/optiverse/tenants
CONTROL_TENANT_PANEL_HOST=<VPS_PUBLIC_IPV4>
CONTROL_TENANT_BIND_HOST=127.0.0.1
CONTROL_TENANT_START_PORT=8001
CONTROL_TENANT_RUNTIME=systemd

CONTROL_BASE_DOMAIN=nexecode.com
CONTROL_PUBLIC_HOSTNAME=optiverse.nexecode.com
CONTROL_ACME_EMAIL=<CERTIFICATE_ADMIN_EMAIL>
CONTROL_NGINX_SITES_AVAILABLE=/etc/nginx/sites-available
CONTROL_NGINX_SITES_ENABLED=/etc/nginx/sites-enabled
CONTROL_ACME_WEBROOT=/var/www/letsencrypt
CONTROL_CERTIFICATE_BASE_DIR=/etc/letsencrypt/live

CONTROL_TENANT_BACKGROUND_SYNC_THREADS=snmp_monitor,onu_status,signal_sample,inventory
CONTROL_TENANT_WORKER_CPU_QUOTA=100%
CONTROL_TENANT_NEW_ONU_CHECK_SECONDS=180
CONTROL_TENANT_NEW_ONU_RECONCILE_SECONDS=900

CONTROL_VPN_PUBLIC_HOST=<VPS_PUBLIC_IPV4>
CONTROL_VPN_PORT_START=52000
CONTROL_VPN_TUNNEL_POOL=10.75.75.0/24
```

`CONTROL_PUBLIC_HOSTNAME` is the control hostname. `CONTROL_BASE_DOMAIN=nexecode.com` makes tenant `connect` become `connect.nexecode.com`. `CONTROL_VPN_PUBLIC_HOST` must be the public IPv4, not a URL. Generate secrets with:

```bash
openssl rand -base64 48
```

## 8. Install the application

```bash
cd /opt/optiverse/Smart-Olt
OPTIVERSE_BIND_HOST=127.0.0.1 \
OPTIVERSE_CONTROL_BIND_HOST=127.0.0.1 \
bash scripts/install_ubuntu.sh
```

The installer prepares Python, PostgreSQL, migrations, static files and core systemd services.

```bash
systemctl is-active postgresql nginx optiverse optiverse-worker optiverse-control
systemctl --failed
ss -lntp | grep -E ':(5432|8000|9000) '
```

Ports 5432, 8000, 8001+ and 9000 must not be publicly exposed.

## 9. Control owner and public gateway

```bash
cd /opt/optiverse/Smart-Olt
OLT_DISABLE_EMBEDDED_SYNC=1 .venv/bin/python manage_control.py createsuperuser
OLT_DISABLE_EMBEDDED_SYNC=1 .venv/bin/python manage_control.py configure_public_gateway
```

The gateway command creates an isolated Nginx site, obtains a certificate through Certbot, validates Nginx and reloads it.

```bash
nginx -t
certbot certificates
curl -I https://optiverse.nexecode.com/
```

A `200` response or login redirect is healthy.

## 10. Tenant creation

Create Tenant requires a tenant name, email, panel username/password and optional VPN details. Creating `connect` automatically creates:

- `https://connect.nexecode.com/`
- isolated PostgreSQL role/database
- protected tenant environment
- migrations and initial tenant superuser
- separate web and sync systemd services
- separate Nginx site and TLS certificate
- optional WireGuard `/30` interface

```bash
systemctl status optiverse-connect optiverse-connect-sync --no-pager
curl -I http://127.0.0.1:8001/
curl -I https://connect.nexecode.com/
nginx -t
```

Use the actual port shown in the control panel if it is not 8001.

## 11. Optional tenant VPN

Enable VPN only when the VPS cannot route directly to the tenant's OLT network. Each VPN tenant receives:

- unique `/30` from `10.75.75.0/24`
- UDP port `CONTROL_VPN_PORT_START + tenant ID`
- unique server/client keys
- tenant interface `optiverse-TENANT_ID`
- only its declared LAN/OLT routes
- downloadable Ubuntu client configuration

Allow only the needed UDP range in both host and provider firewalls:

```bash
ufw allow 52001:52999/udp
ufw status verbose
```

For firewalld:

```bash
firewall-cmd --permanent --add-port=52001-52999/udp
firewall-cmd --reload
```

On the customer router, install the downloaded configuration, allow WireGuard traffic, enable forwarding when routing a separate LAN, and provide a return route or controlled customer-side NAT.

```bash
wg show
systemctl status wg-quick@optiverse-<TENANT_ID> --no-pager
ip -br address show optiverse-<TENANT_ID>
ip route
```

The control panel status checks the tenant-specific interface. A recent handshake confirms the tunnel; OLT access still requires correct customer routes and firewalls.

## 12. Production verification

```bash
systemctl is-active postgresql nginx optiverse optiverse-worker optiverse-control
systemctl --failed
nginx -t
certbot renew --dry-run
```

```bash
cd /opt/optiverse/Smart-Olt
OLT_DISABLE_EMBEDDED_SYNC=1 .venv/bin/python manage.py check --deploy
OLT_DISABLE_EMBEDDED_SYNC=1 .venv/bin/python manage_control.py check --deploy
.venv/bin/python scripts/verify_postgres.py
```

```bash
curl -I http://127.0.0.1:9000/
curl -I https://optiverse.nexecode.com/
curl -I https://connect.nexecode.com/
```

```bash
ps -eo pid,ppid,ni,pcpu,pmem,etime,comm,args --sort=-pcpu | head -n 25
free -h
df -h
systemd-cgtop --depth=2
journalctl -u optiverse-control -n 100 --no-pager
journalctl -u optiverse-worker -n 200 --no-pager
```

## 13. Safe updates

```bash
cd /opt/optiverse/Smart-Olt
git status --short
git fetch origin
git log --oneline HEAD..origin/main
git pull --ff-only origin main
```

Never overwrite an unexpected dirty production tree. Run the installer after migrations, dependencies, static assets, systemd templates or environment examples change:

```bash
OPTIVERSE_BIND_HOST=127.0.0.1 \
OPTIVERSE_CONTROL_BIND_HOST=127.0.0.1 \
bash scripts/install_ubuntu.sh
```

Restart tenant services in small batches and leave unrelated VPS services untouched:

```bash
systemctl restart optiverse optiverse-worker optiverse-control
systemctl restart optiverse-connect optiverse-connect-sync
nginx -t && systemctl reload nginx
```

## 14. Backup

Back up PostgreSQL, tenant environments, Nginx sites, WireGuard files and systemd units to encrypted off-server storage.

```bash
install -d -m 700 /var/backups/optiverse
sudo -u postgres pg_dumpall --globals-only | gzip > /var/backups/optiverse/postgres-globals-$(date +%F).sql.gz
sudo -u postgres pg_dump -Fc optiverse_control > /var/backups/optiverse/optiverse_control-$(date +%F).dump
tar -czf /var/backups/optiverse/config-$(date +%F).tar.gz \
  /opt/optiverse/Smart-Olt/.env /opt/optiverse/Smart-Olt/.env.control \
  /opt/optiverse/tenants /etc/nginx/sites-available /etc/nginx/sites-enabled \
  /etc/systemd/system/optiverse*.service /etc/wireguard
chmod 600 /var/backups/optiverse/*
```

Test restoration on a separate machine. A backup stored only on the same VPS is insufficient.

## 15. Go-live checklist

- Existing VPS services and Nginx are backed up.
- DNS resolves control and tenant hostnames.
- `nginx -t` succeeds and certificates are valid.
- PostgreSQL and application upstream ports listen locally only.
- Debug is disabled and secrets are outside Git.
- Web and polling services are separate and active.
- Test tenant creates its DB, services, Nginx site and HTTPS URL.
- VPN tenant-specific interface handshakes and reaches its OLT network.
- Off-server backups and restore procedure are tested.
