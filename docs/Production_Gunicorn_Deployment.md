# OptiVerse production deployment (Ubuntu)

The supported public deployment is:

`Internet -> Nginx/HTTPS -> Gunicorn -> Django -> PostgreSQL`

SNMP, ONU status, signal and traffic polling run in a separate systemd worker.
Do not run polling inside Gunicorn workers. Daphne and Django `runserver` are not
used by the production services.

## First installation

```bash
sudo mkdir -p /opt/optiverse
sudo chown "$USER":"$USER" /opt/optiverse
cd /opt/optiverse
git clone https://github.com/riz-coder/Smart-Olt.git
cd Smart-Olt
cp .env.example .env
cp .env.control.example .env.control   # only when the control plane is required
nano .env
nano .env.control
bash scripts/install_ubuntu.sh
```

Set real PostgreSQL credentials, `DJANGO_SECRET_KEY`, allowed hosts and trusted
HTTPS origins before running the installer. Keep both environment files outside
Git and mode `600`.

The installer creates and enables:

- `optiverse.service`: main Gunicorn web application on `127.0.0.1:8000`.
- `optiverse-worker.service`: isolated synchronization/polling worker.
- `optiverse-control.service`: Gunicorn control plane on `127.0.0.1:9000` when
  `.env.control` exists.

Every automatically provisioned ISP tenant receives two services: a Gunicorn
web service and a separate `-sync` worker. Tenant web workers cannot start
embedded polling.

## Required polling setting

```env
OLT_BACKGROUND_SYNC_THREADS=snmp_monitor,onu_status,signal_sample,inventory
```

`inventory` must remain enabled because it records scheduled PON and uplink
traffic samples. The installer adds it to an older `.env` automatically.

## Nginx and HTTPS

Copy `scripts/nginx_optiverse.conf.example`, replace the domain, validate and
reload Nginx:

```bash
sudo cp scripts/nginx_optiverse.conf.example /etc/nginx/sites-available/optiverse
sudo ln -s /etc/nginx/sites-available/optiverse /etc/nginx/sites-enabled/optiverse
sudo nginx -t
sudo systemctl reload nginx
sudo certbot --nginx -d app.example.com
```

Only ports 80 and 443 should be public. Keep 8000, 9000 and PostgreSQL private.

## Updating an existing server

```bash
cd /opt/optiverse/Smart-Olt
git status
git pull --ff-only origin main
source .venv/bin/activate
pip install -r requirements.txt
python manage.py migrate --noinput
python manage.py collectstatic --noinput
python manage_control.py migrate --noinput       # when control plane is installed
python manage_control.py collectstatic --noinput
sudo systemctl restart optiverse optiverse-worker optiverse-control
```

If `git pull` reports local changes, save them first with
`git stash push -u -m "server backup before update"`; do not delete them blindly.

## Verification

```bash
systemctl is-active optiverse optiverse-worker optiverse-control
systemctl is-enabled optiverse optiverse-worker optiverse-control
pgrep -af 'daphne|runserver'
ss -ltnp | grep -E ':(8000|9000)'
curl -I http://127.0.0.1:8000/
curl -I http://127.0.0.1:9000/
journalctl -u optiverse-worker -n 100 --no-pager
```

The `pgrep` command should return no Daphne or runserver production process.
