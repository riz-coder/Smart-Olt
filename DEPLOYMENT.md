# OptiVerse Deployment

This repository is prepared for a Linux deployment using Django, Daphne, Nginx, systemd, and SQLite.

## What is tracked

Tracked in Git:
- application source code
- Django migrations
- static source files
- `requirements.txt`
- `.env.example`
- deployment scripts/templates

Not tracked in Git:
- `.env`
- `db.sqlite3`, `db.sqlite3-wal`, `db.sqlite3-shm`
- logs
- backups
- virtual environments
- collected `staticfiles/`

## Fresh Linux install

Recommended path:

```bash
sudo apt-get update
sudo apt-get install -y git
sudo mkdir -p /opt/optiverse
sudo chown "$USER:$USER" /opt/optiverse
cd /opt/optiverse
git clone https://github.com/riz-coder/Smart-Olt.git oltportal
cd oltportal
bash scripts/install_ubuntu.sh
```

The installer will:
- create `.venv`
- install Python dependencies
- create `.env` from `.env.example` if missing
- generate a Django secret key
- run migrations
- collect static files
- install and start a systemd service named `optiverse`
- keep autostart disabled, so the app does not start automatically after a machine reboot

## Configure environment

Edit `.env` after install:

```bash
nano /opt/optiverse/oltportal/.env
```

Important values:

```env
DJANGO_DEBUG=False
DJANGO_ALLOWED_HOSTS=your-domain.com,your-server-ip,127.0.0.1,localhost
DJANGO_CSRF_TRUSTED_ORIGINS=https://your-domain.com,http://your-server-ip
SQLITE_DB_PATH=/opt/optiverse/oltportal/db.sqlite3
```

Restart after changes:

```bash
sudo systemctl restart optiverse
```

## Nginx reverse proxy

Copy the example config:

```bash
sudo cp scripts/nginx_optiverse.conf.example /etc/nginx/sites-available/optiverse
sudo nano /etc/nginx/sites-available/optiverse
sudo ln -s /etc/nginx/sites-available/optiverse /etc/nginx/sites-enabled/optiverse
sudo nginx -t
sudo systemctl reload nginx
```

If another default site is active and conflicting:

```bash
sudo rm -f /etc/nginx/sites-enabled/default
sudo nginx -t
sudo systemctl reload nginx
```

## Service commands

```bash
sudo systemctl status optiverse
sudo systemctl start optiverse
sudo systemctl restart optiverse
sudo systemctl stop optiverse
sudo journalctl -u optiverse -f
```

App log files are also written to:

```bash
/opt/optiverse/oltportal/logs/optiverse.out.log
/opt/optiverse/oltportal/logs/optiverse.err.log
```

## Updating from GitHub

```bash
cd /opt/optiverse/oltportal
git pull
source .venv/bin/activate
pip install -r requirements.txt
python manage.py migrate --noinput
python manage.py collectstatic --noinput
sudo systemctl restart optiverse
```

## Create admin user

```bash
cd /opt/optiverse/oltportal
source .venv/bin/activate
python manage.py createsuperuser
```

## Notes

- Daphne is used instead of multi-worker Gunicorn because this app starts background OLT/ONU sync loops. Running multiple web workers can duplicate those loops and increase device/database load.
- SQLite is kept for the current deployment target. Keep the DB file on the server and out of Git.
- For backups, copy `db.sqlite3` while the app is stopped, or use SQLite online backup tooling.
