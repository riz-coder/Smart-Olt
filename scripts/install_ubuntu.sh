#!/usr/bin/env bash
set -euo pipefail

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SERVICE_NAME="${OPTIVERSE_SERVICE_NAME:-optiverse}"
SERVICE_USER="${OPTIVERSE_SERVICE_USER:-$(id -un)}"
SERVICE_GROUP="${OPTIVERSE_SERVICE_GROUP:-$(id -gn)}"
HOST="${OPTIVERSE_BIND_HOST:-127.0.0.1}"
PORT="${OPTIVERSE_BIND_PORT:-8000}"
WEB_WORKERS="${OPTIVERSE_WEB_WORKERS:-3}"
WEB_THREADS="${OPTIVERSE_WEB_THREADS:-4}"
WEB_TIMEOUT="${OPTIVERSE_WEB_TIMEOUT:-180}"
CONTROL_SERVICE_NAME="${OPTIVERSE_CONTROL_SERVICE_NAME:-optiverse-control}"
CONTROL_SERVICE_USER="${OPTIVERSE_CONTROL_SERVICE_USER:-root}"
CONTROL_SERVICE_GROUP="${OPTIVERSE_CONTROL_SERVICE_GROUP:-root}"
CONTROL_HOST="${OPTIVERSE_CONTROL_BIND_HOST:-127.0.0.1}"
CONTROL_PORT="${OPTIVERSE_CONTROL_BIND_PORT:-9000}"
CONTROL_WORKERS="${OPTIVERSE_CONTROL_WORKERS:-2}"
CONTROL_THREADS="${OPTIVERSE_CONTROL_THREADS:-4}"
PYTHON_BIN="${PYTHON_BIN:-python3}"
VENV_DIR="$APP_DIR/.venv"
ENV_FILE="$APP_DIR/.env"

cd "$APP_DIR"

if command -v apt-get >/dev/null 2>&1; then
  echo "Installing system packages..."
  sudo apt-get update
  sudo apt-get install -y python3 python3-venv python3-dev build-essential libxml2-dev libxslt1-dev zlib1g-dev nginx postgresql postgresql-client
fi

if [ ! -d "$VENV_DIR" ]; then
  echo "Creating Python virtual environment..."
  "$PYTHON_BIN" -m venv "$VENV_DIR"
fi

PY="$VENV_DIR/bin/python"
PIP="$VENV_DIR/bin/pip"

echo "Installing Python dependencies..."
"$PY" -m pip install --upgrade pip wheel setuptools
"$PIP" install -r requirements.txt

if [ ! -f "$ENV_FILE" ]; then
  echo "Creating .env from .env.example..."
  cp .env.example "$ENV_FILE"
  SECRET="$($PY - <<'PY'
from django.core.management.utils import get_random_secret_key
print(get_random_secret_key())
PY
)"
  sed -i "s#DJANGO_SECRET_KEY=.*#DJANGO_SECRET_KEY=$SECRET#" "$ENV_FILE"
  DB_SECRET="$($PY -c 'import secrets; print(secrets.token_urlsafe(40))')"
  sed -i "s#DB_PASSWORD=.*#DB_PASSWORD=$DB_SECRET#" "$ENV_FILE"
  sed -i "s#OPTIVERSE_RUNTIME_DIR=.*#OPTIVERSE_RUNTIME_DIR=$APP_DIR#" "$ENV_FILE"
  chmod 600 "$ENV_FILE"
fi

# Traffic polling belongs to the dedicated worker. Preserve any custom thread
# selection while ensuring the inventory/traffic scheduler cannot be omitted.
if grep -q '^OLT_BACKGROUND_SYNC_THREADS=' "$ENV_FILE"; then
  SYNC_THREADS="$(sed -n 's/^OLT_BACKGROUND_SYNC_THREADS=//p' "$ENV_FILE" | tail -n 1)"
  case ",$SYNC_THREADS," in
    *,inventory,*) ;;
    *) sed -i '/^OLT_BACKGROUND_SYNC_THREADS=/ s/$/,inventory/' "$ENV_FILE" ;;
  esac
else
  printf '\nOLT_BACKGROUND_SYNC_THREADS=snmp_monitor,onu_status,signal_sample,inventory\n' >> "$ENV_FILE"
fi

set -a
# shellcheck disable=SC1090
source "$ENV_FILE"
set +a

# Keep polling/import work from starving latency-sensitive Gunicorn workers.
# systemd percentages are per CPU core, so 100% caps the entire background
# service (including status-sync child processes) to one core in aggregate.
WORKER_CPU_QUOTA="${OPTIVERSE_WORKER_CPU_QUOTA:-100%}"

mkdir -p "$APP_DIR/logs" "$APP_DIR/staticfiles" "$APP_DIR/media"

sudo "$PY" scripts/provision_postgres.py --env "$ENV_FILE"

echo "Running migrations..."
"$PY" manage.py migrate --noinput

echo "Collecting static files..."
"$PY" manage.py collectstatic --noinput

if [ -f "$APP_DIR/.env.control" ]; then
  echo "Provisioning and migrating the control-plane database..."
  sudo "$PY" scripts/provision_postgres.py --env "$APP_DIR/.env.control" --prefix CONTROL_
  "$PY" manage_control.py migrate --noinput
  "$PY" manage_control.py collectstatic --noinput
fi

if [ -n "${DJANGO_SUPERUSER_USERNAME:-}" ] && [ -n "${DJANGO_SUPERUSER_PASSWORD:-}" ]; then
  echo "Ensuring Django superuser exists..."
  "$PY" manage.py shell <<PY
from django.contrib.auth import get_user_model
User = get_user_model()
username = "${DJANGO_SUPERUSER_USERNAME}"
email = "${DJANGO_SUPERUSER_EMAIL:-admin@example.com}"
password = "${DJANGO_SUPERUSER_PASSWORD}"
user, created = User.objects.get_or_create(username=username, defaults={"email": email, "is_staff": True, "is_superuser": True})
if created:
    user.set_password(password)
    user.save(update_fields=["password"])
PY
fi

if command -v systemctl >/dev/null 2>&1; then
  echo "Installing Gunicorn web service $SERVICE_NAME..."
  sudo tee "/etc/systemd/system/$SERVICE_NAME.service" >/dev/null <<EOF
[Unit]
Description=OptiVerse OLT Portal
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$SERVICE_USER
Group=$SERVICE_GROUP
WorkingDirectory=$APP_DIR
EnvironmentFile=$ENV_FILE
Environment=OLT_DISABLE_EMBEDDED_SYNC=1
Environment=OLT_ENABLE_EMBEDDED_SYNC=false
Nice=-5
ExecStart=$VENV_DIR/bin/gunicorn oltportal.asgi:application --bind $HOST:$PORT --workers $WEB_WORKERS --worker-class uvicorn.workers.UvicornWorker --timeout $WEB_TIMEOUT --graceful-timeout 30 --keep-alive 5 --max-requests 2000 --max-requests-jitter 200 --access-logfile - --error-logfile -
Restart=always
RestartSec=5
TimeoutStopSec=30
KillSignal=SIGTERM
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

  echo "Installing isolated background synchronization service $SERVICE_NAME-worker..."
  sudo tee "/etc/systemd/system/$SERVICE_NAME-worker.service" >/dev/null <<EOF
[Unit]
Description=OptiVerse Background Synchronization Worker
After=network-online.target postgresql.service
Wants=network-online.target

[Service]
Type=simple
User=$SERVICE_USER
Group=$SERVICE_GROUP
WorkingDirectory=$APP_DIR
EnvironmentFile=$ENV_FILE
Environment=OLT_DISABLE_EMBEDDED_SYNC=0
Environment=OLT_ENABLE_EMBEDDED_SYNC=true
Nice=10
IOSchedulingClass=idle
CPUQuota=$WORKER_CPU_QUOTA
ExecStart=$VENV_DIR/bin/python manage.py run_background_sync
Restart=always
RestartSec=5
TimeoutStopSec=30
KillSignal=SIGTERM
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

  if [ -f "$APP_DIR/.env.control" ]; then
    echo "Installing Gunicorn control-plane service $CONTROL_SERVICE_NAME..."
    sudo tee "/etc/systemd/system/$CONTROL_SERVICE_NAME.service" >/dev/null <<EOF
[Unit]
Description=OptiVerse Master Control Plane
After=network-online.target postgresql.service
Wants=network-online.target

[Service]
Type=simple
User=$CONTROL_SERVICE_USER
Group=$CONTROL_SERVICE_GROUP
WorkingDirectory=$APP_DIR
EnvironmentFile=$APP_DIR/.env.control
Environment=OLT_DISABLE_EMBEDDED_SYNC=1
Environment=OLT_ENABLE_EMBEDDED_SYNC=false
Nice=-5
ExecStart=$VENV_DIR/bin/gunicorn controlplane.wsgi:application --bind $CONTROL_HOST:$CONTROL_PORT --workers $CONTROL_WORKERS --threads $CONTROL_THREADS --worker-class gthread --timeout 120 --graceful-timeout 30 --keep-alive 5 --max-requests 2000 --max-requests-jitter 200 --access-logfile - --error-logfile -
Restart=always
RestartSec=5
TimeoutStopSec=30
KillSignal=SIGTERM
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF
  fi

  sudo systemctl daemon-reload
  sudo systemctl disable --now "$SERVICE_NAME-sync" >/dev/null 2>&1 || true
  sudo systemctl enable --now "$SERVICE_NAME" "$SERVICE_NAME-worker"
  if [ -f "$APP_DIR/.env.control" ]; then
    sudo systemctl enable --now "$CONTROL_SERVICE_NAME"
  fi
  echo "Services installed and enabled for reboot."
  echo "Check: systemctl status $SERVICE_NAME $SERVICE_NAME-worker $CONTROL_SERVICE_NAME"
fi

echo "Install complete. App runs on http://$HOST:$PORT behind Nginx/proxy."
