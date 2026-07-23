#!/usr/bin/env bash
set -euo pipefail

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SERVICE_NAME="${OPTIVERSE_SERVICE_NAME:-optiverse}"
SERVICE_USER="${OPTIVERSE_SERVICE_USER:-$(id -un)}"
SERVICE_GROUP="${OPTIVERSE_SERVICE_GROUP:-$(id -gn)}"
HOST="${OPTIVERSE_BIND_HOST:-127.0.0.1}"
PORT="${OPTIVERSE_BIND_PORT:-8000}"
PYTHON_BIN="${PYTHON_BIN:-python3}"
VENV_DIR="$APP_DIR/.venv"
ENV_FILE="$APP_DIR/.env"

cd "$APP_DIR"

if command -v apt-get >/dev/null 2>&1; then
  echo "Installing system packages..."
  sudo apt-get update
  sudo apt-get install -y python3 python3-venv python3-dev build-essential libxml2-dev libxslt1-dev zlib1g-dev nginx
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
  sed -i "s#SQLITE_DB_PATH=.*#SQLITE_DB_PATH=$APP_DIR/db.sqlite3#" "$ENV_FILE"
fi

set -a
# shellcheck disable=SC1090
source "$ENV_FILE"
set +a

mkdir -p "$APP_DIR/logs" "$APP_DIR/staticfiles" "$APP_DIR/media"

echo "Running migrations..."
"$PY" manage.py migrate --noinput

echo "Collecting static files..."
"$PY" manage.py collectstatic --noinput

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
  echo "Installing systemd service $SERVICE_NAME..."
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
ExecStart=$VENV_DIR/bin/daphne -b $HOST -p $PORT oltportal.asgi:application
Restart=always
RestartSec=5
TimeoutStopSec=30
KillSignal=SIGINT
StandardOutput=append:$APP_DIR/logs/$SERVICE_NAME.out.log
StandardError=append:$APP_DIR/logs/$SERVICE_NAME.err.log

[Install]
WantedBy=multi-user.target
EOF
  sudo systemctl daemon-reload
  sudo systemctl disable "$SERVICE_NAME" >/dev/null 2>&1 || true
  sudo systemctl restart "$SERVICE_NAME"
  echo "Service status: systemctl status $SERVICE_NAME"
  echo "Autostart is disabled. To start manually later: sudo systemctl start $SERVICE_NAME"
fi

echo "Install complete. App runs on http://$HOST:$PORT behind Nginx/proxy."
