#!/bin/sh
set -eu

role="${OPTIVERSE_ROLE:-web}"

wait_for_database() {
    python - <<'PY'
import os
import socket
import sys
import time

host = os.environ.get("DB_HOST", "db")
port = int(os.environ.get("DB_PORT", "5432"))
for _attempt in range(120):
    try:
        with socket.create_connection((host, port), timeout=1):
            sys.exit(0)
    except OSError:
        time.sleep(1)
print(f"Database {host}:{port} was not reachable after 120 seconds.", file=sys.stderr)
sys.exit(1)
PY
}

case "$role" in
    web)
        wait_for_database
        python manage.py migrate --noinput
        python manage.py ensure_optiverse_admin
        python manage.py sync_licence --startup
        ;;
    worker)
        wait_for_database
        attempts=0
        until python manage.py migrate --check >/dev/null 2>&1; do
            attempts=$((attempts + 1))
            if [ "$attempts" -ge 300 ]; then
                echo "Migrations were not ready after 300 seconds." >&2
                exit 1
            fi
            sleep 1
        done
        ;;
    wg)
        ;;
    *)
        echo "Unsupported OPTIVERSE_ROLE: $role" >&2
        exit 64
        ;;
esac

exec "$@"
