#!/bin/sh
set -eu

usage() {
    echo "Usage: $0 /opt/optiverse/tenants/<slug> images.nexecode.com/optiverse-tenant@sha256:<digest>" >&2
    exit 64
}

[ "$#" -eq 2 ] || usage
tenant_dir=$(realpath "$1")
image_ref=$2

case "$tenant_dir" in
    /opt/optiverse/tenants/*) ;;
    *) echo "Refusing tenant directory outside /opt/optiverse/tenants." >&2; exit 64 ;;
esac
if ! printf '%s' "$image_ref" | grep -Eq '^images\.nexecode\.com/optiverse-tenant@sha256:[0-9a-f]{64}$'; then
    echo "An immutable OptiVerse sha256 image reference is required." >&2
    exit 64
fi

compose_file="$tenant_dir/compose.yml"
tenant_env="$tenant_dir/tenant.env"
release_env="$tenant_dir/.release.env"
[ -f "$compose_file" ] && [ -f "$tenant_env" ] || {
    echo "Tenant compose.yml or tenant.env is missing." >&2
    exit 66
}

http_port=$(sed -n 's/^TENANT_HTTP_PORT=//p' "$tenant_env" | tail -n 1)
hostname=$(sed -n 's/^DJANGO_ALLOWED_HOSTS=\([^,]*\).*/\1/p' "$tenant_env" | tail -n 1)
case "$http_port" in *[!0-9]*|'') echo "Invalid TENANT_HTTP_PORT." >&2; exit 65 ;; esac
[ -n "$hostname" ] || { echo "DJANGO_ALLOWED_HOSTS has no hostname." >&2; exit 65; }

previous_ref=""
if [ -f "$release_env" ]; then
    previous_ref=$(sed -n 's/^IMAGE_REF=//p' "$release_env" | tail -n 1)
    cp "$release_env" "$release_env.previous"
fi

umask 077
printf 'IMAGE_REF=%s\n' "$image_ref" > "$release_env.new"
mv "$release_env.new" "$release_env"

compose() {
    docker compose --project-directory "$tenant_dir" --env-file "$tenant_env" --env-file "$release_env" -f "$compose_file" "$@"
}

rollback() {
    if [ -n "$previous_ref" ]; then
        echo "Deployment failed; restoring previous image digest." >&2
        printf 'IMAGE_REF=%s\n' "$previous_ref" > "$release_env.new"
        mv "$release_env.new" "$release_env"
        compose up -d --remove-orphans || true
    fi
}
trap rollback HUP INT TERM

compose pull web worker wg
if ! compose up -d --remove-orphans; then
    rollback
    exit 1
fi

healthy=0
attempt=0
while [ "$attempt" -lt 30 ]; do
    if curl --fail --silent --show-error \
        -H "Host: $hostname" -H "X-Forwarded-Proto: https" \
        "http://127.0.0.1:$http_port/healthz" >/dev/null; then
        healthy=1
        break
    fi
    attempt=$((attempt + 1))
    sleep 2
done

if [ "$healthy" -ne 1 ]; then
    rollback
    exit 1
fi

trap - HUP INT TERM
rm -f "$release_env.previous"
echo "Tenant is healthy on image $image_ref"
