#!/bin/sh
set -eu

usage() {
    echo "Usage: $0 <semantic-version>" >&2
    exit 64
}

[ "$#" -eq 1 ] || usage
version=$1
case "$version" in
    [0-9]*.[0-9]*.[0-9]*) ;;
    *) echo "Version must use semantic form such as 1.4.0." >&2; exit 64 ;;
esac
if ! printf '%s' "$version" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]+)?$'; then
    echo "Invalid semantic version: $version" >&2
    exit 64
fi

registry=${OPTIVERSE_IMAGE_REGISTRY:-images.nexecode.com}
image="$registry/optiverse-tenant:$version"
release_url=${OPTIVERSE_RELEASE_URL:-https://licence.nexecode.com/api/optiverse/v1/releases}
signing_key=${OPTIVERSE_RELEASE_SIGNING_KEY:-}
vendor_token=${OPTIVERSE_VENDOR_UPLOAD_TOKEN:-}

[ -n "$signing_key" ] && [ -f "$signing_key" ] || {
    echo "OPTIVERSE_RELEASE_SIGNING_KEY must point to the Ed25519 private key." >&2
    exit 78
}
[ -n "$vendor_token" ] || {
    echo "OPTIVERSE_VENDOR_UPLOAD_TOKEN is required." >&2
    exit 78
}

if [ "${RELEASE_SKIP_GIT:-0}" != "1" ]; then
    if git rev-parse "v$version" >/dev/null 2>&1; then
        [ "$(git rev-parse "v$version^{commit}")" = "$(git rev-parse HEAD)" ] || {
            echo "Tag v$version already points to another commit." >&2
            exit 65
        }
    else
        git tag "v$version"
        git push origin "v$version"
    fi
fi

docker build --pull --build-arg "VERSION=$version" -t "$image" .
docker push "$image"
repo_digest=$(docker inspect --format '{{range .RepoDigests}}{{println .}}{{end}}' "$image" | grep "^$registry/optiverse-tenant@sha256:" | head -n 1)
digest=${repo_digest##*@}
printf '%s' "$digest" | grep -Eq '^sha256:[0-9a-f]{64}$' || {
    echo "Could not determine the pushed image digest." >&2
    exit 70
}

work_dir=$(mktemp -d)
trap 'rm -rf "$work_dir"' EXIT HUP INT TERM
manifest="$work_dir/manifest.json"
signature_file="$work_dir/signature.bin"
published_at=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
printf '{"product":"optiverse","version":"%s","image":"%s","digest":"%s","published_at":"%s"}' \
    "$version" "$image" "$digest" "$published_at" > "$manifest"
openssl pkeyutl -sign -rawin -inkey "$signing_key" -in "$manifest" -out "$signature_file"
signature=$(openssl base64 -A -in "$signature_file")

status=$(curl --silent --show-error --output "$work_dir/response.json" --write-out '%{http_code}' \
    -H "Authorization: Bearer $vendor_token" \
    -F "manifest=<$manifest;type=application/json" \
    -F "signature=$signature" \
    "$release_url")
if [ "$status" != "201" ]; then
    echo "Release API returned HTTP $status:" >&2
    cat "$work_dir/response.json" >&2
    exit 1
fi

echo "Published OptiVerse $version as $repo_digest"
