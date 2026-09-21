# Optiverse — work for the Optiverse developer

Repo: `github.com/riz-coder/Smart-Olt`. This file is self-contained: it says
what is changing, what the app must become, and the exact interfaces the
other side is already built to. Decisions behind it are in `DECISIONS.md`
(D1–D26) if the "why" is needed.

Status: 2026-09-20. Everything here is **to build** unless marked *as-is*.

---

## 1. What is changing, in one page

- Optiverse stays **hosted-only**. Nexecode runs every tenant; nothing is
  installed at the ISP.
- The **control plane (`controlmanager`, `optiverse.nexecode.com`) is being
  retired.** Tenant creation, licensing, billing and updates move to the
  Nexecode licence panel (`panel.nexecode.com`), which is already built for
  it. Nothing from the control plane moves anywhere — no host metrics, no
  browsing a tenant's OLTs from outside. Support is done by logging into the
  tenant's own panel with an account the tenant gives us.
- Each tenant runs as **one Docker compose stack** on a tenant host:
  `web` + `worker` + `db` (Postgres) + `wg` (WireGuard), one directory
  `/opt/optiverse/tenants/<slug>/`. All tenants run **the same image**. The
  panel's host script (`optiverse-tenant`) and the compose template are
  **written by the panel side** — your deliverable is **the image and what
  runs inside it**, plus the release script that pushes it.
- **Licensing changes shape.** No more per-OLT `pricing_*` written into the
  tenant DB from outside. Each OLT is a subscription on the panel; the tenant
  app asks the panel for a seat when an OLT is added, keeps it **locked**
  until the panel says `active`, and locks it again when the panel says so.
  A licence client inside the app does this over HTTPS.
- **VPN moves into the tenant's own panel.** The tenant enters its OLT
  subnets, downloads its client config, sees handshake status. No vendor
  step. WireGuard runs in the `wg` container of the tenant's stack; the app
  never needs `NET_ADMIN`.

**Do not** `git pull` these changes into the VPS checkout
(`/opt/optiverse/Smart-Olt`) — it is running the live tenant `connect` under
systemd until the migration window. Develop and build elsewhere.

---

## 2. Deliverables

| # | Deliverable | Section |
|---|---|---|
| 1 | Dockerfile — one image, roles by env, non-root, `/app/VERSION` | 3 |
| 2 | `docker/entrypoint.sh` — wait / migrate / admin / exec | 4 |
| 3 | Env interface — exact names, nothing else read | 5 |
| 4 | `GET /healthz` | 6 |
| 5 | `manage.py wg_helper` + tenant VPN page | 7 |
| 6 | Licence client + per-OLT entitlement | 8 |
| 7 | `release.sh` — build, push, manifest, sign, upload | 9 |
| 8 | Removals — control-plane-era code | 10 |

What you receive from us: registry push credential, vendor upload token,
release signing key (yours to generate — see §9), and a test licence token.

---

## 3. Image

- Base `python:3.13-slim` (the VPS venv is 3.13.5). Build deps
  `build-essential libxml2-dev libxslt1-dev zlib1g-dev`; runtime
  `wireguard-tools iproute2` (the `wg` role uses the same image).
- `pip install -r requirements.txt`; `COPY . /app`; `WORKDIR /app`.
- `python manage.py collectstatic --noinput` **at build**. Static is served
  by whitenoise (`CompressedStaticFilesStorage`, *as-is*); no volume, no
  nginx alias.
- Write the version into **`/app/VERSION`** at build (the tag). `checkin`
  reports it (§8).
- `RUN useradd -u 1000 -m optiverse` and **`USER optiverse`**. Everything
  the app writes goes to the mounted paths in §5; nothing under `/app`.
- `ENTRYPOINT ["/app/docker/entrypoint.sh"]`; the command comes from
  compose per role:
  - `web`: `gunicorn oltportal.asgi:application --bind 0.0.0.0:8000
    --workers 1 --worker-class uvicorn.workers.UvicornWorker --timeout 180
    --graceful-timeout 30 --keep-alive 5 --max-requests 2000
    --max-requests-jitter 200 --access-logfile - --error-logfile -`
    **`--workers 1` is mandatory**: `CHANNEL_LAYERS` is
    `InMemoryChannelLayer`, websockets only work within one process.
  - `worker`: `python manage.py run_background_sync`
  - `wg`: `python manage.py wg_helper` (§7)
- Logs to stdout/stderr only. No file logging.
- Tag: `images.nexecode.com/optiverse-tenant:<version>`. Semantic versions,
  e.g. `1.4.0`.

---

## 4. Entrypoint — `docker/entrypoint.sh`

Driven by `OPTIVERSE_ROLE` (`web` | `worker` | `wg`):

1. `web`, `worker`: wait until `DB_HOST:DB_PORT` accepts a TCP connection
   (loop, 1 s, give up at 120 s with exit 1).
2. `web` only:
   - `python manage.py migrate --noinput`
   - ensure the admin user: `get_or_create(username=OPTIVERSE_ADMIN_USERNAME)`
     with `is_staff`, `is_superuser`, `email=OPTIVERSE_ADMIN_EMAIL`;
     **set the password from `OPTIVERSE_ADMIN_PASSWORD` only when the user is
     created** — never reset it on a restart. The host script generates the
     password and passes it in; the image prints nothing.
3. `worker` only: loop on `python manage.py migrate --check` until exit 0
   (web has migrated), 1 s, up to 300 s.
4. `wg`: nothing to wait for.
5. `exec "$@"`.

---

## 5. Environment — the complete list

The stack passes these through compose `env_file`. There is no `.env` file
inside the image (`settings._load_local_env` finds nothing — fine).

**Required** (*as-is* names, already read by `settings.py` / `database.py`):

```
DJANGO_SECRET_KEY                  generated once per tenant by the host script
DJANGO_DEBUG=False
DJANGO_ALLOWED_HOSTS=<hostname>,127.0.0.1,localhost
DJANGO_CSRF_TRUSTED_ORIGINS=https://<hostname>
DJANGO_SECURE_SSL_REDIRECT=True
DJANGO_SESSION_COOKIE_SECURE=True
DJANGO_CSRF_COOKIE_SECURE=True
DJANGO_SESSION_COOKIE_NAME=optiverse_<slug_>_sessionid     (slug with - → _)
DJANGO_CSRF_COOKIE_NAME=optiverse_<slug_>_csrftoken
DJANGO_TIME_ZONE=Asia/Karachi
DJANGO_LANGUAGE_CODE=en-us
DB_ENGINE=postgresql
DB_NAME / DB_USER / DB_PASSWORD
DB_HOST=db
DB_PORT=5432
DB_SSLMODE=disable
OPTIVERSE_RUNTIME_DIR=/runtime
ONU_STATUS_SYNC_PROGRESS_FILE=/runtime/onu_status_sync_progress.json
OLT_BACKGROUND_SYNC_THREADS=snmp_monitor,onu_status,signal_sample,inventory
```

**Per role** (*as-is*): `web` gets `OLT_DISABLE_EMBEDDED_SYNC=1` and
`OLT_ENABLE_EMBEDDED_SYNC=false`; `worker` gets `OLT_DISABLE_EMBEDDED_SYNC=0`
and `OLT_ENABLE_EMBEDDED_SYNC=true`.

**Tuning** (*as-is*, today's defaults; the template carries them, the app
keeps its own defaults if absent): `NEW_ONU_CHECK_SECONDS=180`,
`NEW_ONU_RECONCILE_SECONDS=900`, `SNMP_MONITOR_MAX_WORKERS=1`,
`ONU_STATUS_SYNC_MAX_WORKERS=1`, `ONU_SIGNAL_SAMPLE_MAX_WORKERS=1`,
`ONU_STATUS_SYNC_OLT_TIMEOUT_SECONDS=180`, `ONU_STATUS_SYNC_OLT_BATCH_SIZE=1000`,
`ONU_STATUS_SYNC_PON_TIMEOUT_SECONDS=12`, `ONU_STATUS_SYNC_SNMP_CHUNK_SIZE=40`,
`ONU_SIGNAL_SAMPLE_SECONDS=3600`, `OLT_ONU_OPTICAL_SAMPLE_INTERVAL_SECONDS=3600`,
`OLT_ONU_OPTICAL_RETENTION_DAYS=15`, `OLT_ONU_STATUS_RETENTION_DAYS=30`,
`OLT_ONU_TRAFFIC_RETENTION_DAYS=30`, `OLT_PON_TRAFFIC_RETENTION_DAYS=30`,
`OLT_PON_PORT_TRAFFIC_RETENTION_DAYS=30`, `OLT_UPLINK_PORT_TRAFFIC_RETENTION_DAYS=30`,
`OLT_DASHBOARD_STATUS_RETENTION_DAYS=180`, `OLT_SAMPLE_RETENTION_CLEANUP_SECONDS=3600`.
Optional mail: `OLT_EMAIL_HOST/PORT/USER/PASSWORD/USE_TLS/USE_SSL/TIMEOUT`.

**New** (you add the readers):

```
OPTIVERSE_ROLE=web|worker|wg
OPTIVERSE_ADMIN_USERNAME=admin
OPTIVERSE_ADMIN_EMAIL
OPTIVERSE_ADMIN_PASSWORD                      used only on first create (§4)
OPTIVERSE_LICENCE_URL=https://licence.nexecode.com/api/optiverse/v1
OPTIVERSE_LICENCE_TOKEN                       the licence API token (§8)
OPTIVERSE_VPN_PUBLIC_HOST=vpn-<slug>.nexecode.com
OPTIVERSE_VPN_PORT                            public UDP port on the host
OPTIVERSE_WG_LISTEN_PORT=51820                inside the wg container
OPTIVERSE_WG_STATE_DIR=/etc/optiverse/wg
OPTIVERSE_WG_SOCKET=/run/optiverse/wg.sock
```

**Removed — must not be read any more** (control-plane era):
`OPTIVERSE_PUBLIC_API_URL`, `OPTIVERSE_TENANT_BASE_DIR`,
`OPTIVERSE_WG_SERVER_CONFIG`, `OPTIVERSE_AGENT_TOKEN`,
`OPTIVERSE_OLT_MANAGEMENT_SUBNET`, `OPTIVERSE_TENANT_AUTO_PROVISION`,
`CONTROL_*`.

**Mounted paths** (owned by UID 1000 unless stated):

| Container path | Host | Purpose |
|---|---|---|
| `/runtime` | `<tenant>/runtime/` | progress JSON, telnet locks, authorize-progress |
| `/app/media` | `<tenant>/media/` | `MEDIA_ROOT` (empty today; mounted for the future) |
| `/etc/optiverse/wg` | `<tenant>/wg/` | wg server key, peer, routes, state (§7) |
| `/run/optiverse` | tmpfs, shared by web/worker/wg | the helper socket |
| `/var/lib/postgresql/data` (db) | `<tenant>/pg/` | Postgres 17, UID 999 |

---

## 6. `GET /healthz`

Unauthenticated, no session, exempt from the SSL redirect, cheap:
`SELECT 1` on the default DB. `200 {"status":"ok","db":true}`; anything
else `503 {"status":"fail","db":false}`. The host script polls it after
`compose up` and during updates. (Until it exists the script polls
`GET /login/` with `Host` and `X-Forwarded-Proto: https` — build this so
that stops.)

---

## 7. WireGuard: `wg_helper` and the tenant VPN page

**Topology.** `web` and `worker` run with `network_mode: service:wg` — they
share the `wg` container's network namespace, so the routes the helper adds
apply to SNMP/telnet/SSH from both. `wg` has `cap_add: [NET_ADMIN]`; the
app containers have no capabilities. Kernel WireGuard comes from the host
(`modprobe wireguard`); **no `/dev/net/tun`, no `ip_forward`** — nothing is
forwarded, the app itself talks to the OLTs from inside this namespace. The
default route stays via the docker bridge (the licence API must remain
reachable); the helper adds routes **only** for the tenant's OLT subnets via
`wg0`, `src` the tunnel address.

**`manage.py wg_helper`** (role `wg`):
- On start: load `$OPTIVERSE_WG_STATE_DIR/state.json` (server private key —
  generate on first run, `0600` — tunnel address, peer public key, peer
  tunnel address, routes). Create `wg0`, `wg setconf`, address, `mtu 1420`,
  up, routes. Listen on `$OPTIVERSE_WG_LISTEN_PORT` (51820).
- Serve a **unix socket** at `$OPTIVERSE_WG_SOCKET`, JSON per line,
  request `{"op": …, …}` → response `{"ok": true, …}` or
  `{"ok": false, "error": "…"}`:
  - `server_key` → `{public_key, tunnel_address}`
  - `set_peer {public_key, tunnel_client_address}` — replaces the single peer
  - `set_routes {routes: ["192.168.1.0/24", …]}` — replaces all routes;
    refuse anything overlapping the tunnel pool `10.75.75.0/24` or the docker
    bridge; refuse default routes
  - `status` → `{last_handshake_s, rx_bytes, tx_bytes, routes, peer_public_key}`
  - persist every change to `state.json`, re-apply on start.
- Tunnel addresses: server `.1`, client `.2` of a `/30` inside
  `10.75.75.0/24` (*as-is* pool). Pick the first `/30`; a tenant has one
  tunnel.

**Tenant VPN page** (replaces the control-plane-era one):
- Tenant enters **OLT subnets only** (no public IP — the client is a
  roaming peer). Page generates the client keypair once, calls
  `set_peer` + `set_routes`, and offers **Download client config**:

      [Interface]
      PrivateKey = <client private key>
      Address = <client tunnel /30>
      [Peer]
      PublicKey = <server public key from server_key>
      Endpoint = $OPTIVERSE_VPN_PUBLIC_HOST:$OPTIVERSE_VPN_PORT
      AllowedIPs = <server tunnel /32>
      PersistentKeepalive = 25

- Shows handshake status from `status`. Subnets editable any time.
- Remove: `TenantProvisioning` model, the page that prints a `docker run
  optiverse-agent …` command, `agent/`, `_tenant_docker_command`, and every
  `OPTIVERSE_AGENT_TOKEN` reader (`oltmanager/views.py` ~8520–8680).

---

## 8. Licence client and per-OLT entitlement

**Endpoint base** `$OPTIVERSE_LICENCE_URL`. Auth on every call:
`Authorization: Bearer $OPTIVERSE_LICENCE_TOKEN`. JSON in, JSON out; 422
on a bad body. Requests time out at 10 s.

### 8.1 `POST /validate` — on start, then every hour, and on demand

Body `{}`. Response:

```
{
  "data": {
    "licence": "OPT-0001",
    "status": "active" | "suspended" | "expired",
    "customer": "<company>",
    "tenant": {"slug": "connect", "hostname": "connect.nexecode.com"},
    "olts": [
      {"ref": "<uuid>", "status": "active",  "expires_at": "2026-10-19T00:00:00Z"},
      {"ref": "<uuid>", "status": "pending"},
      {"ref": "<uuid>", "status": "locked",  "expires_at": "…", "reason": "unpaid"}
    ],
    "issued_at": "2026-09-20T09:00:00Z",
    "signature_kid": "…", "signature_alg": "RS256", "signature": "<base64>"
  }
}
```

Headers `X-License-Signature-Kid`, `X-License-Signature-Alg` repeat the two
fields. **Verify**: take `data`, remove `signature_kid`, `signature_alg`,
`signature`, serialise as canonical JSON (sorted keys, no whitespace,
`ensure_ascii=False`), RSA-SHA256 verify against the public key from
`GET https://licence.nexecode.com/api/v1/licenses/public-key` (cache it;
`kid` selects it). A response that does not verify is treated as a network
failure, not as a new state.

**Rules the app enforces:**
- Cache the last **verified** response on disk (`/runtime/licence.json`)
  with the time it was received.
- Licence `suspended` or `expired` → **every OLT locked immediately**.
- Per OLT: the app's OLT row carries `licence_ref` (UUID, generated by the
  app when the OLT is created, **never regenerated**). An OLT is usable
  only when the list has its `ref` with `status: "active"`. `pending`,
  `locked`, or **absent from the list** = locked. Show `expires_at` on the
  OLT.
- **Grace for network failure only:** if validate cannot be reached (or
  does not verify) the last verified state stands for **72 h** from when it
  was received; after that, every OLT locks until a validate succeeds. An
  explicit answer never has grace.
- `expires_at` is a timestamp; the panel locks at
  `expires_at + 3 days` and will say so in the next validate — the app does
  not compute grace itself, it obeys the list.
- The `pricing_mode / pricing_expires_at / pricing_locked /
  pricing_locked_reason` columns: keep the lock UI they drive, but they are
  now **written only by the licence client** from the list (or drop them and
  drive the lock from `licence.json`; your call — nothing outside the app
  writes them any more).

### 8.2 `POST /olts` — when the tenant adds an OLT

Body `{"ref": "<uuid>", "name": "…", "ip_address": "…"}`.
`201 {"ref", "status": "pending", "amount": 5000.00, "currency": "PKR",
"invoice_url": "https://panel.nexecode.com/portal/invoices/<id>"}`; the
same `ref` again → `200` with the current state and no new invoice.
The OLT is created locked with a **"Pay to activate"** link to
`invoice_url`; after payment the next validate (hourly, or a **Re-check**
button that calls validate now) shows it `active` and it unlocks. Renewals:
the panel invoices the tenant 7 days before expiry; show the expiry and a
**Renew** link (the portal) on each OLT.

`DELETE /olts/{ref}` → `200 {"ref", "ends_at": "…"}`: the subscription ends
at its current expiry, no refund. Offer this as **End subscription** on the
OLT; deleting an OLT in the app calls it.

### 8.3 `POST /checkin` — every hour, after validate

Body `{"version": "<contents of /app/VERSION>", "olt_count": n,
"onu_count": n, "wg_last_handshake_s": n | null}` → `200 {}`. Telemetry
only; it never changes entitlement.

### 8.4 Where it runs

In `worker` (the hourly loop) **and** in `web` (on start, and the Re-check
button). Both read/write the same `/runtime/licence.json`; a simple file
lock is enough.

---

## 9. `release.sh <version>` on the dev server

1. `git tag v<version>` and push.
2. `docker build -t images.nexecode.com/optiverse-tenant:<version>
   --build-arg VERSION=<version> .` (the build arg writes `/app/VERSION`).
3. `docker push images.nexecode.com/optiverse-tenant:<version>` (push
   credential — dev server only).
4. `DIGEST=$(docker inspect --format '{{index .RepoDigests 0}}' …)` →
   the `sha256:<64 hex>` part.
5. Write the manifest **once, as bytes, and never re-serialise it**:

       {"product":"optiverse","version":"<version>","image":"images.nexecode.com/optiverse-tenant:<version>","digest":"sha256:<hex>","published_at":"<ISO-8601 UTC Z>"}

6. Sign the exact bytes with the **Optiverse release key** (Ed25519,
   generate once on the dev server, keep it there only; publish the public
   half to us). `signature` = base64.
7. `POST https://licence.nexecode.com/api/optiverse/v1/releases` with
   `Authorization: Bearer <vendor upload token>` and form fields `manifest`
   (the exact bytes) and `signature`. `201` = it is on the panel's Releases
   page and the panel can push it to tenants; `409` = version exists — bump.

---

## 10. Removals

When §3–§9 are in and the panel has taken over:
- `controlplane/`, `controlmanager/`, `manage_control.py`, `.env.control*`,
  `control_staticfiles/`, the `seed_current_tenant` and
  `configure_public_gateway` commands, `scripts/provision_postgres.py`,
  `scripts/*.service.example`, `scripts/nginx_optiverse.conf.example`,
  `scripts/install_ubuntu.sh`, and the deployment-guide docs that describe
  the systemd/control-plane layout.
- Everything in §7 "Remove".
- Any code that writes `pricing_*` from outside the licence client.

Do this in a **separate, later** commit — the VPS checkout still runs the
control plane until the migration window.

---

## 11. Acceptance — how we will check the image

Run on any machine with docker, no panel needed except §8:

1. `docker run --rm image cat /app/VERSION` prints the tag; `id -u` inside
   is 1000.
2. A compose stack from the panel's template comes up; `web` migrates,
   creates `admin` with the given password, `/healthz` → 200; a restart
   does **not** change the password.
3. `worker` starts only after migrations; `docker logs` shows the four sync
   threads.
4. `wg`: `server_key` returns a public key; `set_peer` + `set_routes` make
   `wg show wg0` inside the container show the peer and `ip route` show the
   subnets via `wg0`; restart the container and both are back; a route of
   `0.0.0.0/0` or `10.75.75.0/24` is refused.
5. From `web`'s shell, `curl https://licence.nexecode.com` works (default
   route intact) and a route to an OLT subnet points at `wg0`.
6. Licence: with a test token — validate verifies; an OLT added → locked
   with a pay link; after we mark the invoice paid, Re-check unlocks it; with
   the network cut, the OLT stays usable for 72 h and locks after; a
   `suspended` answer locks everything at once.
7. `release.sh` → `201` from the panel; the digest the panel shows equals
   `docker inspect`'s.
