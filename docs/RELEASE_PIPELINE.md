# OptiVerse image release pipeline

Tenant hosts do not run `git pull`. A production tag builds one immutable
image for the `web`, `worker`, and `wg` roles, pushes it to the private
registry, and registers its signed digest with the Nexecode licence panel.

## One-time setup

1. Provide `images.nexecode.com` and create separate credentials:
   - CI: push access.
   - tenant hosts: pull-only access.
2. Generate the release key on a trusted build machine:

   ```sh
   openssl genpkey -algorithm Ed25519 -out optiverse-release-key.pem
   openssl pkey -in optiverse-release-key.pem -pubout -out optiverse-release-key.pub
   ```

   Keep the private key out of Git. Give only the public key to the Laravel
   release verifier.
3. Add these GitHub environment secrets to the `production` environment:
   - `OPTIVERSE_REGISTRY_USERNAME`
   - `OPTIVERSE_REGISTRY_PASSWORD`
   - `OPTIVERSE_RELEASE_PRIVATE_KEY_B64`
   - `OPTIVERSE_VENDOR_UPLOAD_TOKEN`
4. Install Docker Engine plus the Compose plugin on each tenant host and log
   it into the registry using its pull-only credential.

## Publishing

A push to `main` runs tests and proves that the image builds. It does not
publish a production release. Create and push a semantic version tag:

```sh
git tag v1.0.0
git push origin v1.0.0
```

The workflow builds `images.nexecode.com/optiverse-tenant:1.0.0`, pushes it,
signs the exact release manifest bytes, and posts the manifest and signature
to `/api/optiverse/v1/releases`.

For a trusted development server, the same operation is available as:

```sh
export OPTIVERSE_RELEASE_SIGNING_KEY=/secure/optiverse-release-key.pem
export OPTIVERSE_VENDOR_UPLOAD_TOKEN=...
sh ./release.sh 1.0.0
```

## Tenant deployment contract

The Laravel panel creates `/opt/optiverse/tenants/<slug>/` with:

- `compose.yml`, based on `deploy/tenant-compose.yml`;
- `tenant.env`, based on `deploy/tenant.env.example`;
- `.release.env`, containing the approved immutable `IMAGE_REF`;
- `runtime/`, `media/`, `wg/`, and `pg/` persistent directories.

New tenants use the latest approved release digest. Existing tenants update
only after an explicit panel action. The panel invokes:

```sh
sh scripts/deploy_tenant_release.sh \
  /opt/optiverse/tenants/connect \
  images.nexecode.com/optiverse-tenant@sha256:<64-hex-digest>
```

The host script accepts only tenant directories under
`/opt/optiverse/tenants`, accepts only immutable OptiVerse image digests,
pulls the image, recreates the stack, and polls `/healthz`. If health checking
fails, it restores the previous image digest. Database migrations must remain
backwards compatible because a code rollback cannot reverse an irreversible
database migration.

Nginx, certificates, DNS, and firewall changes are deliberately outside this
release script. Tenant provisioning must perform those separately with its
own validation and rollback rules.
