# PostgreSQL deployment

The app and control plane support PostgreSQL only, both locally and in production.
Missing database credentials are an error; no other database backend is used as a fallback.

## Portal `.env`

```dotenv
DB_ENGINE=postgresql
DB_HOST=127.0.0.1
DB_PORT=5432
DB_NAME=optiverse_tenant_cc_isp
DB_USER=optiverse_tenant_cc_isp
DB_PASSWORD=<generated-secret>
DB_SSLMODE=prefer
OPTIVERSE_RUNTIME_DIR=/opt/optiverse/Smart-Olt
```

The engine selects PostgreSQL, host/port locate it, and name/user/password identify the tenant's dedicated database and role.
The runtime directory contains progress snapshots and command locks; it is not the database.
For remote database connections use verified TLS (`DB_SSLMODE=verify-full`) with the required certificate configuration.

## Control-plane `.env.control`

```dotenv
CONTROL_DB_ENGINE=postgresql
CONTROL_DB_HOST=127.0.0.1
CONTROL_DB_PORT=5432
CONTROL_DB_NAME=optiverse_control
CONTROL_DB_USER=optiverse_control
CONTROL_DB_PASSWORD=<different-generated-secret>
CONTROL_TENANT_DB_ENGINE=postgresql
CONTROL_TENANT_DB_HOST=127.0.0.1
CONTROL_TENANT_DB_PORT=5432
```

The control database is separate from tenant databases. New tenants receive their own PostgreSQL database and login role.
Automatic local provisioning requires a trusted root control service and PostgreSQL peer administration (`runuser -u postgres`).
Keep PostgreSQL local-only unless a separately secured remote database deployment is required. Protect env files and backups with mode 600/700.

## Local Windows

Install PostgreSQL 14+ or use the official Windows binary distribution. Keep it bound to 127.0.0.1.
The local installation uses `D:\RIZWAN\CRM\postgres-local\data` and port 5432.
App and control credentials are in the untracked `.env` and `.env.control`, respectively.
`CONTROL_PG_ADMIN_PASSWORD` is used only by the trusted Windows control plane to create tenant databases; it is not the panel password. Linux uses peer administration instead.
To start the prepared local database after a restart:

```powershell
powershell -ExecutionPolicy Bypass -File scripts/start_local.ps1
```

The production migration has already been completed. Initial import tools are not part of the application.
The helper starts the local database if necessary, then runs the app normally. Use `-DatabaseOnly` to start just PostgreSQL.

## Future code updates

```bash
git pull --ff-only
.venv/bin/pip install -r requirements.txt
.venv/bin/python manage.py migrate --noinput
.venv/bin/python manage_control.py migrate --noinput
sudo systemctl restart optiverse optiverse-control
```

Run tenant migrations separately with each tenant's env settings. Do not re-import old data during normal updates.
Schedule regular `pg_dump -Fc` backups for every database, and test restores into a separate database.
