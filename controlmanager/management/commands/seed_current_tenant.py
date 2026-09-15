from django.core.management.base import BaseCommand
from django.conf import settings

from controlmanager.models import Tenant
from controlmanager.services import TenantSnapshotError, refresh_tenant_database_snapshot


class Command(BaseCommand):
    help = "Seed the currently deployed app as a tenant in the master control plane."

    def add_arguments(self, parser):
        parser.add_argument("--name", default="CC_ISP")
        parser.add_argument("--host", default="10.101.11.22")
        parser.add_argument("--port", type=int, default=8000)
        parser.add_argument("--db", default="")
        parser.add_argument("--codebase", default="/opt/optiverse/Smart-Olt")
        parser.add_argument("--env", default="/opt/optiverse/Smart-Olt/.env")
        parser.add_argument("--service", default="optiverse")
        parser.add_argument("--admin", default="rizwan")
        parser.add_argument("--password", default="")
        parser.add_argument("--email", default="")
        parser.add_argument("--refresh", action="store_true")

    def handle(self, *args, **options):
        from oltportal.database import database_config
        config = database_config()
        tenant, created = Tenant.objects.update_or_create(
            name=options["name"],
            defaults={
                "isp_name": options["name"],
                "owner_name": options["name"],
                "owner_email": options["email"],
                "status": Tenant.STATUS_ACTIVE,
                "panel_scheme": "http",
                "panel_host": options["host"],
                "panel_port": options["port"],
                "codebase_path": options["codebase"],
                "database_path": "",
                "database_engine": "postgresql",
                "database_name": options["db"] or config['NAME'],
                "database_user": config['USER'],
                "database_password": config['PASSWORD'],
                "database_host": config['HOST'],
                "database_port": int(config['PORT']),
                "env_path": options["env"],
                "service_name": options["service"],
                "panel_admin_username": options["admin"],
                "panel_admin_initial_password": options["password"],
            },
        )
        self.stdout.write(self.style.SUCCESS(f"Tenant {'created' if created else 'updated'}: {tenant.name}"))
        if options["refresh"]:
            try:
                result = refresh_tenant_database_snapshot(tenant)
            except TenantSnapshotError as exc:
                raise SystemExit(str(exc))
            self.stdout.write(self.style.SUCCESS(f"Snapshot: {result['olt_count']} OLTs, {result['onu_count']} ONUs"))
