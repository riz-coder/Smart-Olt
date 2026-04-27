from django.core.management.base import BaseCommand

from oltmanager.models import OLT
from oltmanager.utils import sync_onu_detail_fields_for_olt


class Command(BaseCommand):
    help = "Run a one-time ONU detail backfill for cached capability and distance fields."

    def add_arguments(self, parser):
        parser.add_argument("--olt-id", type=int, help="Run hard fill for a single OLT id.")

    def handle(self, *args, **options):
        olt_id = options.get("olt_id")
        olts = OLT.objects.order_by("id")
        if olt_id:
            olts = olts.filter(pk=olt_id)
        olts = list(olts)
        if not olts:
            self.stdout.write(self.style.WARNING("No OLTs found for ONU detail hard fill."))
            return

        self.stdout.write(
            f"Starting hard ONU detail fill for {len(olts)} OLT(s)."
        )
        for olt in olts:
            self.stdout.write(f"Running {olt.name}...")
            try:
                result = sync_onu_detail_fields_for_olt(olt)
                checked = int(result.get("checked") or 0)
                updated = int(result.get("updated") or 0)
                self.stdout.write(
                    self.style.SUCCESS(f"{olt.name}: {checked} checked, {updated} detail filled")
                )
            except Exception as exc:
                self.stdout.write(self.style.ERROR(f"{olt.name}: failed | {exc}"))
