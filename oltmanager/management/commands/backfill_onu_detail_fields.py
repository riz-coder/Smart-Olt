from concurrent.futures import ThreadPoolExecutor, as_completed

from django.core.management.base import BaseCommand
from django.utils import timezone

from oltmanager.models import OLT
from oltmanager.utils import sync_onu_detail_fields_for_olt


class Command(BaseCommand):
    help = "Run a one-time detail-field backfill for configured ONUs."

    def add_arguments(self, parser):
        parser.add_argument("--olt-id", type=int, help="Run backfill for a single OLT id.")
        parser.add_argument("--workers", type=int, default=1, help="Parallel OLT workers.")

    def handle(self, *args, **options):
        olt_id = options.get("olt_id")
        workers = max(1, int(options.get("workers") or 1))

        olts = OLT.objects.order_by("id")
        if olt_id:
            olts = olts.filter(pk=olt_id)
        olts = list(olts)
        if not olts:
            self.stdout.write(self.style.WARNING("No OLTs found for ONU detail backfill."))
            return

        def _run_olt_backfill(olt):
            result = sync_onu_detail_fields_for_olt(olt)
            olt.attached_vlan_sync_updated_at = timezone.now()
            olt.save(update_fields=["attached_vlan_sync_updated_at"])
            return {
                "olt_id": olt.id,
                "olt_name": olt.name,
                "checked": int(result.get("checked") or 0),
                "updated": int(result.get("updated") or 0),
                "status": str(result.get("status") or ""),
            }

        self.stdout.write(
            f"Starting one-time ONU detail backfill for {len(olts)} OLT(s) with {workers} worker(s)."
        )
        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="onu-detail-backfill") as executor:
            futures = {executor.submit(_run_olt_backfill, olt): olt for olt in olts}
            for future in as_completed(futures):
                olt = futures[future]
                try:
                    result = future.result()
                    self.stdout.write(
                        self.style.SUCCESS(
                            f"{result['olt_name']}: {result['checked']} checked, {result['updated']} updated | {result['status']}"
                        )
                    )
                except Exception as exc:
                    self.stdout.write(self.style.ERROR(f"{olt.name}: {exc}"))
