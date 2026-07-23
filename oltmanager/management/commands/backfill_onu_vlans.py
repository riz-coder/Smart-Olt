from concurrent.futures import ThreadPoolExecutor, as_completed

from django.core.management.base import BaseCommand
from django.utils import timezone

from oltmanager.models import OLT
from oltmanager.utils import sync_onu_attached_vlans_for_olt


class Command(BaseCommand):
    help = "Run a one-time attached VLAN backfill for configured ONUs."

    def add_arguments(self, parser):
        parser.add_argument("--olt-id", type=int, help="Run backfill for a single OLT id.")
        parser.add_argument("--workers", type=int, default=2, help="Parallel OLT workers.")

    def handle(self, *args, **options):
        olt_id = options.get("olt_id")
        workers = max(1, int(options.get("workers") or 2))

        olts = OLT.objects.order_by("id")
        if olt_id:
            olts = olts.filter(pk=olt_id)
        olts = list(olts)
        if not olts:
            self.stdout.write(self.style.WARNING("No OLTs found for VLAN backfill."))
            return

        def _run_olt_backfill(olt):
            result = sync_onu_attached_vlans_for_olt(olt, fallback_missing=False)
            total_checked = int(result.get("checked") or 0)
            total_updated = int(result.get("updated") or 0)
            status_text = str(result.get("status") or "No VLAN batch run.")
            olt.attached_vlan_sync_status = (
                f"One-time VLAN backfill complete | Checked:{total_checked} "
                f"Updated:{total_updated} | {status_text}"
            )[:300]
            olt.attached_vlan_sync_updated_at = timezone.now()
            olt.save(
                update_fields=[
                    "attached_vlan_sync_status",
                    "attached_vlan_sync_updated_at",
                ]
            )
            return {
                "olt_id": olt.id,
                "olt_name": olt.name,
                "checked": total_checked,
                "updated": total_updated,
                "status": status_text,
            }

        self.stdout.write(
            f"Starting one-time VLAN backfill for {len(olts)} OLT(s) with {workers} worker(s)."
        )
        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="onu-vlan-backfill") as executor:
            futures = {executor.submit(_run_olt_backfill, olt): olt for olt in olts}
            for future in as_completed(futures):
                olt = futures[future]
                try:
                    result = future.result()
                    self.stdout.write(
                        self.style.SUCCESS(
                            f"OLT {result['olt_id']} {result['olt_name']}: checked={result['checked']} "
                            f"updated={result['updated']} | {result['status']}"
                        )
                    )
                except Exception as exc:
                    olt.attached_vlan_sync_status = f"One-time VLAN backfill failed: {exc}"[:300]
                    olt.attached_vlan_sync_updated_at = timezone.now()
                    olt.save(update_fields=["attached_vlan_sync_status", "attached_vlan_sync_updated_at"])
                    self.stdout.write(self.style.ERROR(f"OLT {olt.id} {olt.name}: {exc}"))
