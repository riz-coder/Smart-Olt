import datetime

from django.core.management.base import BaseCommand
from django.utils import timezone


class Command(BaseCommand):
    help = "Prune old high-volume sample history rows in bounded SQLite-friendly chunks."

    def add_arguments(self, parser):
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Show configured retention cutoffs without deleting rows.",
        )
        parser.add_argument(
            "--until-empty",
            action="store_true",
            help="Keep pruning bounded batches until no expired rows remain.",
        )

    def handle(self, *args, **options):
        from django.conf import settings
        from oltmanager.models import (
            DashboardStatusSample,
            ONUOpticalSample,
            ONUStatusSample,
            ONUTrafficSample,
            PONTrafficSample,
            PONPortTrafficSample,
            UplinkPortTrafficSample,
        )
        from oltmanager.utils import prune_sample_history

        if options["dry_run"]:
            retention_days = getattr(settings, "OLT_SAMPLE_RETENTION_DAYS", {}) or {}
            models = {
                "onu_optical": ONUOpticalSample,
                "onu_status": ONUStatusSample,
                "onu_traffic": ONUTrafficSample,
                "pon_traffic": PONTrafficSample,
                "pon_port_traffic": PONPortTrafficSample,
                "uplink_port_traffic": UplinkPortTrafficSample,
                "dashboard_status": DashboardStatusSample,
            }
            now = timezone.now()
            for key, model in models.items():
                days = int(retention_days.get(key) or 0)
                if days <= 0:
                    continue
                cutoff = now - datetime.timedelta(days=days)
                count = model.objects.filter(sampled_at__lt=cutoff).count()
                self.stdout.write(f"{key}: {count} rows older than {days} days")
            return

        totals = {}
        run_count = 0
        while True:
            run_count += 1
            deleted = prune_sample_history()
            for key, count in deleted.items():
                totals[key] = totals.get(key, 0) + int(count or 0)
            if not options["until_empty"] or not any(int(count or 0) for count in deleted.values()):
                break
            self.stdout.write(f"batch {run_count}: {deleted}")

        for key, count in totals.items():
            self.stdout.write(f"{key}: deleted {count}")
