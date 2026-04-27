import os
import sys
import time


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "oltportal.settings")
os.environ.setdefault("OLT_DISABLE_EMBEDDED_SYNC", "1")

import django  # noqa: E402

django.setup()

from django.db.models import Count  # noqa: E402
from django.utils import timezone  # noqa: E402

from oltmanager.models import OLT  # noqa: E402
from oltmanager.utils import sync_onu_attached_vlans_for_olt  # noqa: E402


def log(message):
    stamp = timezone.now().astimezone().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{stamp}] {message}", flush=True)


def run():
    olts = list(
        OLT.objects.annotate(total=Count("configured_onus"))
        .filter(total__gt=0)
        .order_by("total", "id")
    )
    log(f"Starting hard ONU VLAN fill for {len(olts)} OLT(s) using display service-port all.")

    for olt in olts:
        total = int(getattr(olt, "total", 0) or 0)
        log(f"Running {olt.name} ({total} ONUs)...")
        started_at = time.time()
        result = sync_onu_attached_vlans_for_olt(olt)
        total_checked = int(result.get("checked") or 0)
        total_updated = int(result.get("updated") or 0)
        status = str(result.get("status") or "").strip()
        elapsed = round(time.time() - started_at, 1)
        olt.attached_vlan_sync_status = (
            f"Hard fill complete | checked:{total_checked} "
            f"updated:{total_updated} | {status}"
        )[:300]
        olt.attached_vlan_sync_updated_at = timezone.now()
        olt.save(
            update_fields=[
                "attached_vlan_sync_status",
                "attached_vlan_sync_updated_at",
            ]
        )
        log(
            f"{olt.name}: {total_checked} checked, {total_updated} VLAN filled ({elapsed}s)"
        )

    log("Hard ONU VLAN fill complete for all OLTs.")


if __name__ == "__main__":
    run()
