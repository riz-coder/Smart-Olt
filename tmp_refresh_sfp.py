import os
import django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'oltportal.settings')
django.setup()

from oltmanager.models import OLT
from oltmanager.utils import fetch_pon_ports_snapshot, save_pon_ports_snapshot

for olt in OLT.objects.all().order_by('name'):
    try:
        groups, status = fetch_pon_ports_snapshot(olt)
        if groups:
            save_pon_ports_snapshot(olt, groups, status)
        filled = 0
        total = 0
        for group in groups or []:
            for row in (group.get('ports') or []):
                total += 1
                if str(row.get('sfp_tx') or '').strip():
                    filled += 1
        print(f"{olt.name}\t{filled}/{total}\t{status}")
    except Exception as exc:
        print(f"{olt.name}\tERROR\t{exc}")
