"""
Management command: test_epon_snmp

Live SNMP probe for EPON ONU optical power OIDs on a real Huawei OLT.
Shows raw OID walk results so you can verify which OIDs return data and
what the index structure looks like.

Usage:
    python manage.py test_epon_snmp --olt-id 1
    python manage.py test_epon_snmp --olt-id 1 --slot 2 --port 0 --onu-id 3
    python manage.py test_epon_snmp --olt-id 1 --walk-all
"""

import asyncio
import re

from django.core.management.base import BaseCommand, CommandError

from oltmanager.models import OLT


EPON_DDM_OIDS = {
    # hwEponDeviceOntOpticsDdmInfoTable (authoritative, 4-part index: frame.slot.port.onu_id)
    "epon_olt_rx  (.104.1.1)": "1.3.6.1.4.1.2011.6.128.1.1.2.104.1.1",
    "epon_onu_tx  (.104.1.4)": "1.3.6.1.4.1.2011.6.128.1.1.2.104.1.4",
    "epon_onu_rx  (.104.1.5)": "1.3.6.1.4.1.2011.6.128.1.1.2.104.1.5",
    # Old/wrong OIDs (keeping for comparison — should return nothing on EPON)
    "old_epon_rx  (.34.1.4)":  "1.3.6.1.4.1.2011.6.128.1.1.2.34.1.4",
    "old_epon_tx  (.34.1.3)":  "1.3.6.1.4.1.2011.6.128.1.1.2.34.1.3",
    # GPON OIDs (for comparison — should return nothing on EPON slots)
    "gpon_onu_rx  (.51.1.4)":  "1.3.6.1.4.1.2011.6.128.1.1.2.51.1.4",
    "gpon_olt_rx  (.51.1.6)":  "1.3.6.1.4.1.2011.6.128.1.1.2.51.1.6",
    # Entity fallback (model-independent)
    "entity_rx   (5.25.31..8)": "1.3.6.1.4.1.2011.5.25.31.1.1.3.1.8",
    "ifName                  ": "1.3.6.1.2.1.31.1.1.1.1",
}


def _fmt_dbm(raw):
    try:
        v = int(str(raw).strip())
    except (TypeError, ValueError):
        return f"(non-int: {raw})"
    if v in (2147483647, -2147483648, 0):
        return f"(sentinel/zero: {v})"
    return f"{v / 100:.2f} dBm  [raw={v}]"


class Command(BaseCommand):
    help = "Live SNMP test for EPON ONU optical power OIDs on a Huawei OLT."

    def add_arguments(self, parser):
        parser.add_argument("--olt-id", type=int, required=True, help="OLT database ID")
        parser.add_argument("--slot", type=int, default=None, help="EPON slot to focus on")
        parser.add_argument("--port", type=int, default=None, help="EPON port number")
        parser.add_argument("--onu-id", type=int, default=None, help="ONU ID within the port")
        parser.add_argument("--walk-all", action="store_true", help="Walk full OID tree (shows all entries)")
        parser.add_argument("--limit", type=int, default=256, help="Max SNMP rows per walk (default 256)")
        parser.add_argument("--mp-model", type=int, default=1, choices=[0, 1], help="SNMP mp_model: 1=v2c 0=v1")

    def handle(self, *args, **options):
        olt_id = options["olt_id"]
        try:
            olt = OLT.objects.get(pk=olt_id)
        except OLT.DoesNotExist:
            raise CommandError(f"OLT with id={olt_id} not found.")

        self.stdout.write(self.style.SUCCESS(f"\n{'='*60}"))
        self.stdout.write(self.style.SUCCESS(f"  OLT: {olt.name}  IP: {olt.ip_address}:{olt.snmp_port}"))
        self.stdout.write(self.style.SUCCESS(f"  Community: {olt.snmp_community}   mp_model={options['mp_model']}"))
        self.stdout.write(self.style.SUCCESS(f"{'='*60}\n"))

        try:
            from pysnmp.hlapi.asyncio import (
                CommunityData, ContextData, ObjectIdentity, ObjectType,
                SnmpEngine, UdpTransportTarget, next_cmd,
            )
        except ImportError:
            raise CommandError("pysnmp not installed. Run: pip install pysnmp")

        limit = options["limit"]
        mp_model = options["mp_model"]

        async def _walk(base_oid):
            rows = {}
            target = await UdpTransportTarget.create(
                (olt.ip_address, olt.snmp_port), timeout=2.0, retries=1
            )
            engine = SnmpEngine()
            current = base_oid
            for _ in range(limit * 2):
                err, stat, _, vbs = await next_cmd(
                    engine,
                    CommunityData(olt.snmp_community, mpModel=mp_model),
                    target,
                    ContextData(),
                    ObjectType(ObjectIdentity(current)),
                )
                if err or stat:
                    engine.close_dispatcher()
                    return rows, str(err or stat)
                if not vbs:
                    break
                stop = False
                for oid, val in vbs:
                    oid_s = str(oid)
                    if not oid_s.startswith(base_oid + "."):
                        stop = True
                        break
                    rows[oid_s] = str(val)
                    current = oid_s
                    if len(rows) >= limit:
                        stop = True
                        break
                if stop:
                    break
            engine.close_dispatcher()
            return rows, ""

        slot_filter = options.get("slot")
        port_filter = options.get("port")
        onu_filter = options.get("onu_id")

        oids_to_check = EPON_DDM_OIDS if options["walk_all"] else {
            k: v for k, v in EPON_DDM_OIDS.items()
            if "104" in k or "34" in k or "51" in k or "ifName" in k
        }

        for label, base_oid in oids_to_check.items():
            self.stdout.write(self.style.WARNING(f"\n── {label.strip()} ──"))
            self.stdout.write(f"   OID: {base_oid}")
            try:
                rows, err = asyncio.run(_walk(base_oid))
            except Exception as exc:
                self.stdout.write(self.style.ERROR(f"   ERROR: {exc}"))
                continue

            if err:
                self.stdout.write(self.style.ERROR(f"   SNMP error: {err}"))
                continue

            if not rows:
                self.stdout.write("   (no rows returned — OID not supported or empty table)")
                continue

            self.stdout.write(f"   Rows returned: {len(rows)}")

            for oid_text, raw_val in sorted(rows.items())[:40]:
                suffix = oid_text[len(base_oid) + 1:]
                parts = suffix.split(".")

                # Attempt index interpretation
                index_info = ""
                if len(parts) >= 4:
                    try:
                        frame, sl, po, onu = int(parts[-4]), int(parts[-3]), int(parts[-2]), int(parts[-1])
                        index_info = f"[frame={frame} slot={sl} port={po} onu_id={onu}]"
                        if slot_filter is not None and sl != slot_filter:
                            continue
                        if port_filter is not None and po != port_filter:
                            continue
                        if onu_filter is not None and onu != onu_filter:
                            continue
                    except (ValueError, IndexError):
                        pass
                elif len(parts) >= 2:
                    try:
                        index_info = f"[ifIndex={parts[-2]} onu_id={parts[-1]}]"
                    except (ValueError, IndexError):
                        pass

                # Format value
                if "ifName" in label:
                    val_display = str(raw_val)
                elif re.search(r"-?\d{2,}", str(raw_val)):
                    val_display = _fmt_dbm(raw_val)
                else:
                    val_display = str(raw_val)

                self.stdout.write(f"   .{suffix}  {index_info}  =>  {val_display}")

            if len(rows) == 40:
                self.stdout.write(f"   ... (showing first 40 of {len(rows)} rows)")

        # Summarise what was found
        self.stdout.write(self.style.SUCCESS(f"\n{'='*60}"))
        self.stdout.write(self.style.SUCCESS("  SUMMARY"))
        self.stdout.write(self.style.SUCCESS(f"{'='*60}"))
        for label, base_oid in EPON_DDM_OIDS.items():
            if "104" not in label and "34" not in label:
                continue
            try:
                rows, _ = asyncio.run(_walk(base_oid))
                count = len(rows)
            except Exception:
                count = -1
            status = self.style.SUCCESS(f"{count} rows") if count > 0 else self.style.ERROR("empty / not supported")
            self.stdout.write(f"  {label.strip():<30}  {base_oid}  →  {status}")

        self.stdout.write("")
        self.stdout.write("Run with --slot N --port N --onu-id N to filter to a specific ONU.")
        self.stdout.write("Run with --walk-all to also check entity/ifName OIDs.")
