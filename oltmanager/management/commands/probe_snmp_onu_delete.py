import json

from django.core.management.base import BaseCommand, CommandError

from oltmanager.models import OLT
from oltmanager.utils import probe_onu_snmp_delete


class Command(BaseCommand):
    help = (
        "Build and optionally apply Huawei service-port then XPON ONU deletion via SNMP RowStatus destroy(6). "
        "Default mode is dry-run and does not delete anything."
    )

    def add_arguments(self, parser):
        target = parser.add_mutually_exclusive_group(required=True)
        target.add_argument("--olt-id", type=int, help="OLT database ID")
        target.add_argument("--olt-name", help="OLT name")
        target.add_argument("--olt-ip", help="OLT IP address")
        parser.add_argument("--frame", type=int, default=0, help="Frame number, default 0")
        parser.add_argument("--slot", type=int, required=True, help="Slot number")
        parser.add_argument("--port", type=int, required=True, help="PON port number")
        parser.add_argument("--ont-id", "--onu-id", dest="ont_id", type=int, required=True, help="ONT/ONU ID")
        parser.add_argument(
            "--service-port-id",
            action="append",
            default=[],
            help="Attached CLI service-port ID. Can be supplied multiple times; each is deleted before the ONU.",
        )
        parser.add_argument(
            "--apply",
            action="store_true",
            help="Delete verified service-flow rows, then the ONU. Without this flag only preflight checks run.",
        )
        parser.add_argument(
            "--verify-delay",
            type=float,
            default=0.4,
            help="Seconds to wait before after-delete verification, default 0.4",
        )
        parser.add_argument(
            "--service-flow-offset",
            type=int,
            choices=(0, 1),
            default=None,
            help=(
                "Override Huawei SNMP service-flow index mapping: 0 means flowIndex=service-port ID, "
                "1 means flowIndex=service-port ID+1. Default auto prefers 0 if both rows are active."
            ),
        )

    def handle(self, *args, **options):
        olt = self._get_olt(options)
        payload = probe_onu_snmp_delete(
            olt,
            options["slot"],
            options["port"],
            options["ont_id"],
            frame=options["frame"],
            apply=options["apply"],
            verify_delay=options["verify_delay"],
            service_port_ids=options["service_port_id"],
            service_flow_index_offset=options["service_flow_offset"],
        )
        payload["olt"] = {
            "id": olt.pk,
            "name": olt.name,
            "ip_address": olt.ip_address,
            "snmp_port": olt.snmp_port,
        }
        output = json.dumps(payload, indent=2, sort_keys=True, default=str)
        if payload.get("ok"):
            self.stdout.write(self.style.SUCCESS(output))
        else:
            self.stdout.write(self.style.ERROR(output))

    def _get_olt(self, options):
        if options.get("olt_id") is not None:
            lookup = {"pk": options["olt_id"]}
        elif options.get("olt_name"):
            lookup = {"name": options["olt_name"]}
        else:
            lookup = {"ip_address": options["olt_ip"]}
        try:
            return OLT.objects.get(**lookup)
        except OLT.DoesNotExist:
            raise CommandError(f"OLT not found for {lookup}.")
        except OLT.MultipleObjectsReturned:
            raise CommandError(f"Multiple OLTs found for {lookup}; use --olt-id instead.")
