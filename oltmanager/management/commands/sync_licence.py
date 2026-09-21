from django.core.management.base import BaseCommand, CommandError

from oltmanager.licensing import LicenceError, licence_is_configured, run_licence_cycle


class Command(BaseCommand):
    help = "Validate the signed tenant licence, apply OLT entitlements, and check in."

    def add_arguments(self, parser):
        parser.add_argument(
            "--startup",
            action="store_true",
            help="Attempt startup validation but allow cached network grace to keep the web process available.",
        )

    def handle(self, *args, **options):
        if not licence_is_configured():
            if options["startup"]:
                self.stdout.write("Licence integration is not configured; startup validation skipped.")
                return
            raise CommandError("OPTIVERSE_LICENCE_URL and OPTIVERSE_LICENCE_TOKEN are required.")
        try:
            result = run_licence_cycle()
        except LicenceError as exc:
            if options["startup"]:
                self.stderr.write(f"Startup licence validation failed; cached grace rules were applied: {exc}")
                return
            raise CommandError(str(exc)) from exc
        self.stdout.write(self.style.SUCCESS(
            f"Licence verified ({result['licence_status']}); {result['olt_count']} entitlement(s) applied."
        ))
