import signal

from django.core.management.base import BaseCommand, CommandError

from oltmanager.wireguard import WireGuardError, WireGuardHelper


class Command(BaseCommand):
    help = "Run the tenant WireGuard interface and Unix-socket control helper."

    def handle(self, *args, **options):
        stopping = {"value": False}

        def stop(*_args):
            stopping["value"] = True

        signal.signal(signal.SIGTERM, stop)
        signal.signal(signal.SIGINT, stop)
        try:
            helper = WireGuardHelper()
            self.stdout.write("OptiVerse WireGuard helper started.")
            helper.serve(lambda: stopping["value"])
        except WireGuardError as exc:
            raise CommandError(str(exc)) from exc
