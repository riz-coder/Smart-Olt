import signal
import time

from django.core.management.base import BaseCommand

from oltmanager.apps import ensure_background_sync_threads
from oltmanager.licensing import LicenceError, licence_is_configured, run_licence_cycle


class Command(BaseCommand):
    help = "Keep the embedded OLT background sync threads alive in a dedicated worker process."

    def handle(self, *args, **options):
        stopping = {"value": False}

        def _stop(*_args):
            stopping["value"] = True

        signal.signal(signal.SIGTERM, _stop)
        signal.signal(signal.SIGINT, _stop)
        ensure_background_sync_threads()
        self.stdout.write("OptiVerse background sync worker started.")
        next_licence_sync = 0.0
        while not stopping["value"]:
            started = ensure_background_sync_threads()
            if started:
                self.stdout.write(f"Recovered background thread(s): {', '.join(started)}")
            if licence_is_configured() and time.monotonic() >= next_licence_sync:
                try:
                    result = run_licence_cycle()
                except LicenceError as exc:
                    self.stderr.write(f"Licence sync failed: {exc}")
                else:
                    self.stdout.write(
                        f"Licence verified; {result['olt_count']} entitlement(s) applied."
                    )
                next_licence_sync = time.monotonic() + 3600
            time.sleep(30)
        self.stdout.write("OptiVerse background sync worker stopped.")
