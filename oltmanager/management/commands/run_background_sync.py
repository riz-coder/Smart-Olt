import signal
import time

from django.core.management.base import BaseCommand

from oltmanager.apps import ensure_background_sync_threads


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
        while not stopping["value"]:
            started = ensure_background_sync_threads()
            if started:
                self.stdout.write(f"Recovered background thread(s): {', '.join(started)}")
            time.sleep(30)
        self.stdout.write("OptiVerse background sync worker stopped.")
