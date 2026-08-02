import signal
import time

from django.core.management.base import BaseCommand


class Command(BaseCommand):
    help = "Keep the embedded OLT background sync threads alive in a dedicated worker process."

    def handle(self, *args, **options):
        stopping = {"value": False}

        def _stop(*_args):
            stopping["value"] = True

        signal.signal(signal.SIGTERM, _stop)
        signal.signal(signal.SIGINT, _stop)
        self.stdout.write("OptiVerse background sync worker started.")
        while not stopping["value"]:
            time.sleep(5)
        self.stdout.write("OptiVerse background sync worker stopped.")
