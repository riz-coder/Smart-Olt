"""Run one tenant's HTTP/WebSocket server and sync threads in one process."""
import threading

from django.core.management.base import BaseCommand

from oltmanager.apps import ensure_background_sync_threads


class Command(BaseCommand):
    help = 'Run the tenant web app and monitored background sync together.'

    def add_arguments(self, parser):
        parser.add_argument('--host', default='0.0.0.0')
        parser.add_argument('--port', type=int, default=8000)

    def handle(self, *args, **options):
        import uvicorn

        stopping = threading.Event()

        def monitor():
            while not stopping.wait(30):
                started = ensure_background_sync_threads()
                if started:
                    self.stdout.write(f'Recovered sync threads: {", ".join(started)}')

        started = ensure_background_sync_threads()
        self.stdout.write(f'Tenant web + sync active; started threads: {", ".join(started)}')
        threading.Thread(target=monitor, name='tenant-sync-monitor', daemon=True).start()
        try:
            uvicorn.run('oltportal.asgi:application', host=options['host'],
                        port=options['port'], workers=1, reload=False)
        finally:
            stopping.set()
