"""Fresh-process entry point: never inherit live web threads or their locks."""
import os


def run_status_sync(queue, olt_id, batch_size, timeout):
    os.environ['OLT_DISABLE_EMBEDDED_SYNC'] = '1'
    os.environ['OLT_ENABLE_EMBEDDED_SYNC'] = 'false'
    import django
    django.setup()
    from django.db import connections
    from .status_sync_batches import sync_olt_batches
    from oltmanager.models import OLT
    from oltmanager.utils import olt_background_enabled_q
    try:
        olt = OLT.objects.filter(pk=olt_id).filter(olt_background_enabled_q()).first()
        if not olt:
            queue.put(('ok', None))
            return
        result = sync_olt_batches(olt, batch_size, timeout)
        queue.put(('ok', result))
    except Exception as exc:
        queue.put(('error', repr(exc)))
    finally:
        connections.close_all()
