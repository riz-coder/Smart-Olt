"""Fresh-process entry point: never inherit live web threads or their locks."""
import os


def run_status_sync(queue, olt_id, batch_size, timeout):
    os.environ['OLT_DISABLE_EMBEDDED_SYNC'] = '1'
    os.environ['OLT_ENABLE_EMBEDDED_SYNC'] = 'false'
    import django
    django.setup()
    from django.db import connections
    from oltmanager.models import ConfiguredONU, OLT
    from oltmanager.utils import (
        olt_background_enabled_q, sync_runtime_statuses_for_olt,
        update_onu_status_sync_progress,
    )
    try:
        olt = OLT.objects.filter(pk=olt_id).filter(olt_background_enabled_q()).first()
        if not olt:
            queue.put(('ok', None))
            return
        total = ConfiguredONU.objects.filter(olt=olt).count()
        total = min(total, batch_size) if batch_size else total
        update_onu_status_sync_progress(olt.id, olt=olt.name, running=True,
                                       done=False, failed=False, checked=0, total=total,
                                       message=f'Starting ONU status sync for {total} ONUs...')

        def progress(payload):
            update_onu_status_sync_progress(olt.id, olt=olt.name, **(payload or {}))

        result = sync_runtime_statuses_for_olt(
            olt, only_non_online=False, limit=batch_size, write_samples=False,
            max_seconds=max(30, timeout - 20), on_progress=progress,
        )
        queue.put(('ok', result))
    except Exception as exc:
        queue.put(('error', repr(exc)))
    finally:
        connections.close_all()
