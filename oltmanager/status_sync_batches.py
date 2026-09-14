"""Process a fixed OLT inventory in non-overlapping batches, with OLT-wide progress."""
import math
import logging

logger = logging.getLogger('oltmanager.sync')


def cycle_timeout(total, batch_size, timeout):
    return max(1, math.ceil(total / max(1, batch_size))) * (timeout + 10) + 30


def sync_olt_batches(olt, batch_size, timeout):
    from .models import ConfiguredONU
    from .utils import sync_runtime_statuses_for_olt, update_onu_status_sync_progress

    # Freeze membership/order once: DB updates must not move records between pages.
    ids = list(ConfiguredONU.objects.filter(olt=olt).order_by('status_updated_at', 'id').values_list('id', flat=True))
    total = len(ids)
    size = max(1, int(batch_size or total or 1))
    verified = updated = 0
    batches = math.ceil(total / size)

    def publish(**payload):
        update_onu_status_sync_progress(olt.pk, olt=olt.name, **payload)

    publish(running=True, done=False, failed=False, partial=False, checked=0,
            total=total, updated=0, message=f'Starting ONU status sync for {total} ONUs...')
    for offset in range(0, total, size):
        batch_ids = ids[offset:offset + size]
        batch_number = offset // size + 1
        batch_checked = 0

        def progress(payload):
            nonlocal batch_checked
            batch_checked = max(batch_checked, min(len(batch_ids), int(payload.get('checked') or 0)))
            # A batch's terminal event is not the OLT's terminal event.
            publish(running=True, done=False, failed=False, partial=False,
                    checked=verified + batch_checked,
                    total=total, updated=updated + int(payload.get('updated') or 0),
                    message=f'Batch {batch_number}/{batches}: {payload.get("message") or "Checking ONU status..."}')

        try:
            result = sync_runtime_statuses_for_olt(
                olt, only_non_online=False, record_ids=batch_ids, write_samples=False,
                max_seconds=max(30, timeout - 20), on_progress=progress,
            ) or {}
        except Exception:
            logger.exception('OLT %s status batch %s failed; continuing remaining batches.', olt.pk, batch_number)
            result = {}
        verified += int(result.get('verified') or 0)
        updated += int(result.get('updated') or 0)
        logger.info('OLT %s status batch %s/%s processed: selected=%s cumulative_verified=%s/%s',
                    olt.pk, batch_number, batches, len(batch_ids), verified, total)
        publish(running=True, done=False, checked=verified, total=total, updated=updated,
                message=f'Batch {batch_number}/{batches} processed; {verified}/{total} ONUs verified.')

    pending = total - verified
    partial = bool(pending and total and verified / total >= 0.60)
    failed = bool(pending and not partial)
    label = 'Partial' if partial else 'Incomplete' if failed else 'Completed'
    message = f'{label}: {verified}/{total} verified, {pending} pending, {updated} updated.'
    if pending:
        message += ' Pending ONUs will be prioritized next cycle.'
    publish(running=False, done=True, failed=failed, partial=partial,
            checked=verified, total=total, updated=updated, message=message)
    return {'olt': olt.name, 'checked': verified, 'verified': verified, 'total': total,
            'updated': updated, 'pending': pending, 'partial': partial, 'failed': failed,
            'status': message}
