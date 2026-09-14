from unittest.mock import patch

from django.test import TestCase
from django.utils import timezone

from .models import OLT, ConfiguredONU
from .status_sync_batches import sync_olt_batches, cycle_timeout


class StatusBatchTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.olt = OLT.objects.create(name='Batch test', ip_address='192.0.2.1')
        ConfiguredONU.objects.bulk_create([
            ConfiguredONU(olt=cls.olt, slot=0, port=i // 128, ont_id=i % 128)
            for i in range(2505)
        ])

    def run_batches(self, counts=None, fail_first=False):
        seen, events = [], []
        def sync(olt, **kwargs):
            ids = kwargs['record_ids']
            seen.append(ids)
            # Reorder persisted state during the cycle: snapshot membership must hold.
            ConfiguredONU.objects.filter(pk__in=ids).update(status_updated_at=timezone.now())
            if fail_first and len(seen) == 1:
                raise TimeoutError('test timeout')
            verified = len(ids) if counts is None else counts[len(seen) - 1]
            kwargs['on_progress']({'checked': verified, 'done': True, 'updated': verified})
            return {'verified': verified, 'updated': verified}
        with patch('oltmanager.utils.sync_runtime_statuses_for_olt', side_effect=sync), patch(
                'oltmanager.utils.update_onu_status_sync_progress', side_effect=lambda *args, **kw: events.append(kw)), patch(
                'oltmanager.status_sync_batches.logger'):
            result = sync_olt_batches(self.olt, 1000, 180)
        return seen, events, result

    def test_every_onu_once_and_full_total_until_final_completion(self):
        seen, events, result = self.run_batches()
        self.assertEqual(list(map(len, seen)), [1000, 1000, 505])
        flat = [pk for batch in seen for pk in batch]
        self.assertEqual(len(set(flat)), 2505)
        self.assertEqual(set(flat), set(ConfiguredONU.objects.values_list('pk', flat=True)))
        self.assertTrue(all(event['total'] == 2505 for event in events))
        self.assertTrue(all(not event['done'] for event in events[:-1]))
        self.assertEqual(result['verified'], 2505)
        self.assertEqual(result['pending'], 0)
        self.assertTrue(events[-1]['done'])
        self.assertEqual([e['checked'] for e in events], sorted(e['checked'] for e in events))

    def test_partial_percentage_uses_full_olt_not_first_batch(self):
        seen, events, result = self.run_batches([1000, 0, 0])
        self.assertEqual(len(seen), 3)
        self.assertFalse(result['partial'])
        self.assertTrue(result['failed'])
        self.assertEqual(result['pending'], 1505)

    def test_sixty_percent_partial_and_remaining_batches_still_run(self):
        seen, events, result = self.run_batches([600, 600, 303])
        self.assertEqual(len(seen), 3)
        self.assertTrue(result['partial'])
        self.assertFalse(result['failed'])

    def test_failed_batch_does_not_skip_later_batches(self):
        seen, events, result = self.run_batches(fail_first=True)
        self.assertEqual(len(seen), 3)
        self.assertEqual(result['verified'], 1505)
        self.assertEqual(result['pending'], 1000)

    def test_timeout_scales_with_number_of_batches(self):
        self.assertEqual(cycle_timeout(2505, 1000, 180), 600)
        self.assertGreater(cycle_timeout(4747, 1000, 180), cycle_timeout(1000, 1000, 180))

    def test_explicit_ids_are_olt_scoped_and_missing_status_is_not_offline(self):
        from .utils import sync_runtime_statuses_for_olt
        records = list(ConfiguredONU.objects.filter(olt=self.olt).order_by('pk')[:2])
        ConfiguredONU.objects.filter(pk__in=[r.pk for r in records]).update(
            derived_status='online', run_state='online', status_source='snmp_runtime', status_first_seen_at=timezone.now())
        other = OLT.objects.create(name='Other', ip_address='192.0.2.2')
        outsider = ConfiguredONU.objects.create(olt=other, slot=0, port=0, ont_id=99)
        first = records[0]
        snapshot = {'items': {(first.slot, first.port, first.ont_id): 'online', (99, 99, 99): 'online'}, 'truncated': False}
        with patch('oltmanager.utils._slot_pon_tech', return_value='GPON'), patch(
                'oltmanager.utils.get_active_onu_trap_status_map', return_value={}), patch(
                'oltmanager.utils.fetch_olt_snmp_status_map_for_records', return_value=snapshot):
            result = sync_runtime_statuses_for_olt(self.olt, only_non_online=False,
                record_ids=[r.pk for r in records] + [outsider.pk], write_samples=False)
        self.assertEqual(result['verified'], 1)
        self.assertEqual(result['pending'], 1)
        records[1].refresh_from_db()
        self.assertEqual(records[1].derived_status, 'online')
