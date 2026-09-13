import tempfile
from pathlib import Path
from unittest.mock import patch

from django.test import SimpleTestCase, override_settings
from oltmanager import utils


class SyncProgressHandoffTests(SimpleTestCase):
    def test_fresh_writer_retains_previous_olt_and_cycle(self):
        with tempfile.TemporaryDirectory() as directory:
            with override_settings(ONU_STATUS_SYNC_PROGRESS_FILE=str(Path(directory) / 'progress.json')):
                with patch.dict(utils._ONU_STATUS_SYNC_PROGRESS, {}, clear=True):
                    utils.start_onu_status_sync_progress([{'id': 1, 'name': 'First'}, {'id': 2, 'name': 'Second'}])
                    utils._ONU_STATUS_SYNC_PROGRESS.clear()
                    utils.update_onu_status_sync_progress(1, running=False, done=True, checked=10, total=10)
                    utils._ONU_STATUS_SYNC_PROGRESS.clear()
                    utils.update_onu_status_sync_progress(2, running=True, checked=5, total=20)
                    snapshot = utils.get_onu_status_sync_progress()
                    self.assertTrue(snapshot['running'])
                    self.assertEqual(snapshot['total_olts'], 2)
                    self.assertEqual(snapshot['done_olts'], 1)
                    self.assertEqual(snapshot['checked'], 15)
                    utils._ONU_STATUS_SYNC_PROGRESS.clear()
                    utils.finish_onu_status_sync_progress()
                    snapshot = utils.get_onu_status_sync_progress()
                    self.assertFalse(snapshot['running'])
                    self.assertEqual(snapshot['checked'], 15)
                    self.assertTrue(snapshot['last_completed_at'])
