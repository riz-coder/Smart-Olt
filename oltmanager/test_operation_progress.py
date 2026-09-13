import json
import subprocess
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

from django.test import SimpleTestCase


class OperationProgressTests(SimpleTestCase):
    def run_process(self, database, action):
        code = '''
import json, sys
from django.conf import settings
settings.configure(DATABASES={'default': {'NAME': sys.argv[1]}})
from oltmanager.operation_progress import SharedTasks
tasks = SharedTasks('mapping')
if sys.argv[2] == 'save':
    tasks['test'] = {'done': False, 'step': 0}
    tasks['test']['step'] = 3
    tasks['test'].update(done=True, ok=True)
if sys.argv[2] == 'orphan':
    tasks['test'] = {'done': False, '_pid': 999999999, '_birth': 'missing'}
print(json.dumps(dict(tasks.get('test') or {})))
'''
        result = subprocess.run([sys.executable, '-c', code, str(database), action],
                                capture_output=True, text=True, check=True, timeout=30)
        return json.loads(result.stdout)

    def test_nested_updates_survive_process_exit(self):
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / 'db.sqlite3'
            saved = self.run_process(database, 'save')
            self.assertEqual(saved, self.run_process(database, 'read'))
            self.assertTrue(saved['done'])
            self.assertTrue(saved['ok'])
            self.assertEqual(saved['step'], 3)

    def test_tenant_isolation(self):
        with tempfile.TemporaryDirectory() as directory:
            self.run_process(Path(directory) / 'one' / 'db.sqlite3', 'save')
            self.assertEqual(self.run_process(Path(directory) / 'two' / 'db.sqlite3', 'read'), {})

    def test_orphan_stops_without_claiming_success(self):
        with tempfile.TemporaryDirectory() as directory:
            result = self.run_process(Path(directory) / 'db.sqlite3', 'orphan')
            self.assertTrue(result['done'])
            self.assertFalse(result['ok'])
            self.assertTrue(result['result_unknown'])

    def test_priority_keeps_full_cycle_gap(self):
        from oltmanager import apps
        with patch.object(apps, '_ONU_STATUS_PRIORITY_IDS', []), patch.object(apps.time, 'sleep') as sleep:
            self.assertTrue(apps._queue_onu_status_sync_priority(42))
            self.assertTrue(apps._queue_onu_status_sync_priority(42))
            apps._wait_onu_status_cycle_gap()
            sleep.assert_called_once_with(600)
            self.assertEqual(apps._ONU_STATUS_PRIORITY_IDS, [42])

    def test_action_worker_records_terminal_result(self):
        from django.http import JsonResponse
        from types import SimpleNamespace
        from oltmanager import views
        tasks = {'test': {'done': False}}
        with patch.object(views, '_ONU_ACTION_TASKS', tasks), patch.object(views, 'configured_onu_action',
                return_value=JsonResponse({'ok': True, 'action': 'delete', 'redirect_url': '/unconfigured/'})):
            views._run_onu_action_task('test', SimpleNamespace(), 1, 0, 0, 1, 'delete')
        self.assertTrue(tasks['test']['done'])
        self.assertTrue(tasks['test']['ok'])

    def test_action_worker_exception_is_terminal_unknown(self):
        from types import SimpleNamespace
        from oltmanager import views
        tasks = {'test': {'done': False}}
        with patch.object(views, '_ONU_ACTION_TASKS', tasks), patch.object(views, 'logger'), patch.object(
                views, 'configured_onu_action', side_effect=RuntimeError('test')):
            views._run_onu_action_task('test', SimpleNamespace(), 1, 0, 0, 1, 'delete')
        self.assertTrue(tasks['test']['done'])
        self.assertFalse(tasks['test']['ok'])
        self.assertTrue(tasks['test']['result_unknown'])
