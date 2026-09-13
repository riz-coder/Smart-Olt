import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


class SharedAuthorizeProgressTests(unittest.TestCase):
    def run_process(self, database, action):
        code = '''
import json, sys
from django.conf import settings
settings.configure(DATABASES={'default': {'NAME': sys.argv[1]}})
from oltmanager.authorize_progress import save_authorize_progress, get_authorize_progress
if sys.argv[2] == 'save':
    save_authorize_progress('test-task', {'done': True, 'ok': True, 'step': 4})
print(json.dumps(get_authorize_progress('test-task')))
'''
        result = subprocess.run([sys.executable, '-c', code, str(database), action],
                                capture_output=True, text=True, check=True, timeout=30)
        return json.loads(result.stdout)

    def test_result_survives_writer_exit_and_is_visible_to_another_process(self):
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / 'db.sqlite3'
            written = self.run_process(database, 'save')
            self.assertEqual(self.run_process(database, 'read'), written)
            self.assertTrue(written['done'])

    def test_separate_tenant_cannot_read_same_task_id(self):
        with tempfile.TemporaryDirectory() as directory:
            first = Path(directory) / 'first' / 'db.sqlite3'
            second = Path(directory) / 'second' / 'db.sqlite3'
            self.run_process(first, 'save')
            self.assertEqual(self.run_process(second, 'read'), {})
