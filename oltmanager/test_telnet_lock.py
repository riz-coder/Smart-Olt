import os
import tempfile
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from django.test import SimpleTestCase
from django.utils import timezone

from . import utils


class TelnetHostLockTests(SimpleTestCase):
    def setUp(self):
        self.olt = SimpleNamespace(ip_address='192.0.2.44', port=23)

    def test_stale_session_cleanup_releases_its_file_lock(self):
        session = Mock()
        file_lock = Mock()
        record = {'tn': session, 'host_key': '192.0.2.44:23',
                  'updated_at': timezone.now() - timedelta(minutes=5), 'file_lock': file_lock}
        with patch.dict(utils._TELNET_SESSIONS, {id(session): record}, clear=True), \
                patch.object(utils, '_release_telnet_host_file_lock') as release:
            utils._close_competing_telnet_sessions(self.olt)
        session.close.assert_called_once_with()
        release.assert_called_once_with(file_lock)
        self.assertNotIn(id(session), utils._TELNET_SESSIONS)

    def test_lock_path_is_shared_across_tenant_runtime_directories(self):
        with tempfile.TemporaryDirectory() as directory:
            shared = str(Path(directory) / 'device-locks')
            with patch.dict(os.environ, {'OPTIVERSE_TELNET_LOCK_DIR': shared,
                    'OPTIVERSE_RUNTIME_DIR': str(Path(directory) / 'tenant-one')}):
                first = utils._telnet_lock_path(self.olt)
            with patch.dict(os.environ, {'OPTIVERSE_TELNET_LOCK_DIR': shared,
                    'OPTIVERSE_RUNTIME_DIR': str(Path(directory) / 'tenant-two')}):
                second = utils._telnet_lock_path(self.olt)
        self.assertEqual(first, second)
        self.assertEqual(Path(first).parent, Path(shared))

    def test_stale_cleanup_runs_before_file_lock_wait(self):
        events = []
        fake_session = Mock()
        with patch.object(utils, '_close_competing_telnet_sessions', side_effect=lambda *a, **k: events.append('cleanup')), \
                patch.object(utils, '_acquire_telnet_host_file_lock', side_effect=lambda *a, **k: (events.append('lock') or (None, 'busy'))):
            session, status = utils.open_telnet_authenticated_session(self.olt)
        self.assertIsNone(session)
        self.assertEqual(status, 'busy')
        self.assertEqual(events, ['cleanup', 'lock'])

    def test_onboarding_defers_duplicate_all_ont_inventory(self):
        olt = SimpleNamespace(ip_address='192.0.2.44', port=23, onboarding_status='running',
            pon_ports_cache=[{'slot': '1', 'board_type': 'H805GPFD', 'ports': [
                {'port': '0', 'status': 'Up', 'admin_state': 'Enabled', 'onus': 'Online:0 Offline:0'}]}],
            olt_cards_cache=[])
        session = Mock()
        with patch.object(utils, 'fetch_snmp_pon_port_states', return_value={'ports': {}, 'status': ''}), \
                patch.object(utils, 'open_telnet_authenticated_session', return_value=(session, 'ok')), \
                patch.object(utils, '_prepare_telnet_cli_session'), \
                patch.object(utils, '_get_ont_counts_from_db', return_value=({}, 0)), \
                patch.object(utils, '_run_telnet_command') as command, \
                patch.object(utils, '_get_ont_signal_averages_from_db', return_value={}), \
                patch.object(utils, '_close_telnet_session'):
            groups, status = utils.fetch_pon_ports_snapshot(olt)
        self.assertTrue(groups)
        self.assertIn('deferred to ONU import', status)
        command.assert_not_called()
