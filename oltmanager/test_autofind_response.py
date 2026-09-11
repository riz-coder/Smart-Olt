from types import SimpleNamespace
from unittest.mock import patch

from django.test import RequestFactory, SimpleTestCase

from oltmanager import views


class AutofindResponseTests(SimpleTestCase):
    def test_device_failure_returns_json_without_exposing_backend(self):
        request = RequestFactory().get('/unconfigured/group/5/')
        request.user = SimpleNamespace(is_authenticated=True)
        with patch.object(views.OLT.objects, 'only', side_effect=PermissionError('private path')):
            with self.assertLogs(views.logger, level='ERROR'):
                response = views.unconfigured_onus_group_data(request, 5)
        self.assertEqual(response.status_code, 500)
        self.assertEqual(response['Content-Type'], 'application/json')
        self.assertNotIn(b'private path', response.content)

    def test_serial_cache_preserves_resync_configuration(self):
        row = dict(olt_id=5, olt__name='Test OLT', slot=0, port=1, ont_id=2,
                   sn='ABCD12345678', description='Customer', onu_mode_cache='bridging',
                   user_vlan_cache='238', attached_vlans_cache='238', mapping_mode_cache='priority',
                   download_profile_index_cache=10, upload_profile_index_cache=11)
        with patch.dict(views._AUTOFIND_EXISTING_SERIAL_CACHE, updated_at=None, items=None):
            with patch.object(views.ConfiguredONU.objects, 'values') as rows:
                rows.return_value.exclude.return_value = [row]
                records = views._get_cached_autofind_existing_serial_map()
        self.assertEqual(records['ABCD12345678']['description'], 'Customer')
        self.assertEqual(records['ABCD12345678']['user_vlan_cache'], '238')
        self.assertEqual(records['ABCD12345678']['olt_name'], 'Test OLT')
