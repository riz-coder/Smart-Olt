from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.test import TestCase

from .models import OLT, ConfiguredONU
from .views import _report_parse_dbm, _report_signal_candidates


class HealthReportSignalTests(TestCase):
    def setUp(self):
        cache.clear()
        self.olt = OLT.objects.create(name='Report test', ip_address='192.0.2.10', username='test', password='test')
        self.user = get_user_model().objects.create_user(username='report-test', password='test-only')
        self.client.force_login(self.user)
        for index, reading in enumerate(['-20.55 dBm', ' -29.50 DBM ', '-31.75', '--', '', 'offline',
                'NaN', 'Infinity', 'error -99', '1e9999', '-999999999999999999999999', '.5 dBm']):
            ConfiguredONU.objects.create(olt=self.olt, slot=0, port=0, ont_id=index, sn=f'REPORT{index}',
                derived_status='online', signal_bucket='bad', onu_rx=reading)

    def tearDown(self):
        cache.clear()
        super().tearDown()

    def test_postgres_query_skips_invalid_readings_and_orders_numerically(self):
        readings = [row['onu_rx_dbm'] for row in _report_signal_candidates([self.olt.pk])]
        self.assertEqual(readings, [-31.75, -29.5, -20.55, .5])

    def test_report_renders_with_mixed_readings(self):
        response = self.client.get('/report/')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context['totals']['total'], 12)
        self.assertEqual([row['dbm'] for row in response.context['worst_signals']], [-31.75, -29.5, -20.55, .5])

    def test_parser_rejects_invalid_values(self):
        self.assertEqual(_report_parse_dbm(' -20.55 dBm '), -20.55)
        for value in ['NaN', 'Infinity', '--', 'error -99', '1e9999']:
            self.assertIsNone(_report_parse_dbm(value))
