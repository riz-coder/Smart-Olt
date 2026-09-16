from django.test import SimpleTestCase

from .views import _dashboard_graph_config, _traffic_counter_delta


class TrafficGraphTests(SimpleTestCase):
    def test_counter_reset_is_not_rendered_as_a_huge_spike(self):
        self.assertIsNone(_traffic_counter_delta(100, 2_000_000))

    def test_real_32_bit_counter_rollover_is_supported(self):
        self.assertEqual(_traffic_counter_delta(25, 4_294_967_280), 41)

    def test_month_view_uses_daily_calendar_buckets(self):
        config = _dashboard_graph_config("4w")
        self.assertEqual(config["since"].day, 1)
        self.assertEqual(config["bucket_days"], 1)

    def test_year_view_contains_twelve_calendar_months(self):
        config = _dashboard_graph_config("12m")
        self.assertEqual(config["bucket_months"], 1)
        end_index = config["since"].year * 12 + config["since"].month - 1 + 11
        current = _dashboard_graph_config("4w")["since"]
        self.assertEqual((end_index // 12, end_index % 12 + 1), (current.year, current.month))

