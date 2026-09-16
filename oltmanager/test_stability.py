from types import SimpleNamespace
from unittest.mock import Mock, patch

from django.test import SimpleTestCase
from django.utils import timezone

from .views import _build_onu_stability_summary, _count_onu_status_transitions


class ONUStabilityTests(SimpleTestCase):
    def test_flaps_count_every_status_sync_transition(self):
        statuses = ["online", "online", "offline", "offline", "online", "power_failure", "online"]
        self.assertEqual(_count_onu_status_transitions(statuses), 4)

    def test_blank_samples_do_not_create_false_flaps(self):
        self.assertEqual(_count_onu_status_transitions(["online", "", None, "ONLINE"]), 0)

    def test_current_day_cache_is_refreshed_after_new_sync_samples(self):
        stale = {"flaps": 0}
        fresh = {"flaps": 2}
        record = SimpleNamespace(
            stability_report_date=timezone.localdate(),
            stability_report_cache=stale,
            save=Mock(),
        )
        with patch("oltmanager.views._calculate_onu_stability_summary", return_value=fresh) as calculate:
            result = _build_onu_stability_summary(Mock(), 1, 2, 3, record=record)
        self.assertEqual(result["flaps"], 2)
        calculate.assert_called_once()
        record.save.assert_called_once_with(update_fields=["stability_report_date", "stability_report_cache"])

