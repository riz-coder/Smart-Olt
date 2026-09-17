from unittest import TestCase

from .utils import _inventory_slot_is_complete


class ConfigSyncPerformanceTests(TestCase):
    def test_nearly_complete_large_slot_does_not_force_full_retry(self):
        self.assertTrue(_inventory_slot_is_complete(980, 1000))

    def test_significantly_incomplete_slot_still_retries(self):
        self.assertFalse(_inventory_slot_is_complete(900, 1000))

    def test_unknown_expected_count_requires_some_inventory(self):
        self.assertTrue(_inventory_slot_is_complete(1, 0))
        self.assertFalse(_inventory_slot_is_complete(0, 0))
