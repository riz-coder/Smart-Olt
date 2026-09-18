from unittest import TestCase

from .utils import _inventory_slot_is_complete, _snmp_inventory_is_usable


class ConfigSyncPerformanceTests(TestCase):
    def test_nearly_complete_large_slot_does_not_force_full_retry(self):
        self.assertTrue(_inventory_slot_is_complete(980, 1000))

    def test_significantly_incomplete_slot_still_retries(self):
        self.assertFalse(_inventory_slot_is_complete(900, 1000))

    def test_unknown_expected_count_requires_some_inventory(self):
        self.assertTrue(_inventory_slot_is_complete(1, 0))
        self.assertFalse(_inventory_slot_is_complete(0, 0))

    def test_snmp_inventory_requires_at_least_sixty_percent_of_database(self):
        self.assertTrue(_snmp_inventory_is_usable(600, 1000))
        self.assertFalse(_snmp_inventory_is_usable(599, 1000))
        self.assertFalse(_snmp_inventory_is_usable(0, 1000))

    def test_first_inventory_accepts_nonempty_snmp_result(self):
        self.assertTrue(_snmp_inventory_is_usable(1, 0))
