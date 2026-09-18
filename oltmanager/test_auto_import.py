import json
from types import SimpleNamespace
from unittest.mock import Mock, patch

from django.test import Client, SimpleTestCase, TestCase
from django.urls import reverse

from . import apps
from .models import OLT
from .utils import detect_new_onus_from_cli_identity, detect_new_onus_from_snmp


class ImmediateImportQueueTests(SimpleTestCase):
    def setUp(self):
        apps._IMMEDIATE_SYNC_RUNNING.clear()
        apps._IMMEDIATE_SYNC_PENDING.clear()
        self.addCleanup(apps._IMMEDIATE_SYNC_RUNNING.clear)
        self.addCleanup(apps._IMMEDIATE_SYNC_PENDING.clear)

    @patch("oltmanager.apps.time.time", return_value=100.0)
    def test_keys_detected_during_active_import_are_queued(self, now):
        apps._IMMEDIATE_SYNC_RUNNING[7] = 90.0

        started = apps._schedule_immediate_inventory_sync(7, [(0, 1, 2, 3), (0, 1, 2, 3)])

        self.assertFalse(started)
        self.assertEqual(apps._IMMEDIATE_SYNC_PENDING[7], {(0, 1, 2, 3)})


class TrapAutoImportTests(TestCase):
    def setUp(self):
        self.olt = OLT.objects.create(
            name="Trap OLT",
            ip_address="192.0.2.10",
            username="admin",
            password="test-only",
        )

    @patch("oltmanager.apps._schedule_immediate_inventory_sync", return_value=True)
    def test_unknown_new_onu_trap_still_schedules_targeted_validation(self, schedule):
        response = Client().post(
            reverse("onu_trap_ingest"),
            data=json.dumps({
                "olt_ip": self.olt.ip_address,
                "slot": 1,
                "port": 2,
                "ont_id": 3,
                "alarm_name": "ONU provisioned externally",
            }),
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["imports_scheduled"], 1)
        schedule.assert_called_once_with(self.olt.pk, [(0, 1, 2, 3)])


class CliIdentityDetectionTests(SimpleTestCase):
    @patch("oltmanager.utils.fetch_configured_onu_status_rows")
    @patch("oltmanager.models.ConfiguredONU.objects.filter")
    def test_lightweight_cli_scan_returns_only_missing_keys(self, configured_filter, fetch_rows):
        queryset = Mock()
        queryset.values_list.return_value = [(0, 1, 0, 1)]
        configured_filter.return_value = queryset
        fetch_rows.return_value = {
            "rows": [
                {"frame": 0, "slot": 1, "port": 0, "ont_id": 1},
                {"frame": 0, "slot": 1, "port": 0, "ont_id": 2},
            ],
            "status": "two identities",
        }
        olt = SimpleNamespace(pk=4, pon_ports_cache=[{"slot": 1, "ports": [{}]}], olt_cards_cache=[])

        result = detect_new_onus_from_cli_identity(olt)

        self.assertFalse(result["incomplete"])
        self.assertEqual(result["new_keys"], [(0, 1, 0, 2)])

    @patch("oltmanager.utils.fetch_configured_onu_status_rows")
    @patch("oltmanager.models.ConfiguredONU.objects.filter")
    def test_incomplete_cli_scan_never_emits_new_keys(self, configured_filter, fetch_rows):
        queryset = Mock()
        queryset.values_list.return_value = [(0, 1, 0, value) for value in range(10)]
        configured_filter.return_value = queryset
        fetch_rows.return_value = {
            "rows": [
                {"frame": 0, "slot": 1, "port": 0, "ont_id": 50},
                {"frame": 0, "slot": 1, "port": 0, "ont_id": 51},
            ],
            "status": "partial",
        }
        olt = SimpleNamespace(pk=4, pon_ports_cache=[{"slot": 1, "ports": [{}]}], olt_cards_cache=[])

        result = detect_new_onus_from_cli_identity(olt)

        self.assertTrue(result["incomplete"])
        self.assertEqual(result["new_keys"], [])


class SnmpIdentityDetectionTests(SimpleTestCase):
    @patch("oltmanager.utils.fetch_olt_snmp_status_map")
    @patch("oltmanager.models.ConfiguredONU.objects.filter")
    def test_snmp_and_database_keys_use_same_frame_slot_port_ont_shape(
        self, configured_filter, fetch_status,
    ):
        queryset = Mock()
        queryset.values_list.return_value = [(0, 1, 2, 3)]
        configured_filter.return_value = queryset
        fetch_status.return_value = {
            "items": {(1, 2, 3): "online", (1, 2, 4): "online"},
            "status": "ok",
        }

        result = detect_new_onus_from_snmp(SimpleNamespace(pk=4))

        self.assertEqual(result["new_keys"], [(0, 1, 2, 4)])
        self.assertEqual(result["snmp_count"], 2)
        self.assertEqual(result["db_count"], 1)
