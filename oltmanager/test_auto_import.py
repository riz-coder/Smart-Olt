import json
from unittest.mock import patch

from django.test import Client, SimpleTestCase, TestCase
from django.urls import reverse

from . import apps
from .models import OLT


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
