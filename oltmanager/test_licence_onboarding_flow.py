from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse

from oltmanager.models import OLT


class LicenceOnboardingFlowTests(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_superuser(
            username="licence-admin",
            email="admin@example.com",
            password="test-only-password",
        )
        self.client.force_login(self.user)

    def create_waiting_olt(self, **overrides):
        values = {
            "name": "Pending OLT",
            "ip_address": "192.0.2.10",
            "username": "admin",
            "password": "test-only",
            "is_ready": False,
            "onboarding_status": "awaiting_licence",
            "onboarding_snmp_mode": "manual",
            "licence_status": "pending",
            "pricing_locked": True,
            "pricing_locked_reason": "Payment pending.",
        }
        values.update(overrides)
        return OLT.objects.create(**values)

    @patch("oltmanager.views._dashboard_snmp_down_olt_ids", return_value=set())
    @patch("oltmanager.views._schedule_missing_device_snapshots_if_due")
    @patch("oltmanager.views.licence_is_configured", return_value=True)
    def test_pending_olt_is_visible_with_pending_status(self, _configured, _snapshots, _down):
        olt = self.create_waiting_olt()

        response = self.client.get(reverse("olt_settings_olt"))

        self.assertContains(response, olt.name)
        self.assertContains(response, "PENDING")
        self.assertContains(response, ">Pending</span>")

    @patch("oltmanager.views._schedule_olt_onboarding")
    @patch("oltmanager.views.run_licence_cycle", return_value={"olt_count": 1})
    @patch("oltmanager.views.licence_is_configured", return_value=True)
    def test_recheck_does_not_auto_start_active_olt(self, _configured, _cycle, schedule):
        olt = self.create_waiting_olt(licence_status="active", pricing_locked=False)

        response = self.client.post(reverse("licence_recheck"))

        self.assertRedirects(response, reverse("olt_settings_olt"))
        olt.refresh_from_db()
        self.assertEqual(olt.onboarding_status, "awaiting_licence")
        schedule.assert_not_called()

    @patch("oltmanager.views._schedule_olt_onboarding")
    @patch("oltmanager.views._active_olt_onboarding", return_value=None)
    def test_active_click_starts_onboarding(self, _active, schedule):
        olt = self.create_waiting_olt(licence_status="active", pricing_locked=False)

        response = self.client.post(reverse("olt_activate", args=[olt.pk]))

        self.assertRedirects(response, reverse("olt_add_progress", args=[olt.pk]))
        olt.refresh_from_db()
        self.assertEqual(olt.onboarding_status, "queued")
        schedule.assert_called_once_with(olt.pk, "manual")

    @patch("oltmanager.views._schedule_olt_onboarding")
    def test_pending_olt_cannot_be_started(self, schedule):
        olt = self.create_waiting_olt()

        response = self.client.post(reverse("olt_activate", args=[olt.pk]))

        self.assertRedirects(response, reverse("olt_settings_olt"))
        olt.refresh_from_db()
        self.assertEqual(olt.onboarding_status, "awaiting_licence")
        schedule.assert_not_called()
