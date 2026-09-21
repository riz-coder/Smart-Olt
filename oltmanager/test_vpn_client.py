import tempfile
from pathlib import Path
from unittest.mock import patch

from django.test import SimpleTestCase, override_settings

from oltmanager.vpn import client_config, configure_client, ensure_client_state, load_client_state


class VPNClientStateTests(SimpleTestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.settings = override_settings(
            OPTIVERSE_WG_STATE_DIR=self.temporary.name,
            OPTIVERSE_WG_SOCKET=str(Path(self.temporary.name) / "wg.sock"),
            OPTIVERSE_VPN_PUBLIC_HOST="vpn-connect.nexecode.com",
            OPTIVERSE_VPN_PORT=52001,
        )
        self.settings.enable()
        self.addCleanup(self.settings.disable)

    def test_client_key_is_generated_only_once(self):
        first = ensure_client_state()
        second = ensure_client_state()
        self.assertEqual(first["private_key"], second["private_key"])
        self.assertEqual(first["public_key"], second["public_key"])
        self.assertEqual(first["tunnel_address"], "10.75.75.2/30")

    @patch("oltmanager.vpn.helper_request")
    def test_configure_persists_helper_accepted_routes(self, helper):
        helper.side_effect = [
            {"ok": True},
            {"ok": True, "routes": ["192.168.10.0/24"]},
        ]
        configure_client(["192.168.10.0/24"])
        self.assertEqual(load_client_state()["routes"], ["192.168.10.0/24"])

    @patch("oltmanager.vpn.helper_request")
    def test_downloaded_config_contains_public_endpoint_without_olt_routes(self, helper):
        ensure_client_state()
        helper.return_value = {
            "ok": True,
            "public_key": "server-public-key",
            "tunnel_address": "10.75.75.1/30",
        }
        config = client_config()
        self.assertIn("Endpoint = vpn-connect.nexecode.com:52001", config)
        self.assertIn("AllowedIPs = 10.75.75.1/32", config)
