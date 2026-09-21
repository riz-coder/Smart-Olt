import ipaddress
from pathlib import Path
from unittest.mock import patch

from django.test import SimpleTestCase

from oltmanager.wireguard import WireGuardError, WireGuardHelper


class WireGuardRouteValidationTests(SimpleTestCase):
    def setUp(self):
        self.helper = object.__new__(WireGuardHelper)

    @patch.object(WireGuardHelper, "_existing_bridge_networks", return_value=[])
    def test_normalizes_valid_olt_subnets(self, _networks):
        self.assertEqual(
            self.helper.validate_routes(["192.168.20.0/24", "10.10.0.0/16"]),
            ["10.10.0.0/16", "192.168.20.0/24"],
        )

    @patch.object(WireGuardHelper, "_existing_bridge_networks", return_value=[])
    def test_rejects_default_and_tunnel_routes(self, _networks):
        with self.assertRaises(WireGuardError):
            self.helper.validate_routes(["0.0.0.0/0"])
        with self.assertRaises(WireGuardError):
            self.helper.validate_routes(["10.75.75.0/24"])

    @patch.object(
        WireGuardHelper,
        "_existing_bridge_networks",
        return_value=[ipaddress.ip_network("172.20.0.0/16")],
    )
    def test_rejects_container_network_overlap(self, _networks):
        with self.assertRaises(WireGuardError):
            self.helper.validate_routes(["172.20.10.0/24"])

    @patch("oltmanager.wireguard.os.chmod")
    @patch("oltmanager.wireguard.os.chown", create=True)
    def test_helper_socket_is_shared_with_non_root_app_group(self, chown, chmod):
        self.helper.socket_path = Path("/run/optiverse/wg.sock")

        self.helper._grant_app_socket_access()

        chown.assert_called_once_with(self.helper.socket_path, -1, 1000)
        chmod.assert_called_once_with(self.helper.socket_path, 0o660)

    @patch("oltmanager.wireguard.os.chmod")
    @patch("oltmanager.wireguard.os.chown", side_effect=PermissionError, create=True)
    def test_helper_socket_has_private_directory_fallback(self, _chown, chmod):
        self.helper.socket_path = Path("/run/optiverse/wg.sock")

        self.helper._grant_app_socket_access()

        chmod.assert_called_once_with(self.helper.socket_path, 0o666)
