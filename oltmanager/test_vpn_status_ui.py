from django.test import SimpleTestCase

from oltmanager.views import _vpn_tunnel_is_up


class VPNTunnelStatusTests(SimpleTestCase):
    def test_recent_handshake_is_up(self):
        status = {"peer_public_key": "peer-key", "last_handshake_s": 25}
        self.assertTrue(_vpn_tunnel_is_up(status))

    def test_old_handshake_is_down(self):
        status = {"peer_public_key": "peer-key", "last_handshake_s": 181}
        self.assertFalse(_vpn_tunnel_is_up(status))

    def test_missing_handshake_or_peer_is_down(self):
        self.assertFalse(_vpn_tunnel_is_up(None))
        self.assertFalse(_vpn_tunnel_is_up({"peer_public_key": "peer-key", "last_handshake_s": None}))
        self.assertFalse(_vpn_tunnel_is_up({"peer_public_key": "", "last_handshake_s": 10}))
