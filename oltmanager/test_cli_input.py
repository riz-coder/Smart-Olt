from unittest import TestCase
from unittest.mock import Mock, patch

from .utils import send_telnet_input


class InteractiveCliInputTests(TestCase):
    @patch("oltmanager.utils._touch_telnet_session")
    def test_xterm_delete_byte_is_sent_as_cli_backspace(self, touch):
        session = Mock()

        send_telnet_input(session, "\x7f")

        touch.assert_called_once_with(session)
        session.write.assert_called_once_with(b"\x08")

    @patch("oltmanager.utils._touch_telnet_session")
    def test_escape_sequences_and_normal_text_remain_unchanged(self, touch):
        session = Mock()

        send_telnet_input(session, "display ont info\x1b[D")

        touch.assert_called_once_with(session)
        session.write.assert_called_once_with(b"display ont info\x1b[D")
