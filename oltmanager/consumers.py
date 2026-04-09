import json
import threading
from asgiref.sync import sync_to_async
from channels.generic.websocket import AsyncWebsocketConsumer
from django.shortcuts import get_object_or_404
from django.utils import timezone

from .models import OLT, OLTLoginHistory
from .utils import close_telnet_session, open_telnet_authenticated_session, read_telnet_output, send_telnet_input


_CLI_WS_LOCK = threading.Lock()
_CLI_WS_SESSIONS = {}


def _session_key(user_id, olt_id):
    return f"{user_id}:{olt_id}"


class OLTCLIConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        user = self.scope.get('user')
        if not user or not user.is_authenticated:
            await self.close(code=4401)
            return

        self.user = user
        self.olt_id = int(self.scope['url_route']['kwargs']['pk'])
        self.olt = await sync_to_async(get_object_or_404)(OLT, pk=self.olt_id)

        # Ensure single active ws session per user+olt
        await sync_to_async(self._close_existing_session)()

        tn, status = await sync_to_async(open_telnet_authenticated_session)(self.olt)
        if tn is None:
            await self.accept()
            await self.send_json({'type': 'output', 'data': f"Connection failed: {status}\r\n"})
            await self.close()
            return

        with _CLI_WS_LOCK:
            _CLI_WS_SESSIONS[_session_key(self.user.id, self.olt_id)] = {
                'tn': tn,
                'updated_at': timezone.now(),
            }

        await self.accept()
        await self._log_action('cli_open', 'Interactive terminal opened')

        await sync_to_async(send_telnet_input)(tn, b"\r\n")
        banner = await sync_to_async(read_telnet_output)(tn, 0.2, 6)
        if banner:
            await self.send_json({'type': 'output', 'data': banner})

    async def disconnect(self, close_code):
        await sync_to_async(self._close_existing_session)()
        await self._log_action('cli_close', 'Interactive terminal closed')

    async def receive(self, text_data=None, bytes_data=None):
        if not text_data:
            return
        try:
            payload = json.loads(text_data)
        except json.JSONDecodeError:
            return

        if payload.get('type') != 'input':
            return

        data = payload.get('data', '')
        if not isinstance(data, str):
            return

        tn = await sync_to_async(self._get_session_tn)()
        if tn is None:
            await self.send_json({'type': 'output', 'data': "\r\nSession disconnected.\r\n"})
            return

        await sync_to_async(send_telnet_input)(tn, data)

        # Fast echo for single-key input, longer wait for Enter/tab/navigation.
        if data == "\t":
            output = await sync_to_async(read_telnet_output)(tn, 0.12, 10)
        elif data in ("\r", "\n", "\r\n") or data.startswith("\u001b"):
            output = await sync_to_async(read_telnet_output)(tn, 0.10, 12)
        elif data in ("\b", "\u007f"):
            output = await sync_to_async(read_telnet_output)(tn, 0.03, 5)
        else:
            output = await sync_to_async(read_telnet_output)(tn, 0.015, 2)
        if output:
            await self.send_json({'type': 'output', 'data': output})

        if '\r' in data or '\n' in data:
            first_line = data.replace('\r', '').replace('\n', '').strip()
            if first_line:
                await self._log_action('cli_command', f"Command: {first_line[:180]}")

    async def send_json(self, data):
        await self.send(text_data=json.dumps(data))

    def _get_session_tn(self):
        with _CLI_WS_LOCK:
            session = _CLI_WS_SESSIONS.get(_session_key(self.user.id, self.olt_id))
            if not session:
                return None
            session['updated_at'] = timezone.now()
            return session.get('tn')

    def _close_existing_session(self):
        key = _session_key(self.user.id, self.olt_id)
        with _CLI_WS_LOCK:
            session = _CLI_WS_SESSIONS.pop(key, None)
        if session:
            close_telnet_session(session.get('tn'))

    async def _log_action(self, action, details):
        username = getattr(self.user, 'username', '') or str(self.user)
        try:
            await sync_to_async(OLTLoginHistory.objects.create)(
                olt=self.olt,
                user=self.user,
                username=username,
                action=action[:50],
                details=(details or '')[:300],
            )
        except Exception:
            # Do not break interactive CLI if history table is not migrated yet.
            return
