import asyncio
import json
import threading
from asgiref.sync import sync_to_async
from channels.generic.websocket import AsyncWebsocketConsumer
from django.shortcuts import get_object_or_404
from django.utils import timezone

from .models import OLT, OLTLoginHistory
from .utils import close_telnet_session, open_telnet_authenticated_session, read_telnet_raw, send_telnet_input


_CLI_WS_LOCK = threading.Lock()
_CLI_WS_SESSIONS = {}

# Telnet read/write run off the ORM thread so the continuous output pump and the
# keystroke writer overlap (a real terminal needs both directions at once).
_read_raw = sync_to_async(read_telnet_raw, thread_sensitive=False)
_write_input = sync_to_async(send_telnet_input, thread_sensitive=False)


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
        self._pump_task = None

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

        # Stream device output continuously; nudge for the initial prompt.
        self._pump_task = asyncio.create_task(self._pump_output())
        await _write_input(tn, b"\r\n")

    async def disconnect(self, close_code):
        task = getattr(self, '_pump_task', None)
        if task:
            task.cancel()
            try:
                await task
            except (asyncio.CancelledError, Exception):
                pass
        await sync_to_async(self._close_existing_session)()
        await self._log_action('cli_close', 'Interactive terminal closed')

    async def _pump_output(self):
        """Continuously forward raw device output to the browser terminal."""
        try:
            while True:
                tn = await sync_to_async(self._get_session_tn)()
                if tn is None:
                    await self.send_json({'type': 'output', 'data': "\r\nSession disconnected.\r\n"})
                    break
                data = await _read_raw(tn)
                if data is None:
                    await self.send_json({'type': 'output', 'data': "\r\nSession closed.\r\n"})
                    break
                if data:
                    await self.send_json({'type': 'output', 'data': data})
                    # Brief yield keeps bursts (help/tab/long dumps) flowing smoothly.
                    await asyncio.sleep(0.005)
                else:
                    await asyncio.sleep(0.035)
        except asyncio.CancelledError:
            return
        except Exception:
            return

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

        # Send the raw keystroke(s) straight to the device. The device echoes and
        # handles its own line editing (backspace, tab completion, '?' help); the
        # output pump renders whatever comes back — exactly like PuTTY.
        await _write_input(tn, data)

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
