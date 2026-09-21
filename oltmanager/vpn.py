import base64
import json
import os
import socket
import tempfile
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from django.conf import settings


class VPNError(RuntimeError):
    pass


def _state_dir():
    path = Path(settings.OPTIVERSE_WG_STATE_DIR)
    path.mkdir(parents=True, exist_ok=True)
    return path


def _client_path():
    return _state_dir() / "client.json"


def _atomic_json(path, payload):
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
    try:
        if hasattr(os, "fchmod"):
            os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, sort_keys=True, separators=(",", ":"))
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        os.chmod(path, 0o600)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def load_client_state():
    try:
        payload = json.loads(_client_path().read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None
    except (OSError, ValueError, TypeError) as exc:
        raise VPNError(f"Cannot read VPN client state: {exc}") from exc
    required = {"private_key", "public_key", "tunnel_address", "routes"}
    if not isinstance(payload, dict) or not required.issubset(payload):
        raise VPNError("VPN client state is incomplete")
    return payload


def ensure_client_state():
    state = load_client_state()
    if state:
        return state
    private_key = X25519PrivateKey.generate()
    private_raw = private_key.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    public_raw = private_key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    state = {
        "private_key": base64.b64encode(private_raw).decode("ascii"),
        "public_key": base64.b64encode(public_raw).decode("ascii"),
        "tunnel_address": "10.75.75.2/30",
        "routes": [],
    }
    _atomic_json(_client_path(), state)
    return state


def helper_request(operation, **values):
    request = {"op": operation, **values}
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.settimeout(5)
    try:
        client.connect(settings.OPTIVERSE_WG_SOCKET)
        client.sendall(json.dumps(request, separators=(",", ":")).encode("utf-8") + b"\n")
        stream = client.makefile("rb")
        line = stream.readline(65537)
    except (OSError, TimeoutError) as exc:
        raise VPNError(f"WireGuard helper is unavailable: {exc}") from exc
    finally:
        client.close()
    try:
        response = json.loads(line.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise VPNError("WireGuard helper returned an invalid response") from exc
    if not response.get("ok"):
        raise VPNError(str(response.get("error") or "WireGuard operation failed"))
    return response


def configure_client(routes):
    state = ensure_client_state()
    helper_request(
        "set_peer",
        public_key=state["public_key"],
        tunnel_client_address=state["tunnel_address"],
    )
    response = helper_request("set_routes", routes=routes)
    state["routes"] = list(response.get("routes") or [])
    _atomic_json(_client_path(), state)
    return state


def client_config():
    state = load_client_state()
    if not state:
        raise VPNError("Configure the VPN before downloading its client configuration")
    server = helper_request("server_key")
    public_host = str(getattr(settings, "OPTIVERSE_VPN_PUBLIC_HOST", "") or "").strip()
    public_port = int(getattr(settings, "OPTIVERSE_VPN_PORT", 0) or 0)
    if not public_host or not public_port:
        raise VPNError("VPN public endpoint is not configured")
    server_ip = str(server["tunnel_address"]).split("/", 1)[0]
    return "\n".join([
        "[Interface]",
        f"PrivateKey = {state['private_key']}",
        f"Address = {state['tunnel_address']}",
        "",
        "[Peer]",
        f"PublicKey = {server['public_key']}",
        f"Endpoint = {public_host}:{public_port}",
        f"AllowedIPs = {server_ip}/32",
        "PersistentKeepalive = 25",
        "",
    ])


def vpn_status():
    return helper_request("status")
