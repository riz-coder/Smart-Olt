import base64
import ipaddress
import json
import os
import socket
import subprocess
import tempfile
import time
from pathlib import Path

from django.conf import settings


class WireGuardError(RuntimeError):
    pass


def _run(args, *, input_text=None, check=True):
    try:
        return subprocess.run(
            args,
            input=input_text,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=check,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        detail = getattr(exc, "stderr", "") or str(exc)
        raise WireGuardError(detail.strip()) from exc


class WireGuardHelper:
    interface = "wg0"
    tunnel_network = ipaddress.ip_network("10.75.75.0/30")
    server_address = "10.75.75.1/30"
    client_address = "10.75.75.2/30"

    def __init__(self):
        self.state_dir = Path(settings.OPTIVERSE_WG_STATE_DIR)
        self.socket_path = Path(settings.OPTIVERSE_WG_SOCKET)
        self.listen_port = int(settings.OPTIVERSE_WG_LISTEN_PORT)
        self.state_path = self.state_dir / "state.json"
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.state = self._load_state()

    def _generate_private_key(self):
        return _run(["wg", "genkey"]).stdout.strip()

    def _public_key(self):
        return _run(["wg", "pubkey"], input_text=self.state["server_private_key"] + "\n").stdout.strip()

    def _load_state(self):
        try:
            state = json.loads(self.state_path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            state = {}
        except (OSError, ValueError, TypeError) as exc:
            raise WireGuardError(f"Cannot read WireGuard state: {exc}") from exc
        if not state.get("server_private_key"):
            state["server_private_key"] = self._generate_private_key()
        state.setdefault("peer_public_key", "")
        state.setdefault("tunnel_client_address", self.client_address)
        state.setdefault("routes", [])
        self._save_state(state)
        return state

    def _save_state(self, state=None):
        state = state or self.state
        fd, temporary = tempfile.mkstemp(prefix=".state.", dir=str(self.state_dir))
        try:
            if hasattr(os, "fchmod"):
                os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(state, handle, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, self.state_path)
            os.chmod(self.state_path, 0o600)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)

    def _config(self):
        lines = [
            "[Interface]",
            f"PrivateKey = {self.state['server_private_key']}",
            f"ListenPort = {self.listen_port}",
        ]
        peer = self.state.get("peer_public_key")
        if peer:
            allowed = [str(ipaddress.ip_interface(self.client_address).ip) + "/32", *self.state.get("routes", [])]
            lines.extend(["", "[Peer]", f"PublicKey = {peer}", f"AllowedIPs = {','.join(allowed)}"])
        return "\n".join(lines) + "\n"

    def _existing_bridge_networks(self):
        result = _run(["ip", "-j", "route", "show"], check=False)
        try:
            rows = json.loads(result.stdout or "[]")
        except ValueError:
            rows = []
        networks = []
        for row in rows:
            destination = row.get("dst")
            device = str(row.get("dev") or "")
            if not destination or destination == "default" or device == self.interface:
                continue
            try:
                network = ipaddress.ip_network(destination, strict=False)
            except ValueError:
                continue
            if device.startswith(("eth", "br-", "docker", "ens", "enp")):
                networks.append(network)
        return networks

    def validate_routes(self, routes):
        if not isinstance(routes, list):
            raise WireGuardError("routes must be a JSON list")
        bridge_networks = self._existing_bridge_networks()
        normalized = []
        for raw in routes:
            try:
                network = ipaddress.ip_network(str(raw), strict=True)
            except ValueError as exc:
                raise WireGuardError(f"Invalid OLT subnet: {raw}") from exc
            if network.version != 4 or network.prefixlen == 0:
                raise WireGuardError("Default and non-IPv4 routes are not allowed")
            if network.overlaps(ipaddress.ip_network("10.75.75.0/24")):
                raise WireGuardError("OLT subnet overlaps the WireGuard tunnel pool")
            if any(network.overlaps(existing) for existing in bridge_networks):
                raise WireGuardError("OLT subnet overlaps a container/host connected network")
            normalized.append(str(network))
        if len(normalized) != len(set(normalized)):
            raise WireGuardError("Duplicate OLT subnets are not allowed")
        return sorted(normalized)

    def apply(self, *, previous_routes=None):
        _run(["ip", "link", "add", self.interface, "type", "wireguard"], check=False)
        fd, config_path = tempfile.mkstemp(prefix="wg-", dir=str(self.state_dir))
        try:
            if hasattr(os, "fchmod"):
                os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(self._config())
            _run(["wg", "setconf", self.interface, config_path])
        finally:
            if os.path.exists(config_path):
                os.unlink(config_path)
        _run(["ip", "address", "replace", self.server_address, "dev", self.interface])
        _run(["ip", "link", "set", "dev", self.interface, "mtu", "1420", "up"])
        for route in previous_routes or []:
            if route not in self.state.get("routes", []):
                _run(["ip", "route", "del", route, "dev", self.interface], check=False)
        for route in self.state.get("routes", []):
            _run(["ip", "route", "replace", route, "dev", self.interface, "src", "10.75.75.1"])

    def status(self):
        peer = self.state.get("peer_public_key")
        result = {
            "last_handshake_s": None,
            "rx_bytes": 0,
            "tx_bytes": 0,
            "routes": list(self.state.get("routes", [])),
            "peer_public_key": peer,
        }
        if not peer:
            return result
        handshakes = _run(["wg", "show", self.interface, "latest-handshakes"], check=False).stdout.splitlines()
        transfers = _run(["wg", "show", self.interface, "transfer"], check=False).stdout.splitlines()
        for line in handshakes:
            fields = line.split()
            if len(fields) == 2 and fields[0] == peer and fields[1].isdigit() and int(fields[1]) > 0:
                result["last_handshake_s"] = max(0, int(time.time()) - int(fields[1]))
        for line in transfers:
            fields = line.split()
            if len(fields) == 3 and fields[0] == peer:
                result["rx_bytes"], result["tx_bytes"] = int(fields[1]), int(fields[2])
        return result

    def request(self, payload):
        operation = payload.get("op") if isinstance(payload, dict) else None
        if operation == "server_key":
            return {"public_key": self._public_key(), "tunnel_address": self.server_address}
        if operation == "set_peer":
            public_key = str(payload.get("public_key") or "").strip()
            try:
                if len(base64.b64decode(public_key, validate=True)) != 32:
                    raise ValueError
            except ValueError as exc:
                raise WireGuardError("Invalid WireGuard peer public key") from exc
            client_address = str(payload.get("tunnel_client_address") or self.client_address)
            if client_address != self.client_address:
                raise WireGuardError(f"Client tunnel address must be {self.client_address}")
            self.state["peer_public_key"] = public_key
            self.state["tunnel_client_address"] = client_address
            self._save_state()
            self.apply()
            return {"peer_public_key": public_key, "tunnel_client_address": client_address}
        if operation == "set_routes":
            previous = list(self.state.get("routes", []))
            self.state["routes"] = self.validate_routes(payload.get("routes"))
            self._save_state()
            self.apply(previous_routes=previous)
            return {"routes": list(self.state["routes"])}
        if operation == "status":
            return self.status()
        raise WireGuardError("Unsupported operation")

    def serve(self, stop_requested):
        self.apply()
        self.socket_path.parent.mkdir(parents=True, exist_ok=True)
        if self.socket_path.exists() or self.socket_path.is_socket():
            self.socket_path.unlink()
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            server.bind(str(self.socket_path))
            os.chmod(self.socket_path, 0o660)
            server.listen(8)
            server.settimeout(1)
            while not stop_requested():
                try:
                    connection, _address = server.accept()
                except socket.timeout:
                    continue
                with connection:
                    stream = connection.makefile("rwb")
                    line = stream.readline(65537)
                    try:
                        if not line or len(line) > 65536:
                            raise WireGuardError("Invalid request size")
                        response = {"ok": True, **self.request(json.loads(line.decode("utf-8")))}
                    except (WireGuardError, ValueError, TypeError, json.JSONDecodeError) as exc:
                        response = {"ok": False, "error": str(exc)}
                    stream.write(json.dumps(response, separators=(",", ":")).encode("utf-8") + b"\n")
                    stream.flush()
        finally:
            server.close()
            if self.socket_path.exists():
                self.socket_path.unlink()
