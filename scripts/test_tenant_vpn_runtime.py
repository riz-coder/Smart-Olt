"""Disposable Linux Docker test; never touches a real tenant, OLT, or public port."""
import base64
import json
import subprocess
import tempfile
import time
import uuid
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey


def command(*args):
    return subprocess.check_output(list(args), text=True, stderr=subprocess.STDOUT).strip()


def keys():
    key = X25519PrivateKey.generate()
    private = key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                                serialization.NoEncryption())
    public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return base64.b64encode(private).decode(), base64.b64encode(public).decode()


def main():
    name = 'optiverse-vpntest-' + uuid.uuid4().hex[:10]
    containers = []
    network = None
    image = 'optiverse-tenant-app:latest'
    codebase = Path(__file__).resolve().parent.parent
    with tempfile.TemporaryDirectory(prefix='optiverse-vpntest-') as directory:
        try:
            network = command('docker', 'network', 'create', '--label', 'optiverse.test=true', name)
            info = json.loads(command('docker', 'network', 'inspect', network))[0]
            import ipaddress
            subnet = ipaddress.ip_network(info['IPAM']['Config'][0]['Subnet'])
            ips = [str(subnet.network_address + 2), str(subnet.network_address + 3)]
            pair = [keys(), keys()]
            for index in range(2):
                opposite = 1-index
                allowed = f'10.254.250.{opposite+1}/32'
                if index == 0:
                    allowed += ', 10.80.99.1/32'
                config = Path(directory) / f'{index}.conf'
                config.write_text(f'[Interface]\nPrivateKey = {pair[index][0]}\nListenPort = 51820\n\n'
                                  f'[Peer]\nPublicKey = {pair[opposite][1]}\nEndpoint = {ips[opposite]}:51820\n'
                                  f'AllowedIPs = {allowed}\nPersistentKeepalive = 1\n')
                config.chmod(0o600)
                container = command('docker', 'run', '-d', '--name', f'{name}-{index}',
                    '--network', name, '--ip', ips[index], '--cap-add', 'NET_ADMIN', '--user', '0:0',
                    '-v', f'{codebase}:/app:ro', '-v', f'{config}:/run/optiverse/wg0.conf:ro',
                    '-e', 'OPTIVERSE_RUN_USER=1000:1000',
                    '-e', f'OPTIVERSE_VPN_ADDRESS=10.254.250.{index+1}/32',
                    '-e', f'OPTIVERSE_VPN_ROUTES={allowed.replace(" ", "")}',
                    image, 'python', '/app/docker/vpn_entrypoint.py', 'sleep', '120')
                containers.append(container)
            time.sleep(3)
            command('docker', 'exec', '--user', '0:0', containers[1],
                    'ip', 'addr', 'add', '10.80.99.1/32', 'dev', 'lo')
            command('docker', 'exec', '-d', containers[1], 'python', '-m', 'http.server',
                    '18880', '--bind', '10.80.99.1')
            probe = "import urllib.request; print(urllib.request.urlopen('http://10.80.99.1:18880', timeout=3).status)"
            for attempt in range(10):
                try:
                    result = command('docker', 'exec', containers[0], 'python', '-c', probe)
                    if result != '200':
                        raise RuntimeError(result)
                    break
                except subprocess.CalledProcessError:
                    if attempt == 9:
                        raise
                    time.sleep(1)
            handshake = command('docker', 'exec', '--user', '0:0', containers[0],
                                'wg', 'show', 'wg0', 'latest-handshakes')
            assert int(handshake.split()[-1]) > 0
            route = command('docker', 'exec', containers[0], 'ip', 'route', 'get', '10.80.99.1')
            assert 'dev wg0' in route and 'src 10.254.250.1' in route, route
            print('PASS: Ubuntu-style tunnel handshake + routed HTTP 200 + correct tunnel source IP.')
        finally:
            for container in containers:
                command('docker', 'rm', '-f', container)
            if network:
                command('docker', 'network', 'rm', network)
            print('Disposable VPN test containers/network cleaned up.')


if __name__ == '__main__':
    main()
