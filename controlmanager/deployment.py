"""Public tenant addresses and isolated site-to-site VPN configuration."""
import ipaddress
import os
import re
import json
from pathlib import Path


RESERVED_LABELS = {'www', 'control', 'admin', 'api', 'mail', 'smtp', 'ftp', 'vpn'}


def subdomain_label(value):
    label = str(value or '').strip().lower()
    if not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label) or label in RESERVED_LABELS:
        raise ValueError('Use letters, numbers and hyphens for the subdomain. Names such as control and www are reserved.')
    return label


def base_domain():
    value = os.environ.get('CONTROL_BASE_DOMAIN', '').strip().lower().rstrip('.')
    if value and (len(value) > 189 or '.' not in value or any(
            not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', p) for p in value.split('.'))):
        raise ValueError('CONTROL_BASE_DOMAIN must contain only a domain name, without a protocol or port.')
    if value:
        try:
            ipaddress.ip_address(value)
        except ValueError:
            pass
        else:
            raise ValueError('CONTROL_BASE_DOMAIN must be a domain, not an IP address.')
    return value


def route_networks(value):
    networks = []
    for item in re.split(r'[,\s]+', str(value or '').strip()):
        if not item:
            continue
        net = ipaddress.ip_network(item, strict=False)
        if net.version != 4 or net.prefixlen == 0 or net.is_loopback or net.is_multicast or net.is_link_local:
            raise ValueError('Enter specific IPv4 local or OLT subnets. The default route is not allowed.')
        networks.append(net)
    return list(ipaddress.collapse_addresses(networks))


def tunnel_pool():
    pool = ipaddress.ip_network(os.environ.get('CONTROL_VPN_TUNNEL_POOL', '10.75.75.0/24'))
    if pool.version != 4 or pool.prefixlen > 24:
        raise ValueError('CONTROL_VPN_TUNNEL_POOL must be an IPv4 /24 or larger pool.')
    return pool


def host_route(value):
    return f'{ipaddress.ip_interface(value).ip}/32'


def _allocate_tunnel_addresses(tenant):
    pool = tunnel_pool()
    # Preserve an already valid pair when connection settings are reapplied.
    try:
        server = ipaddress.ip_interface(tenant.vpn_server_address)
        client = ipaddress.ip_interface(tenant.wg_client_address)
        existing = ipaddress.ip_network(f'{server.ip}/30', strict=False)
        if (client.ip in existing and existing.subnet_of(pool)
                and server.ip == existing.network_address + 1
                and client.ip == existing.network_address + 2):
            return f'{server.ip}/30', f'{client.ip}/30'
    except ValueError:
        pass

    from .models import Tenant
    used = set()
    for server_address in Tenant.objects.exclude(pk=tenant.pk).exclude(vpn_server_address='').values_list('vpn_server_address', flat=True):
        try:
            used.add(ipaddress.ip_network(f'{ipaddress.ip_interface(server_address).ip}/30', strict=False))
        except ValueError:
            continue
    for subnet in pool.subnets(new_prefix=30):
        server_ip = subnet.network_address + 1
        if subnet not in used:
            return f'{server_ip}/30', f'{subnet.network_address + 2}/30'
    raise ValueError('VPN tunnel address pool is exhausted. Configure a larger non-overlapping pool.')


def prepare_deployment(tenant, keypair):
    from .models import Tenant
    if not tenant.subdomain:
        candidate = re.sub(r'[^a-z0-9-]+', '-', tenant.slug.lower()).strip('-')[:50] or 'isp'
        if candidate in RESERVED_LABELS:
            candidate = f'isp-{candidate}'
        if Tenant.objects.exclude(pk=tenant.pk).filter(subdomain=candidate).exists():
            candidate = f'{candidate}-{tenant.pk}'
        tenant.subdomain = candidate
    tenant.subdomain = subdomain_label(tenant.subdomain)
    domain = base_domain()
    tenant.public_hostname = f'{tenant.subdomain}.{domain}' if domain else ''
    if tenant.vpn_enabled:
        host = os.environ.get('CONTROL_VPN_PUBLIC_HOST', '').strip()
        try:
            ip = ipaddress.ip_address(host)
            if ip.version != 4:
                raise ValueError('Use the VPS IPv4 address for CONTROL_VPN_PUBLIC_HOST.')
        except ValueError as exc:
            raise ValueError('Set CONTROL_VPN_PUBLIC_HOST to the server public IPv4 address before enabling VPN.') from exc
        routes = route_networks(tenant.vpn_routes)
        if not routes or not tenant.client_public_ip:
            raise ValueError('VPN requires the client public IPv4 and local/OLT subnets.')
        client_ip = ipaddress.ip_address(tenant.client_public_ip)
        if client_ip.version != 4:
            raise ValueError('Client VPN endpoint must be IPv4.')
        # Tunnel addresses are unique /30s; overlapping customer LANs are fine.
        tunnel_network = tunnel_pool()
        for route in routes:
            if route.overlaps(tunnel_network) or ip in route or client_ip in route:
                raise ValueError('Client route overlaps the VPN tunnel pool or public endpoint. Use a distinct subnet.')
        tenant.vpn_server_address, tenant.wg_client_address = _allocate_tunnel_addresses(tenant)
        if not tenant.vpn_listen_port:
            port = int(os.environ.get('CONTROL_VPN_PORT_START', '52000')) + int(tenant.pk)
            if not 1024 <= port <= 65535:
                raise ValueError('VPN UDP port is outside the available range.')
            if Tenant.objects.exclude(pk=tenant.pk).filter(vpn_listen_port=port).exists():
                raise ValueError('VPN UDP port already allocated.')
            tenant.vpn_listen_port = port
        if not 1 <= int(tenant.client_vpn_port) <= 65535:
            raise ValueError('Client VPN port must be between 1 and 65535.')
        if not tenant.vpn_server_private_key:
            tenant.vpn_server_private_key, tenant.wg_server_public_key = keypair()
        if not tenant.wg_client_private_key:
            tenant.wg_client_private_key, tenant.wg_client_public_key = keypair()
        tenant.wg_server_endpoint = f'{host}:{tenant.vpn_listen_port}'
        tenant.vpn_routes = '\n'.join(map(str, routes))
    tenant.save(update_fields=['subdomain', 'public_hostname', 'vpn_listen_port',
        'vpn_server_address', 'vpn_server_private_key', 'wg_server_public_key',
        'wg_client_address', 'wg_client_private_key', 'wg_client_public_key',
        'wg_server_endpoint', 'vpn_routes', 'updated_at'])


def client_config(tenant):
    if not tenant.vpn_enabled:
        raise ValueError('VPN is not enabled for this tenant.')
    return '\n'.join([
        '[Interface]', f'PrivateKey = {tenant.wg_client_private_key}',
        f'Address = {tenant.wg_client_address}', f'ListenPort = {tenant.client_vpn_port}',
        '', '[Peer]', f'PublicKey = {tenant.wg_server_public_key}',
        f'Endpoint = {tenant.wg_server_endpoint}',
        # Customer LANs are behind this client, not behind the server!
        f'AllowedIPs = {host_route(tenant.vpn_server_address)}', 'PersistentKeepalive = 25', '',
    ])


def server_config(tenant):
    allowed = [host_route(tenant.wg_client_address), *map(str, route_networks(tenant.vpn_routes))]
    return '\n'.join([
        '[Interface]', f'PrivateKey = {tenant.vpn_server_private_key}',
        f'Address = {tenant.vpn_server_address}', f'ListenPort = {tenant.vpn_listen_port}',
        '', '[Peer]', f'PublicKey = {tenant.wg_client_public_key}',
        f'Endpoint = {tenant.client_public_ip}:{tenant.client_vpn_port}',
        f'AllowedIPs = {", ".join(allowed)}', 'PersistentKeepalive = 25', '',
    ])


def write_vpn_files(tenant):
    directory = Path(tenant.env_path).parent / 'vpn'
    directory.mkdir(parents=True, exist_ok=True)
    for name, content in [('wg0.conf', server_config(tenant)), ('client.conf', client_config(tenant))]:
        path = directory / name
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, 'w', encoding='utf-8') as handle:
            handle.write(content)
        os.chmod(path, 0o600)
    tenant.wg_config_path = str(directory / 'client.conf')
    tenant.save(update_fields=['wg_config_path', 'updated_at'])


def proxy_text(tenant):
    # Validate even when called outside the create form.
    expected = f'{subdomain_label(tenant.subdomain)}.{base_domain()}'
    if not base_domain() or tenant.public_hostname != expected:
        raise ValueError('Tenant public hostname does not match CONTROL_BASE_DOMAIN.')
    port = int(tenant.panel_port)
    if not 1 <= port <= 65535:
        raise ValueError('Invalid tenant upstream port.')
    static_root = json.dumps(str(Path(tenant.codebase_path) / 'staticfiles'))
    return (f'{expected} {{\n'
            f'    handle_path /static/* {{\n        root * {static_root}\n        file_server\n    }}\n'
            f'    handle {{\n        reverse_proxy 127.0.0.1:{port}\n    }}\n}}\n')


def publish_proxy(tenant, run):
    if not tenant.public_hostname:
        remove_proxy(tenant, run)
        return
    directory = Path(os.environ.get('CONTROL_CADDY_SITES_DIR', '/etc/caddy/optiverse-tenants'))
    if not directory.is_dir():
        raise ValueError('Public proxy is not installed. Run the public deployment setup first.')
    path = directory / f'tenant-{tenant.pk}.caddy'
    previous = path.read_text() if path.exists() else None
    path.write_text(proxy_text(tenant), encoding='utf-8')
    os.chmod(path, 0o644)
    ok, output = run(['caddy', 'validate', '--config', '/etc/caddy/Caddyfile'], timeout=30)
    if ok:
        ok, output = run(['systemctl', 'reload', 'caddy'], timeout=30)
    if not ok:
        if previous is None:
            path.unlink(missing_ok=True)
        else:
            path.write_text(previous, encoding='utf-8')
        raise ValueError('Public proxy configuration could not be activated: ' + output[:300])


def remove_proxy(tenant, run):
    directory = Path(os.environ.get('CONTROL_CADDY_SITES_DIR', '/etc/caddy/optiverse-tenants'))
    path = directory / f'tenant-{tenant.pk}.caddy'
    if not path.exists():
        return
    previous = path.read_text()
    path.unlink()
    ok, output = run(['caddy', 'validate', '--config', '/etc/caddy/Caddyfile'], timeout=30)
    if ok:
        ok, output = run(['systemctl', 'reload', 'caddy'], timeout=30)
    if not ok:
        path.write_text(previous)
        raise ValueError('Could not remove the public tenant route: ' + output[:300])
