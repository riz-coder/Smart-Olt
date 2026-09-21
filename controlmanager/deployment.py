"""Public tenant addresses and isolated client-initiated remote VPN configuration."""
import ipaddress
import os
import re
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


def public_control_hostname():
    value = os.environ.get('CONTROL_PUBLIC_HOSTNAME', '').strip().lower().rstrip('.')
    if not value:
        return ''
    if len(value) > 253 or any(
            not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', part)
            for part in value.split('.')):
        raise ValueError('CONTROL_PUBLIC_HOSTNAME must contain only a hostname, without a protocol or port.')
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return value
    raise ValueError('CONTROL_PUBLIC_HOSTNAME must be a hostname, not an IP address.')


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
        if not routes:
            raise ValueError('VPN requires at least one remote local/OLT subnet.')
        client_ip = None
        if tenant.client_public_ip:
            client_ip = ipaddress.ip_address(tenant.client_public_ip)
            if client_ip.version != 4:
                raise ValueError('Legacy client VPN endpoint must be IPv4.')
        # Tunnel addresses are unique /30s; overlapping customer LANs are fine.
        tunnel_network = tunnel_pool()
        for route in routes:
            if route.overlaps(tunnel_network) or ip in route or (client_ip and client_ip in route):
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
        # HTTPS and WireGuard share the canonical tenant hostname. WireGuard
        # remains isolated by its tenant-specific UDP port.
        endpoint_host = tenant.public_hostname or host
        tenant.wg_server_endpoint = f'{endpoint_host}:{tenant.vpn_listen_port}'
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
        # No Endpoint: remote clients may use dynamic IP/NAT and initiate the tunnel.
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


def _nginx_available_dir():
    return Path(os.environ.get('CONTROL_NGINX_SITES_AVAILABLE', '/etc/nginx/sites-available'))


def _nginx_enabled_dir():
    return Path(os.environ.get('CONTROL_NGINX_SITES_ENABLED', '/etc/nginx/sites-enabled'))


def _acme_webroot():
    return Path(os.environ.get('CONTROL_ACME_WEBROOT', '/var/www/letsencrypt'))


def _certificate_dir(hostname):
    base = Path(os.environ.get('CONTROL_CERTIFICATE_BASE_DIR', '/etc/letsencrypt/live'))
    return base / hostname


def _nginx_site_text(hostname, upstream_port, static_root, *, tls):
    challenge_root = str(_acme_webroot())
    http_action = 'return 301 https://$host$request_uri;' if tls else (
        'proxy_pass http://127.0.0.1:%s;\n'
        '        proxy_http_version 1.1;\n'
        '        proxy_set_header Host $host;\n'
        '        proxy_set_header X-Real-IP $remote_addr;\n'
        '        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n'
        '        proxy_set_header X-Forwarded-Proto $scheme;\n'
        '        proxy_set_header Upgrade $http_upgrade;\n'
        '        proxy_set_header Connection "upgrade";' % int(upstream_port)
    )
    text = (
        'server {\n'
        '    listen 80;\n'
        '    listen [::]:80;\n'
        f'    server_name {hostname};\n\n'
        '    location ^~ /.well-known/acme-challenge/ {\n'
        f'        root {challenge_root};\n'
        '        default_type text/plain;\n'
        '    }\n\n'
        '    location / {\n'
        f'        {http_action}\n'
        '    }\n'
        '}\n'
    )
    if not tls:
        return text
    cert_dir = _certificate_dir(hostname)
    return text + (
        '\nserver {\n'
        '    listen 443 ssl;\n'
        '    listen [::]:443 ssl;\n'
        f'    server_name {hostname};\n\n'
        f'    ssl_certificate {cert_dir / "fullchain.pem"};\n'
        f'    ssl_certificate_key {cert_dir / "privkey.pem"};\n'
        '    include /etc/letsencrypt/options-ssl-nginx.conf;\n\n'
        '    client_max_body_size 32m;\n'
        '    location /static/ {\n'
        f'        alias {str(static_root).rstrip("/")}/;\n'
        '        access_log off;\n'
        '        expires 7d;\n'
        '    }\n\n'
        '    location / {\n'
        f'        proxy_pass http://127.0.0.1:{int(upstream_port)};\n'
        '        proxy_http_version 1.1;\n'
        '        proxy_set_header Host $host;\n'
        '        proxy_set_header X-Real-IP $remote_addr;\n'
        '        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n'
        '        proxy_set_header X-Forwarded-Proto https;\n'
        '        proxy_set_header Upgrade $http_upgrade;\n'
        '        proxy_set_header Connection "upgrade";\n'
        '        proxy_read_timeout 300s;\n'
        '    }\n'
        '}\n'
    )


def _nginx_test_and_reload(run):
    ok, output = run(['nginx', '-t'], timeout=30)
    if ok:
        ok, output = run(['systemctl', 'reload', 'nginx'], timeout=30)
    return ok, output


def _ensure_certificate(hostname, run):
    cert_dir = _certificate_dir(hostname)
    if (cert_dir / 'fullchain.pem').is_file() and (cert_dir / 'privkey.pem').is_file():
        return
    email = os.environ.get('CONTROL_ACME_EMAIL', '').strip()
    if not email or '@' not in email:
        raise ValueError('Set CONTROL_ACME_EMAIL before provisioning public HTTPS sites.')
    ok, output = run([
        'certbot', 'certonly', '--webroot', '-w', str(_acme_webroot()),
        '-d', hostname, '--non-interactive', '--agree-tos', '--keep-until-expiring',
        '--email', email,
    ], timeout=180)
    if not ok:
        raise ValueError('HTTPS certificate could not be issued: ' + output[:300])


def _publish_nginx_site(name, hostname, upstream_port, static_root, run):
    available = _nginx_available_dir()
    enabled = _nginx_enabled_dir()
    if not available.is_dir() or not enabled.is_dir():
        raise ValueError('Nginx site directories are missing. Run the public gateway setup first.')
    _acme_webroot().mkdir(parents=True, exist_ok=True)
    path = available / name
    link = enabled / name
    previous = path.read_text(encoding='utf-8') if path.exists() else None
    link_existed = link.exists() or link.is_symlink()
    try:
        path.write_text(_nginx_site_text(hostname, upstream_port, static_root, tls=False), encoding='utf-8')
        os.chmod(path, 0o644)
        if available.resolve() != enabled.resolve() and not link_existed:
            link.symlink_to(path)
        ok, output = _nginx_test_and_reload(run)
        if not ok:
            raise ValueError(output[:300])
        _ensure_certificate(hostname, run)
        path.write_text(_nginx_site_text(hostname, upstream_port, static_root, tls=True), encoding='utf-8')
        ok, output = _nginx_test_and_reload(run)
        if not ok:
            raise ValueError(output[:300])
    except Exception as exc:
        if previous is None:
            path.unlink(missing_ok=True)
        else:
            path.write_text(previous, encoding='utf-8')
        if not link_existed and link != path:
            link.unlink(missing_ok=True)
        _nginx_test_and_reload(run)
        if isinstance(exc, ValueError):
            raise
        raise ValueError(f'Public Nginx proxy could not be activated: {exc}') from exc


def proxy_text(tenant, *, tls=True):
    # Validate even when called outside the create form.
    expected = f'{subdomain_label(tenant.subdomain)}.{base_domain()}'
    if not base_domain() or tenant.public_hostname != expected:
        raise ValueError('Tenant public hostname does not match CONTROL_BASE_DOMAIN.')
    port = int(tenant.panel_port)
    if not 1 <= port <= 65535:
        raise ValueError('Invalid tenant upstream port.')
    return _nginx_site_text(
        expected, port, Path(tenant.codebase_path) / 'staticfiles', tls=tls,
    )


def publish_proxy(tenant, run):
    if not tenant.public_hostname:
        remove_proxy(tenant, run)
        return
    _publish_nginx_site(
        f'optiverse-tenant-{int(tenant.pk)}', tenant.public_hostname, int(tenant.panel_port),
        Path(tenant.codebase_path) / 'staticfiles', run,
    )


def remove_proxy(tenant, run):
    available = _nginx_available_dir()
    enabled = _nginx_enabled_dir()
    path = available / f'optiverse-tenant-{int(tenant.pk)}'
    link = enabled / path.name
    if not path.exists() and not link.exists() and not link.is_symlink():
        return
    previous = path.read_text(encoding='utf-8') if path.exists() else None
    link_target = os.readlink(link) if link.is_symlink() else None
    path.unlink(missing_ok=True)
    if link != path:
        link.unlink(missing_ok=True)
    ok, output = _nginx_test_and_reload(run)
    if not ok:
        if previous is not None:
            path.write_text(previous, encoding='utf-8')
        if link != path and link_target is not None:
            link.symlink_to(link_target)
        raise ValueError('Could not remove the public tenant route: ' + output[:300])
