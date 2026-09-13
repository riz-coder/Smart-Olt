import os
import tempfile
from pathlib import Path
from unittest.mock import patch

from django.test import TestCase

from . import deployment
from .forms import TenantCreateForm
from .models import Tenant
from .services import _wireguard_keypair, _write_tenant_env_file
from .services import _write_docker_tenant_runtime


class TenantDeploymentTests(TestCase):
    def setUp(self):
        self.env = patch.dict(os.environ, {'CONTROL_BASE_DOMAIN': '',
            'CONTROL_VPN_PUBLIC_HOST': '203.0.113.10',
            'CONTROL_VPN_TUNNEL_POOL': '10.254.0.0/16',
            'CONTROL_VPN_TRANSPORT_POOL': '172.30.0.0/16', 'CONTROL_VPN_PORT_START': '52000'})
        self.env.start()
        self.addCleanup(self.env.stop)

    def tenant(self, name='nexus', **kwargs):
        return Tenant.objects.create(name=name, panel_host='10.101.11.22', panel_port=8001,
                                     codebase_path='/opt/optiverse/Smart-Olt', **kwargs)

    def test_blank_domain_preserves_local_url(self):
        tenant = self.tenant()
        deployment.prepare_deployment(tenant, _wireguard_keypair)
        self.assertEqual(tenant.panel_url, 'http://10.101.11.22:8001')
        self.assertEqual(tenant.subdomain, 'nexus')
        self.assertFalse(tenant.vpn_enabled)

    def test_public_url_has_no_internal_port_and_secure_env(self):
        with patch.dict(os.environ, CONTROL_BASE_DOMAIN='example.com'):
            tenant = self.tenant()
            deployment.prepare_deployment(tenant, _wireguard_keypair)
            self.assertEqual(tenant.panel_url, 'https://nexus.example.com')
            self.assertIn('reverse_proxy 127.0.0.1:8001', deployment.proxy_text(tenant))
            with tempfile.TemporaryDirectory() as directory:
                tenant.env_path = str(Path(directory) / '.env')
                tenant.database_path = str(Path(directory) / 'db.sqlite3')
                _write_tenant_env_file(tenant)
                content = Path(tenant.env_path).read_text()
                self.assertIn('DJANGO_CSRF_TRUSTED_ORIGINS=https://nexus.example.com', content)
                self.assertIn('DJANGO_SESSION_COOKIE_SECURE=True', content)

    def test_overlapping_lans_have_distinct_tunnels_keys_ports_and_networks(self):
        first = self.tenant(vpn_enabled=True, client_public_ip='203.0.113.20', vpn_routes='192.168.1.0/24')
        second = self.tenant('second', vpn_enabled=True, client_public_ip='203.0.113.30', vpn_routes='192.168.1.0/24')
        for item in (first, second):
            deployment.prepare_deployment(item, _wireguard_keypair)
        for field in ('vpn_server_address', 'wg_client_address', 'vpn_listen_port', 'wg_client_public_key'):
            self.assertNotEqual(getattr(first, field), getattr(second, field))
        self.assertNotEqual(deployment.vpn_transport_subnet(first), deployment.vpn_transport_subnet(second))
        self.assertIn('192.168.1.0/24', deployment.server_config(first))
        self.assertNotIn('192.168.1.0/24', deployment.client_config(first))
        self.assertIn(f'AllowedIPs = {first.vpn_server_address}', deployment.client_config(first))

    def test_reapply_preserves_keys(self):
        tenant = self.tenant(vpn_enabled=True, client_public_ip='203.0.113.20', vpn_routes='192.168.1.0/24')
        deployment.prepare_deployment(tenant, _wireguard_keypair)
        keys = (tenant.vpn_server_private_key, tenant.wg_client_private_key)
        deployment.prepare_deployment(tenant, _wireguard_keypair)
        self.assertEqual(keys, (tenant.vpn_server_private_key, tenant.wg_client_private_key))

    def test_dangerous_or_transport_routes_rejected(self):
        for value in ('0.0.0.0/0', '127.0.0.0/8', '::/0'):
            with self.assertRaises(ValueError):
                deployment.route_networks(value)
        tenant = self.tenant(vpn_enabled=True, client_public_ip='203.0.113.20', vpn_routes='172.30.1.0/24')
        with self.assertRaises(ValueError):
            deployment.prepare_deployment(tenant, _wireguard_keypair)

    def test_form_rejects_missing_vpn_routes_and_reserved_subdomain(self):
        form = TenantCreateForm(data={'name': 'nexus', 'owner_email': 'a@example.com',
            'panel_admin_username': 'admin', 'panel_admin_initial_password': 'test-password',
            'subdomain': 'control', 'vpn_enabled': True})
        self.assertFalse(form.is_valid())
        self.assertIn('subdomain', form.errors)
        self.assertIn('vpn_routes', form.errors)
        self.assertIn('client_public_ip', form.errors)

    def test_local_creation_needs_no_vpn_endpoint(self):
        with patch.dict(os.environ, CONTROL_VPN_PUBLIC_HOST=''):
            form = TenantCreateForm(data={'name': 'nexus', 'owner_email': 'a@example.com',
                'panel_admin_username': 'admin', 'panel_admin_initial_password': 'test-password'})
            self.assertTrue(form.is_valid(), form.errors)

    def test_proxy_rollback_on_validation_failure(self):
        with patch.dict(os.environ, CONTROL_BASE_DOMAIN='example.com'):
            tenant = self.tenant()
            deployment.prepare_deployment(tenant, _wireguard_keypair)
            with tempfile.TemporaryDirectory() as directory:
                with patch.dict(os.environ, CONTROL_CADDY_SITES_DIR=directory):
                    path = Path(directory) / f'tenant-{tenant.pk}.caddy'
                    path.write_text('old configuration')
                    with self.assertRaises(ValueError):
                        deployment.publish_proxy(tenant, lambda *a, **k: (False, 'invalid'))
                    self.assertEqual(path.read_text(), 'old configuration')

    def test_vpn_runtime_has_one_container_and_no_host_network_capability(self):
        tenant = self.tenant(vpn_enabled=True, client_public_ip='203.0.113.20', vpn_routes='192.168.1.0/24')
        deployment.prepare_deployment(tenant, _wireguard_keypair)
        with tempfile.TemporaryDirectory() as directory:
            tenant.codebase_path = directory
            tenant.env_path = str(Path(directory) / '.env')
            tenant.database_path = str(Path(directory) / 'db.sqlite3')
            Path(directory, 'manage.py').touch()
            Path(tenant.database_path).touch()
            calls = []

            def run(args, **kwargs):
                calls.append(args)
                return (False, '') if 'inspect' in args else (True, 'container-id')

            with patch('controlmanager.services._run_command', side_effect=run), \
                 patch('controlmanager.services._prepare_docker_lock_permissions'), \
                 patch('controlmanager.services._wait_tenant_http'), \
                 patch('controlmanager.services._docker_user_args', return_value=['--user', '1000:1000']):
                _write_docker_tenant_runtime(tenant)
            launches = [args for args in calls if args[:3] == ['docker', 'run', '-d']]
            self.assertEqual(len(launches), 1)
            launch = launches[0]
            self.assertNotIn('host', launch)
            self.assertIn('NET_ADMIN', launch)
            self.assertIn('run_tenant', launch)
            self.assertIn('/app/docker/vpn_entrypoint.py', launch)
            self.assertEqual(tenant.worker_container_name, '')
