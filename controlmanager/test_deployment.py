import os
import tempfile
from pathlib import Path
from unittest.mock import patch

from django.test import TestCase

from . import deployment
from .forms import TenantCreateForm
from .models import Tenant
from .services import _tenant_related_service_names, _wireguard_keypair, _write_tenant_env_file


class TenantDeploymentTests(TestCase):
    def setUp(self):
        self.env = patch.dict(os.environ, {'CONTROL_BASE_DOMAIN': '',
            'CONTROL_VPN_PUBLIC_HOST': '203.0.113.10',
            'CONTROL_VPN_TUNNEL_POOL': '10.75.75.0/24',
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
                tenant.database_name = 'optiverse_test'
                tenant.database_user = 'optiverse_test'
                tenant.database_password = 'test-only'
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
        self.assertIn('192.168.1.0/24', deployment.server_config(first))
        self.assertNotIn('192.168.1.0/24', deployment.client_config(first))
        self.assertIn('AllowedIPs = 10.75.75.1/32', deployment.client_config(first))
        self.assertEqual(first.vpn_server_address, '10.75.75.1/30')
        self.assertEqual(first.wg_client_address, '10.75.75.2/30')
        self.assertEqual(second.vpn_server_address, '10.75.75.5/30')
        self.assertEqual(second.wg_client_address, '10.75.75.6/30')
        self.assertIn('AllowedIPs = 10.75.75.2/32, 192.168.1.0/24', deployment.server_config(first))
        self.assertIn('Address = 10.75.75.1/30', deployment.server_config(first))
        self.assertIn(f'ListenPort = {first.vpn_listen_port}', deployment.server_config(first))

    def test_deleted_tenant_tunnel_slot_is_reused(self):
        first = self.tenant(vpn_enabled=True, client_public_ip='203.0.113.20', vpn_routes='192.168.1.0/24')
        deployment.prepare_deployment(first, _wireguard_keypair)
        first.delete()
        replacement = self.tenant('replacement', vpn_enabled=True,
            client_public_ip='203.0.113.21', vpn_routes='192.168.2.0/24')
        deployment.prepare_deployment(replacement, _wireguard_keypair)
        self.assertEqual(replacement.vpn_server_address, '10.75.75.1/30')
        self.assertEqual(replacement.wg_client_address, '10.75.75.2/30')

    def test_legacy_host_addresses_are_normalized_without_changing_ips(self):
        tenant = self.tenant(vpn_enabled=True, client_public_ip='203.0.113.20',
            vpn_routes='192.168.1.0/24', vpn_server_address='10.75.75.9/32',
            wg_client_address='10.75.75.10/32')
        deployment.prepare_deployment(tenant, _wireguard_keypair)
        self.assertEqual(tenant.vpn_server_address, '10.75.75.9/30')
        self.assertEqual(tenant.wg_client_address, '10.75.75.10/30')

    def test_reapply_preserves_keys(self):
        tenant = self.tenant(vpn_enabled=True, client_public_ip='203.0.113.20', vpn_routes='192.168.1.0/24')
        deployment.prepare_deployment(tenant, _wireguard_keypair)
        keys = (tenant.vpn_server_private_key, tenant.wg_client_private_key)
        deployment.prepare_deployment(tenant, _wireguard_keypair)
        self.assertEqual(keys, (tenant.vpn_server_private_key, tenant.wg_client_private_key))

    def test_dangerous_or_tunnel_routes_rejected(self):
        for value in ('0.0.0.0/0', '127.0.0.0/8', '::/0'):
            with self.assertRaises(ValueError):
                deployment.route_networks(value)
        tenant = self.tenant(vpn_enabled=True, client_public_ip='203.0.113.20', vpn_routes='10.75.75.0/24')
        with self.assertRaises(ValueError):
            deployment.prepare_deployment(tenant, _wireguard_keypair)

    def test_form_uses_name_for_subdomain_and_rejects_missing_vpn_details(self):
        form = TenantCreateForm(data={'name': 'nexus', 'owner_email': 'a@example.com',
            'panel_admin_username': 'admin', 'panel_admin_initial_password': 'test-password',
            'vpn_enabled': True})
        self.assertFalse(form.is_valid())
        self.assertIn('vpn_routes', form.errors)
        self.assertIn('client_public_ip', form.errors)

    def test_create_form_exposes_only_required_tenant_inputs(self):
        form = TenantCreateForm()
        self.assertEqual(list(form.fields), [
            'name', 'owner_email', 'panel_admin_username',
            'panel_admin_initial_password', 'vpn_enabled',
            'client_public_ip', 'vpn_routes',
        ])

    def test_local_creation_needs_no_vpn_endpoint(self):
        with patch.dict(os.environ, CONTROL_VPN_PUBLIC_HOST=''):
            form = TenantCreateForm(data={'name': 'nexus', 'owner_email': 'a@example.com',
                'panel_admin_username': 'admin', 'panel_admin_initial_password': 'test-password'})
            self.assertTrue(form.is_valid(), form.errors)

    def test_tenant_delete_targets_web_and_sync_services(self):
        tenant = self.tenant()
        tenant.service_name = 'optiverse-nexus.service'
        self.assertEqual(
            _tenant_related_service_names(tenant),
            ('optiverse-nexus', 'optiverse-nexus-sync'),
        )

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
