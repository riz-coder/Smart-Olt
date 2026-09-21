import os
import tempfile
from pathlib import Path
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse

from . import deployment
from .forms import TenantCreateForm
from .models import Tenant
from .services import (
    _tenant_related_service_names,
    _wireguard_keypair,
    _write_tenant_env_file,
    prepare_tenant_defaults,
)


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
            proxy = deployment.proxy_text(tenant)
            self.assertIn('server_name nexus.example.com;', proxy)
            self.assertIn('proxy_pass http://127.0.0.1:8001;', proxy)
            with tempfile.TemporaryDirectory() as directory:
                tenant.env_path = str(Path(directory) / '.env')
                tenant.database_name = 'optiverse_test'
                tenant.database_user = 'optiverse_test'
                tenant.database_password = 'test-only'
                _write_tenant_env_file(tenant)
                content = Path(tenant.env_path).read_text()
                self.assertIn('DJANGO_CSRF_TRUSTED_ORIGINS=https://nexus.example.com', content)
                self.assertIn('OPTIVERSE_PUBLIC_HOSTNAME=nexus.example.com', content)
                self.assertIn('DJANGO_SESSION_COOKIE_SECURE=True', content)
                self.assertIn(
                    'OLT_BACKGROUND_SYNC_THREADS=snmp_monitor,onu_status,signal_sample,inventory',
                    content,
                )

    def test_overlapping_lans_have_distinct_tunnels_keys_ports_and_networks(self):
        first = self.tenant(vpn_enabled=True, vpn_routes='192.168.1.0/24')
        second = self.tenant('second', vpn_enabled=True, vpn_routes='192.168.1.0/24')
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
        self.assertNotIn('Endpoint =', deployment.server_config(first))
        self.assertIn('Endpoint = 203.0.113.10:', deployment.client_config(first))
        self.assertIn('Address = 10.75.75.1/30', deployment.server_config(first))
        self.assertIn(f'ListenPort = {first.vpn_listen_port}', deployment.server_config(first))

    def test_deleted_tenant_tunnel_slot_is_reused(self):
        first = self.tenant(vpn_enabled=True, vpn_routes='192.168.1.0/24')
        deployment.prepare_deployment(first, _wireguard_keypair)
        first.delete()
        replacement = self.tenant('replacement', vpn_enabled=True, vpn_routes='192.168.2.0/24')
        deployment.prepare_deployment(replacement, _wireguard_keypair)
        self.assertEqual(replacement.vpn_server_address, '10.75.75.1/30')
        self.assertEqual(replacement.wg_client_address, '10.75.75.2/30')

    def test_legacy_host_addresses_are_normalized_without_changing_ips(self):
        tenant = self.tenant(vpn_enabled=True,
            vpn_routes='192.168.1.0/24', vpn_server_address='10.75.75.9/32',
            wg_client_address='10.75.75.10/32')
        deployment.prepare_deployment(tenant, _wireguard_keypair)
        self.assertEqual(tenant.vpn_server_address, '10.75.75.9/30')
        self.assertEqual(tenant.wg_client_address, '10.75.75.10/30')

    def test_reapply_preserves_keys(self):
        tenant = self.tenant(vpn_enabled=True, vpn_routes='192.168.1.0/24')
        deployment.prepare_deployment(tenant, _wireguard_keypair)
        keys = (tenant.vpn_server_private_key, tenant.wg_client_private_key)
        deployment.prepare_deployment(tenant, _wireguard_keypair)
        self.assertEqual(keys, (tenant.vpn_server_private_key, tenant.wg_client_private_key))

    def test_dangerous_or_tunnel_routes_rejected(self):
        for value in ('0.0.0.0/0', '127.0.0.0/8', '::/0'):
            with self.assertRaises(ValueError):
                deployment.route_networks(value)
        tenant = self.tenant(vpn_enabled=True, vpn_routes='10.75.75.0/24')
        with self.assertRaises(ValueError):
            deployment.prepare_deployment(tenant, _wireguard_keypair)

    def test_form_uses_name_for_subdomain_and_rejects_missing_vpn_routes(self):
        form = TenantCreateForm(data={'name': 'nexus', 'owner_email': 'a@example.com',
            'panel_admin_username': 'admin', 'panel_admin_initial_password': 'test-password',
            'vpn_enabled': True})
        self.assertFalse(form.is_valid())
        self.assertIn('vpn_routes', form.errors)

    def test_remote_vpn_does_not_require_client_public_ip(self):
        form = TenantCreateForm(data={'name': 'remote-isp', 'owner_email': 'a@example.com',
            'panel_admin_username': 'admin', 'panel_admin_initial_password': 'test-password',
            'vpn_enabled': True, 'vpn_routes': '192.168.50.0/24'})
        self.assertTrue(form.is_valid(), form.errors)

    def test_create_form_exposes_only_required_tenant_inputs(self):
        form = TenantCreateForm()
        self.assertEqual(list(form.fields), [
            'name', 'owner_email', 'panel_admin_username',
            'panel_admin_initial_password', 'vpn_enabled',
            'vpn_routes',
        ])

    def test_local_creation_needs_no_vpn_endpoint(self):
        with patch.dict(os.environ, CONTROL_VPN_PUBLIC_HOST=''):
            form = TenantCreateForm(data={'name': 'nexus', 'owner_email': 'a@example.com',
                'panel_admin_username': 'admin', 'panel_admin_initial_password': 'test-password'})
            self.assertTrue(form.is_valid(), form.errors)

    @patch('controlmanager.services._tenant_port_is_available', return_value=True)
    def test_new_tenant_never_keeps_reserved_base_port(self, port_available):
        tenant = Tenant.objects.create(name='new-tenant')

        prepare_tenant_defaults(tenant)

        self.assertEqual(tenant.panel_port, 8001)
        port_available.assert_called_with(8001)

    @patch('controlmanager.services._tenant_port_is_available')
    def test_new_tenant_skips_ports_already_occupied_on_linux(self, port_available):
        port_available.side_effect = lambda port: port >= 8003
        Tenant.objects.create(name='existing-tenant', panel_port=8001)
        tenant = Tenant.objects.create(name='new-tenant')

        prepare_tenant_defaults(tenant)

        self.assertEqual(tenant.panel_port, 8003)

    def test_tenant_delete_targets_web_and_sync_services(self):
        tenant = self.tenant()
        tenant.service_name = 'optiverse-nexus.service'
        self.assertEqual(
            _tenant_related_service_names(tenant),
            ('optiverse-nexus', 'optiverse-nexus-sync'),
        )

    @patch('controlmanager.services._run_command')
    def test_vpn_status_checks_the_tenant_specific_interface(self, run_command):
        tenant = self.tenant(vpn_enabled=True)
        user = get_user_model().objects.create_superuser(
            username='control-owner', email='owner@example.com', password='test-only-password',
        )
        self.client.force_login(user)
        run_command.return_value = (True, 'peer-public-key\t0')

        response = self.client.get(reverse('control_tenant_vpn_status', args=[tenant.pk]))

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()['interface'], f'optiverse-{tenant.pk}')
        run_command.assert_called_once_with(
            ['wg', 'show', f'optiverse-{tenant.pk}', 'latest-handshakes'], timeout=10,
        )

    def test_proxy_rollback_on_validation_failure(self):
        with patch.dict(os.environ, CONTROL_BASE_DOMAIN='example.com'):
            tenant = self.tenant()
            deployment.prepare_deployment(tenant, _wireguard_keypair)
            with tempfile.TemporaryDirectory() as directory:
                with patch.dict(os.environ, {
                    'CONTROL_NGINX_SITES_AVAILABLE': directory,
                    'CONTROL_NGINX_SITES_ENABLED': directory,
                    'CONTROL_ACME_WEBROOT': str(Path(directory) / 'acme'),
                }):
                    path = Path(directory) / f'optiverse-tenant-{tenant.pk}'
                    path.write_text('old configuration')
                    with self.assertRaises(ValueError):
                        deployment.publish_proxy(tenant, lambda *a, **k: (False, 'invalid'))
                    self.assertEqual(path.read_text(), 'old configuration')

    def test_nexecode_control_and_tenant_hostnames_are_independent(self):
        with patch.dict(os.environ, {
            'CONTROL_BASE_DOMAIN': 'nexecode.com',
            'CONTROL_PUBLIC_HOSTNAME': 'optiverse.nexecode.com',
        }):
            tenant = self.tenant('connect')
            deployment.prepare_deployment(tenant, _wireguard_keypair)
            self.assertEqual(deployment.public_control_hostname(), 'optiverse.nexecode.com')
            self.assertEqual(tenant.public_hostname, 'connect.nexecode.com')
            self.assertEqual(tenant.panel_url, 'https://connect.nexecode.com')

    def test_vpn_endpoint_uses_the_same_canonical_tenant_hostname(self):
        with patch.dict(os.environ, CONTROL_BASE_DOMAIN='nexecode.com'):
            tenant = self.tenant('connect', vpn_enabled=True, vpn_routes='192.168.10.0/24')
            deployment.prepare_deployment(tenant, _wireguard_keypair)

            self.assertEqual(
                tenant.wg_server_endpoint,
                f'connect.nexecode.com:{tenant.vpn_listen_port}',
            )
            self.assertIn(
                f'Endpoint = connect.nexecode.com:{tenant.vpn_listen_port}',
                deployment.client_config(tenant),
            )

    @patch('controlmanager.views.get_tenant_olts')
    @patch('controlmanager.views.refresh_tenant_database_snapshot')
    def test_postgresql_tenant_detail_loads_olts_without_legacy_database_path(
        self, refresh_snapshot, get_olts,
    ):
        tenant = self.tenant(
            database_engine='postgresql',
            database_name='optiverse_tenant_nexus',
            database_user='optiverse_tenant_nexus',
            database_password='test-only',
            database_path='',
        )
        user = get_user_model().objects.create_superuser(
            username='control-owner', email='owner@example.com', password='test-only-password',
        )
        self.client.force_login(user)
        get_olts.return_value = [{'id': 7, 'name': 'OLT-7'}]

        response = self.client.get(reverse('control_tenant_detail', args=[tenant.pk]))

        self.assertEqual(response.status_code, 200)
        refresh_snapshot.assert_called_once_with(tenant, record_snapshot=False)
        get_olts.assert_called_once_with(tenant)
        self.assertEqual(response.context['tenant_olts'], [{'id': 7, 'name': 'OLT-7'}])
