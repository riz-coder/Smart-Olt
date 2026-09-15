import os
from unittest import skipUnless
from unittest.mock import Mock, patch

from django.core.exceptions import ImproperlyConfigured
from django.test import SimpleTestCase, TransactionTestCase
from django.db import connection
from django.utils import timezone

from oltportal.database import database_config
from .tenant_database import Cursor
from .models import Tenant
from .services import get_tenant_olts, get_tenant_olt_onus, update_tenant_olt_pricing, delete_tenant_onu, delete_tenant_olt
from .services import _postgres_admin_query


class PostgresConfigurationTests(SimpleTestCase):
    def test_postgres_configuration_is_explicit_and_asgi_safe(self):
        with patch.dict(os.environ, {'DB_ENGINE': 'postgresql', 'DB_NAME': 'tenant',
                'DB_USER': 'tenant', 'DB_PASSWORD': 'test-only'}, clear=True):
            config = database_config()
        self.assertEqual(config['ENGINE'], 'django.db.backends.postgresql')
        self.assertEqual(config['NAME'], 'tenant')
        self.assertEqual(config['CONN_MAX_AGE'], 0)

    def test_control_database_settings_are_isolated(self):
        with patch.dict(os.environ, {'DB_ENGINE': 'postgresql', 'DB_NAME': 'app',
                'CONTROL_DB_NAME': 'control', 'CONTROL_DB_USER': 'control', 'CONTROL_DB_PASSWORD': 'test-only'}, clear=True):
            config = database_config('CONTROL_')
        self.assertEqual(config['NAME'], 'control')

    def test_missing_credentials_fail_without_silent_fallback(self):
        with patch.dict(os.environ, {'DB_ENGINE': 'postgresql'}, clear=True):
            with self.assertRaises(ImproperlyConfigured):
                database_config()

    def test_control_query_placeholders_and_case_ordering(self):
        raw = Mock()
        Cursor(raw, 'postgresql').execute('SELECT name FROM oltmanager_olt WHERE id=%s ORDER BY LOWER(name)', [4])
        raw.execute.assert_called_once_with('SELECT name FROM oltmanager_olt WHERE id=%s ORDER BY LOWER(name)', [4])

    def test_unsupported_engine_is_rejected(self):
        with patch.dict(os.environ, {'DB_ENGINE': 'unsupported'}, clear=True):
            with self.assertRaises(ImproperlyConfigured):
                database_config()

    def test_windows_admin_lookup_handles_missing_role(self):
        from psycopg import sql
        with patch.dict(os.environ, {'CONTROL_PG_ADMIN_PASSWORD': 'test-only'}), \
                patch('controlmanager.services.os.name', 'nt'), patch('psycopg.connect') as connect:
            cursor = connect.return_value.__enter__.return_value.execute.return_value
            cursor.description = ('exists',)
            cursor.fetchone.return_value = None
            self.assertIsNone(_postgres_admin_query(sql.SQL('SELECT 1 FROM pg_roles WHERE false')))
            cursor.fetchone.return_value = (1,)
            self.assertEqual(_postgres_admin_query(sql.SQL('SELECT 1')), 1)


@skipUnless(connection.vendor == 'postgresql', 'Requires a PostgreSQL test database')
class PostgresTenantQueryTests(TransactionTestCase):
    """Real PostgreSQL reads/pricing/deletions, confined to the Django test DB."""
    def setUp(self):
        with connection.cursor() as cursor:
            cursor.execute("""CREATE TABLE oltmanager_olt (
                id integer PRIMARY KEY, name varchar(160), ip_address inet,
                hardware_version varchar(100), sw_version varchar(100), snmp_last_status text,
                pricing_mode varchar(20), pricing_expires_at timestamptz,
                pricing_locked boolean, pricing_locked_reason text)""")
            cursor.execute("""CREATE TABLE oltmanager_configuredonu (
                id integer PRIMARY KEY, olt_id integer REFERENCES oltmanager_olt(id),
                slot integer, port integer, ont_id integer, sn text, description text,
                derived_status text, attached_vlans_cache text, onu_rx text, olt_rx text,
                ont_distance_m double precision)""")
            cursor.execute("INSERT INTO oltmanager_olt VALUES (1,'Nexus','192.168.1.1','test','test','ok','standard',NULL,false,'')")
            cursor.execute("INSERT INTO oltmanager_configuredonu VALUES (1,1,0,1,2,'ABC','Client','online','100','-20','-21',3)")
        config = connection.settings_dict
        self.tenant = Tenant.objects.create(name='postgres-test', database_engine='postgresql',
            database_name=config['NAME'], database_user=config['USER'], database_password=config['PASSWORD'],
            database_host=config['HOST'], database_port=int(config['PORT'] or 5432))

    def tearDown(self):
        with connection.cursor() as cursor:
            cursor.execute('DROP TABLE oltmanager_configuredonu')
            cursor.execute('DROP TABLE oltmanager_olt')
        super().tearDown()

    def test_tenant_queries_pricing_and_deletion(self):
        row = get_tenant_olts(self.tenant)[0]
        self.assertEqual(row['online_count'], 1)
        self.assertEqual(row['ip_address'], '192.168.1.1')
        _, onus = get_tenant_olt_onus(self.tenant, 1, 'ABC')
        self.assertEqual(len(onus), 1)
        expiry = timezone.now()
        update_tenant_olt_pricing(self.tenant, 1, pricing_mode='custom', expires_at=expiry, locked=True)
        row = get_tenant_olts(self.tenant)[0]
        self.assertTrue(row['pricing_locked'])
        self.assertEqual(row['pricing_expires_at'], expiry)
        self.assertIn('deleted=1', delete_tenant_onu(self.tenant, 1))
        self.assertIn('deleted=1', delete_tenant_olt(self.tenant, 1))
