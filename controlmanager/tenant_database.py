"""Control-plane DB-only access to PostgreSQL tenants."""
import ipaddress

import psycopg
from psycopg.rows import dict_row


DATABASE_ERRORS = (psycopg.Error, ValueError)


class Cursor:
    def __init__(self, raw, vendor):
        self.raw, self.vendor = raw, vendor

    def execute(self, query, params=None):
        self.raw.execute(query, params or [])
        return self

    def fetchall(self):
        return [self._normalize(row) for row in self.raw.fetchall()]

    def fetchone(self):
        return self._normalize(self.raw.fetchone())

    def _normalize(self, row):
        if row is not None and self.vendor == 'postgresql':
            return {key: str(value) if isinstance(value, (ipaddress.IPv4Address, ipaddress.IPv6Address)) else value
                    for key, value in row.items()}
        return row

    @property
    def rowcount(self):
        return self.raw.rowcount


class Connection:
    def __init__(self, raw, vendor):
        self.raw, self.vendor = raw, vendor

    def cursor(self):
        return Cursor(self.raw.cursor(), self.vendor)

    def commit(self):
        self.raw.commit()

    def rollback(self):
        self.raw.rollback()

    def close(self):
        self.raw.close()


def connect(tenant, read_only=True):
    if tenant.database_engine != 'postgresql' or not all((tenant.database_name, tenant.database_user, tenant.database_password)):
        raise ValueError('Tenant PostgreSQL credentials are incomplete; migration is required.')
    raw = psycopg.connect(dbname=tenant.database_name, user=tenant.database_user,
        password=tenant.database_password, host=tenant.database_host,
        port=tenant.database_port, row_factory=dict_row, connect_timeout=10)
    raw.read_only = read_only
    return Connection(raw, 'postgresql')


def table_exists(cursor, name):
    cursor.execute('SELECT 1 FROM information_schema.tables WHERE table_schema=\'public\' AND table_name=%s', [name])
    return cursor.fetchone() is not None


def columns(cursor, table):
    cursor.execute("SELECT column_name AS name FROM information_schema.columns WHERE table_schema='public' AND table_name=%s", [table])
    return {row['name'] for row in cursor.fetchall()}


def references(cursor, target):
    if cursor.vendor == 'postgresql':
        cursor.execute("""SELECT tc.table_name, kcu.column_name FROM information_schema.table_constraints tc
            JOIN information_schema.key_column_usage kcu ON tc.constraint_name=kcu.constraint_name
                AND tc.constraint_schema=kcu.constraint_schema
            JOIN information_schema.constraint_column_usage ccu ON tc.constraint_name=ccu.constraint_name
                AND tc.constraint_schema=ccu.constraint_schema
            WHERE tc.constraint_type='FOREIGN KEY' AND tc.table_schema='public' AND ccu.table_name=%s""", [target])
        return [(row['table_name'], row['column_name']) for row in cursor.fetchall()]


def size_mb(tenant):
    conn = connect(tenant)
    try:
        cursor = conn.cursor()
        cursor.execute('SELECT pg_database_size(current_database()) AS size')
        return cursor.fetchone()['size'] / 1024 ** 2
    finally:
        conn.close()
