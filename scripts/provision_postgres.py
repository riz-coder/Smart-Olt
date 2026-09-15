"""Create the local PostgreSQL role/database described by a protected env file."""
import argparse
import os
from pathlib import Path
import subprocess

from psycopg import sql
def read_env(path):
    values = {}
    for raw in path.read_text(encoding='utf-8').splitlines():
        line = raw.strip()
        if line and not line.startswith('#') and '=' in line:
            key, value = line.split('=', 1)
            values[key.strip()] = value.strip().strip(chr(34)).strip(chr(39))
    return values


def provision(path, prefix=''):
    if os.geteuid() != 0:
        raise RuntimeError('Run as root; PostgreSQL peer administration is required.')
    env = read_env(path)
    name, user, password = (env[prefix + key] for key in ('DB_NAME', 'DB_USER', 'DB_PASSWORD'))
    if env.get(prefix + 'DB_HOST', '127.0.0.1') not in {'127.0.0.1', 'localhost'}:
        raise RuntimeError('This helper provisions local databases only.')
    if not name.startswith('optiverse_') or not user.startswith('optiverse_'):
        raise RuntimeError('Use the managed optiverse_ database/user prefix.')
    if not password or password.startswith('replace-'):
        raise RuntimeError('Set a generated DB_PASSWORD first.')
    def admin(statement):
        result = subprocess.run(['runuser', '-u', 'postgres', '--', 'psql', '-X', '-At', '-v', 'ON_ERROR_STOP=1', '-d', 'postgres'],
            input=statement.as_string(), text=True, capture_output=True, check=False)
        if result.returncode:
            raise RuntimeError('PostgreSQL provisioning failed. Check its service and administrator permissions.')
        return result.stdout.strip()
    if not admin(sql.SQL('SELECT 1 FROM pg_roles WHERE rolname={}').format(sql.Literal(user))):
        admin(sql.SQL('CREATE ROLE {} LOGIN PASSWORD {}').format(sql.Identifier(user), sql.Literal(password)))
    if not admin(sql.SQL('SELECT 1 FROM pg_database WHERE datname={}').format(sql.Literal(name))):
        admin(sql.SQL('CREATE DATABASE {} OWNER {} TEMPLATE template0').format(sql.Identifier(name), sql.Identifier(user)))
    print(f'PostgreSQL database ready: {name}')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--env', type=Path, required=True)
    parser.add_argument('--prefix', default='')
    args = parser.parse_args()
    provision(args.env, args.prefix)
