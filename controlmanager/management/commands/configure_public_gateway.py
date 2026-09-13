import json
import os
import shutil
from pathlib import Path

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

from controlmanager.deployment import base_domain
from controlmanager.services import _run_command


class Command(BaseCommand):
    help = 'Prepare the one-time public HTTPS gateway after DNS and .env.control are configured.'

    def handle(self, *args, **options):
        try:
            domain = base_domain()
        except ValueError as exc:
            raise CommandError(str(exc))
        if not domain:
            raise CommandError('Set CONTROL_BASE_DOMAIN in .env.control first.')
        if os.name == 'nt':
            raise CommandError('Run this command on the Ubuntu VPS.')
        if not shutil.which('caddy'):
            raise CommandError('Install Caddy first.')
        target = Path('/etc/caddy/Caddyfile')
        marker = '# Managed by OptiVerse public gateway'
        existing = target.read_text() if target.exists() else ''
        # A fresh package's stock Caddyfile is allowed; custom sites are preserved.
        stock = ' '.join(line.split('#', 1)[0].strip() for line in existing.splitlines()).split()
        is_stock = stock == ':80 { root * /usr/share/caddy file_server }'.split()
        if existing and marker not in existing and not is_stock:
            raise CommandError('Existing custom Caddyfile detected. Add the gateway import manually before proceeding.')
        sites = Path(os.environ.get('CONTROL_CADDY_SITES_DIR', '/etc/caddy/optiverse-tenants'))
        sites.mkdir(parents=True, exist_ok=True)
        os.chmod(sites, 0o755)
        port = int(os.environ.get('CONTROL_PUBLIC_UPSTREAM_PORT', '9000'))
        if not 1 <= port <= 65535:
            raise CommandError('Invalid control upstream port.')
        root = json.dumps(str(settings.BASE_DIR / 'control_staticfiles'))
        content = (f'{marker}\n'
                   f'{domain}, control.{domain} {{\n'
                   f'    handle_path /static/* {{\n        root * {root}\n        file_server\n    }}\n'
                   f'    handle {{\n        reverse_proxy 127.0.0.1:{port}\n    }}\n}}\n'
                   f'import {json.dumps(str(sites / "*.caddy"))}\n')
        backup = target.with_suffix('.before-optiverse')
        if existing and not backup.exists():
            backup.write_text(existing)
        target.write_text(content)
        ok, output = _run_command(['caddy', 'validate', '--config', str(target)], timeout=30)
        if not ok:
            target.write_text(existing)
            raise CommandError(output)
        ok, output = _run_command(['systemctl', 'reload-or-restart', 'caddy'], timeout=45)
        if not ok:
            target.write_text(existing)
            raise CommandError(output)
        self.stdout.write(self.style.SUCCESS('Public gateway ready. Apply connection settings to each existing tenant.'))
