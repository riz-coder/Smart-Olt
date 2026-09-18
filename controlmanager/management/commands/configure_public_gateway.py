import os
import shutil
from pathlib import Path

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

from controlmanager import deployment
from controlmanager.services import _run_command


class Command(BaseCommand):
    help = 'Prepare the one-time Nginx/Certbot HTTPS gateway without changing unrelated sites.'

    def handle(self, *args, **options):
        try:
            tenant_domain = deployment.base_domain()
            control_host = deployment.public_control_hostname()
        except ValueError as exc:
            raise CommandError(str(exc)) from exc
        if not tenant_domain:
            raise CommandError('Set CONTROL_BASE_DOMAIN in .env.control first.')
        if not control_host:
            raise CommandError('Set CONTROL_PUBLIC_HOSTNAME in .env.control first.')
        if control_host == tenant_domain or not control_host.endswith(f'.{tenant_domain}'):
            raise CommandError('CONTROL_PUBLIC_HOSTNAME must be a subdomain of CONTROL_BASE_DOMAIN.')
        if os.name == 'nt':
            raise CommandError('Run this command on the Linux VPS.')
        for command in ('nginx', 'certbot', 'systemctl'):
            if not shutil.which(command):
                raise CommandError(f'Install {command} before configuring the public gateway.')

        port = int(os.environ.get('CONTROL_PUBLIC_UPSTREAM_PORT', '9000'))
        if not 1 <= port <= 65535:
            raise CommandError('Invalid control upstream port.')
        try:
            deployment._publish_nginx_site(
                'optiverse-control', control_host, port,
                Path(settings.BASE_DIR) / 'control_staticfiles', _run_command,
            )
        except ValueError as exc:
            raise CommandError(str(exc)) from exc
        self.stdout.write(self.style.SUCCESS(
            f'Nginx HTTPS gateway ready: https://{control_host}/; '
            f'tenants will use https://<name>.{tenant_domain}/'
        ))
