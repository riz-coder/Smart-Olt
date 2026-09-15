"""Authenticated, non-device-mutating HTTP smoke checks after migration."""
import argparse
import importlib
import os
from pathlib import Path
import sys
import time
import urllib.request

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--settings', default='oltportal.settings')
    parser.add_argument('--port', type=int, default=8000)
    parser.add_argument('--paths', nargs='+', default=['/', '/configured/', '/configured/status-sync/progress/', '/unconfigured/'])
    args = parser.parse_args()
    os.environ['DJANGO_SETTINGS_MODULE'] = args.settings
    os.environ['OLT_DISABLE_EMBEDDED_SYNC'] = '1'
    os.environ['OLT_ENABLE_EMBEDDED_SYNC'] = 'false'
    import django
    django.setup()
    from django.conf import settings
    from django.contrib.auth import get_user_model
    from django.db import connection
    if connection.vendor != 'postgresql':
        raise RuntimeError('The smoke-check process is not using PostgreSQL.')
    print('Database backend: PostgreSQL', flush=True)
    user = get_user_model().objects.filter(is_superuser=True, is_active=True).first()
    if not user:
        raise RuntimeError('No active superuser was migrated.')
    store = importlib.import_module(settings.SESSION_ENGINE).SessionStore()
    store['_auth_user_id'] = str(user.pk)
    store['_auth_user_backend'] = 'django.contrib.auth.backends.ModelBackend'
    store['_auth_user_hash'] = user.get_session_auth_hash()
    store.set_expiry(600)
    store.save()
    try:
        for path in args.paths:
            request = urllib.request.Request(f'http://127.0.0.1:{args.port}{path}',
                headers={'Cookie': f'{settings.SESSION_COOKIE_NAME}={store.session_key}'})
            started = time.monotonic()
            with urllib.request.urlopen(request, timeout=45) as response:
                body = response.read()
                if '/login/' in response.url:
                    raise RuntimeError('Authenticated request unexpectedly returned the login page.')
                print(f'{path}: HTTP {response.status}, {time.monotonic() - started:.3f}s, {len(body)} bytes', flush=True)
    finally:
        store.delete()
