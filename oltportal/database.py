"""Explicit database configuration shared by portal and control plane."""
import os
from django.core.exceptions import ImproperlyConfigured


def database_config(prefix=''):
    def value(key, default=''):
        return os.environ.get(prefix + key, default)
    engine = value('DB_ENGINE', 'postgresql').lower()
    if engine in {'postgres', 'postgresql', 'django.db.backends.postgresql'}:
        required = ['DB_NAME', 'DB_USER', 'DB_PASSWORD']
        missing = [key for key in required if not value(key)]
        if missing:
            raise ImproperlyConfigured('Missing PostgreSQL settings: ' + ', '.join(prefix + key for key in missing))
        return {'ENGINE': 'django.db.backends.postgresql', 'NAME': value('DB_NAME'),
                'USER': value('DB_USER'), 'PASSWORD': value('DB_PASSWORD'),
                'HOST': value('DB_HOST', '127.0.0.1'), 'PORT': value('DB_PORT', '5432'),
                'CONN_MAX_AGE': max(0, int(value('DB_CONN_MAX_AGE', '0') or 0)),
                'CONN_HEALTH_CHECKS': True,
                'OPTIONS': {'connect_timeout': 10, 'sslmode': value('DB_SSLMODE', 'prefer')}}
    raise ImproperlyConfigured('Only PostgreSQL is supported. Unsupported DB_ENGINE: ' + engine)
