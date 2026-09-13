"""Tenant-scoped authorization snapshots shared by all web processes."""
from pathlib import Path

from django.conf import settings
from django.core.cache.backends.filebased import FileBasedCache


def _store():
    # The database's parent is the persistent tenant mount in both containers.
    database = Path(settings.DATABASES['default']['NAME']).resolve()
    return FileBasedCache(str(database.parent / 'authorize_progress'), {
        'TIMEOUT': 86400,
        'OPTIONS': {'MAX_ENTRIES': 10000},
    })


def save_authorize_progress(task_id, task):
    _store().set(str(task_id), dict(task))


def get_authorize_progress(task_id):
    return _store().get(str(task_id)) or {}
