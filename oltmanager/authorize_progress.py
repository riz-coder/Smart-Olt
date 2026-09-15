"""Tenant-scoped authorization snapshots shared by all web processes."""
from pathlib import Path

from django.conf import settings
from django.core.cache.backends.filebased import FileBasedCache


def _store():
    # Progress must be tenant-scoped and shared across web processes.
    configured = getattr(settings, 'OPTIVERSE_RUNTIME_DIR', '')
    database = settings.DATABASES['default']
    if configured:
        directory = Path(configured)
    else:
        directory = Path(settings.BASE_DIR) / 'runtime' / database['NAME']
    return FileBasedCache(str(directory / 'authorize_progress'), {
        'TIMEOUT': 86400,
        'OPTIONS': {'MAX_ENTRIES': 10000},
    })


def save_authorize_progress(task_id, task):
    _store().set(str(task_id), dict(task))


def get_authorize_progress(task_id):
    return _store().get(str(task_id)) or {}
