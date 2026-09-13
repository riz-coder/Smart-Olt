"""Shared completion state for mapping, speed/VLAN and ONU actions."""
import os
import time
from collections.abc import MutableMapping
from pathlib import Path

from .authorize_progress import _store


def _process_birth(pid):
    try:
        # Field 22, after the command name (which can contain spaces).
        return Path(f'/proc/{int(pid)}/stat').read_text().rsplit(')', 1)[1].split()[19]
    except (OSError, IndexError, ValueError):
        return ''


class _Snapshot(dict):
    def __init__(self, data, save):
        super().__init__(data)
        self._save = save

    def __setitem__(self, key, value):
        super().__setitem__(key, value)
        self._save(self)

    def update(self, *args, **kwargs):
        super().update(*args, **kwargs)
        self._save(self)


class SharedTasks(MutableMapping):
    def __init__(self, kind):
        self.kind = kind
        self.local_keys = set()

    def key(self, task_id):
        return f'operation:{self.kind}:{task_id}'

    def __getitem__(self, task_id):
        value = _store().get(self.key(task_id))
        if value is None:
            raise KeyError(task_id)
        if not value.get('done') and value.get('_birth') and _process_birth(value['_pid']) != value['_birth']:
            value.update(done=True, ok=False, result_unknown=True,
                         message='The app restarted before completion could be confirmed. Check the ONU state before retrying.')
            _store().set(self.key(task_id), value)
        return _Snapshot(value, lambda data: self._save(task_id, data))

    def _save(self, task_id, value):
        data = dict(value)
        data['_updated_at'] = time.time()
        _store().set(self.key(task_id), data)

    def __setitem__(self, task_id, value):
        data = dict(value)
        data.setdefault('_pid', os.getpid())
        data.setdefault('_birth', _process_birth(os.getpid()))
        self._save(task_id, data)
        self.local_keys.add(task_id)

    def __delitem__(self, task_id):
        _store().delete(self.key(task_id))
        self.local_keys.discard(task_id)

    def __iter__(self):
        return iter([key for key in list(self.local_keys) if _store().get(self.key(key)) is not None])

    def __len__(self):
        return sum(1 for _ in self)
