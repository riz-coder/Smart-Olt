from unittest.mock import Mock, patch

from django.test import SimpleTestCase

from . import views


class OnboardingDatabaseLockTests(SimpleTestCase):
    def test_duplicate_worker_does_not_run(self):
        cursor = Mock()
        cursor.fetchone.return_value = (False,)
        fake_connection = Mock()
        fake_connection.cursor.return_value = cursor
        with patch.object(views, 'connection', fake_connection), \
                patch.object(views, '_run_olt_onboarding_worker_locked') as worker:
            views._run_olt_onboarding_worker(17, 'manual')
        worker.assert_not_called()
        cursor.execute.assert_called_once_with('SELECT pg_try_advisory_lock(%s, %s)', [0x4F4C54, 17])

    def test_lock_is_released_after_worker_finishes(self):
        cursor = Mock()
        cursor.fetchone.return_value = (True,)
        fake_connection = Mock()
        fake_connection.cursor.return_value = cursor
        with patch.object(views, 'connection', fake_connection), \
                patch.object(views, '_run_olt_onboarding_worker_locked') as worker:
            views._run_olt_onboarding_worker(18, 'manual')
        worker.assert_called_once_with(18, 'manual')
        self.assertEqual(cursor.execute.call_args_list[-1].args,
                         ('SELECT pg_advisory_unlock(%s, %s)', [0x4F4C54, 18]))
