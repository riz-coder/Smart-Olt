from types import SimpleNamespace
from unittest.mock import patch

from django.test import SimpleTestCase

from . import utils


class OnuResetTests(SimpleTestCase):
    def test_factory_restore_common_oid_and_no_reboot(self):
        for tech in ('GPON', 'EPON'):
            with self.subTest(tech=tech), patch.object(utils, 'OltWriteOperationGuard') as guard, \
                 patch.object(utils, '_resolve_snmp_gpon_ifindex', return_value=42), \
                 patch.object(utils, '_snmp_set_value', return_value=(None, None, 0, [])) as send, \
                 patch.object(utils, 'execute_onu_cli_reset_action') as cli:
                guard.return_value.__enter__.return_value.ok = True
                olt = SimpleNamespace(snmp_write_community='test')
                result = utils.execute_onu_factory_restore_action(olt, 1, 2, 0)
                self.assertTrue(result['ok'])
                send.assert_called_once_with(olt, '1.3.6.1.4.1.2011.6.145.1.1.1.9.1.1.42.0',
                                             1, value_type='Integer', mp_model=1)
                cli.assert_not_called()

    def test_factory_restore_rejection_falls_back_but_timeout_does_not_repeat(self):
        for indication, status, fallback in [(None, 'notWritable', True), ('timeout', None, False)]:
            with self.subTest(indication=indication), patch.object(utils, 'OltWriteOperationGuard') as guard, \
                 patch.object(utils, '_resolve_snmp_gpon_ifindex', return_value=42), \
                 patch.object(utils, '_snmp_set_value', return_value=(indication, status, 0, [])), \
                 patch.object(utils, 'execute_onu_cli_reset_action', return_value={'ok': True}) as cli:
                guard.return_value.__enter__.return_value.ok = True
                olt = SimpleNamespace(snmp_write_community='test')
                result = utils.execute_onu_factory_restore_action(olt, 1, 2, 3, frame=0)
                if fallback:
                    cli.assert_called_once_with(olt, 1, 2, 3, frame=0, factory_restore=True)
                else:
                    cli.assert_not_called()
                    self.assertTrue(result['result_unknown'])

    def test_reset_uses_only_correct_control_table(self):
        olt = SimpleNamespace(snmp_write_community='test')
        for tech, table in [('GPON', 46), ('EPON', 57)]:
            with self.subTest(tech=tech), \
                 patch.object(utils, '_slot_pon_tech', return_value=tech), \
                 patch.object(utils, '_resolve_snmp_gpon_ifindex', return_value=4194304000), \
                 patch.object(utils, '_snmp_set_value', return_value=(None, None, 0, [])) as send:
                result = utils.execute_onu_snmp_control_action(olt, 1, 2, 7, 'reset', frame=0)
                self.assertTrue(result['ok'])
                send.assert_called_once_with(
                    olt, f'1.3.6.1.4.1.2011.6.128.1.1.2.{table}.1.2.4194304000.7',
                    1, value_type='Integer', mp_model=1,
                )

    def test_reset_failure_never_tries_capability_table(self):
        with patch.object(utils, '_slot_pon_tech', return_value='GPON'), \
             patch.object(utils, '_resolve_snmp_gpon_ifindex', return_value=42), \
             patch.object(utils, '_snmp_set_value', return_value=('timeout', None, 0, [])) as send:
            result = utils.execute_onu_snmp_control_action(
                SimpleNamespace(snmp_write_community='test'), 0, 0, 0, 'reset',
            )
            self.assertFalse(result['ok'])
            self.assertEqual(send.call_count, 2)
            self.assertTrue(all('.46.1.2.42.0' in call.args[1] for call in send.call_args_list))

    def test_cli_only_on_snmp_failure_and_same_target(self):
        olt = SimpleNamespace()
        for accepted in (True, False):
            with self.subTest(accepted=accepted), \
                 patch.object(utils, 'OltWriteOperationGuard') as guard, \
                 patch.object(utils, 'execute_onu_snmp_control_action', return_value={'ok': accepted}), \
                 patch.object(utils, 'execute_onu_cli_reset_action', return_value={'ok': True}) as cli:
                guard.return_value.__enter__.return_value.ok = True
                result = utils.execute_onu_reset_action(olt, 2, 3, 4, frame=1)
                self.assertTrue(result['ok'])
                if accepted:
                    cli.assert_not_called()
                else:
                    cli.assert_called_once_with(olt, 2, 3, 4, frame=1)
