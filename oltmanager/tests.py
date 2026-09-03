from django.test import SimpleTestCase

from .utils import (
    _format_sfp_tx_dbm,
    _parse_ont_autofind_blocks,
    _parse_pon_sfp_tx_from_text,
    _parse_service_port_detail_map_from_current_config,
    _parse_single_ont_optical_info,
    _parse_snmp_gpon_fsp_from_ifname,
)


class PonSfpTxParsingTests(SimpleTestCase):
    def test_parse_tx_value_after_label_not_port_number(self):
        output = "Port 7    TX optical power(dBm) : 7.17"

        self.assertEqual(_parse_pon_sfp_tx_from_text(output), "7.17 dBm")

    def test_parse_centidbm_tx_value(self):
        output = "TX power(dBm): 715"

        self.assertEqual(_parse_pon_sfp_tx_from_text(output), "7.15 dBm")

    def test_format_rejects_unreasonable_plain_dbm(self):
        self.assertEqual(_format_sfp_tx_dbm("715 dBm"), "7.15 dBm")
        self.assertEqual(_format_sfp_tx_dbm("99999"), "")


class SnmpIfIndexParsingTests(SimpleTestCase):
    def test_parse_flexible_gpon_ifnames(self):
        self.assertEqual(_parse_snmp_gpon_fsp_from_ifname("GPON 0/0/1"), (0, 0, 1))
        self.assertEqual(_parse_snmp_gpon_fsp_from_ifname("GPON0/0/1"), (0, 0, 1))
        self.assertEqual(_parse_snmp_gpon_fsp_from_ifname("GPON_0/0/1"), (0, 0, 1))
        self.assertEqual(_parse_snmp_gpon_fsp_from_ifname("0/0/1"), (0, 0, 1))


class OntAutofindParsingTests(SimpleTestCase):
    def test_parse_block_autofind_sn_from_display_value(self):
        output = """
        Number              : 1
        F/S/P               : 0/1/1
        Ont SN              : 48575443D47D5FAE (HWTCD47D5FAE)
        Ont EquipmentID     : MT-1504
        Ont autofind time   : 2026-09-03 13:09:56+05:00
        ----------------------------------------------------------------------------
        """

        rows = _parse_ont_autofind_blocks(output)

        self.assertEqual(rows[0]["sn"], "HWTCD47D5FAE")
        self.assertEqual(rows[0]["slot"], 1)
        self.assertEqual(rows[0]["port"], 1)

    def test_parse_plain_12_hex_autofind_serial(self):
        output = """
        F/S/P               : 0/2/3
        Ont SN              : 000062CD2C06
        ----------------------------------------------------------------------------
        """

        rows = _parse_ont_autofind_blocks(output)

        self.assertEqual(rows[0]["sn"], "000062CD2C06")

    def test_parse_epon_mac_autofind_row(self):
        output = """
        F/S/P               : 0/3/4
        Ont MAC             : E4A8-B6A4-2B92
        ----------------------------------------------------------------------------
        """

        rows = _parse_ont_autofind_blocks(output)

        self.assertEqual(rows[0]["sn"], "E4A8B6A42B92")
        self.assertEqual(rows[0]["pon_type"], "EPON")


class ServicePortProfileParsingTests(SimpleTestCase):
    def test_parse_service_port_profiles_by_onu(self):
        output = (
            "service-port 1060 vlan 10 gpon 0/7/0 ont 1 gemport 1 multi-service "
            "user-vlan 10 tag-transform translate inbound traffic-table index 20 "
            "outbound traffic-table index 30"
        )
        profile_map = {"20": "10M-UP", "30": "20M-DOWN"}

        parsed = _parse_service_port_detail_map_from_current_config(output, profile_map)

        self.assertEqual(parsed[(0, 7, 0, 1)]["service_port_id"], "1060")
        self.assertEqual(parsed[(0, 7, 0, 1)]["user_vlan"], "10")
        self.assertEqual(parsed[(0, 7, 0, 1)]["upload_profile_name"], "10M-UP")
        self.assertEqual(parsed[(0, 7, 0, 1)]["download_profile_name"], "20M-DOWN")


class OntOpticalParsingTests(SimpleTestCase):
    def test_parse_single_ont_optical_info(self):
        output = """
        Rx optical power(dBm)                  : -21.670
        Tx optical power(dBm)                  : 2.140
        OLT Rx ONT optical power(dBm)          : -30.000
        """

        parsed = _parse_single_ont_optical_info(output)

        self.assertEqual(parsed["onu_rx"], "-21.67 dBm")
        self.assertEqual(parsed["tx_power"], "2.14 dBm")
        self.assertEqual(parsed["olt_rx"], "-30.00 dBm")
