from .. import utils


class HuaweiOLTAdapter:
    vendor = "huawei"

    def fetch_device_snapshot(self, olt):
        return utils.fetch_snmp_snapshot(olt)

    def fetch_cards(self, olt):
        return utils.fetch_olt_cards(olt)

    def fetch_pon_ports(self, olt):
        return utils.fetch_pon_ports_snapshot(olt)

    def open_telnet_session(self, olt):
        return utils.open_telnet_authenticated_session(olt)

    def run_session_command(self, tn, command):
        return utils.run_telnet_session_command(tn, command)

    def send_session_input(self, tn, data):
        return utils.send_telnet_input(tn, data)

    def read_session_output(self, tn, wait=0.2, rounds=5):
        return utils.read_telnet_output(tn, wait=wait, rounds=rounds)

    def close_telnet_session(self, tn):
        return utils.close_telnet_session(tn)
