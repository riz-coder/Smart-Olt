import re

NUM = r"[-+]?\d+(?:\.\d+)?(?:e[-+]?\d+)?"


def parse_tx_value(text):
    if not text:
        return ""
    patterns = (
        rf"(?i)\btx(?:\s*power)?(?:\s*\(dbm\))?\s*[:=]\s*({NUM})",
        rf"(?i)\btransmit\s+power(?:\s*\(dbm\))?\s*[:=]\s*({NUM})",
        rf"(?i)\btx(?:\s*power)?(?:\s*\(dbm\))?\s+({NUM})",
        rf"(?i)\btxpower(?:\s*\(dbm\))?\s*[:=]?\s*({NUM})",
    )
    for pattern in patterns:
        match = re.search(pattern, text)
        if match:
            return f"{match.group(1)} dBm"
    return ""


def parse_tx_map_from_bulk_output(slot, text):
    tx_map = {}
    if not text:
        return tx_map

    table_patterns = (
        re.compile(
            rf"(?im)^\s*0/{re.escape(str(slot))}/(\d+)\s+.*?\btx(?:\s*power|power)?(?:\s*\(dbm\))?\s*[:=]?\s*({NUM})"
        ),
        re.compile(
            rf"(?im)^\s*0/{re.escape(str(slot))}/(\d+)\s+.*?({NUM})\s*(?:dbm)?\s*$"
        ),
    )
    for pattern in table_patterns:
        for match in pattern.finditer(text):
            port = int(match.group(1))
            value = match.group(2)
            tx_map[port] = f"{value} dBm"

    if tx_map:
        return tx_map

    current_port = None
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        pm = re.search(rf"\b0/{re.escape(str(slot))}/(\d+)\b", line)
        if pm:
            current_port = int(pm.group(1))
            continue
        if current_port is None:
            continue
        tx_value = parse_tx_value(line)
        if tx_value:
            tx_map[current_port] = tx_value
            current_port = None

    return tx_map


def parse_tx_map_from_scu_bulk_output(port_numbers, text):
    tx_map = {}
    if not text:
        return tx_map
    port_set = set(port_numbers or [])
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        match = re.match(r"^(\d+)\s+(.+)$", line)
        if not match:
            # Also support lines like "0/1/3 ... TxPower..."
            m2 = re.match(r"^0/\d+/(\d+)\s+(.+)$", line)
            if not m2:
                continue
            port = int(m2.group(1))
            remainder = m2.group(2)
        else:
            port = int(match.group(1))
            remainder = match.group(2)

        if port not in port_set:
            continue
        tx_value = parse_tx_value(remainder)
        if tx_value:
            tx_map[port] = tx_value
            continue
        end_value = re.search(rf"({NUM})\s*(?:dbm)?\s*$", remainder, flags=re.IGNORECASE)
        if end_value:
            tx_map[port] = f"{end_value.group(1)} dBm"
    return tx_map
