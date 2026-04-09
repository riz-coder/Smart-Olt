from ..adapters import HuaweiOLTAdapter


def get_olt_adapter(olt):
    vendor = (getattr(olt, "vendor", "") or "").strip().lower()
    if "huawei" in vendor:
        return HuaweiOLTAdapter()
    # Default to Huawei for now because current command set targets Huawei OLTs.
    return HuaweiOLTAdapter()

