import os
import socket
import time
from datetime import datetime, timezone


def env(name, default=""):
    return os.environ.get(name, default).strip()


TENANT_ID = env("OPTIVERSE_TENANT_ID", "unknown")
API_URL = env("OPTIVERSE_API_URL", "unknown")
OLT_SUBNET = env("OPTIVERSE_OLT_MANAGEMENT_SUBNET", "")
CONFIG_DIR = env("OPTIVERSE_TENANT_CONFIG_DIR", "")


def log(message):
    stamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
    print(f"{stamp} tenant={TENANT_ID} {message}", flush=True)


def main():
    log("OptiVerse tenant agent started")
    log(f"api_url={API_URL}")
    log(f"olt_management_subnet={OLT_SUBNET or '-'}")
    log(f"config_dir={CONFIG_DIR or '-'}")
    log(f"hostname={socket.gethostname()}")

    # Phase-1 placeholder loop. Future Phase-2 will poll the control API for
    # queued OLT/SNMP/CLI jobs and post heartbeat/status back.
    while True:
        log("alive")
        time.sleep(60)


if __name__ == "__main__":
    main()
