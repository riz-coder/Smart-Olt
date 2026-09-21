"""Signed OptiVerse entitlement client used by tenant web and worker roles."""

import base64
import datetime as dt
import json
import os
import tempfile
import threading
import urllib.error
import urllib.request
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import urlparse

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from django.conf import settings
from django.db import transaction
from django.utils import timezone
from django.utils.dateparse import parse_datetime

from oltmanager.models import ConfiguredONU, OLT
from oltmanager.vpn import VPNError, vpn_status


class LicenceError(RuntimeError):
    pass


class LicenceNotConfigured(LicenceError):
    pass


_PROCESS_LOCK = threading.RLock()


@contextmanager
def _licence_lock():
    """Serialize cache/state changes across web and worker processes on Linux."""
    with _PROCESS_LOCK:
        lock_path = _runtime_dir() / "licence.lock"
        handle = lock_path.open("a+b")
        try:
            try:
                import fcntl
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            except ImportError:  # Windows development fallback; process lock still applies.
                pass
            yield
        finally:
            try:
                import fcntl
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
            except ImportError:
                pass
            handle.close()


def licence_is_configured():
    return bool(
        getattr(settings, "OPTIVERSE_LICENCE_URL", "")
        and getattr(settings, "OPTIVERSE_LICENCE_TOKEN", "")
    )


def _runtime_dir():
    raw = str(getattr(settings, "OPTIVERSE_RUNTIME_DIR", "") or "").strip()
    path = Path(raw) if raw else Path(settings.BASE_DIR) / "runtime"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _request_json(method, path_or_url, body=None, *, authenticated=True):
    if not licence_is_configured() and authenticated:
        raise LicenceNotConfigured("OptiVerse licence API is not configured.")
    url = path_or_url if path_or_url.startswith(("http://", "https://")) else f"{settings.OPTIVERSE_LICENCE_URL}/{path_or_url.lstrip('/')}"
    headers = {"Accept": "application/json"}
    data = None
    if authenticated:
        headers["Authorization"] = f"Bearer {settings.OPTIVERSE_LICENCE_TOKEN}"
    if body is not None:
        data = json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(url, data=data, headers=headers, method=method)
    timeout = int(getattr(settings, "OPTIVERSE_LICENCE_TIMEOUT_SECONDS", 10))
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            payload = response.read()
            parsed = json.loads(payload.decode("utf-8")) if payload else {}
            return parsed, dict(response.headers.items())
    except urllib.error.HTTPError as exc:
        detail = exc.read(2048).decode("utf-8", errors="replace")
        raise LicenceError(f"Licence API returned HTTP {exc.code}: {detail}") from exc
    except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
        raise LicenceError(f"Licence API request failed: {exc}") from exc


def _extract_public_key(payload):
    if isinstance(payload, str):
        return payload
    if not isinstance(payload, dict):
        return ""
    data = payload.get("data") if isinstance(payload.get("data"), dict) else payload
    for key in ("public_key", "key", "pem"):
        if data.get(key):
            return str(data[key])
    return ""


def _public_key(kid):
    cache_path = _runtime_dir() / f"licence-public-key-{str(kid or 'default').replace('/', '_')}.pem"
    if cache_path.exists():
        return cache_path.read_bytes()
    payload, _headers = _request_json(
        "GET",
        settings.OPTIVERSE_LICENCE_PUBLIC_KEY_URL,
        authenticated=True,
    )
    pem = _extract_public_key(payload).encode("utf-8")
    if not pem:
        raise LicenceError("Licence public-key response did not contain a PEM key.")
    _atomic_write(cache_path, pem, mode=0o644)
    return pem


def _canonical_signed_bytes(data):
    signed = dict(data)
    signed.pop("signature", None)
    signed.pop("signature_kid", None)
    signed.pop("signature_alg", None)
    return json.dumps(signed, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def _verify(data, headers):
    if not isinstance(data, dict):
        raise LicenceError("Licence validate response has no data object.")
    kid = data.get("signature_kid") or headers.get("X-License-Signature-Kid") or headers.get("x-license-signature-kid")
    algorithm = data.get("signature_alg") or headers.get("X-License-Signature-Alg") or headers.get("x-license-signature-alg")
    signature = data.get("signature")
    # Older Laravel responses label the same RSA PKCS#1/SHA-256 signature as
    # "sha256". RS256 is the protocol name; accept the legacy label while still
    # performing the identical asymmetric verification below.
    if str(algorithm or "").upper() not in {"RS256", "SHA256"} or not signature:
        raise LicenceError("Licence response signature metadata is missing or unsupported.")
    try:
        key = serialization.load_pem_public_key(_public_key(kid))
        key.verify(
            base64.b64decode(signature, validate=True),
            _canonical_signed_bytes(data),
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
    except (ValueError, TypeError, InvalidSignature) as exc:
        raise LicenceError("Licence response signature verification failed.") from exc


def _atomic_write(path, content, *, mode=0o600):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
    try:
        if hasattr(os, "fchmod"):
            os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        os.chmod(path, mode)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _cache_path():
    return _runtime_dir() / "licence.json"


def _write_verified_cache(data):
    document = {
        "received_at": timezone.now().astimezone(dt.timezone.utc).isoformat().replace("+00:00", "Z"),
        "data": data,
    }
    _atomic_write(
        _cache_path(),
        json.dumps(document, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8"),
    )
    return document


def _read_cache():
    try:
        return json.loads(_cache_path().read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return None


def _expiry(value):
    parsed = parse_datetime(str(value or ""))
    if parsed and timezone.is_naive(parsed):
        parsed = timezone.make_aware(parsed, dt.timezone.utc)
    return parsed


def _apply(data):
    licence_status = str(data.get("status") or "").lower()
    global_lock = licence_status in {"suspended", "expired"}
    rows = {str(item.get("ref")): item for item in data.get("olts", []) if isinstance(item, dict) and item.get("ref")}
    with transaction.atomic():
        for olt in OLT.objects.select_for_update().all():
            entitlement = rows.get(str(olt.licence_ref))
            status = str((entitlement or {}).get("status") or "absent").lower()
            reason = str((entitlement or {}).get("reason") or "").strip()
            if global_lock:
                locked = True
                reason = f"Licence is {licence_status}."
            else:
                locked = status != "active"
                if locked and not reason:
                    reason = {
                        "pending": "Payment pending. Pay to activate this OLT.",
                        "absent": "OLT is not included in the verified licence.",
                    }.get(status, "OLT subscription is locked.")
            olt.licence_status = status
            olt.pricing_locked = locked
            olt.pricing_locked_reason = reason if locked else ""
            olt.pricing_expires_at = _expiry((entitlement or {}).get("expires_at"))
            olt.save(update_fields=[
                "licence_status", "pricing_locked", "pricing_locked_reason", "pricing_expires_at"
            ])
    return {"licence_status": licence_status, "olt_count": len(rows)}


def _lock_all_after_expired_grace():
    cached = _read_cache()
    received = parse_datetime(str((cached or {}).get("received_at") or ""))
    grace = int(getattr(settings, "OPTIVERSE_LICENCE_GRACE_SECONDS", 72 * 60 * 60))
    if received and timezone.is_naive(received):
        received = timezone.make_aware(received, dt.timezone.utc)
    if received and timezone.now() - received <= dt.timedelta(seconds=grace):
        return False
    OLT.objects.update(
        licence_status="network_grace_expired",
        pricing_locked=True,
        pricing_locked_reason="Licence validation has been unavailable for more than 72 hours.",
    )
    return True


def validate_and_apply():
    with _licence_lock():
        try:
            payload, headers = _request_json("POST", "validate", {})
            data = payload.get("data") if isinstance(payload, dict) else None
            _verify(data, headers)
            _write_verified_cache(data)
            result = _apply(data)
            result.update({"ok": True, "from_cache": False})
            return result
        except LicenceError:
            _lock_all_after_expired_grace()
            raise


def register_olt(olt):
    payload, _headers = _request_json("POST", "olts", {
        "ref": str(olt.licence_ref),
        "name": olt.name,
        "ip_address": str(olt.ip_address),
    })
    status = str(payload.get("status") or "pending").lower()
    olt.licence_status = status
    invoice_url = str(payload.get("invoice_url") or "").strip()
    parsed_invoice = urlparse(invoice_url)
    olt.licence_invoice_url = invoice_url if parsed_invoice.scheme == "https" and parsed_invoice.hostname else ""
    olt.pricing_locked = status != "active"
    olt.pricing_locked_reason = "" if status == "active" else "Payment pending. Pay to activate this OLT."
    olt.save(update_fields=["licence_status", "licence_invoice_url", "pricing_locked", "pricing_locked_reason"])
    return payload


def end_olt_subscription(olt):
    payload, _headers = _request_json("DELETE", f"olts/{olt.licence_ref}")
    return payload


def _version():
    try:
        return (Path(settings.BASE_DIR) / "VERSION").read_text(encoding="utf-8").strip() or "development"
    except OSError:
        return "development"


def checkin():
    try:
        handshake = vpn_status().get("last_handshake_s")
    except VPNError:
        handshake = None
    payload = {
        "version": _version(),
        "olt_count": OLT.objects.count(),
        "onu_count": ConfiguredONU.objects.count(),
        "wg_last_handshake_s": handshake,
    }
    _request_json("POST", "checkin", payload)


def run_licence_cycle():
    # Registration is idempotent by licence_ref, so interrupted OLT creation
    # can safely recover without producing a second invoice.
    for olt in OLT.objects.filter(licence_status__in=["registration_pending", "absent"]):
        try:
            register_olt(olt)
        except LicenceError:
            continue
    result = validate_and_apply()
    checkin()
    return result
