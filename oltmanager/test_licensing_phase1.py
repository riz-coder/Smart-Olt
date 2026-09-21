import base64
import copy
import json
from unittest.mock import patch

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from django.test import SimpleTestCase

from oltmanager.licensing.service import LicenceError, _verify


class LicenceSignatureTests(SimpleTestCase):
    def setUp(self):
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.public_pem = self.private_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def signed_data(self):
        data = {
            "licence": "OPT-0001",
            "status": "active",
            "olts": [{"ref": "6d3c8ff7-dc74-4e88-a48d-e94d965d779f", "status": "active"}],
            "signature_kid": "test-key",
            "signature_alg": "RS256",
        }
        canonical = json.dumps(
            {key: value for key, value in data.items() if key not in {"signature_kid", "signature_alg"}},
            sort_keys=True,
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
        signature = self.private_key.sign(canonical, padding.PKCS1v15(), hashes.SHA256())
        data["signature"] = base64.b64encode(signature).decode("ascii")
        return data

    @patch("oltmanager.licensing.service._public_key")
    def test_valid_signature_is_accepted(self, public_key):
        public_key.return_value = self.public_pem
        _verify(self.signed_data(), {})

    @patch("oltmanager.licensing.service._public_key")
    def test_tampered_response_is_rejected(self, public_key):
        public_key.return_value = self.public_pem
        data = copy.deepcopy(self.signed_data())
        data["status"] = "suspended"
        with self.assertRaises(LicenceError):
            _verify(data, {})
