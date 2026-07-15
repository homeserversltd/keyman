import hashlib
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lib"))
import keyman_caduceus_access as access

FIXTURE_SKELETON = bytes.fromhex("63616475636575732d666978747572652d736b656c65746f6e2d7631006279746573")
FIXTURE_PIN = "2468"
FIXTURE_IDENTITY = "911ec7c51dbfff3d9e8d45c80895fd9eb01a1c0a211046eb066564a77a914811"
FIXTURE_SEED = "6f307d5a08788689e0c34b8e8315049b56533299f4e988f22132b721edcf7f43"
FIXTURE_PUBLIC = "2d3339908e1f76eb0cc89058b5252a2243e7d831378dbc78cb5e646ad49bf9a6"


def encrypt_fixture(plaintext: bytes, password: bytes, salt: bytes) -> bytes:
    key_iv = PBKDF2HMAC(algorithm=hashes.SHA256(), length=48, salt=salt, iterations=10_000).derive(password)
    pad = 16 - len(plaintext) % 16
    encryptor = Cipher(algorithms.AES(key_iv[:32]), modes.CBC(key_iv[32:])).encryptor()
    return b"Salted__" + salt + encryptor.update(plaintext + bytes([pad]) * pad) + encryptor.finalize()


class CaduceusAccessTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.key_dir = root / "key"
        self.vault_dir = root / "vault"
        self.key_dir.mkdir()
        self.vault_dir.mkdir()
        (self.key_dir / "skeleton.key").write_bytes(FIXTURE_SKELETON)
        suite = b'service-suite-fixture-password'
        (self.vault_dir / "service_suite.key").write_bytes(
            encrypt_fixture(b'username="service_suite"\npassword="service-suite-fixture-password"\n', FIXTURE_SKELETON, b"suite123")
        )
        (self.vault_dir / "caduceus.key").write_bytes(
            encrypt_fixture(f'username="{FIXTURE_IDENTITY}"\npassword="{FIXTURE_PIN}"\n'.encode(), suite, b"caduceus")
        )

    def tearDown(self) -> None:
        self.temp.cleanup()

    def derive(self, pin: str) -> access.DerivedCaduceusSigner:
        with mock.patch.object(access, "_require_root"):
            return access.verify_and_derive_caduceus(pin, key_dir=self.key_dir, vault_dir=self.vault_dir)

    def test_fixture_vector_verifies_and_derives_exact_ed25519_signer(self) -> None:
        self.assertEqual(hashlib.sha256(FIXTURE_SKELETON).hexdigest(), FIXTURE_IDENTITY)
        with self.derive(FIXTURE_PIN) as signer:
            self.assertEqual(signer.identity_sha256, FIXTURE_IDENTITY)
            private = signer.private_key()
            self.assertEqual(private.private_bytes_raw().hex(), FIXTURE_SEED)
            self.assertEqual(private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex(), FIXTURE_PUBLIC)
        self.assertEqual(signer._seed, bytearray())

    def test_wrong_pin_refuses_without_public_or_private_output(self) -> None:
        with self.assertRaisesRegex(access.CaduceusAccessRefused, "caduceus-pin-refused"):
            self.derive("wrong")

    def test_non_root_call_is_refused_before_key_access(self) -> None:
        with mock.patch.object(access.os, "geteuid", return_value=1000):
            with self.assertRaisesRegex(access.CaduceusAccessRefused, "caduceus-staff-root-required"):
                access.verify_and_derive_caduceus(FIXTURE_PIN, key_dir=self.key_dir, vault_dir=self.vault_dir)

    def test_missing_corrupt_and_identity_mismatch_refuse(self) -> None:
        (self.vault_dir / "caduceus.key").unlink()
        with self.assertRaisesRegex(access.CaduceusAccessRefused, "caduceus-key-unavailable"):
            self.derive(FIXTURE_PIN)
        (self.vault_dir / "caduceus.key").write_bytes(b"not-a-key")
        with self.assertRaises(access.CaduceusAccessRefused):
            self.derive(FIXTURE_PIN)

    def test_status_reads_no_secret_and_reports_only_shape(self) -> None:
        runtime = Path(self.temp.name) / "runtime"
        (runtime / "lib").mkdir(parents=True)
        (runtime / "lib" / "keyman_caduceus_access.py").write_text("# installed\n", encoding="utf-8")
        receipt = access.caduceus_access_status(runtime_dir=runtime)
        self.assertTrue(receipt["ok"])
        self.assertEqual(receipt["private_material"], "[REDACTED]")
        self.assertNotIn("seed", receipt)
        self.assertNotIn("pin", receipt)

    def test_new_access_implementation_has_no_legacy_or_secret_leak_paths(self) -> None:
        source = (ROOT / "lib" / "keyman_caduceus_access.py").read_text(encoding="utf-8")
        forbidden = ["export" + "key", "/mnt/" + "keyexchange", "temp" + "file", "print(", "logging.", "subprocess"]
        for term in forbidden:
            self.assertNotIn(term, source)
        self.assertIn("compare_digest", source)
        self.assertIn("_wipe", source)


if __name__ == "__main__":
    unittest.main()
