import hashlib
import os
import shutil
import stat
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
FIXTURE_NEW_PIN = "9753"
FIXTURE_IDENTITY = "911ec7c51dbfff3d9e8d45c80895fd9eb01a1c0a211046eb066564a77a914811"
FIXTURE_SEED = "6f307d5a08788689e0c34b8e8315049b56533299f4e988f22132b721edcf7f43"
FIXTURE_PUBLIC = "2d3339908e1f76eb0cc89058b5252a2243e7d831378dbc78cb5e646ad49bf9a6"
FIXTURE_SUITE_PASSWORD = b"service-suite-fixture-password"


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
        self.write_skeleton(FIXTURE_SKELETON)
        self.write_suite()
        self.write_credential(FIXTURE_PIN)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def write_skeleton(self, raw: bytes) -> None:
        (self.key_dir / "skeleton.key").write_bytes(raw)

    def write_suite(self, username: str = "service_suite") -> None:
        (self.vault_dir / "service_suite.key").write_bytes(encrypt_fixture(
            f'username="{username}"\npassword="{FIXTURE_SUITE_PASSWORD.decode()}"\n'.encode(),
            FIXTURE_SKELETON.split(b"\x00", 1)[0],
            b"suite123",
        ))

    def write_credential(self, pin: str, identity: str = FIXTURE_IDENTITY) -> None:
        (self.vault_dir / "caduceus.key").write_bytes(encrypt_fixture(
            f'username="{identity}"\npassword="{pin}"\n'.encode(),
            FIXTURE_SUITE_PASSWORD,
            b"caduceus",
        ))

    def root_call(self, function, *args):
        with mock.patch.object(access, "_require_root"):
            return function(*args, key_dir=self.key_dir, vault_dir=self.vault_dir)

    def derive(self, pin: str) -> access.DerivedCaduceusSigner:
        return self.root_call(access.verify_and_derive_caduceus, pin)

    def bind(self) -> access.DerivedCaduceusSigner:
        return self.root_call(access.bind_derived_caduceus)

    def test_fixture_vector_verifies_and_derives_exact_ed25519_signer(self) -> None:
        self.assertEqual(hashlib.sha256(FIXTURE_SKELETON).hexdigest(), FIXTURE_IDENTITY)
        with self.derive(FIXTURE_PIN) as signer:
            self.assertEqual(signer.identity_sha256, FIXTURE_IDENTITY)
            private = signer.private_key()
            self.assertEqual(private.private_bytes_raw().hex(), FIXTURE_SEED)
            self.assertEqual(private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex(), FIXTURE_PUBLIC)
        self.assertEqual(signer._seed, bytearray())

    def test_identity_hashes_raw_skeleton_bytes_not_legacy_canonical_bytes(self) -> None:
        raw = b"fixture-skeleton\ntrailing-bytes"
        self.assertNotEqual(
            access._identity_for_raw_skeleton(bytearray(raw)),
            access._identity_for_skeleton(access._canonical_skeleton_identity_bytes(bytearray(raw))),
        )
        self.assertEqual(access._identity_for_raw_skeleton(bytearray(raw)), hashlib.sha256(raw).hexdigest())

    def test_bind_derived_uses_current_credential_and_projects_only_public_material(self) -> None:
        expected_epoch = hashlib.sha256(bytes.fromhex(FIXTURE_PUBLIC)).hexdigest()
        with self.derive(FIXTURE_PIN) as presented, self.bind() as bound:
            self.assertEqual(bound.identity_sha256, FIXTURE_IDENTITY)
            self.assertEqual(bound.private_key().private_bytes_raw().hex(), FIXTURE_SEED)
            self.assertEqual(bound.public_key_hex, FIXTURE_PUBLIC)
            self.assertEqual(bound.signer_epoch, expected_epoch)
            self.assertEqual(bound.epoch, expected_epoch)
            self.assertEqual(bound.public_key_hex, presented.public_key_hex)
            self.assertEqual(bound.signer_epoch, presented.signer_epoch)
        self.assertEqual(bound._seed, bytearray())
        self.assertEqual(bound.public_key_hex, FIXTURE_PUBLIC)
        with self.assertRaisesRegex(access.CaduceusAccessRefused, "caduceus-derived-signer-closed"):
            bound.private_key()

    def test_bind_derived_refuses_non_root_before_key_access(self) -> None:
        with mock.patch.object(access.os, "geteuid", return_value=1000), mock.patch.object(access, "_read") as read:
            with self.assertRaisesRegex(access.CaduceusAccessRefused, "caduceus-staff-root-required"):
                access.bind_derived_caduceus(key_dir=self.key_dir, vault_dir=self.vault_dir)
        read.assert_not_called()

    def test_bind_derived_refuses_missing_or_corrupt_credential_without_signer(self) -> None:
        (self.vault_dir / "caduceus.key").unlink()
        with self.assertRaisesRegex(access.CaduceusAccessRefused, "caduceus-key-unavailable"):
            self.bind()
        (self.vault_dir / "caduceus.key").write_bytes(b"not-a-key")
        with self.assertRaises(access.CaduceusAccessRefused):
            self.bind()

    def test_newline_terminated_skeleton_uses_legacy_passphrase_and_raw_identity(self) -> None:
        raw_skeleton = FIXTURE_SKELETON + b"\n"
        self.write_skeleton(raw_skeleton)
        raw_identity = hashlib.sha256(raw_skeleton).hexdigest()
        self.write_credential(FIXTURE_PIN, identity=raw_identity)
        with self.derive(FIXTURE_PIN) as signer:
            self.assertEqual(signer.identity_sha256, raw_identity)
        identity_bytes = access._canonical_skeleton_identity_bytes(bytearray(b"  keep-space  \n"))
        self.assertEqual(identity_bytes, bytearray(b"  keep-space  "))
        self.assertEqual(access._legacy_skeleton_passphrase(identity_bytes), bytearray(b"  keep-space  "))
        self.assertEqual(access._canonical_skeleton_identity_bytes(bytearray(b"keep-cr\r\n")), bytearray(b"keep-cr\r"))
        self.assertEqual(access._canonical_skeleton_identity_bytes(bytearray(b"secret\ntrailing")), bytearray(b"secret"))
        self.assertEqual(access._canonical_skeleton_identity_bytes(bytearray(b"secret\r\ntrailing")), bytearray(b"secret\r"))
        self.assertEqual(
            access._canonical_skeleton_identity_bytes(bytearray(b"x" * 512)),
            bytearray(b"x" * 511),
        )
        self.assertEqual(access._legacy_skeleton_passphrase(bytearray(b"prefix\x00identity-tail")), bytearray(b"prefix"))

    def test_wrong_pin_refuses_without_public_or_private_output(self) -> None:
        with self.assertRaisesRegex(access.CaduceusAccessRefused, "caduceus-pin-refused"):
            self.derive("wrong")

    def test_non_root_call_is_refused_before_key_access(self) -> None:
        with mock.patch.object(access.os, "geteuid", return_value=1000):
            with self.assertRaisesRegex(access.CaduceusAccessRefused, "caduceus-staff-root-required"):
                access.verify_and_derive_caduceus(FIXTURE_PIN, key_dir=self.key_dir, vault_dir=self.vault_dir)

    def test_missing_corrupt_identity_and_service_suite_username_refuse(self) -> None:
        (self.vault_dir / "caduceus.key").unlink()
        with self.assertRaisesRegex(access.CaduceusAccessRefused, "caduceus-key-unavailable"):
            self.derive(FIXTURE_PIN)
        (self.vault_dir / "caduceus.key").write_bytes(b"not-a-key")
        with self.assertRaises(access.CaduceusAccessRefused):
            self.derive(FIXTURE_PIN)
        self.write_credential(FIXTURE_PIN, identity="not-the-canonical-identity")
        with self.assertRaisesRegex(access.CaduceusAccessRefused, "caduceus-identity-mismatch"):
            self.derive(FIXTURE_PIN)
        self.write_suite(username="wrong-suite")
        with self.assertRaisesRegex(access.CaduceusAccessRefused, "caduceus-service-suite-identity-mismatch"):
            self.derive(FIXTURE_PIN)

    def test_provision_refuses_overwrite_and_creates_mode_0600(self) -> None:
        before = (self.vault_dir / "caduceus.key").read_bytes()
        with self.assertRaisesRegex(access.CaduceusAccessRefused, "caduceus-key-exists"):
            self.root_call(access.provision_caduceus, FIXTURE_NEW_PIN)
        self.assertEqual((self.vault_dir / "caduceus.key").read_bytes(), before)
        (self.vault_dir / "caduceus.key").unlink()
        status = self.root_call(access.provision_caduceus, FIXTURE_NEW_PIN)
        self.assertTrue(status["ok"])
        self.assertEqual(status["private_material"], "[REDACTED]")
        self.assertEqual(stat.S_IMODE((self.vault_dir / "caduceus.key").stat().st_mode), 0o600)
        with self.derive(FIXTURE_NEW_PIN):
            pass

    def test_pin_change_is_atomic_and_rotates_bound_public_epoch(self) -> None:
        target = self.vault_dir / "caduceus.key"
        before = target.read_bytes()
        with self.bind() as before_bind:
            before_identity = before_bind.identity_sha256
            before_public = before_bind.public_key_hex
            before_epoch = before_bind.signer_epoch
        with self.assertRaisesRegex(access.CaduceusAccessRefused, "caduceus-pin-refused"):
            self.root_call(access.change_caduceus_pin, "wrong-old", FIXTURE_NEW_PIN)
        self.assertEqual(target.read_bytes(), before)
        with self.bind() as unchanged_bind:
            self.assertEqual(unchanged_bind.identity_sha256, before_identity)
            self.assertEqual(unchanged_bind.public_key_hex, before_public)
            self.assertEqual(unchanged_bind.signer_epoch, before_epoch)
        status = self.root_call(access.change_caduceus_pin, FIXTURE_PIN, FIXTURE_NEW_PIN)
        self.assertTrue(status["ok"])
        self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)
        self.assertNotEqual(target.read_bytes(), before)
        with self.assertRaisesRegex(access.CaduceusAccessRefused, "caduceus-pin-refused"):
            self.derive(FIXTURE_PIN)
        with self.assertRaisesRegex(access.CaduceusAccessRefused, "caduceus-pin-refused"):
            self.root_call(access.verify_and_derive_caduceus, FIXTURE_PIN)
        with self.derive(FIXTURE_NEW_PIN) as presented, self.bind() as rebound:
            self.assertEqual(rebound.identity_sha256, before_identity)
            self.assertNotEqual(rebound.public_key_hex, before_public)
            self.assertNotEqual(rebound.signer_epoch, before_epoch)
            self.assertEqual(rebound.public_key_hex, presented.public_key_hex)
            self.assertEqual(rebound.signer_epoch, presented.signer_epoch)

    def test_replace_then_directory_fsync_failure_is_commit_uncertain(self) -> None:
        target = self.vault_dir / "caduceus.key"
        before = target.read_bytes()
        calls = 0
        real_fsync = access.os.fsync

        def fail_second_fsync(fd: int) -> None:
            nonlocal calls
            calls += 1
            if calls == 2:
                raise OSError("fixture directory fsync failed")
            real_fsync(fd)

        with mock.patch.object(access.os, "fsync", side_effect=fail_second_fsync):
            with self.assertRaisesRegex(access.CaduceusAccessCommitUncertain, "caduceus-key-commit-uncertain"):
                self.root_call(access.change_caduceus_pin, FIXTURE_PIN, FIXTURE_NEW_PIN)
        self.assertNotEqual(target.read_bytes(), before)
        with self.derive(FIXTURE_NEW_PIN):
            pass

    def test_provision_and_change_leave_no_plaintext_artifacts(self) -> None:
        (self.vault_dir / "caduceus.key").unlink()
        self.root_call(access.provision_caduceus, FIXTURE_PIN)
        self.root_call(access.change_caduceus_pin, FIXTURE_PIN, FIXTURE_NEW_PIN)
        paths = list(self.vault_dir.iterdir())
        self.assertEqual({path.name for path in paths}, {"service_suite.key", "caduceus.key"})
        self.assertNotIn(FIXTURE_PIN.encode(), (self.vault_dir / "caduceus.key").read_bytes())
        self.assertNotIn(FIXTURE_NEW_PIN.encode(), (self.vault_dir / "caduceus.key").read_bytes())

    def test_status_reads_no_secret_and_requires_importable_module(self) -> None:
        runtime = Path(self.temp.name) / "runtime"
        (runtime / "lib").mkdir(parents=True)
        target = runtime / "lib" / "keyman_caduceus_access.py"
        shutil.copy2(ROOT / "lib" / "keyman_caduceus_access.py", target)
        receipt = access.caduceus_access_status(runtime_dir=runtime)
        self.assertTrue(receipt["ok"])
        self.assertEqual(receipt["private_material"], "[REDACTED]")
        self.assertNotIn("seed", receipt)
        self.assertNotIn("pin", receipt)
        target.write_text("this is not valid Python (", encoding="utf-8")
        self.assertFalse(access.caduceus_access_status(runtime_dir=runtime)["ok"])

    def test_new_access_implementation_has_no_legacy_or_plaintext_leak_paths(self) -> None:
        source = (ROOT / "lib" / "keyman_caduceus_access.py").read_text(encoding="utf-8")
        forbidden = ["export" + "key", "/mnt/" + "keyexchange", "print(", "logging.", "subprocess"]
        for term in forbidden:
            self.assertNotIn(term, source)
        self.assertIn("compare_digest", source)
        self.assertIn("_wipe", source)
        self.assertIn("best-effort", source)


if __name__ == "__main__":
    unittest.main()
