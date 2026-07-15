"""In-memory Keyman access membrane for the root-run Caduceus staff process.

This module deliberately has no command-line face.  Its only private operation
opens the fixed ``caduceus.key`` credential, verifies one presented PIN, and
returns a zeroizable Ed25519 signer derived according to the household tablet.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

_SERVICE_NAME: Final = "caduceus"
_HEADER: Final = b"Salted__"
_SALT_BYTES: Final = 8
_PBKDF2_ITERATIONS: Final = 10_000
_SERVICE_SUITE_NAME: Final = "service_suite.key"
_CADUCEUS_NAME: Final = "caduceus.key"
_RECORD = re.compile(rb'^username="([^"\r\n]+)"\r?\npassword="([^"\r\n]*)"\r?\n?$', re.DOTALL)


class CaduceusAccessRefused(RuntimeError):
    """A redacted refusal for missing, malformed, or mismatched Keyman data."""


def _wipe(value: bytearray) -> None:
    for index in range(len(value)):
        value[index] = 0


def _read(path: Path) -> bytearray:
    try:
        return bytearray(path.read_bytes())
    except OSError as exc:
        raise CaduceusAccessRefused("caduceus-key-unavailable") from exc


def _decrypt_openssl(ciphertext: bytearray, password: bytearray) -> bytearray:
    if len(ciphertext) < len(_HEADER) + _SALT_BYTES + 16 or not hmac.compare_digest(ciphertext[:8], _HEADER):
        raise CaduceusAccessRefused("caduceus-key-malformed")
    salt = bytes(ciphertext[8 : 8 + _SALT_BYTES])
    key_iv = bytearray(
        PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=48,
            salt=salt,
            iterations=_PBKDF2_ITERATIONS,
        ).derive(bytes(password))
    )
    try:
        decryptor = Cipher(algorithms.AES(bytes(key_iv[:32])), modes.CBC(bytes(key_iv[32:]))).decryptor()
        padded = bytearray(decryptor.update(bytes(ciphertext[16:])) + decryptor.finalize())
    except ValueError as exc:
        raise CaduceusAccessRefused("caduceus-key-corrupt") from exc
    finally:
        _wipe(key_iv)
    if not padded:
        raise CaduceusAccessRefused("caduceus-key-corrupt")
    pad = padded[-1]
    if pad < 1 or pad > 16 or len(padded) < pad or not hmac.compare_digest(padded[-pad:], bytes([pad]) * pad):
        _wipe(padded)
        raise CaduceusAccessRefused("caduceus-key-corrupt")
    plaintext = bytearray(padded[:-pad])
    _wipe(padded)
    return plaintext


def _record(plaintext: bytearray) -> tuple[bytearray, bytearray]:
    match = _RECORD.fullmatch(bytes(plaintext))
    if match is None:
        raise CaduceusAccessRefused("caduceus-key-malformed")
    return bytearray(match.group(1)), bytearray(match.group(2))


def _require_root() -> None:
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        raise CaduceusAccessRefused("caduceus-staff-root-required")


@dataclass
class DerivedCaduceusSigner:
    """Private, in-memory signer. Call close() as soon as the bind completes."""

    _seed: bytearray
    identity_sha256: str

    def private_key(self) -> Ed25519PrivateKey:
        if not self._seed:
            raise CaduceusAccessRefused("caduceus-derived-signer-closed")
        return Ed25519PrivateKey.from_private_bytes(bytes(self._seed))

    def close(self) -> None:
        _wipe(self._seed)
        self._seed.clear()

    def __enter__(self) -> "DerivedCaduceusSigner":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


def verify_and_derive_caduceus(pin: str, *, key_dir: Path = Path("/root/key"), vault_dir: Path = Path("/vault/.keys")) -> DerivedCaduceusSigner:
    """Verify one PIN and derive the tablet-defined signer without serialization.

    This root-only in-process operation is service-scoped: it accepts no service
    selector and opens only the fixed caduceus credential. It emits no receipt,
    invokes no child process, and creates no temporary file.
    """
    _require_root()
    pin_bytes = bytearray(pin.encode("utf-8"))
    skeleton = _read(key_dir / "skeleton.key")
    suite_ciphertext = _read(vault_dir / _SERVICE_SUITE_NAME)
    service_ciphertext = _read(vault_dir / _CADUCEUS_NAME)
    suite_plaintext = bytearray()
    credential_plaintext = bytearray()
    suite_password = bytearray()
    suite_username = bytearray()
    username = bytearray()
    stored_pin = bytearray()
    try:
        identity = hashlib.sha256(bytes(skeleton)).hexdigest()
        suite_plaintext = _decrypt_openssl(suite_ciphertext, skeleton)
        suite_username, suite_password = _record(suite_plaintext)
        credential_plaintext = _decrypt_openssl(service_ciphertext, suite_password)
        username, stored_pin = _record(credential_plaintext)
        if not hmac.compare_digest(bytes(username), identity.encode("ascii")):
            raise CaduceusAccessRefused("caduceus-identity-mismatch")
        if not hmac.compare_digest(bytes(stored_pin), bytes(pin_bytes)):
            raise CaduceusAccessRefused("caduceus-pin-refused")
        seed = bytearray(hashlib.sha256(identity.encode("ascii") + b"\x00" + bytes(pin_bytes)).digest())
        return DerivedCaduceusSigner(seed, identity)
    finally:
        for value in (pin_bytes, skeleton, suite_ciphertext, service_ciphertext, suite_plaintext, credential_plaintext, suite_username, suite_password, username, stored_pin):
            _wipe(value)


def caduceus_access_status(*, runtime_dir: Path) -> dict[str, object]:
    """Return only installation shape; never open Keyman credential material."""
    return {
        "schema": "keyman.caduceus_access.status.v1",
        "ok": (runtime_dir / "lib" / "keyman_caduceus_access.py").is_file(),
        "operation": "root-in-process-caduceus-verify-and-derive",
        "service": _SERVICE_NAME,
        "private_material": "[REDACTED]",
        "first_missing_signal": "none" if (runtime_dir / "lib" / "keyman_caduceus_access.py").is_file() else "caduceus-access-module-missing",
    }
