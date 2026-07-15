"""Root-only in-memory Keyman access for the Caduceus staff process.

Canonical Caduceus identity bytes are the Keyman skeleton secret selected with
legacy ``fgets(buffer, 512, ...)`` semantics: bytes through the first ``LF`` in
that 511-byte read window, with that one ``LF`` removed.  They are not broad
raw-file hashing.  The legacy service-suite PBKDF2 passphrase is separately the
canonical secret's C-string prefix.  Neither interpretation uses broad
whitespace stripping.

Python can overwrite mutable bytearrays best-effort.  It cannot honestly erase
immutable ``str``/``bytes`` values or cryptography key objects; this membrane
therefore guarantees no serialization, logging, child process, or plaintext
file rather than claiming universal zeroization.
"""
from __future__ import annotations

import hashlib
import hmac
import importlib.util
import os
import re
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

_SERVICE_NAME: Final = "caduceus"
_SERVICE_SUITE_USERNAME: Final = "service_suite"
_HEADER: Final = b"Salted__"
_SALT_BYTES: Final = 8
_PBKDF2_ITERATIONS: Final = 10_000
_SERVICE_SUITE_NAME: Final = "service_suite.key"
_CADUCEUS_NAME: Final = "caduceus.key"
_RECORD = re.compile(rb'^username="([^"\r\n]+)"\r?\npassword="([^"\r\n]*)"\r?\n?$', re.DOTALL)


class CaduceusAccessRefused(RuntimeError):
    """A redacted refusal for missing, malformed, or mismatched Keyman data."""


class CaduceusAccessCommitUncertain(CaduceusAccessRefused):
    """Replacement occurred, but Keyman cannot prove the directory commit durable."""


def _wipe(value: bytearray) -> None:
    for index in range(len(value)):
        value[index] = 0


def _read(path: Path) -> bytearray:
    try:
        return bytearray(path.read_bytes())
    except OSError as exc:
        raise CaduceusAccessRefused("caduceus-key-unavailable") from exc


def _canonical_skeleton_identity_bytes(raw: bytearray) -> bytearray:
    """Return canonical secret bytes, not serialized-file bytes or a file hash.

    This exactly selects the first legacy ``fgets(buffer, 512, ...)`` result:
    stop through the first LF within the 511-byte data window, then remove that
    LF only.  CR and every other selected byte remain intact.
    """
    read_window = raw[:511]
    newline = read_window.find(b"\n")
    identity_line = bytearray(read_window if newline < 0 else read_window[:newline])
    if not identity_line:
        raise CaduceusAccessRefused("caduceus-skeleton-malformed")
    return identity_line


def _legacy_skeleton_passphrase(identity_bytes: bytearray) -> bytearray:
    """Legacy C passes the C-string prefix, ending at its first NUL, to PBKDF2."""
    nul = identity_bytes.find(b"\x00")
    passphrase = bytearray(identity_bytes if nul < 0 else identity_bytes[:nul])
    if not passphrase:
        raise CaduceusAccessRefused("caduceus-skeleton-malformed")
    return passphrase


def _identity_for_skeleton(canonical_identity: bytearray) -> str:
    return hashlib.sha256(bytes(canonical_identity)).hexdigest()


def _decrypt_openssl(ciphertext: bytearray, password: bytearray) -> bytearray:
    if len(ciphertext) < len(_HEADER) + _SALT_BYTES + 16 or not hmac.compare_digest(ciphertext[:8], _HEADER):
        raise CaduceusAccessRefused("caduceus-key-malformed")
    salt = bytes(ciphertext[8 : 8 + _SALT_BYTES])
    key_iv = bytearray(PBKDF2HMAC(
        algorithm=hashes.SHA256(), length=48, salt=salt, iterations=_PBKDF2_ITERATIONS,
    ).derive(bytes(password)))
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


def _encrypt_openssl(plaintext: bytearray, password: bytearray) -> bytearray:
    salt = os.urandom(_SALT_BYTES)
    key_iv = bytearray(PBKDF2HMAC(
        algorithm=hashes.SHA256(), length=48, salt=salt, iterations=_PBKDF2_ITERATIONS,
    ).derive(bytes(password)))
    try:
        encryptor = Cipher(algorithms.AES(bytes(key_iv[:32])), modes.CBC(bytes(key_iv[32:]))).encryptor()
        padded = bytes(plaintext) + bytes([16 - len(plaintext) % 16]) * (16 - len(plaintext) % 16)
        return bytearray(_HEADER + salt + encryptor.update(padded) + encryptor.finalize())
    finally:
        _wipe(key_iv)


def _record(plaintext: bytearray) -> tuple[bytearray, bytearray]:
    match = _RECORD.fullmatch(bytes(plaintext))
    if match is None:
        raise CaduceusAccessRefused("caduceus-key-malformed")
    return bytearray(match.group(1)), bytearray(match.group(2))


def _require_root() -> None:
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        raise CaduceusAccessRefused("caduceus-staff-root-required")


def _pin_bytes(pin: str) -> bytearray:
    value = bytearray(pin.encode("utf-8"))
    if not value or b'"' in value or b"\r" in value or b"\n" in value:
        _wipe(value)
        raise CaduceusAccessRefused("caduceus-pin-invalid")
    return value


def _service_suite_password(canonical_skeleton: bytearray, vault_dir: Path) -> bytearray:
    suite_ciphertext = _read(vault_dir / _SERVICE_SUITE_NAME)
    suite_plaintext = bytearray()
    suite_username = bytearray()
    suite_password = bytearray()
    try:
        suite_plaintext = _decrypt_openssl(suite_ciphertext, canonical_skeleton)
        suite_username, suite_password = _record(suite_plaintext)
        if not hmac.compare_digest(bytes(suite_username), _SERVICE_SUITE_USERNAME.encode("ascii")):
            raise CaduceusAccessRefused("caduceus-service-suite-identity-mismatch")
        result = bytearray(suite_password)
        return result
    finally:
        for value in (suite_ciphertext, suite_plaintext, suite_username, suite_password):
            _wipe(value)


def _credential(identity: str, suite_password: bytearray, vault_dir: Path) -> tuple[bytearray, bytearray]:
    service_ciphertext = _read(vault_dir / _CADUCEUS_NAME)
    credential_plaintext = bytearray()
    username = bytearray()
    stored_pin = bytearray()
    try:
        credential_plaintext = _decrypt_openssl(service_ciphertext, suite_password)
        username, stored_pin = _record(credential_plaintext)
        if not hmac.compare_digest(bytes(username), identity.encode("ascii")):
            raise CaduceusAccessRefused("caduceus-identity-mismatch")
        return bytearray(username), bytearray(stored_pin)
    finally:
        for value in (service_ciphertext, credential_plaintext, username, stored_pin):
            _wipe(value)


def _atomic_ciphertext_write(target: Path, ciphertext: bytearray, *, replace: bool) -> None:
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        fd, temporary = tempfile.mkstemp(prefix=f".{target.name}.", dir=target.parent)
    except OSError as exc:
        raise CaduceusAccessRefused("caduceus-key-write-refused") from exc
    temporary_path = Path(temporary)
    committed = False
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb", closefd=True) as handle:
            handle.write(ciphertext)
            handle.flush()
            os.fsync(handle.fileno())
        if replace:
            os.replace(temporary_path, target)
            committed = True
        else:
            try:
                os.link(temporary_path, target)
            except FileExistsError as exc:
                raise CaduceusAccessRefused("caduceus-key-exists") from exc
            temporary_path.unlink()
        directory_fd = os.open(target.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except OSError as exc:
        if committed:
            raise CaduceusAccessCommitUncertain("caduceus-key-commit-uncertain") from exc
        raise CaduceusAccessRefused("caduceus-key-write-refused") from exc
    finally:
        if temporary_path.exists():
            temporary_path.unlink()


def _credential_plaintext(identity: str, pin: bytearray) -> bytearray:
    return bytearray(b'username="' + identity.encode("ascii") + b'"\npassword="' + bytes(pin) + b'"\n')


@dataclass
class DerivedCaduceusSigner:
    """Private in-memory signer. Call close() immediately after the bind."""

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
    """Constant-time verify one PIN and derive the tablet-defined signer in memory."""
    _require_root()
    pin_bytes = _pin_bytes(pin)
    raw_skeleton = _read(key_dir / "skeleton.key")
    canonical_identity = bytearray()
    legacy_passphrase = bytearray()
    suite_password = bytearray()
    username = bytearray()
    stored_pin = bytearray()
    try:
        canonical_identity = _canonical_skeleton_identity_bytes(raw_skeleton)
        legacy_passphrase = _legacy_skeleton_passphrase(canonical_identity)
        identity = _identity_for_skeleton(canonical_identity)
        suite_password = _service_suite_password(legacy_passphrase, vault_dir)
        username, stored_pin = _credential(identity, suite_password, vault_dir)
        if not hmac.compare_digest(bytes(stored_pin), bytes(pin_bytes)):
            raise CaduceusAccessRefused("caduceus-pin-refused")
        seed = bytearray(hashlib.sha256(identity.encode("ascii") + b"\x00" + bytes(pin_bytes)).digest())
        return DerivedCaduceusSigner(seed, identity)
    finally:
        for value in (pin_bytes, raw_skeleton, canonical_identity, legacy_passphrase, suite_password, username, stored_pin):
            _wipe(value)


def provision_caduceus(initial_pin: str, *, key_dir: Path = Path("/root/key"), vault_dir: Path = Path("/vault/.keys")) -> dict[str, object]:
    """Create the fixed credential once, without plaintext files or legacy CLI paths."""
    _require_root()
    target = vault_dir / _CADUCEUS_NAME
    if target.exists():
        raise CaduceusAccessRefused("caduceus-key-exists")
    pin_bytes = _pin_bytes(initial_pin)
    raw_skeleton = _read(key_dir / "skeleton.key")
    canonical_identity = bytearray()
    legacy_passphrase = bytearray()
    suite_password = bytearray()
    plaintext = bytearray()
    ciphertext = bytearray()
    try:
        canonical_identity = _canonical_skeleton_identity_bytes(raw_skeleton)
        legacy_passphrase = _legacy_skeleton_passphrase(canonical_identity)
        identity = _identity_for_skeleton(canonical_identity)
        suite_password = _service_suite_password(legacy_passphrase, vault_dir)
        plaintext = _credential_plaintext(identity, pin_bytes)
        ciphertext = _encrypt_openssl(plaintext, suite_password)
        _atomic_ciphertext_write(target, ciphertext, replace=False)
        return {"schema": "keyman.caduceus_access.status.v1", "ok": True, "operation": "provisioned", "private_material": "[REDACTED]"}
    finally:
        for value in (pin_bytes, raw_skeleton, canonical_identity, legacy_passphrase, suite_password, plaintext, ciphertext):
            _wipe(value)


def change_caduceus_pin(old_pin: str, new_pin: str, *, key_dir: Path = Path("/root/key"), vault_dir: Path = Path("/vault/.keys")) -> dict[str, object]:
    """Verify old PIN then atomically replace only the encrypted fixed credential."""
    _require_root()
    old_bytes = _pin_bytes(old_pin)
    new_bytes = _pin_bytes(new_pin)
    raw_skeleton = _read(key_dir / "skeleton.key")
    canonical_identity = bytearray()
    legacy_passphrase = bytearray()
    suite_password = bytearray()
    username = bytearray()
    stored_pin = bytearray()
    plaintext = bytearray()
    ciphertext = bytearray()
    try:
        canonical_identity = _canonical_skeleton_identity_bytes(raw_skeleton)
        legacy_passphrase = _legacy_skeleton_passphrase(canonical_identity)
        identity = _identity_for_skeleton(canonical_identity)
        suite_password = _service_suite_password(legacy_passphrase, vault_dir)
        username, stored_pin = _credential(identity, suite_password, vault_dir)
        if not hmac.compare_digest(bytes(stored_pin), bytes(old_bytes)):
            raise CaduceusAccessRefused("caduceus-pin-refused")
        plaintext = _credential_plaintext(identity, new_bytes)
        ciphertext = _encrypt_openssl(plaintext, suite_password)
        _atomic_ciphertext_write(vault_dir / _CADUCEUS_NAME, ciphertext, replace=True)
        return {"schema": "keyman.caduceus_access.status.v1", "ok": True, "operation": "pin-changed", "private_material": "[REDACTED]"}
    finally:
        for value in (old_bytes, new_bytes, raw_skeleton, canonical_identity, legacy_passphrase, suite_password, username, stored_pin, plaintext, ciphertext):
            _wipe(value)


def access_module_importable(path: Path) -> bool:
    """Secret-free installed-runtime import check, including crypto dependency."""
    name = "_keyman_caduceus_access_install_check"
    try:
        spec = importlib.util.spec_from_file_location(name, path)
        if spec is None or spec.loader is None:
            return False
        module = importlib.util.module_from_spec(spec)
        import sys
        sys.modules[name] = module
        spec.loader.exec_module(module)
        return True
    except (ImportError, OSError, SyntaxError, ValueError):
        return False
    finally:
        import sys
        sys.modules.pop(name, None)


def caduceus_access_status(*, runtime_dir: Path) -> dict[str, object]:
    """Return only installed membrane shape; never open credential material."""
    module = runtime_dir / "lib" / "keyman_caduceus_access.py"
    installed = module.is_file()
    importable = installed and access_module_importable(module)
    return {
        "schema": "keyman.caduceus_access.status.v1",
        "ok": importable,
        "operation": "root-in-process-caduceus-verify-and-derive",
        "service": _SERVICE_NAME,
        "private_material": "[REDACTED]",
        "first_missing_signal": "none" if importable else "caduceus-access-module-or-crypto-dependency-unavailable",
    }
