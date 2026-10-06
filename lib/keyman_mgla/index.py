#!/usr/bin/env python3
"""MGLA key operations over Keyman's existing credential ladder.

Private seeds enter only through newkey.sh stdin and leave only through the
operation-scoped exportkey.sh path. The module never generates, exports, or
signs a key from a CI process.
"""

from __future__ import annotations

import argparse
import base64
import fcntl
import hashlib
import os
import re
import signal
import stat
import subprocess
import sys
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator, NoReturn

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

MAX_SERVICE_NAME = 238
MAX_BODY_BYTES = 16 * 1024
_SERVICE_RE = re.compile(r"[A-Za-z0-9_]+\Z")
_SEED_RE = re.compile(rb"[0-9a-f]{64}\Z")
_FIELDS = ("product", "band", "licensee", "grant", "issued", "expiry", "key")
_ACTIVE_EXPORTS: dict[Path, tuple[int, int]] = {}


class Refusal(Exception):
    """A named, non-secret MGLA refusal."""

    def __init__(self, name: str, exit_code: int = 1) -> None:
        super().__init__(name)
        self.name = name
        self.exit_code = exit_code


def refuse(name: str, exit_code: int = 1) -> NoReturn:
    raise Refusal(name, exit_code)


def safe_root() -> Path | None:
    raw = os.environ.get("KEYMAN_ROOT")
    if raw is None:
        return None
    candidate = Path(raw)
    if not candidate.is_absolute() or raw == "/" or raw.endswith("/"):
        refuse("unsafe-keyman-root")
    try:
        resolved = candidate.resolve(strict=True)
    except OSError:
        refuse("keyman-root-missing")
    if resolved != candidate or not resolved.is_dir():
        refuse("unsafe-keyman-root")
    return resolved


def runtime_paths() -> tuple[Path, Path, Path, Path, Path]:
    root = safe_root()
    if root is None:
        return (
            Path("/root/key/skeleton.key"),
            Path("/vault/.keys/service_suite.key"),
            Path("/vault/.keys"),
            Path("/mnt/keyexchange"),
            Path("/vault/keyman"),
        )
    return (
        root / "root/key/skeleton.key",
        root / "vault/.keys/service_suite.key",
        root / "vault/.keys",
        root / "mnt/keyexchange",
        root / "vault/keyman",
    )


def validate_service(service: str) -> None:
    if (
        not service
        or len(service) > MAX_SERVICE_NAME
        or _SERVICE_RE.fullmatch(service) is None
    ):
        refuse("invalid-service-name")


def require_regular(path: Path, refusal: str) -> os.stat_result:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        refuse(refusal)
    except OSError:
        refuse(refusal)
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        refuse(refusal)
    return metadata


def require_directory(path: Path, refusal: str) -> os.stat_result:
    try:
        metadata = path.lstat()
    except OSError:
        refuse(refusal)
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        refuse(refusal)
    return metadata


def require_hierarchy() -> tuple[Path, Path, Path, Path, Path]:
    paths = runtime_paths()
    require_regular(paths[0], "keyman-hierarchy-missing")
    require_regular(paths[1], "keyman-hierarchy-missing")
    require_directory(paths[2], "keyman-hierarchy-missing")
    require_directory(paths[4], "keyman-hierarchy-missing")
    return paths


def exchange_is_tmpfs(path: Path) -> bool:
    try:
        resolved = str(path.resolve(strict=True))
        mountinfo = Path("/proc/self/mountinfo").read_text(encoding="ascii")
    except (OSError, UnicodeError):
        return False
    escaped = resolved.replace("\\", "\\134").replace(" ", "\\040").replace("\t", "\\011")
    for line in mountinfo.splitlines():
        fields = line.split()
        try:
            separator = fields.index("-")
        except ValueError:
            continue
        if len(fields) > separator + 1 and fields[4] == escaped and fields[separator + 1] == "tmpfs":
            return True
    return False


def require_exchange(exchange: Path) -> None:
    if not exchange.is_dir() or not exchange_is_tmpfs(exchange):
        refuse("key-exchange-tmpfs-missing")


@contextmanager
def mgla_lock(skeleton: Path) -> Iterator[None]:
    """Serialize MGLA operations without creating another vault artifact."""
    descriptor = -1
    try:
        descriptor = os.open(skeleton, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            refuse("keyman-hierarchy-missing")
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    except Refusal:
        raise
    except OSError:
        refuse("keyman-lock-failed")
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def encoded(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def public_key(private_key: Ed25519PrivateKey) -> bytes:
    return private_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )


def key_id(public: bytes) -> str:
    return hashlib.sha256(public).hexdigest()[:16]


def keyman_environment() -> dict[str, str]:
    environment = os.environ.copy()
    environment["KEYMAN_MGLA_SCOPED"] = "1"
    return environment


def run_ladder(script: Path, arguments: list[str], *, input_bytes: bytearray | None = None) -> None:
    try:
        result = subprocess.run(
            [str(script), *arguments],
            input=input_bytes,
            stdin=None if input_bytes is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=keyman_environment(),
            check=False,
        )
    except OSError:
        refuse("keyman-ladder-unavailable")
    if result.returncode != 0:
        refusal = "keyman-newkey-failed" if "newkey.sh" in script.name else "keyman-export-failed"
        refuse(refusal)


def secure_remove(path: Path, identity: tuple[int, int]) -> None:
    """Overwrite and remove only the exact export this process created."""
    try:
        before = path.lstat()
    except FileNotFoundError:
        _ACTIVE_EXPORTS.pop(path, None)
        return
    except OSError:
        refuse("export-cleanup-failed")
    if (
        stat.S_ISLNK(before.st_mode)
        or not stat.S_ISREG(before.st_mode)
        or (before.st_dev, before.st_ino) != identity
    ):
        refuse("export-cleanup-failed")
    descriptor = -1
    try:
        descriptor = os.open(path, os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0))
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != identity:
            refuse("export-cleanup-failed")
        remaining = opened.st_size
        zeroes = b"\0" * 4096
        offset = 0
        while remaining:
            amount = min(remaining, len(zeroes))
            written = os.pwrite(descriptor, zeroes[:amount], offset)
            if written != amount:
                refuse("export-cleanup-failed")
            remaining -= written
            offset += written
        os.fsync(descriptor)
        current = path.lstat()
        if (
            stat.S_ISLNK(current.st_mode)
            or not stat.S_ISREG(current.st_mode)
            or (current.st_dev, current.st_ino) != identity
        ):
            refuse("export-cleanup-failed")
        os.unlink(path)
        directory_fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
        _ACTIVE_EXPORTS.pop(path, None)
    except Refusal:
        raise
    except OSError:
        refuse("export-cleanup-failed")
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def cleanup_active_exports() -> None:
    for path, identity in list(_ACTIVE_EXPORTS.items()):
        secure_remove(path, identity)


def read_seed_file(path: Path) -> bytearray:
    descriptor = -1
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) & 0o077
            or metadata.st_size > 1024
        ):
            refuse("invalid-keyman-credential")
        chunks = bytearray()
        while len(chunks) <= 1024:
            block = os.read(descriptor, 1025 - len(chunks))
            if not block:
                break
            chunks.extend(block)
        match = re.fullmatch(rb'username="mgla"\npassword="([0-9a-f]{64})"\n', chunks)
        if match is None:
            chunks[:] = b"\0" * len(chunks)
            refuse("invalid-keyman-credential")
        seed = bytearray.fromhex(match.group(1).decode("ascii"))
        chunks[:] = b"\0" * len(chunks)
        return seed
    except Refusal:
        raise
    except OSError:
        refuse("credential-export-unreadable")
    finally:
        if descriptor >= 0:
            os.close(descriptor)


@contextmanager
def exported_seed(service: str, exchange: Path, runtime: Path) -> Iterator[bytearray]:
    validate_service(service)
    output = exchange / service
    try:
        output.lstat()
    except FileNotFoundError:
        pass
    except OSError:
        refuse("exchange-artifact-unreadable")
    else:
        refuse("exchange-artifact-exists")
    run_ladder(runtime / "exportkey.sh", ["--scoped", service])
    identity: tuple[int, int] | None = None
    seed: bytearray | None = None
    try:
        metadata = require_regular(output, "credential-export-missing")
        identity = (metadata.st_dev, metadata.st_ino)
        _ACTIVE_EXPORTS[output] = identity
        seed = read_seed_file(output)
        yield seed
    finally:
        if seed is not None:
            seed[:] = b"\0" * len(seed)
        if identity is not None:
            secure_remove(output, identity)


def make_private(seed: bytearray) -> Ed25519PrivateKey:
    if len(seed) != 32:
        refuse("invalid-keyman-credential")
    try:
        return Ed25519PrivateKey.from_private_bytes(bytes(seed))
    except (TypeError, ValueError):
        refuse("invalid-keyman-credential")


def validate_body(body: bytes) -> bytes:
    if body.startswith(b"MGLA-KEY1|"):
        refuse("key-line-is-not-an-attestation")
    if not body.startswith(b"MGLA1|") or len(body) > MAX_BODY_BYTES:
        refuse("invalid-mgla1-body")
    if any(byte < 0x20 or byte > 0x7E for byte in body):
        refuse("invalid-mgla1-body")
    pieces = body.split(b"|")
    if len(pieces) != len(_FIELDS) + 1 or pieces[0] != b"MGLA1":
        refuse("invalid-mgla1-body")
    for piece, field in zip(pieces[1:], _FIELDS, strict=True):
        name, separator, value = piece.partition(b"=")
        if not separator or name != field.encode("ascii") or not value:
            refuse("invalid-mgla1-body")
    return body


def mglakey(service: str, skeleton: Path, suite: Path, vault: Path, exchange: Path, runtime: Path) -> str:
    validate_service(service)
    require_regular(vault / f"{service}.key", "credential-missing")
    with mgla_lock(skeleton):
        require_exchange(exchange)
        with exported_seed(service, exchange, runtime) as seed:
            private = make_private(seed)
            public = public_key(private)
            identifier = key_id(public)
            return f"MGLA-KEY1|key={identifier}|pub={encoded(public)}"


def sign_body(service: str, body: bytes, skeleton: Path, suite: Path, vault: Path, exchange: Path, runtime: Path) -> bytes:
    validate_service(service)
    literal_body = validate_body(body)
    require_regular(vault / f"{service}.key", "credential-missing")
    with mgla_lock(skeleton):
        require_exchange(exchange)
        signature: bytes | None = None
        with exported_seed(service, exchange, runtime) as seed:
            private = make_private(seed)
            public = public_key(private)
            identifier = key_id(public)
            supplied_id = literal_body.split(b"|")[-1].partition(b"=")[2].decode("ascii")
            if supplied_id != identifier:
                refuse("key-id-mismatch")
            signature = private.sign(literal_body)
        if signature is None:
            refuse("signature-failed")
        return literal_body + b"|sig=" + encoded(signature).encode("ascii")


def succession(old_service: str, new_service: str, skeleton: Path, suite: Path, vault: Path, exchange: Path, runtime: Path) -> str:
    validate_service(old_service)
    validate_service(new_service)
    if old_service == new_service:
        refuse("succession-services-must-differ")
    for service in (old_service, new_service):
        require_regular(vault / f"{service}.key", "credential-missing")
    with mgla_lock(skeleton):
        require_exchange(exchange)
        signature: bytes | None = None
        body: str | None = None
        with exported_seed(old_service, exchange, runtime) as old_seed:
            old_private = make_private(old_seed)
            old_public = public_key(old_private)
            old_id = key_id(old_public)
            with exported_seed(new_service, exchange, runtime) as new_seed:
                new_private = make_private(new_seed)
                new_public = public_key(new_private)
                new_id = key_id(new_public)
                del new_private
            if old_id == new_id:
                refuse("succession-keys-must-differ")
            body = f"MGLA-SUCC1|old={old_id}|new={new_id}|pub={encoded(new_public)}"
            signature = old_private.sign(body.encode("ascii"))
        if body is None or signature is None:
            refuse("succession-signature-failed")
        return body + "|ssig=" + encoded(signature)


def keygen(service: str, paths: tuple[Path, Path, Path, Path, Path]) -> list[str]:
    validate_service(service)
    skeleton, suite, vault, exchange, runtime = paths
    if not sys.stdin.isatty():
        refuse("keygen-requires-tty")
    if any(name in os.environ for name in ("CI", "GITHUB_ACTIONS", "GITLAB_CI", "WOODPECKER", "BUILDKITE", "JENKINS_URL")):
        refuse("keygen-forbidden-in-ci")
    credential = vault / f"{service}.key"
    try:
        credential.lstat()
    except FileNotFoundError:
        pass
    except OSError:
        refuse("credential-state-unreadable")
    else:
        refuse("credential-exists-overwrite-refused")
    with mgla_lock(skeleton):
        require_exchange(exchange)
        seed = bytearray(os.urandom(32))
        payload = bytearray(b"mgla\n" + seed.hex().encode("ascii") + b"\n")
        try:
            run_ladder(runtime / "newkey.sh", ["--stdin", service], input_bytes=payload)
            private = make_private(seed)
            public = public_key(private)
            identifier = key_id(public)
            line = f"MGLA-KEY1|key={identifier}|pub={encoded(public)}"
            return [f"key={identifier}", line]
        finally:
            seed[:] = b"\0" * len(seed)
            payload[:] = b"\0" * len(payload)


def handle_signal(signum: int, _frame: object) -> None:
    try:
        cleanup_active_exports()
    except Refusal:
        os.write(2, b"MGLA REFUSAL: export-cleanup-failed\n")
        raise SystemExit(1)
    os.write(2, b"MGLA REFUSAL: interrupted\n")
    raise SystemExit(128 + signum)


def main(argv: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if not arguments:
        print("Usage: keyman mgla <keygen|keyline|sign|succeed> ...", file=sys.stderr)
        return 2
    for signum in (signal.SIGINT, signal.SIGTERM):
        signal.signal(signum, handle_signal)
    try:
        action = arguments[0]
        if action == "keygen" and len(arguments) == 2:
            validate_service(arguments[1])
            if not sys.stdin.isatty():
                refuse("keygen-requires-tty")
            if any(name in os.environ for name in ("CI", "GITHUB_ACTIONS", "GITLAB_CI", "WOODPECKER", "BUILDKITE", "JENKINS_URL")):
                refuse("keygen-forbidden-in-ci")
        paths = require_hierarchy()
        if action == "keygen" and len(arguments) == 2:
            output = keygen(arguments[1], paths)
        elif action == "keyline" and len(arguments) == 2:
            output = [mglakey(arguments[1], *paths)]
        elif action == "sign" and len(arguments) == 2:
            body = sys.stdin.buffer.read(MAX_BODY_BYTES + 1)
            output = [sign_body(arguments[1], body, *paths)]
        elif action == "succeed" and len(arguments) == 3:
            output = [succession(arguments[1], arguments[2], *paths)]
        else:
            refuse("usage-error", 2)
        for line in output:
            if isinstance(line, bytes):
                sys.stdout.buffer.write(line + b"\n")
            else:
                print(line)
        return 0
    except Refusal as exc:
        try:
            cleanup_active_exports()
        except Refusal:
            print("MGLA REFUSAL: export-cleanup-failed", file=sys.stderr)
            return 1
        print(f"MGLA REFUSAL: {exc.name}", file=sys.stderr)
        return exc.exit_code
    except KeyboardInterrupt:
        try:
            cleanup_active_exports()
        except Refusal:
            print("MGLA REFUSAL: export-cleanup-failed", file=sys.stderr)
            return 1
        print("MGLA REFUSAL: interrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
