#!/usr/bin/env python3
"""Forward-only Python installer for Keyman.

This is the new explicit installer membrane for the small Keyman vault system.
It preserves the existing shell/C runtime while making installation intent
visible: vault-only, field-node local-console secret, and homeserver full
deploy are separate profiles instead of implicit branches hidden inside
``keystartup.sh``.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import secrets
import shutil
import string
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

ROOT = Path(__file__).resolve().parents[2]
ROOT_CONFIG = ROOT / "index.json"
REDACTED = "[REDACTED]"


@dataclass
class InstallPaths:
    source_dir: Path
    runtime_dir: Path
    key_dir: Path
    vault_dir: Path
    exchange_dir: Path
    deploy_secret_file: Path
    sshd_dropin: Path

    @property
    def skeleton_key(self) -> Path:
        return self.key_dir / "skeleton.key"

    @property
    def service_suite_key(self) -> Path:
        return self.vault_dir / "service_suite.key"

    @property
    def nas_key(self) -> Path:
        return self.vault_dir / "nas.key"


@dataclass
class InstallOptions:
    command: str
    profile: str
    dry_run: bool
    admin_user: str
    admin_secret: str | None
    master_secret: str | None
    current_service_suite_secret: str | None
    new_service_suite_secret: str | None
    set_admin_secret: bool
    rotate_service_suite: bool
    write_deploy_secret: bool
    ssh_interactive_auth: str
    build_crypto: bool
    copy_runtime: bool
    init_vault: bool
    create_nas_key: bool
    mount_exchange_tmpfs: bool
    restart_ssh: bool
    replace_existing: bool
    receipt_path: Path | None
    paths: InstallPaths


@dataclass
class Action:
    name: str
    target: str
    mutation: bool
    status: str = "planned"
    detail: dict[str, Any] = field(default_factory=dict)

    def receipt(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "target": self.target,
            "mutation": self.mutation,
            "status": self.status,
            "detail": self.detail,
        }


class InstallerError(RuntimeError):
    pass


class KeymanInstaller:
    def __init__(self, options: InstallOptions) -> None:
        self.options = options
        self.actions: list[Action] = []
        self.started_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    def plan(self) -> list[Action]:
        p = self.options.paths
        if self.options.build_crypto:
            self.actions.append(Action("build-keyman-crypto", str(p.source_dir), True))
        if self.options.copy_runtime:
            self.actions.append(Action("copy-runtime-tree", f"{p.source_dir} -> {p.runtime_dir}", True))
        if self.options.init_vault:
            self.actions.append(Action("ensure-key-directories", f"{p.key_dir}, {p.vault_dir}, {p.exchange_dir}", True))
            if self.options.mount_exchange_tmpfs:
                self.actions.append(Action("ensure-exchange-tmpfs", str(p.exchange_dir), True))
            self.actions.append(Action("ensure-skeleton-key", str(p.skeleton_key), True, detail={"secret_material": REDACTED}))
            self.actions.append(Action("ensure-service-suite-key", str(p.service_suite_key), True, detail={"secret_material": REDACTED}))
            if self.options.create_nas_key:
                self.actions.append(Action("ensure-nas-key", str(p.nas_key), True, detail={"secret_material": REDACTED}))
        if self.options.set_admin_secret:
            self.actions.append(
                Action(
                    "set-admin-secret",
                    self.options.admin_user,
                    True,
                    detail={"secret": REDACTED, "local_console_intent": True},
                )
            )
        if self.options.rotate_service_suite:
            self.actions.append(
                Action(
                    "rotate-service-suite",
                    str(p.vault_dir),
                    True,
                    detail={"current_secret": REDACTED, "new_secret": REDACTED, "rewraps_service_keys": True},
                )
            )
        if self.options.write_deploy_secret:
            self.actions.append(Action("write-deploy-secret-file", str(p.deploy_secret_file), True, detail={"secret": REDACTED}))
        if self.options.ssh_interactive_auth != "keep":
            self.actions.append(Action("configure-ssh-interactive-auth", self.options.ssh_interactive_auth, True))
        if self.options.restart_ssh:
            self.actions.append(Action("restart-ssh-service", "sshd|ssh", True))
        return self.actions

    def run(self) -> dict[str, Any]:
        if not self.actions:
            self.plan()
        if self.options.dry_run:
            for action in self.actions:
                action.status = "dry-run"
            return self.receipt(ok=True, first_missing_signal="none")

        self._require_root_for_mutations()
        for action in self.actions:
            handler = getattr(self, f"_do_{action.name.replace('-', '_')}")
            handler(action)
        return self.receipt(ok=True, first_missing_signal="none")

    def verify(self) -> dict[str, Any]:
        p = self.options.paths
        access_module = p.runtime_dir / "lib" / "keyman_caduceus_access.py"
        access_artifact = p.runtime_dir / "lib" / "keyman_caduceus_access.runtime.json"
        access_importable = self._access_module_importable(access_module)
        access_binding = self._access_artifact_matches(access_module, access_artifact)
        checks = {
            "runtime_dir": p.runtime_dir.is_dir(),
            "keyman_crypto": (p.runtime_dir / "keyman-crypto").exists(),
            "utils_sh": (p.runtime_dir / "utils.sh").exists(),
            "newkey_sh": (p.runtime_dir / "newkey.sh").exists(),
            "exportkey_sh": (p.runtime_dir / "exportkey.sh").exists(),
            "caduceus_access_module": access_module.is_file(),
            "caduceus_access_artifact": access_artifact.is_file(),
            "caduceus_access_source_binding": access_binding,
            "caduceus_access_importable": access_importable,
            "key_dir": p.key_dir.is_dir(),
            "vault_dir": p.vault_dir.is_dir(),
            "skeleton_key": p.skeleton_key.exists(),
            "service_suite_key": p.service_suite_key.exists(),
        }
        ok = all(checks.values())
        return {
            "schema": "keyman.installer.verify.v1",
            "ok": ok,
            "profile": self.options.profile,
            "checks": checks,
            "caduceus_access": {
                "installed": checks["caduceus_access_module"],
                "runtime_artifact": checks["caduceus_access_artifact"],
                "source_binding_verified": checks["caduceus_access_source_binding"],
                "importable_with_crypto_dependency": checks["caduceus_access_importable"],
                "operation": "root-in-process-caduceus-verify-and-derive",
                "service": "caduceus",
                "private_material": REDACTED,
            },
            "secret_material": REDACTED,
            "first_missing_signal": "none" if ok else "keyman-install-incomplete",
        }

    @staticmethod
    def _access_artifact_matches(module: Path, artifact: Path) -> bool:
        """Prove the installed admitted module is exactly the declared source artifact."""
        try:
            declaration = json.loads(artifact.read_text(encoding="utf-8"))
            return declaration == {
                "schema": "keyman.caduceus_access.runtime.v1",
                "module": "keyman_caduceus_access.py",
                "sha256": hashlib.sha256(module.read_bytes()).hexdigest(),
                "install_path": "/opt/keyman/runtime/lib/keyman_caduceus_access.py",
                "consumer": "caduceus-access.service",
            }
        except (OSError, ValueError, TypeError):
            return False

    @staticmethod
    def _access_module_importable(path: Path) -> bool:
        """Check installed code and its crypto import without opening Keyman data."""
        name = "_keyman_caduceus_access_install_check"
        try:
            spec = importlib.util.spec_from_file_location(name, path)
            if spec is None or spec.loader is None:
                return False
            module = importlib.util.module_from_spec(spec)
            sys.modules[name] = module
            spec.loader.exec_module(module)
            return True
        except (ImportError, OSError, SyntaxError, ValueError):
            return False
        finally:
            sys.modules.pop(name, None)

    def receipt(self, *, ok: bool, first_missing_signal: str) -> dict[str, Any]:
        return {
            "schema": "keyman.installer.receipt.v1",
            "ok": ok,
            "command": self.options.command,
            "profile": self.options.profile,
            "dry_run": self.options.dry_run,
            "started_at": self.started_at,
            "completed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "admin_user": self.options.admin_user,
            "admin_secret": REDACTED if self.options.admin_secret else "not-supplied",
            "master_secret": REDACTED if self.options.master_secret else "generated-or-existing",
            "set_admin_secret": self.options.set_admin_secret,
            "rotate_service_suite": self.options.rotate_service_suite,
            "current_service_suite_secret": REDACTED if self.options.current_service_suite_secret else "not-supplied",
            "new_service_suite_secret": REDACTED if self.options.new_service_suite_secret else "not-supplied",
            "write_deploy_secret": self.options.write_deploy_secret,
            "ssh_interactive_auth": self.options.ssh_interactive_auth,
            "secret_material": REDACTED,
            "first_missing_signal": first_missing_signal,
            "actions": [action.receipt() for action in self.actions],
        }

    def _require_root_for_mutations(self) -> None:
        if hasattr(os, "geteuid") and os.geteuid() != 0:
            raise InstallerError("install requires root for vault paths, chpasswd, tmpfs, and permissions; rerun with sudo or use plan")

    def _do_build_keyman_crypto(self, action: Action) -> None:
        self._run(["make"], cwd=self.options.paths.source_dir)
        action.status = "done"

    def _do_copy_runtime_tree(self, action: Action) -> None:
        src = self.options.paths.source_dir.resolve()
        dst = self.options.paths.runtime_dir.resolve()
        if src == dst:
            action.status = "skipped"
            action.detail["reason"] = "source-is-runtime"
            return
        dst.mkdir(parents=True, exist_ok=True)
        os.chmod(dst, 0o700)
        for item in src.iterdir():
            if item.name in {".git", "__pycache__", ".pytest_cache"}:
                continue
            target = dst / item.name
            if item.is_dir():
                if target.exists():
                    shutil.rmtree(target)
                shutil.copytree(item, target, ignore=shutil.ignore_patterns("__pycache__", "*.pyc", ".git"))
            else:
                shutil.copy2(item, target)
            self._secure_runtime_path(target)
        action.status = "done"

    def _secure_runtime_path(self, path: Path) -> None:
        if path.is_dir():
            os.chmod(path, 0o700)
            for child in path.rglob("*"):
                self._secure_runtime_path(child)
            return
        executable_names = {"keyman-crypto", "index.py"}
        if path.suffix == ".sh" or path.name in executable_names:
            os.chmod(path, 0o700)
        else:
            os.chmod(path, 0o600)

    def _do_ensure_key_directories(self, action: Action) -> None:
        for directory in [self.options.paths.key_dir, self.options.paths.vault_dir, self.options.paths.exchange_dir]:
            directory.mkdir(parents=True, exist_ok=True)
            os.chmod(directory, 0o700)
        action.status = "done"

    def _do_ensure_exchange_tmpfs(self, action: Action) -> None:
        exchange_dir = self.options.paths.exchange_dir
        if self._is_mountpoint(exchange_dir):
            action.status = "skipped"
            action.detail["reason"] = "already-mounted"
            return
        self._run(["mount", "-t", "tmpfs", "-o", "size=100M,mode=700", "tmpfs", str(exchange_dir)])
        action.status = "done"

    def _do_ensure_skeleton_key(self, action: Action) -> None:
        key_path = self.options.paths.skeleton_key
        if key_path.exists() and not self.options.replace_existing:
            action.status = "skipped"
            action.detail["reason"] = "exists"
            return
        password = self.options.master_secret or self._generate_master_secret()
        self._reject_unquoted_keyman_value(password, "master secret")
        key_path.write_text(password + "\n", encoding="utf-8")
        os.chmod(key_path, 0o600)
        action.status = "done"

    def _do_ensure_service_suite_key(self, action: Action) -> None:
        target = self.options.paths.service_suite_key
        if target.exists() and not self.options.replace_existing:
            action.status = "skipped"
            action.detail["reason"] = "exists"
            return
        master = self._read_master_secret()
        self._write_encrypted_key(target, "service_suite", master, master)
        action.status = "done"

    def _do_ensure_nas_key(self, action: Action) -> None:
        target = self.options.paths.nas_key
        if target.exists() and not self.options.replace_existing:
            action.status = "skipped"
            action.detail["reason"] = "exists"
            return
        master = self._read_master_secret()
        self._write_encrypted_key(target, "nas", master, master)
        action.status = "done"

    def _do_set_admin_secret(self, action: Action) -> None:
        password = self.options.admin_secret
        if not password:
            raise InstallerError("setting admin secret requires --admin-secret, --admin-secret-env, or --admin-secret-file")
        self._run(["chpasswd"], input_text=f"{self.options.admin_user}:{password}\n")
        action.status = "done"

    def _do_rotate_service_suite(self, action: Action) -> None:
        current_secret = self.options.current_service_suite_secret
        new_secret = self.options.new_service_suite_secret
        if not current_secret or not new_secret:
            raise InstallerError("rotating service suite requires --current-service-suite-secret-* and --new-service-suite-secret-*")
        if current_secret == new_secret:
            raise InstallerError("new service-suite secret must differ from current service-suite secret")
        self._reject_unquoted_keyman_value(new_secret, "new service-suite secret")
        observed = self._decrypt_service_suite_secret()
        if observed != current_secret:
            raise InstallerError("current service-suite secret did not match installed service_suite.key")
        services = self._service_key_names()
        for service_name in services:
            self._run([str(self.options.paths.runtime_dir / "exportkey.sh"), service_name])
        for service_name in services:
            decrypted = self.options.paths.exchange_dir / service_name
            if not decrypted.exists():
                raise InstallerError(f"exported service payload missing for {service_name}")
            reencrypt_input = self.options.paths.exchange_dir / f"reencrypt_{service_name}_{os.getpid()}"
            reencrypt_input.write_text(f"service={service_name}\nnew_password={new_secret}\n", encoding="utf-8")
            os.chmod(reencrypt_input, 0o600)
            try:
                self._run([str(self.options.paths.runtime_dir / "keyman-crypto"), "reencrypt", str(reencrypt_input)])
            finally:
                self._shred_or_unlink(reencrypt_input)
                self._shred_or_unlink(decrypted)
        suite_plain = self.options.paths.exchange_dir / "service_suite.rotate"
        suite_plain.parent.mkdir(parents=True, exist_ok=True)
        suite_plain.write_text(f'username="service_suite"\npassword="{new_secret}"\n', encoding="utf-8")
        os.chmod(suite_plain, 0o600)
        try:
            self._run([str(self.options.paths.runtime_dir / "keyman-crypto"), "encrypt_suite_key", str(suite_plain)])
        finally:
            self._shred_or_unlink(suite_plain)
        action.status = "done"
        action.detail["service_key_count"] = len(services)

    def _decrypt_service_suite_secret(self) -> str:
        suite = self.options.paths.service_suite_key
        require = [self.options.paths.skeleton_key, suite]
        for path in require:
            if not path.exists():
                raise InstallerError(f"required Keyman secret file is missing: {path}")
        self.options.paths.exchange_dir.mkdir(parents=True, exist_ok=True)
        out = self.options.paths.exchange_dir / f"service_suite_verify_{os.getpid()}"
        try:
            self._run([
                "openssl", "enc", "-d", "-aes-256-cbc", "-pbkdf2",
                "-in", str(suite), "-out", str(out), "-pass", f"file:{self.options.paths.skeleton_key}",
            ])
            data = out.read_text(encoding="utf-8")
            for line in data.splitlines():
                if line.startswith("password="):
                    return line.split('"', 2)[1]
            raise InstallerError("service_suite.key decrypted but contained no password field")
        finally:
            self._shred_or_unlink(out)

    def _service_key_names(self) -> list[str]:
        if not self.options.paths.vault_dir.exists():
            raise InstallerError(f"vault key directory missing: {self.options.paths.vault_dir}")
        names = []
        for path in sorted(self.options.paths.vault_dir.glob("*.key")):
            if path.name == "service_suite.key":
                continue
            names.append(path.stem)
        return names

    def _do_write_deploy_secret_file(self, action: Action) -> None:
        password = self.options.admin_secret
        if not password:
            raise InstallerError("writing deploy secret requires an explicit admin secret")
        target = self.options.paths.deploy_secret_file
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(password + "\n", encoding="utf-8")
        os.chmod(target, 0o600)
        action.status = "done"

    def _do_configure_ssh_interactive_auth(self, action: Action) -> None:
        mode = self.options.ssh_interactive_auth
        if mode not in {"disable", "enable"}:
            action.status = "skipped"
            action.detail["reason"] = "keep"
            return
        lines = [
            "# Managed by Keyman Python installer.",
            "# Desired state: local console secrets may exist; SSH follows this explicit policy.",
        ]
        if mode == "disable":
            lines.extend(["PasswordAuthentication no", "KbdInteractiveAuthentication no", "PubkeyAuthentication yes"])
        else:
            lines.extend(["PasswordAuthentication yes", "KbdInteractiveAuthentication yes", "PubkeyAuthentication yes"])
        target = self.options.paths.sshd_dropin
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("\n".join(lines) + "\n", encoding="utf-8")
        os.chmod(target, 0o644)
        action.status = "done"

    def _do_restart_ssh_service(self, action: Action) -> None:
        for service in ("sshd", "ssh"):
            result = subprocess.run(["systemctl", "restart", service], text=True, capture_output=True, check=False)
            if result.returncode == 0:
                action.status = "done"
                action.detail["service"] = service
                return
        raise InstallerError("failed to restart sshd or ssh service")

    def _write_encrypted_key(self, target: Path, username: str, secret: str, master_secret: str) -> None:
        self._reject_unquoted_keyman_value(secret, f"{username} secret")
        plaintext = f'username="{username}"\npassword="{secret}"\n'
        self.options.paths.exchange_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(self.options.paths.exchange_dir, 0o700)
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=self.options.paths.exchange_dir, delete=False) as handle:
            input_path = Path(handle.name)
            handle.write(plaintext)
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            self._run(
                [
                    "openssl",
                    "enc",
                    "-aes-256-cbc",
                    "-pbkdf2",
                    "-salt",
                    "-in",
                    str(input_path),
                    "-out",
                    str(target),
                    "-pass",
                    f"file:{self.options.paths.skeleton_key}",
                ]
            )
            os.chmod(target, 0o600)
        finally:
            self._shred_or_unlink(input_path)

    def _read_master_secret(self) -> str:
        key_path = self.options.paths.skeleton_key
        if not key_path.exists():
            raise InstallerError("skeleton key is missing before service-suite creation")
        return key_path.read_text(encoding="utf-8").strip()

    def _generate_master_secret(self) -> str:
        alphabet = string.ascii_letters + string.digits + "-._~"
        while True:
            value = "".join(secrets.choice(alphabet) for _ in range(32))
            if value[0] not in "-._~" and any(c.isdigit() for c in value) and any(c.isupper() for c in value) and any(c.islower() for c in value):
                return value

    def _reject_unquoted_keyman_value(self, value: str, label: str) -> None:
        if not value:
            raise InstallerError(f"{label} cannot be empty")
        if '"' in value or "\n" in value:
            raise InstallerError(f"{label} cannot contain a double quote or newline because legacy keyman-crypto parses quoted values")

    def _run(self, argv: list[str], *, cwd: Path | None = None, input_text: str | None = None) -> subprocess.CompletedProcess[str]:
        result = subprocess.run(argv, cwd=cwd, input=input_text, text=True, capture_output=True, check=False)
        if result.returncode != 0:
            raise InstallerError(f"command failed: {argv[0]} exited {result.returncode}: {result.stderr.strip()}")
        return result

    def _shred_or_unlink(self, path: Path) -> None:
        if not path.exists():
            return
        result = subprocess.run(["shred", "-u", str(path)], text=True, capture_output=True, check=False)
        if result.returncode != 0 and path.exists():
            path.unlink()

    def _is_mountpoint(self, path: Path) -> bool:
        return subprocess.run(["mountpoint", "-q", str(path)], check=False).returncode == 0


def load_root_config() -> dict[str, Any]:
    if not ROOT_CONFIG.exists():
        return {}
    return json.loads(ROOT_CONFIG.read_text(encoding="utf-8"))


def default_paths(config: dict[str, Any], source_dir: Path) -> InstallPaths:
    paths = config.get("paths", {})
    return InstallPaths(
        source_dir=source_dir,
        runtime_dir=Path(paths.get("runtime_dir", "/vault/keyman")),
        key_dir=Path(paths.get("key_dir", "/root/key")),
        vault_dir=Path(paths.get("vault_dir", "/vault/.keys")),
        exchange_dir=Path(paths.get("exchange_dir", "/mnt/keyexchange")),
        deploy_secret_file=Path(paths.get("deploy_secret_file", "/deploy/operator-secret.txt")),
        sshd_dropin=Path(paths.get("sshd_dropin", "/etc/ssh/sshd_config.d/99-keyman-operator-access.conf")),
    )


def resolve_secret(*, literal: str | None, env_name: str | None, file_path: str | None, label: str) -> str | None:
    supplied = [value is not None for value in (literal, env_name, file_path)].count(True)
    if supplied > 1:
        raise InstallerError(f"supply only one {label} source")
    if literal is not None:
        return literal
    if env_name is not None:
        value = os.environ.get(env_name)
        if not value:
            raise InstallerError(f"environment variable {env_name} for {label} is missing or empty")
        return value
    if file_path is not None:
        value = Path(file_path).read_text(encoding="utf-8").strip()
        if not value:
            raise InstallerError(f"file for {label} is empty")
        return value
    return None


def build_options(ns: argparse.Namespace) -> InstallOptions:
    config = load_root_config()
    profiles = config.get("profiles", {})
    profile = profiles.get(ns.profile)
    if not profile:
        raise InstallerError(f"unknown profile {ns.profile!r}; expected one of: {', '.join(sorted(profiles))}")

    source_dir = Path(ns.source_dir).resolve() if ns.source_dir else ROOT
    paths = default_paths(config, source_dir)
    paths.runtime_dir = Path(ns.runtime_dir or paths.runtime_dir)
    paths.key_dir = Path(ns.key_dir or paths.key_dir)
    paths.vault_dir = Path(ns.vault_dir or paths.vault_dir)
    paths.exchange_dir = Path(ns.exchange_dir or paths.exchange_dir)
    paths.deploy_secret_file = Path(ns.deploy_secret_file or paths.deploy_secret_file)
    paths.sshd_dropin = Path(ns.sshd_dropin or paths.sshd_dropin)

    admin_secret = resolve_secret(
        literal=ns.admin_secret,
        env_name=ns.admin_secret_env,
        file_path=ns.admin_secret_file,
        label="admin secret",
    )
    master_secret = resolve_secret(
        literal=ns.master_secret,
        env_name=ns.master_secret_env,
        file_path=ns.master_secret_file,
        label="master secret",
    )
    current_service_suite_secret = resolve_secret(
        literal=None,
        env_name=ns.current_service_suite_secret_env,
        file_path=ns.current_service_suite_secret_file,
        label="current service-suite secret",
    )
    new_service_suite_secret = resolve_secret(
        literal=None,
        env_name=ns.new_service_suite_secret_env,
        file_path=ns.new_service_suite_secret_file,
        label="new service-suite secret",
    )

    set_admin_secret = ns.set_admin_secret if ns.set_admin_secret is not None else bool(profile.get("set_admin_secret", False))
    write_deploy_secret = ns.write_deploy_secret if ns.write_deploy_secret is not None else bool(profile.get("write_deploy_secret", False))
    ssh_interactive_auth = ns.ssh_interactive_auth or str(profile.get("ssh_password_auth", "keep"))
    admin_user = ns.admin_user or str(profile.get("admin_user", "owner"))

    return InstallOptions(
        command=ns.command,
        profile=ns.profile,
        dry_run=(ns.command == "plan") or ns.dry_run,
        admin_user=admin_user,
        admin_secret=admin_secret,
        master_secret=master_secret,
        current_service_suite_secret=current_service_suite_secret,
        new_service_suite_secret=new_service_suite_secret,
        set_admin_secret=set_admin_secret,
        rotate_service_suite=ns.rotate_service_suite,
        write_deploy_secret=write_deploy_secret,
        ssh_interactive_auth=ssh_interactive_auth,
        build_crypto=not ns.no_build_crypto,
        copy_runtime=not ns.no_copy_runtime,
        init_vault=not ns.no_init_vault,
        create_nas_key=not ns.no_nas_key,
        mount_exchange_tmpfs=not ns.no_mount_exchange_tmpfs,
        restart_ssh=ns.restart_ssh,
        replace_existing=ns.replace_existing,
        receipt_path=Path(ns.receipt) if ns.receipt else None,
        paths=paths,
    )


def write_receipt(receipt: dict[str, Any], path: Path | None) -> None:
    text = json.dumps(receipt, indent=2, sort_keys=True) + "\n"
    if path:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    print(text, end="")


def add_common_flags(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--profile", default="vault-only", choices=sorted(load_root_config().get("profiles", {"vault-only": {}})))
    parser.add_argument("--source-dir", help="Keyman source tree to copy/build from; default is this repo root")
    parser.add_argument("--runtime-dir")
    parser.add_argument("--key-dir")
    parser.add_argument("--vault-dir")
    parser.add_argument("--exchange-dir")
    parser.add_argument("--deploy-secret-file")
    parser.add_argument("--sshd-dropin")
    parser.add_argument("--admin-user")
    parser.add_argument("--admin-secret", help="Explicit admin secret. Prefer --admin-secret-env or --admin-secret-file outside disposable lab flows.")
    parser.add_argument("--admin-secret-env", help="Environment variable containing the admin secret")
    parser.add_argument("--admin-secret-file", help="File containing the admin secret")
    parser.add_argument("--master-secret", help="Explicit Keyman master/skeleton secret. Usually omit to generate.")
    parser.add_argument("--master-secret-env")
    parser.add_argument("--master-secret-file")
    parser.add_argument("--current-service-suite-secret-env", help="Environment variable containing the current service-suite secret for rotate")
    parser.add_argument("--current-service-suite-secret-file", help="File containing the current service-suite secret for rotate")
    parser.add_argument("--new-service-suite-secret-env", help="Environment variable containing the new service-suite secret for rotate")
    parser.add_argument("--new-service-suite-secret-file", help="File containing the new service-suite secret for rotate")
    parser.add_argument("--rotate-service-suite", action="store_true", help="Rotate service_suite.key and rewrap existing service keys")
    parser.add_argument("--set-admin-secret", dest="set_admin_secret", action="store_true", default=None)
    parser.add_argument("--no-set-admin-secret", dest="set_admin_secret", action="store_false")
    parser.add_argument("--write-deploy-secret", dest="write_deploy_secret", action="store_true", default=None)
    parser.add_argument("--no-write-deploy-secret", dest="write_deploy_secret", action="store_false")
    parser.add_argument("--ssh-interactive-auth", dest="ssh_interactive_auth", choices=["keep", "disable", "enable"])
    parser.add_argument("--no-build-crypto", action="store_true")
    parser.add_argument("--no-copy-runtime", action="store_true")
    parser.add_argument("--no-init-vault", action="store_true")
    parser.add_argument("--no-nas-key", action="store_true")
    parser.add_argument("--no-mount-exchange-tmpfs", action="store_true")
    parser.add_argument("--replace-existing", action="store_true", help="Replace existing skeleton/service keys; destructive for existing credentials")
    parser.add_argument("--restart-ssh", action="store_true")
    parser.add_argument("--receipt", help="Write JSON receipt to this path as well as stdout")
    parser.add_argument("--dry-run", action="store_true", help="Plan without mutating even under install")


def build_parser() -> argparse.ArgumentParser:
    description = "Pythonic Keyman installer: explicit vault, local access, and SSH policy profiles."
    parser = argparse.ArgumentParser(description=description, formatter_class=argparse.RawDescriptionHelpFormatter, epilog=examples())
    sub = parser.add_subparsers(dest="command")
    plan = sub.add_parser("plan", help="Print the mutation plan and redacted receipt; no changes")
    add_common_flags(plan)
    install = sub.add_parser("install", help="Apply the selected Keyman install profile")
    add_common_flags(install)
    rotate = sub.add_parser("rotate", help="Locally rotate owner password and/or service-suite key with redacted receipts")
    add_common_flags(rotate)
    rotate.set_defaults(rotate_service_suite=True)
    verify = sub.add_parser("verify", help="Verify installed Keyman runtime/vault shape")
    add_common_flags(verify)
    return parser


def examples() -> str:
    return """
Examples:
  python3 index.py
  python3 index.py plan --profile vault-only
  python3 index.py plan --profile field-node --admin-secret-env KEYMAN_ADMIN_SECRET
  sudo KEYMAN_ADMIN_SECRET=<operator-local-secret> python3 index.py install --profile field-node --admin-secret-env KEYMAN_ADMIN_SECRET
  python3 index.py rotate --dry-run --profile field-node --admin-secret-env NEW_OWNER_SECRET --current-service-suite-secret-env CURRENT_KEYMAN_SECRET --new-service-suite-secret-env NEW_KEYMAN_SECRET

Profile intent:
  vault-only             initialize Keyman without changing OS account secrets
  field-node             operator local TTY secret supplied explicitly; SSH remains key-only
  full-deploy compatibility full deploy posture; use with care

Secret law:
  Receipts redact secret material. Prefer env/file secret sources over literal CLI flags.
"""


def main(argv: Iterable[str] | None = None) -> int:
    args = list(argv if argv is not None else sys.argv[1:])
    parser = build_parser()
    if not args:
        parser.print_help()
        return 0
    ns = parser.parse_args(args)
    if not ns.command:
        parser.print_help()
        return 0
    try:
        options = build_options(ns)
        installer = KeymanInstaller(options)
        if ns.command == "verify":
            receipt = installer.verify()
        else:
            installer.plan()
            receipt = installer.run()
        write_receipt(receipt, options.receipt_path)
        return 0 if receipt.get("ok") else 1
    except InstallerError as exc:
        receipt = {
            "schema": "keyman.installer.receipt.v1",
            "ok": False,
            "error": str(exc),
            "secret_material": REDACTED,
            "first_missing_signal": "keyman-installer-error",
        }
        write_receipt(receipt, None)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
