import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FORBIDDEN_PUBLIC_TERMS = [
    "".join(["C", "h", "i", "a"]),
    "".join(["c", "h", "i", "a"]),
    "23" + "12",
    "KEYMAN_ADMIN_" + "PASSWORD",
    "--admin-" + "password",
    "--master-" + "password",
]


class KeymanInstallerCliTests(unittest.TestCase):
    def run_index(self, *args: str, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
        merged_env = os.environ.copy()
        if env:
            merged_env.update(env)
        return subprocess.run(
            [sys.executable, str(ROOT / "index.py"), *args],
            cwd=ROOT,
            env=merged_env,
            text=True,
            capture_output=True,
            check=False,
        )

    def test_naked_run_prints_public_help_without_product_terms(self) -> None:
        result = self.run_index()
        self.assertEqual(result.returncode, 0, result.stderr)
        for term in FORBIDDEN_PUBLIC_TERMS:
            self.assertNotIn(term, result.stdout)
        self.assertIn("field-node", result.stdout)
        self.assertIn("SSH remains key-only", result.stdout)

    def test_field_node_plan_redacts_supplied_secret(self) -> None:
        result = self.run_index(
            "plan",
            "--profile",
            "field-node",
            "--admin-secret-env",
            "KEYMAN_ADMIN_SECRET",
            env={"KEYMAN_ADMIN_SECRET": "sample-public-test-secret"},
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("sample-public-test-secret", result.stdout)
        payload = json.loads(result.stdout)
        self.assertTrue(payload["ok"])
        self.assertTrue(payload["dry_run"])
        self.assertEqual(payload["profile"], "field-node")
        self.assertEqual(payload["admin_secret"], "[REDACTED]")
        self.assertEqual(payload["ssh_interactive_auth"], "disable")
        action_names = [action["name"] for action in payload["actions"]]
        self.assertIn("set-admin-secret", action_names)
        self.assertIn("configure-ssh-interactive-auth", action_names)

    def test_public_new_surfaces_are_anonymized(self) -> None:
        public_paths = [
            ROOT / "index.json",
            ROOT / "index.py",
            ROOT / "lib" / "keyman_installer" / "README.md",
            ROOT / "lib" / "keyman_installer" / "index.py",
            ROOT / "lib" / "keyman_installer" / "index.json",
        ]
        for path in public_paths:
            text = path.read_text(encoding="utf-8")
            for term in FORBIDDEN_PUBLIC_TERMS:
                self.assertNotIn(term, text, f"{term!r} leaked in {path}")

    def test_rotate_plan_is_local_and_redacted(self) -> None:
        result = self.run_index(
            "rotate",
            "--dry-run",
            "--profile",
            "field-node",
            "--admin-secret-env",
            "NEW_OWNER_SECRET",
            "--current-service-suite-secret-env",
            "CURRENT_KEYMAN_SECRET",
            "--new-service-suite-secret-env",
            "NEW_KEYMAN_SECRET",
            env={
                "NEW_OWNER_SECRET": "sample-new-owner-secret",
                "CURRENT_KEYMAN_SECRET": "sample-current-suite-secret",
                "NEW_KEYMAN_SECRET": "sample-new-suite-secret",
            },
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("sample-new-owner-secret", result.stdout)
        self.assertNotIn("sample-current-suite-secret", result.stdout)
        self.assertNotIn("sample-new-suite-secret", result.stdout)
        payload = json.loads(result.stdout)
        self.assertTrue(payload["ok"])
        self.assertTrue(payload["dry_run"])
        self.assertEqual(payload["profile"], "field-node")
        self.assertTrue(payload["set_admin_secret"])
        self.assertTrue(payload["rotate_service_suite"])
        actions = [action["name"] for action in payload["actions"]]
        self.assertIn("set-admin-secret", actions)
        self.assertIn("rotate-service-suite", actions)
        self.assertEqual(payload["secret_material"], "[REDACTED]")

    def test_caduceus_seed_plan_uses_default_pin_and_redacts_it(self) -> None:
        result = self.run_index("plan", "--install-caduceus", "--seed-caduceus-pin")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn('"1"', result.stdout)
        payload = json.loads(result.stdout)
        action = next(action for action in payload["actions"] if action["name"] == "seed-caduceus-key")
        self.assertEqual(action["detail"], {"identity": "sha256-raw-skeleton-bytes", "pin": "[REDACTED]"})

    def test_caduceus_seed_requires_extension_and_force_requires_seed(self) -> None:
        seed_without_extension = self.run_index("plan", "--seed-caduceus-pin")
        self.assertNotEqual(seed_without_extension.returncode, 0)
        self.assertNotIn("1", seed_without_extension.stderr)
        force_without_seed = self.run_index("plan", "--install-caduceus", "--force-caduceus-pin")
        self.assertNotEqual(force_without_seed.returncode, 0)

    def test_caduceus_seed_uses_untouched_ceremony_and_is_idempotent(self) -> None:
        from keyman_installer.index import KeymanInstaller, build_options, build_parser

        with tempfile.TemporaryDirectory(prefix="keyman-caduceus-fake-root-") as temporary:
            root = Path(temporary)
            runtime = root / "vault/keyman"
            key_dir = root / "root/key"
            vault = root / "vault/.keys"
            exchange = root / "mnt/keyexchange"
            runtime.mkdir(parents=True)
            key_dir.mkdir(parents=True)
            vault.mkdir(parents=True)
            exchange.mkdir(parents=True)
            raw_skeleton = b"raw-skeleton-bytes\n"
            (key_dir / "skeleton.key").write_bytes(raw_skeleton)
            (vault / "service_suite.key").write_bytes(b"fixture")
            ceremony = runtime / "newkey.sh"
            ceremony.write_text("#!/bin/sh\n", encoding="utf-8")
            ceremony.chmod(0o700)
            args = [
                "install", "--install-caduceus", "--seed-caduceus-pin", "test-pin",
                "--no-build-crypto", "--no-copy-runtime", "--no-init-vault", "--no-nas-key", "--no-mount-exchange-tmpfs",
                "--runtime-dir", str(runtime), "--key-dir", str(key_dir), "--vault-dir", str(vault), "--exchange-dir", str(exchange),
            ]
            installer = KeymanInstaller(build_options(build_parser().parse_args(args)))
            calls: list[list[str]] = []

            def ceremony_run(argv, **_):
                calls.append(argv)
                (vault / "caduceus.key").write_bytes(b"encrypted-fixture")
                return subprocess.CompletedProcess(argv, 0, "", "")

            installer._run = ceremony_run  # type: ignore[method-assign]
            installer._require_root_for_mutations = lambda: None  # type: ignore[method-assign]
            receipt = installer.run()
            self.assertTrue(receipt["ok"])
            self.assertEqual(calls, [[str(ceremony), "caduceus", __import__("hashlib").sha256(raw_skeleton).hexdigest(), "test-pin"]])
            self.assertEqual(stat.S_IMODE((vault / "caduceus.key").stat().st_mode), 0o600)
            self.assertNotIn("test-pin", json.dumps(receipt))

            repeated = KeymanInstaller(build_options(build_parser().parse_args(args)))
            repeated._run = ceremony_run  # type: ignore[method-assign]
            repeated._require_root_for_mutations = lambda: None  # type: ignore[method-assign]
            repeat_receipt = repeated.run()
            action = next(item for item in repeat_receipt["actions"] if item["name"] == "seed-caduceus-key")
            self.assertEqual(action["status"], "skipped")
            self.assertEqual(action["detail"]["reason"], "exists")
            self.assertEqual(len(calls), 1)

            forced_args = [*args, "--force-caduceus-pin"]
            forced = KeymanInstaller(build_options(build_parser().parse_args(forced_args)))
            forced._run = ceremony_run  # type: ignore[method-assign]
            forced._require_root_for_mutations = lambda: None  # type: ignore[method-assign]
            forced.run()
            self.assertEqual(len(calls), 2)

    def test_verify_receipt_names_redacted_caduceus_access_shape(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runtime = root / "runtime"
            (runtime / "lib").mkdir(parents=True)
            for name in ["keyman-crypto", "utils.sh", "newkey.sh", "exportkey.sh"]:
                (runtime / name).write_text("fixture\n", encoding="utf-8")
            shutil.copy2(ROOT / "lib" / "keyman_caduceus_access.py", runtime / "lib" / "keyman_caduceus_access.py")
            shutil.copy2(ROOT / "lib" / "keyman_caduceus_access.runtime.json", runtime / "lib" / "keyman_caduceus_access.runtime.json")
            key_dir = root / "key"
            vault = root / "vault"
            key_dir.mkdir()
            vault.mkdir()
            (key_dir / "skeleton.key").write_text("fixture\n", encoding="utf-8")
            (vault / "service_suite.key").write_bytes(b"fixture")
            result = self.run_index(
                "verify", "--runtime-dir", str(runtime), "--key-dir", str(key_dir), "--vault-dir", str(vault)
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        self.assertTrue(payload["ok"])
        self.assertTrue(payload["checks"]["caduceus_access_module"])
        self.assertTrue(payload["checks"]["caduceus_access_artifact"])
        self.assertTrue(payload["checks"]["caduceus_access_source_binding"])
        self.assertTrue(payload["checks"]["caduceus_access_importable"])
        self.assertTrue(payload["caduceus_access"]["importable_with_crypto_dependency"])
        self.assertEqual(payload["caduceus_access"]["operation"], "root-in-process-caduceus-verify-and-derive")
        self.assertEqual(payload["caduceus_access"]["private_material"], "[REDACTED]")


if __name__ == "__main__":
    unittest.main()
