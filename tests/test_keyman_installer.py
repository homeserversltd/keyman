import json
import os
import shutil
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
