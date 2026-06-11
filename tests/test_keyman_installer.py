import json
import os
import subprocess
import sys
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


if __name__ == "__main__":
    unittest.main()
