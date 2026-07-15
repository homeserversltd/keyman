import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lib"))
from keyman_installer.index import KeymanInstaller, build_options, build_parser


class HarmoniaColdBearerFixtureTests(unittest.TestCase):
    def test_empty_root_install_materializes_runtime_access_artifacts_before_caduceus(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            runtime = root / "opt/keyman/runtime"
            key_dir = root / "root/key"
            vault_dir = root / "vault/.keys"
            shutil.copytree(ROOT, source, ignore=shutil.ignore_patterns(".git", ".worktrees", "__pycache__", "*.pyc"))
            parser = build_parser()
            options = build_options(parser.parse_args([
                "install", "--profile", "vault-only",
                "--source-dir", str(source),
                "--runtime-dir", str(runtime),
                "--key-dir", str(key_dir),
                "--vault-dir", str(vault_dir),
                "--exchange-dir", str(root / "exchange"),
                "--no-build-crypto", "--no-mount-exchange-tmpfs", "--no-nas-key",
            ]))
            installer = KeymanInstaller(options)
            installer.plan()
            with mock.patch.object(installer, "_require_root_for_mutations"):
                receipt = installer.run()
            self.assertTrue(receipt["ok"])
            self.assertTrue((runtime / "lib/keyman_caduceus_access.py").is_file())
            self.assertTrue((runtime / "lib/keyman_caduceus_access.runtime.json").is_file())
            verified = installer.verify()
            self.assertTrue(verified["ok"])
            self.assertTrue(verified["checks"]["caduceus_access_source_binding"])
            self.assertTrue(verified["checks"]["caduceus_access_importable"])


if __name__ == "__main__":
    unittest.main()
