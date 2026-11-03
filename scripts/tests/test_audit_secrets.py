import base64
import importlib.util
import os
import stat
import tempfile
import unittest
from pathlib import Path

SPEC = importlib.util.spec_from_file_location(
    "audit_secret_initializer", Path(__file__).resolve().parents[1] / "init-audit-secrets.py"
)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class AuditSecretTests(unittest.TestCase):
    def test_private_random_files_and_repeated_initialization_preserves_them(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / "audit"
            files = MODULE.initialize(directory)
            before = [path.read_bytes() for path in files]
            self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o700)
            self.assertTrue(all(stat.S_IMODE(path.stat().st_mode) == 0o600 for path in files))
            key = before[0].decode().strip().split("=", 1)[1]
            token = before[1].decode().strip().split("=", 1)[1]
            self.assertEqual(len(base64.b64decode(key, validate=True)), 32)
            self.assertGreaterEqual(len(token), 32)
            with self.assertRaisesRegex(ValueError, "refusing to overwrite"):
                MODULE.initialize(directory)
            self.assertEqual([path.read_bytes() for path in files], before)
            other = MODULE.initialize(Path(temporary) / "other")
            self.assertNotEqual(other[0].read_bytes(), before[0])
            self.assertNotEqual(other[1].read_bytes(), before[1])

    def test_public_directory_and_symlink_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / "audit"
            directory.mkdir(mode=0o755)
            os.chmod(directory, 0o755)
            with self.assertRaisesRegex(ValueError, "0700"):
                MODULE.initialize(directory)
            link = Path(temporary) / "link"
            link.symlink_to(directory)
            with self.assertRaisesRegex(ValueError, "symlink"):
                MODULE.initialize(link)
            self.assertEqual(list(directory.iterdir()), [])

    def test_partial_initialization_or_dangling_link_never_overwritten(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            sentinel = directory / "operator.env"
            sentinel.symlink_to(directory / "absent")
            with self.assertRaisesRegex(ValueError, "refusing to overwrite"):
                MODULE.initialize(directory)
            self.assertTrue(sentinel.is_symlink())
            self.assertFalse((directory / "vault.env").exists())


if __name__ == "__main__":
    unittest.main()
