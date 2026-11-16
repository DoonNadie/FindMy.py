"""Offline storage tests: python3 -m unittest discover -s tests -p test_storage.py."""

import importlib.util
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

from cryptography.exceptions import InvalidTag

# Load this optional module alone, without package-level network/Bluetooth dependencies.
_spec = importlib.util.spec_from_file_location(
    "findmy_storage_tests", Path(__file__).resolve().parents[1] / "findmy" / "storage.py"
)
storage = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(storage)
EncryptedStateStore = storage.EncryptedStateStore


@unittest.skipUnless(os.name == "posix", "POSIX permissions required")
class StorageTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name).resolve()
        self.root = self.base / "state"
        self.key = bytes(range(32))
        self.store = EncryptedStateStore(self.root, self.key)

    def test_roundtrip_and_random_nonce(self):
        value = {"secret": "not plaintext ☃", "list": [None, True, 42]}
        self.store.write_json("account.json", value)
        first = (self.root / "account.json").read_bytes()
        self.assertNotIn(b"not plaintext", first)
        self.assertEqual(self.store.read_json("account.json"), value)
        self.store.write_json("account.json", value)
        self.assertNotEqual(first, (self.root / "account.json").read_bytes())
        for value in [None, [], "text", 123, False]:
            self.store.write_json("scalar", value)
            self.assertEqual(self.store.read_json("scalar"), value)

    def test_missing(self):
        with self.assertRaises(FileNotFoundError):
            self.store.read_json("missing")

    def test_authentication(self):
        self.store.write_json("original", {"private": "value"})
        path = self.root / "original"
        original = path.read_bytes()
        path.write_bytes(original[:-1] + bytes([original[-1] ^ 1]))
        with self.assertRaises(InvalidTag):
            self.store.read_json("original")
        path.write_bytes(original)
        wrong = EncryptedStateStore(self.root, b"x" * 32)
        with self.assertRaises(InvalidTag):
            wrong.read_json("original")
        path.rename(self.root / "renamed")
        with self.assertRaises(InvalidTag):
            self.store.read_json("renamed")

    def test_formats(self):
        path = self.root / "bad"
        for content in [b"", b"plaintext", b"FindMyState\x02" + b"x" * 50]:
            path.write_bytes(content)
            path.chmod(0o600)
            with self.assertRaises(ValueError):
                self.store.read_json("bad")

    def test_permissions(self):
        self.store.write_json("file", {})
        self.assertEqual(stat.S_IMODE(self.root.stat().st_mode), 0o700)
        path = self.root / "file"
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        path.chmod(0o644)
        for operation in [lambda: self.store.read_json("file"),
                          lambda: self.store.write_json("file", {})]:
            with self.assertRaises(PermissionError):
                operation()
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o644)
        self.root.chmod(0o755)
        with self.assertRaises(PermissionError):
            EncryptedStateStore(self.root, self.key)
        self.assertEqual(stat.S_IMODE(self.root.stat().st_mode), 0o755)
        with self.assertRaises(PermissionError):
            self.store.write_json("other", {})

    def test_names(self):
        for name in ["", ".", "..", "../outside", "a/b", "a\\b", "a..b",
                     "/absolute", "nul\x00", "é", "x" * 129, None]:
            for operation in [lambda: self.store.read_json(name),
                              lambda: self.store.write_json(name, {})]:
                with self.subTest(name=name), self.assertRaises(ValueError):
                    operation()

    def test_symlinks(self):
        target = self.base / "target"
        target.write_bytes(b"untouched")
        link = self.root / "link"
        link.symlink_to(target)
        for operation in [lambda: self.store.read_json("link"),
                          lambda: self.store.write_json("link", {})]:
            with self.assertRaises((OSError, ValueError)):
                operation()
        self.assertEqual(target.read_bytes(), b"untouched")
        root_link = self.base / "root-link"
        root_link.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(ValueError):
            EncryptedStateStore(root_link, self.key)
        with self.assertRaises(ValueError):
            EncryptedStateStore(root_link / "nested", self.key)
        link.unlink()
        link.symlink_to(self.base / "missing")
        with self.assertRaises((OSError, ValueError)):
            self.store.write_json("link", {})

    def test_hardlinks(self):
        self.store.write_json("file", {})
        os.link(self.root / "file", self.root / "alias")
        with self.assertRaises(PermissionError):
            self.store.read_json("file")
        with self.assertRaises(PermissionError):
            self.store.write_json("file", {})

    def test_atomic_failure(self):
        self.store.write_json("file", {"old": True})
        before = (self.root / "file").read_bytes()
        for method in ["replace", "fsync"]:
            with self.subTest(method=method):
                with patch.object(storage.os, method, side_effect=OSError("injected")):
                    with self.assertRaises(OSError):
                        self.store.write_json("file", {"new": True})
                self.assertEqual((self.root / "file").read_bytes(), before)
                self.assertEqual(sorted(p.name for p in self.root.iterdir()), ["file"])
                self.assertEqual(self.store.read_json("file"), {"old": True})

    def test_invalid_key_and_json_leave_no_files(self):
        for key in [b"", b"x" * 31, b"x" * 33, "x" * 32, bytearray(32)]:
            with self.assertRaises(ValueError):
                EncryptedStateStore(self.base / "unused", key)
        self.assertFalse((self.base / "unused").exists())
        for value in [object(), float("nan")]:
            with self.assertRaises((ValueError, TypeError)):
                self.store.write_json("file", value)
        self.assertEqual(list(self.root.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
