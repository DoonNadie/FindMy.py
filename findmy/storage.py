"""Optional, caller-keyed encrypted JSON state storage (POSIX only).

The key is never persisted. Files use AES-256-GCM and authenticate their logical
name and format version. Missing entries raise FileNotFoundError; malformed
formats raise ValueError and failed authentication raises InvalidTag.

This protects data at rest, not against the same user, root, compromised callers,
rollback, deletion, or concurrent malicious filesystem changes. Symlink checks
and directory-relative operations reduce accidents, but are not a sandbox.
Ancestor directories must be trusted; their permissions are not changed. Writers
are last-writer-wins. An error after replacement (e.g. directory fsync failure)
may mean the new value is already visible.
"""

from __future__ import annotations

import json
import os
import re
import secrets
import stat
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

_HEADER = b"FindMyState\x01"
_NONCE_SIZE = 12
_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")


class EncryptedStateStore:
    """Store JSON values in a private directory using a caller-owned 32-byte key."""

    def __init__(self, root: Path, key: bytes) -> None:
        if not isinstance(key, bytes) or len(key) != 32:
            msg = "key must be exactly 32 bytes"
            raise ValueError(msg)
        self.root = Path(os.path.abspath(root))
        self._cipher = AESGCM(key)
        # Do not resolve(): that would silently accept a symlink root/ancestor.
        self._check_ancestors()
        try:
            self.root.mkdir(mode=0o700)
        except FileExistsError:
            pass
        with_fd = self._open_root()
        os.close(with_fd)

    def _check_ancestors(self) -> None:
        for path in (*reversed(self.root.parents), self.root):
            try:
                info = path.lstat()
            except FileNotFoundError:
                if path == self.root:
                    continue
                raise
            if stat.S_ISLNK(info.st_mode):
                msg = "symlinks are not allowed in the storage path"
                raise ValueError(msg)

    @staticmethod
    def _check_private(info: os.stat_result, *, directory: bool) -> None:
        expected = stat.S_ISDIR if directory else stat.S_ISREG
        mode = 0o700 if directory else 0o600
        if (
            not expected(info.st_mode)
            or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != mode
        ):
            msg = "storage must be owned by this user with mode 0700/0600"
            raise PermissionError(msg)
        if not directory and info.st_nlink != 1:
            msg = "hard-linked state files are not allowed"
            raise PermissionError(msg)

    def _open_root(self) -> int:
        self._check_ancestors()
        fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            self._check_private(os.fstat(fd), directory=True)
        except BaseException:
            os.close(fd)
            raise
        return fd

    @staticmethod
    def _validate_name(name: str) -> None:
        if not isinstance(name, str) or not _NAME.fullmatch(name) or ".." in name:
            msg = "name must be a simple ASCII filename without '..'"
            raise ValueError(msg)

    @staticmethod
    def _aad(name: str) -> bytes:
        return _HEADER + b"\x00" + name.encode("ascii")

    def read_json(self, name: str) -> Any:  # noqa: ANN401
        """Read and authenticate one value; never return unauthenticated JSON."""
        self._validate_name(name)
        root_fd = self._open_root()
        try:
            fd = os.open(
                name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=root_fd
            )
            with os.fdopen(fd, "rb") as stream:
                self._check_private(os.fstat(stream.fileno()), directory=False)
                payload = stream.read()
        finally:
            os.close(root_fd)
        if not payload.startswith(_HEADER) or len(payload) < len(_HEADER) + 12 + 16:
            msg = "unsupported or truncated encrypted state format"
            raise ValueError(msg)
        nonce_start = len(_HEADER)
        ciphertext_start = nonce_start + _NONCE_SIZE
        plaintext = self._cipher.decrypt(
            payload[nonce_start:ciphertext_start],
            payload[ciphertext_start:],
            self._aad(name),
        )
        return json.loads(plaintext)

    def write_json(self, name: str, data: Any) -> None:  # noqa: ANN401
        """Encrypt and atomically replace a value; never write plaintext to disk."""
        self._validate_name(name)
        plaintext = json.dumps(data, ensure_ascii=False, allow_nan=False).encode("utf-8")
        nonce = os.urandom(_NONCE_SIZE)
        payload = _HEADER + nonce + self._cipher.encrypt(nonce, plaintext, self._aad(name))
        root_fd = self._open_root()
        temporary = ".state-" + secrets.token_hex(16)
        created = False
        try:
            try:
                existing = os.stat(name, dir_fd=root_fd, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                self._check_private(existing, directory=False)
            fd = os.open(
                temporary,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600,
                dir_fd=root_fd,
            )
            created = True
            with os.fdopen(fd, "wb") as stream:
                os.fchmod(stream.fileno(), 0o600)
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, name, src_dir_fd=root_fd, dst_dir_fd=root_fd)
            created = False
            os.fsync(root_fd)
        finally:
            try:
                if created:
                    os.unlink(temporary, dir_fd=root_fd)
            finally:
                os.close(root_fd)
