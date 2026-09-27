"""
Cross-platform advisory file locks.

``flock`` on POSIX, ``msvcrt.locking`` on Windows. Both are per open file
description, so two ``os.open`` calls on the same lock file conflict even
inside one process -- which is what makes them usable across the threads
FastMCP runs sync tools on, and also why a caller that may re-enter must
track that itself rather than open the file twice.
"""

from __future__ import annotations

import contextlib
import os
import sys
import time
from pathlib import Path


def try_lock(fd: int) -> bool:
    """Take an exclusive advisory lock without blocking. False if held."""
    if sys.platform == "win32":
        import msvcrt
        try:
            msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
            return True
        except OSError:
            return False
    import fcntl
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return True
    except (BlockingIOError, OSError):
        return False


def release_lock(fd: int) -> None:
    """Release a lock taken by :func:`try_lock`. Never raises."""
    try:
        if sys.platform == "win32":
            import msvcrt
            try:
                os.lseek(fd, 0, os.SEEK_SET)
                msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
            except OSError:
                pass
        else:
            import fcntl
            fcntl.flock(fd, fcntl.LOCK_UN)
    except Exception:
        pass


class LockTimeoutError(RuntimeError):
    """The lock was still held by someone else when the wait ran out."""


@contextlib.contextmanager
def exclusive_lock(lock_path: Path | str, wait_seconds: float, poll_seconds: float = 0.05):
    """Hold an exclusive lock on ``lock_path`` for the duration of the block.

    Raises :class:`LockTimeoutError` if it can't be taken within ``wait_seconds``.
    The lock file is never unlinked: removing it while another process waits
    on that inode lets a third create a fresh file and take a second
    "exclusive" lock on the same resource.
    """
    fd = os.open(str(lock_path), os.O_CREAT | os.O_RDWR, 0o644)
    locked = False
    try:
        deadline = time.monotonic() + max(0.0, wait_seconds)
        while True:
            locked = try_lock(fd)
            if locked or time.monotonic() >= deadline:
                break
            time.sleep(poll_seconds)
        if not locked:
            raise LockTimeoutError(f"{lock_path} still held after {wait_seconds:.1f}s")
        yield
    finally:
        if locked:
            release_lock(fd)
        try:
            os.close(fd)
        except OSError:
            pass
