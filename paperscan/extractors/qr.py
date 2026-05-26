"""QR code scanner for images embedded in documents.

Requires pyzbar + libzbar0 (Linux: apt install libzbar0 / Docker: see Dockerfile).
Degrades gracefully if pyzbar is not installed — returns empty list.
"""
from __future__ import annotations

import io
import os
import contextlib


@contextlib.contextmanager
def _suppress_fd(fd: int):
    """Redirect a raw file descriptor to /dev/null for the duration of the block.

    zbar prints DataBar assertion warnings directly to C-level stderr (fd 2),
    bypassing Python's sys.stderr — so only an fd-level redirect silences them.
    """
    devnull = os.open(os.devnull, os.O_WRONLY)
    saved = os.dup(fd)
    try:
        os.dup2(devnull, fd)
        yield
    finally:
        os.dup2(saved, fd)
        os.close(saved)
        os.close(devnull)


def scan_image_for_qr(image_bytes: bytes) -> list[str]:
    """Decode all QR codes in raw image bytes. Returns decoded text strings."""
    try:
        from pyzbar import pyzbar  # type: ignore[import-untyped]
        from PIL import Image
    except ImportError:
        return []
    try:
        img = Image.open(io.BytesIO(image_bytes))
        with _suppress_fd(2):
            decoded = pyzbar.decode(img)
        return [
            d.data.decode("utf-8", errors="replace")
            for d in decoded
            if d.data
        ]
    except Exception:
        return []
