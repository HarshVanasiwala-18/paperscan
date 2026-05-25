"""QR code scanner for images embedded in documents.

Requires pyzbar + libzbar0 (Linux: apt install libzbar0 / Docker: see Dockerfile).
Degrades gracefully if pyzbar is not installed — returns empty list.
"""
from __future__ import annotations

import io


def scan_image_for_qr(image_bytes: bytes) -> list[str]:
    """Decode all QR codes in raw image bytes. Returns decoded text strings."""
    try:
        from pyzbar import pyzbar  # type: ignore[import-untyped]
        from PIL import Image
    except ImportError:
        return []
    try:
        img = Image.open(io.BytesIO(image_bytes))
        return [
            d.data.decode("utf-8", errors="replace")
            for d in pyzbar.decode(img)
            if d.data
        ]
    except Exception:
        return []
