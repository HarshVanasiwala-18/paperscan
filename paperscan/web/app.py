from __future__ import annotations

import json
import logging
import os
import tempfile
from pathlib import Path

import io

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.responses import FileResponse, JSONResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles

from paperscan.scanner import scan_async, scan_stream_async

logger = logging.getLogger(__name__)

# Load .env from repo root if it exists (no extra dependency required)
_env_file = Path(__file__).parent.parent.parent / ".env"
if _env_file.exists():
    for _line in _env_file.read_text(encoding="utf-8").splitlines():
        _line = _line.strip()
        if _line and not _line.startswith("#") and "=" in _line:
            _k, _, _v = _line.partition("=")
            os.environ.setdefault(_k.strip(), _v.strip())

app = FastAPI(title="Paperscan", description="Prompt injection detector for documents")

_STATIC_DIR = Path(__file__).parent / "static"
_MAX_SIZE = 50 * 1024 * 1024  # 50 MB
_ALLOWED_EXTENSIONS = {
    ".pdf", ".docx", ".pptx",
    ".html", ".htm",
    ".eml",
    ".xlsx",
    ".csv",
    ".json", ".xml",
}

app.mount("/static", StaticFiles(directory=str(_STATIC_DIR)), name="static")

# ── Magic byte signatures (no libmagic dependency) ────────────────────────────
# Binary formats: exact header bytes at offset 0.
# Text formats: keyword presence in first 512 bytes (case-insensitive).
_BINARY_MAGIC: dict[str, bytes] = {
    ".pdf":  b"%PDF",
    ".docx": b"PK\x03\x04",   # OOXML is a ZIP
    ".pptx": b"PK\x03\x04",
    ".xlsx": b"PK\x03\x04",
}


def _check_magic(content: bytes, ext: str) -> bool:
    """Return True if file bytes are consistent with the claimed extension."""
    sig = _BINARY_MAGIC.get(ext)
    if sig is not None:
        return content[:len(sig)] == sig

    head = content[:512].lower()
    if ext in (".html", ".htm"):
        return any(k in head for k in (b"<html", b"<!doctype", b"<head", b"<body"))
    if ext == ".xml":
        stripped = head.lstrip()
        return stripped.startswith((b"<?xml", b"<"))
    if ext == ".json":
        return head.lstrip()[:1] in (b"{", b"[")
    if ext == ".eml":
        # RFC 5322 messages start with a header field or "From " (mbox)
        return any(head.startswith(k) for k in (
            b"from ", b"return-path:", b"received:", b"mime-version:",
            b"to:", b"subject:", b"date:", b"message-id:", b"content-type:",
        )) or b"mime-version:" in head or b"content-type:" in head
    # CSV — plain text, no reliable signature; allow through
    return True


async def _read_upload(file: UploadFile) -> bytes:
    """Stream-read upload, enforcing the size limit before buffering into memory."""
    buf = io.BytesIO()
    total = 0
    while True:
        chunk = await file.read(65536)
        if not chunk:
            break
        total += len(chunk)
        if total > _MAX_SIZE:
            raise HTTPException(413, "File too large. Maximum 50 MB.")
        buf.write(chunk)
    return buf.getvalue()


_FAVICON_SVG = (
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32">'
    '<rect width="32" height="32" rx="7" fill="#f25f45"/>'
    '<path d="M9 8h9l5 5v11a2 2 0 0 1-2 2H9a2 2 0 0 1-2-2V10a2 2 0 0 1 2-2z"'
    ' fill="none" stroke="white" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>'
    '<polyline points="18 8 18 13 23 13" fill="none" stroke="white" stroke-width="1.8" stroke-linecap="round"/>'
    '<line x1="11" y1="17" x2="21" y2="17" stroke="white" stroke-width="1.8" stroke-linecap="round"/>'
    '<line x1="11" y1="21" x2="17" y2="21" stroke="white" stroke-width="1.8" stroke-linecap="round"/>'
    '</svg>'
)


@app.get("/favicon.ico", include_in_schema=False)
async def favicon():
    return Response(content=_FAVICON_SVG, media_type="image/svg+xml",
                    headers={"Cache-Control": "public, max-age=86400"})


@app.get("/.well-known/appspecific/com.chrome.devtools.json", include_in_schema=False)
async def chrome_devtools():
    return Response(content="{}", media_type="application/json")


@app.get("/")
async def index():
    return FileResponse(str(_STATIC_DIR / "index.html"))


@app.post("/scan/stream")
async def scan_stream_endpoint(file: UploadFile = File(...)):
    ext = Path(file.filename or "").suffix.lower()
    if ext not in _ALLOWED_EXTENSIONS:
        allowed = ", ".join(sorted(_ALLOWED_EXTENSIONS))
        raise HTTPException(400, f"Unsupported file type '{ext}'. Allowed: {allowed}")

    content = await _read_upload(file)
    if not _check_magic(content, ext):
        raise HTTPException(415, f"File content does not match the claimed type '{ext}'.")

    with tempfile.NamedTemporaryFile(suffix=ext, delete=False) as tmp:
        tmp.write(content)
        tmp_path = tmp.name

    async def event_stream():
        try:
            async for event in scan_stream_async(tmp_path):
                # Scrub internal paths from error messages before sending to client
                if event.get("type") == "error":
                    event = {"type": "error", "message": "Scan failed — check server logs."}
                yield f"data: {json.dumps(event)}\n\n"
        finally:
            Path(tmp_path).unlink(missing_ok=True)

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.post("/scan")
async def scan_endpoint(file: UploadFile = File(...)):
    ext = Path(file.filename or "").suffix.lower()
    if ext not in _ALLOWED_EXTENSIONS:
        allowed = ", ".join(sorted(_ALLOWED_EXTENSIONS))
        raise HTTPException(400, f"Unsupported file type '{ext}'. Allowed: {allowed}")

    content = await _read_upload(file)
    if not _check_magic(content, ext):
        raise HTTPException(415, f"File content does not match the claimed type '{ext}'.")

    with tempfile.NamedTemporaryFile(suffix=ext, delete=False) as tmp:
        tmp.write(content)
        tmp_path = tmp.name

    try:
        report = await scan_async(tmp_path)
    except Exception as exc:
        logger.exception("Scan failed for upload '%s'", file.filename)
        raise HTTPException(500, "Scan failed — check server logs.")
    finally:
        Path(tmp_path).unlink(missing_ok=True)

    return JSONResponse(content=report.model_dump())
