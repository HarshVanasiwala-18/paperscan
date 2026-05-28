from __future__ import annotations

import io
import json
import logging
import os
import tempfile
import time
from collections import defaultdict, deque
from pathlib import Path

from fastapi import FastAPI, File, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, JSONResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from starlette.middleware.base import BaseHTTPMiddleware

from paperscan.scanner import scan_async, scan_stream_async, scan_text_stream_async

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

# ── Security headers ──────────────────────────────────────────────────────────
_CSP = (
    "default-src 'self'; "
    "script-src 'self' 'unsafe-inline'; "
    "style-src 'self' 'unsafe-inline'; "
    "img-src 'self' blob: data:; "
    "frame-src blob:; "
    "connect-src 'self'; "
    "object-src 'none'; "
    "base-uri 'self'; "
    "upgrade-insecure-requests"
)


class _SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        response.headers.setdefault("Content-Security-Policy", _CSP)
        response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        # HSTS — tell browsers to always use HTTPS (1 year; safe once TLS is confirmed)
        response.headers.setdefault("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
        # Prevent cross-origin info leaks (Spectre/CORS-related)
        response.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
        response.headers.setdefault("Cross-Origin-Resource-Policy", "same-origin")
        return response


app.add_middleware(_SecurityHeadersMiddleware)

# ── Rate limiting (per source IP, sliding window) ─────────────────────────────
_RATE_WINDOW  = 60    # seconds
_RATE_MAX     = 20    # scan requests per window per IP
_rate_buckets: dict[str, deque] = defaultdict(deque)

# How many rightmost X-Forwarded-For hops to trust as proxy additions.
# 0 = never trust X-Forwarded-For (use direct connection IP).
# 1 = trust one reverse proxy (Render, nginx, etc.).
# Set via TRUSTED_PROXY_COUNT env var to prevent IP spoofing in rate limiter.
try:
    _TRUSTED_PROXY_COUNT = int(os.environ.get("TRUSTED_PROXY_COUNT", "0"))
except ValueError:
    _TRUSTED_PROXY_COUNT = 0


def _client_ip(request: Request) -> str:
    if _TRUSTED_PROXY_COUNT > 0:
        forwarded = request.headers.get("X-Forwarded-For", "")
        ips = [ip.strip() for ip in forwarded.split(",") if ip.strip()]
        # Take the IP that is _TRUSTED_PROXY_COUNT hops from the right.
        # With one trusted proxy, that is the last IP added by the proxy itself.
        if len(ips) >= _TRUSTED_PROXY_COUNT:
            return ips[-_TRUSTED_PROXY_COUNT]
    return request.client.host if request.client else "unknown"


def _allow_request(ip: str) -> bool:
    now = time.monotonic()
    bucket = _rate_buckets[ip]
    while bucket and bucket[0] < now - _RATE_WINDOW:
        bucket.popleft()
    if len(bucket) >= _RATE_MAX:
        return False
    bucket.append(now)
    # Prevent unbounded memory growth under IP-spoofing floods.
    # Evict only stale buckets first; full clear only as last resort.
    if len(_rate_buckets) > 20_000:
        stale = [k for k, b in _rate_buckets.items()
                 if not b or b[-1] < now - _RATE_WINDOW]
        for k in stale:
            del _rate_buckets[k]
        if len(_rate_buckets) > 20_000:
            _rate_buckets.clear()
    return True

_STATIC_DIR = Path(__file__).parent / "static"
_MAX_SIZE = 50 * 1024 * 1024  # 50 MB
_ALLOWED_EXTENSIONS = {
    ".pdf", ".docx",
    ".jpg", ".jpeg", ".png",
}

app.mount("/static", StaticFiles(directory=str(_STATIC_DIR)), name="static")

# ── Magic byte signatures (no libmagic dependency) ────────────────────────────
_BINARY_MAGIC: dict[str, bytes] = {
    ".pdf":  b"%PDF",
    ".docx": b"PK\x03\x04",   # OOXML is a ZIP
    ".jpg":  b"\xff\xd8\xff",
    ".jpeg": b"\xff\xd8\xff",
    ".png":  b"\x89PNG",
}


def _check_magic(content: bytes, ext: str) -> bool:
    """Return True if file bytes are consistent with the claimed extension."""
    sig = _BINARY_MAGIC.get(ext)
    if sig is not None:
        return content[:len(sig)] == sig
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
async def scan_stream_endpoint(request: Request, file: UploadFile = File(...)):
    if not _allow_request(_client_ip(request)):
        raise HTTPException(429, "Rate limit exceeded — maximum 20 scans per minute.")
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
                if event.get("type") == "keepalive":
                    # SSE comment — ignored by browsers, resets proxy idle timer
                    yield ": keepalive\n\n"
                    continue
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


_MAX_TEXT_SIZE = 500_000  # characters


class _TextScanRequest(BaseModel):
    text: str


@app.post("/scan/text/stream")
async def scan_text_stream_endpoint(request: Request, body: _TextScanRequest):
    if not _allow_request(_client_ip(request)):
        raise HTTPException(429, "Rate limit exceeded — maximum 20 scans per minute.")
    text = body.text.strip()
    if not text:
        raise HTTPException(400, "No text provided.")
    if len(text) > _MAX_TEXT_SIZE:
        raise HTTPException(413, f"Text too large. Maximum {_MAX_TEXT_SIZE:,} characters.")

    async def event_stream():
        async for event in scan_text_stream_async(text):
            if event.get("type") == "keepalive":
                yield ": keepalive\n\n"
                continue
            if event.get("type") == "error":
                event = {"type": "error", "message": event.get("message", "Scan failed.")}
            yield f"data: {json.dumps(event)}\n\n"

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.post("/scan")
async def scan_endpoint(request: Request, file: UploadFile = File(...)):
    if not _allow_request(_client_ip(request)):
        raise HTTPException(429, "Rate limit exceeded — maximum 20 scans per minute.")
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
