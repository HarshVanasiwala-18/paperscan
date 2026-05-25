from __future__ import annotations

import asyncio
import hashlib
import logging
import time
from collections.abc import AsyncGenerator
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from paperscan.models import ExtractedDocument, ScanReport
from paperscan.aggregator import aggregate

logger = logging.getLogger(__name__)

_MAX_FILE_SIZE = 50 * 1024 * 1024  # 50 MB
_EXTRACT_TIMEOUT = 120.0  # seconds — kills hung MuPDF parses
_ALLOWED_EXTENSIONS = {
    ".pdf", ".docx", ".pptx",
    ".html", ".htm",
    ".eml",
    ".xlsx",
    ".csv",
    ".json", ".xml",
}
_OCR_EXTENSIONS = {".pdf"}
_EXECUTOR = ThreadPoolExecutor(max_workers=4)


def _compute_hash(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _extract(path: str, ext: str) -> ExtractedDocument:
    if ext == ".pdf":
        from paperscan.extractors.pdf import extract_pdf
        return extract_pdf(path)
    if ext == ".docx":
        from paperscan.extractors.docx import extract_docx
        return extract_docx(path)
    if ext == ".pptx":
        from paperscan.extractors.pptx import extract_pptx
        return extract_pptx(path)
    if ext in (".html", ".htm"):
        from paperscan.extractors.html import extract_html
        return extract_html(path)
    if ext == ".eml":
        from paperscan.extractors.email_ext import extract_eml
        return extract_eml(path)
    if ext == ".xlsx":
        from paperscan.extractors.xlsx import extract_xlsx
        return extract_xlsx(path)
    if ext == ".csv":
        from paperscan.extractors.csv_ext import extract_csv
        return extract_csv(path)
    if ext == ".json":
        from paperscan.extractors.structured import extract_json
        return extract_json(path)
    if ext == ".xml":
        from paperscan.extractors.structured import extract_xml
        return extract_xml(path)
    raise ValueError(f"No extractor for '{ext}'")


def _run_ocr(path: str, extracted: ExtractedDocument, ext: str) -> ExtractedDocument:
    if ext in _OCR_EXTENSIONS:
        from paperscan.extractors.ocr import ocr_extract
        return ocr_extract(path, extracted)
    return extracted


async def scan_async(file_path: str) -> ScanReport:
    path = Path(file_path)
    ext = path.suffix.lower()

    # Validation
    if ext not in _ALLOWED_EXTENSIONS:
        raise ValueError(
            f"Unsupported file type '{ext}'. Allowed: {', '.join(_ALLOWED_EXTENSIONS)}"
        )
    if not path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")
    size = path.stat().st_size
    if size > _MAX_FILE_SIZE:
        raise ValueError(f"File too large ({size / 1024 / 1024:.1f} MB). Maximum: 50 MB")

    start = time.perf_counter()
    loop = asyncio.get_running_loop()

    file_hash = await loop.run_in_executor(_EXECUTOR, _compute_hash, file_path)
    try:
        extracted = await asyncio.wait_for(
            loop.run_in_executor(_EXECUTOR, _extract, file_path, ext),
            timeout=_EXTRACT_TIMEOUT,
        )
        extracted = await asyncio.wait_for(
            loop.run_in_executor(_EXECUTOR, _run_ocr, file_path, extracted, ext),
            timeout=_EXTRACT_TIMEOUT,
        )
    except asyncio.TimeoutError:
        raise ValueError(
            f"Extraction timed out after {_EXTRACT_TIMEOUT:.0f}s — "
            "file may be malformed or excessively complex."
        )

    # Run pattern + heuristic in parallel; semantic runs full agentic pipeline
    from paperscan.detectors.patterns import detect_patterns
    from paperscan.detectors.heuristics import detect_heuristics
    from paperscan.detectors.semantic import detect_semantic_full

    pattern_task = loop.run_in_executor(_EXECUTOR, detect_patterns, extracted)
    heuristic_task = loop.run_in_executor(_EXECUTOR, detect_heuristics, extracted)
    semantic_task = loop.run_in_executor(_EXECUTOR, detect_semantic_full, extracted)

    pattern_findings, heuristic_findings, semantic_result = await asyncio.gather(
        pattern_task, heuristic_task, semantic_task
    )

    all_findings = pattern_findings + heuristic_findings + semantic_result.findings
    score, severity = aggregate(all_findings, macro_present=extracted.macro_present)

    duration_ms = int((time.perf_counter() - start) * 1000)

    return ScanReport(
        file=path.name,
        file_hash=file_hash,
        score=score,
        severity=severity,
        findings=all_findings,
        extracted=extracted,
        scan_duration_ms=duration_ms,
        document_type=semantic_result.document_type,
        document_description=semantic_result.document_description,
        risk_narrative=semantic_result.risk_narrative,
        attack_scenario=semantic_result.attack_scenario,
        remediation=semantic_result.remediation,
        attack_sophistication=semantic_result.attack_sophistication,
        semantic_layer_ran=semantic_result.semantic_ran,
        semantic_model=semantic_result.model_used,
        semantic_passes=semantic_result.passes_completed,
        sanitized_text=semantic_result.sanitized_text,
        sanitization_changes=semantic_result.sanitization_changes,
    )


def scan(file_path: str) -> ScanReport:
    """Synchronous entry point — wraps scan_async."""
    return asyncio.run(scan_async(file_path))


async def scan_stream_async(file_path: str) -> AsyncGenerator[dict, None]:
    """Yield SSE-ready progress dicts then a final complete/error event."""
    path = Path(file_path)
    ext = path.suffix.lower()

    if ext not in _ALLOWED_EXTENSIONS:
        yield {"type": "error", "message": f"Unsupported file type '{ext}'"}
        return
    if not path.exists():
        yield {"type": "error", "message": "File not found"}
        return
    if path.stat().st_size > _MAX_FILE_SIZE:
        yield {"type": "error", "message": "File too large (max 50 MB)"}
        return

    start = time.perf_counter()
    loop = asyncio.get_running_loop()

    try:
        yield {"type": "progress", "pass": "extract", "label": "Extracting content surfaces…"}
        file_hash = await loop.run_in_executor(_EXECUTOR, _compute_hash, file_path)
        try:
            extracted = await asyncio.wait_for(
                loop.run_in_executor(_EXECUTOR, _extract, file_path, ext),
                timeout=_EXTRACT_TIMEOUT,
            )
            extracted = await asyncio.wait_for(
                loop.run_in_executor(_EXECUTOR, _run_ocr, file_path, extracted, ext),
                timeout=_EXTRACT_TIMEOUT,
            )
        except asyncio.TimeoutError:
            yield {
                "type": "error",
                "message": f"Extraction timed out after {_EXTRACT_TIMEOUT:.0f}s — file may be malformed.",
            }
            return

        from paperscan.detectors.patterns import detect_patterns
        from paperscan.detectors.heuristics import detect_heuristics
        from paperscan.detectors.semantic import detect_semantic_full

        yield {"type": "progress", "pass": "detect", "label": "Pattern & heuristic detection…"}
        pattern_findings, heuristic_findings = await asyncio.gather(
            loop.run_in_executor(_EXECUTOR, detect_patterns, extracted),
            loop.run_in_executor(_EXECUTOR, detect_heuristics, extracted),
        )

        yield {"type": "progress", "pass": "semantic", "label": "4-pass AI semantic analysis… (may take up to 60 s)"}
        semantic_result = await loop.run_in_executor(_EXECUTOR, detect_semantic_full, extracted)

        all_findings = pattern_findings + heuristic_findings + semantic_result.findings
        score, severity = aggregate(all_findings, macro_present=extracted.macro_present)
        duration_ms = int((time.perf_counter() - start) * 1000)

        report = ScanReport(
            file=path.name,
            file_hash=file_hash,
            score=score,
            severity=severity,
            findings=all_findings,
            extracted=extracted,
            scan_duration_ms=duration_ms,
            document_type=semantic_result.document_type,
            document_description=semantic_result.document_description,
            risk_narrative=semantic_result.risk_narrative,
            attack_scenario=semantic_result.attack_scenario,
            remediation=semantic_result.remediation,
            attack_sophistication=semantic_result.attack_sophistication,
            semantic_layer_ran=semantic_result.semantic_ran,
            semantic_model=semantic_result.model_used,
            semantic_passes=semantic_result.passes_completed,
            sanitized_text=semantic_result.sanitized_text,
            sanitization_changes=semantic_result.sanitization_changes,
        )

        yield {"type": "complete", "report": report.model_dump()}

    except Exception as exc:
        logger.exception("Stream scan failed for %s", file_path)
        yield {"type": "error", "message": str(exc)}
