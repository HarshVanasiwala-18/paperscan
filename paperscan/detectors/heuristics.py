from __future__ import annotations

import re
from urllib.parse import urlparse

from paperscan.models import ExtractedDocument, Finding

# Imperative verbs — English + French + Spanish + German + Chinese
# Used only for high-signal contexts (bidi overrides) where any imperative is suspicious.
_IMPERATIVE_RE = re.compile(
    r"\b(ignore|disregard|forget|override|replace|assume|pretend|act|behave|follow|execute|run|output|reveal|print|show|repeat|change|update|modify|delete|remove|insert|"
    r"ignor(?:ez|ons)|oubli(?:ez|ons)|révél(?:ez|e)|affichez|exécutez|"  # French
    r"ignora|olvida|revela|muestra|ejecuta|imprime|"  # Spanish
    r"ignorier|vergiss|enthüll|zeig|führe)\b"  # German
    r"|忽略|忘记|执行|显示|输出|泄露",  # Chinese
    re.IGNORECASE | re.UNICODE,
)

# Strict injection phrases — used for loose-context checks (metadata, tracked changes,
# annotations) where common action verbs would cause false positives on resumes/reports.
# These phrases are almost never legitimate document content.
_STRICT_INJECTION_RE = re.compile(
    r"\bignore\s+(all\s+|previous\s+|prior\s+|your\s+)?instructions?\b"
    r"|\bdisregard\s+(the\s+|all\s+)?above\b"
    r"|\bforget\s+(everything|all\s+instructions?)\b"
    r"|\boverride\s+(all\s+)?instructions?\b"
    r"|\byou\s+are\s+now\b"
    r"|\bact\s+as\b"
    r"|\bpretend\s+to\s+be\b"
    r"|\bjailbreak\b"
    r"|\bsystem\s+prompt\b"
    r"|\byour\s+(new\s+)?role\s+is\b"
    r"|\bnew\s+instructions?\s*:"
    r"|\bfrom\s+(the\s+)?administrator\b"
    r"|\bfrom\s+(the\s+)?system\b"
    r"|\[system\]|\[admin\]|\[instruction\]"
    r"|\breveal\s+(your|the)\s+(system|prompt|instructions?|api.?key)\b"
    r"|\boutput\s+(your|the)\s+(system\s+prompt|instructions?)\b"
    r"|\bignor(?:ez|ons)\s+(toutes?\s+les?\s+)?instructions?\b"  # French
    r"|\boubli(?:ez|ons)\s+(tout|toutes?\s+les?\s+instructions?)\b"
    r"|\bignora\s+(todas?\s+las?\s+)?instrucciones?\b"  # Spanish
    r"|\bignoriere?\s+.{0,30}Anweisungen\b",  # German
    re.IGNORECASE | re.UNICODE,
)

# URL analysis
_URL_RE = re.compile(r'https?://[^\s<>\'"]{8,}', re.IGNORECASE)
_SHORTENER_DOMAINS = frozenset({
    'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'short.link',
    'cutt.ly', 'rebrand.ly', 'tiny.cc', 'is.gd', 'buff.ly', 'ift.tt',
    'tr.im', 'clck.ru', 'rb.gy', 'shorturl.at', 'snip.ly',
})
_SUSPICIOUS_TLDS = frozenset({
    '.xyz', '.tk', '.top', '.gq', '.ml', '.cf', '.ga', '.pw',
    '.cc', '.work', '.click', '.rest', '.zip', '.mov',
})
_EXFIL_PARAM_RE = re.compile(
    r'[?&](token|api[_-]?key|secret|key|credential|password|passwd|pwd|auth|bearer)=',
    re.IGNORECASE,
)
_IP_URL_RE = re.compile(r'https?://\d{1,3}(?:\.\d{1,3}){3}[:/]', re.IGNORECASE)

_TAG_CHAR_START = 0xE0000
_TAG_CHAR_END = 0xE007F


def _total_hidden_chars(doc: ExtractedDocument) -> int:
    total = 0
    # Exclude OCR token-diff entries — they represent text found only in embedded images
    # (logos, photos) and are already handled by the dedicated OCR divergence check.
    # Counting them here would double-penalise clean PDFs with normal image content.
    _ocr_methods = frozenset({"ocr_only", "extraction_only"})
    for h in doc.hidden_text:
        if h.get("method") not in _ocr_methods:
            total += len(h.get("content", ""))
    for h in doc.ocg_hidden_text:
        total += len(h.get("content", ""))
    for h in doc.clipped_text:
        total += len(h.get("content", ""))
    for h in doc.transparent_text:
        total += len(h.get("content", ""))
    for h in doc.actual_text_spans:
        total += len(h.get("extracted", ""))
    return total


def detect_heuristics(doc: ExtractedDocument) -> list[Finding]:
    findings: list[Finding] = []

    visible_len = max(len(doc.visible_text), 1)
    hidden_len = _total_hidden_chars(doc)
    hidden_ratio = hidden_len / visible_len

    # ── Hidden text ratio ────────────────────────────────────────────────────
    # Thresholds raised: PDFs routinely accumulate small amounts of hidden text
    # from whitespace characters, clip regions, and formatting artifacts.
    # 30% hidden = strong signal; 12% = noteworthy but not alarming.
    if hidden_ratio > 0.30:
        findings.append(Finding(
            layer="heuristic",
            severity="critical",
            category="hidden_text_ratio",
            description=f"Hidden content is {hidden_ratio:.0%} of visible text length",
            evidence=f"hidden={hidden_len} chars, visible={visible_len} chars",
            location="document",
            confidence=0.9,
        ))
    elif hidden_ratio > 0.12:
        findings.append(Finding(
            layer="heuristic",
            severity="medium",
            category="hidden_text_ratio",
            description=f"Hidden content is {hidden_ratio:.0%} of visible text length",
            evidence=f"hidden={hidden_len} chars, visible={visible_len} chars",
            location="document",
            confidence=0.7,
        ))

    # ── Unicode tag characters ───────────────────────────────────────────────
    tag_anomalies = [
        a for a in doc.unicode_anomalies if a.get("category") == "unicode_tag"
    ]
    if tag_anomalies:
        total_tags = sum(a.get("count", 0) for a in tag_anomalies)
        findings.append(Finding(
            layer="heuristic",
            severity="critical",
            category="unicode_tags",
            description=f"Unicode tag characters found ({total_tags} occurrences) — no legitimate use",
            evidence=", ".join(a.get("codepoint", "") for a in tag_anomalies[:5]),
            location="document",
            confidence=1.0,
        ))

    # ── Bidi override anomalies ──────────────────────────────────────────────
    bidi_anomalies = [
        a for a in doc.unicode_anomalies if a.get("category") == "bidi_override"
    ]
    if bidi_anomalies:
        # Only flag if the logical text contains injection-like patterns
        for anomaly in bidi_anomalies:
            logical = anomaly.get("logical_text", "")
            if logical and _IMPERATIVE_RE.search(logical):
                findings.append(Finding(
                    layer="heuristic",
                    severity="high",
                    category="bidi_injection",
                    description="Bidirectional text override with injection-like logical content",
                    evidence=logical[:200],
                    location="document",
                    confidence=0.75,
                ))

    # ── OCG / hidden layers ──────────────────────────────────────────────────
    if doc.ocg_hidden_text:
        for item in doc.ocg_hidden_text:
            findings.append(Finding(
                layer="heuristic",
                severity="high",
                category="ocg_hidden_layer",
                description=f"Hidden OCG layer '{item.get('layer_name', '?')}' contains text",
                evidence=item.get("content", "")[:200],
                location=f"ocg_layer:{item.get('layer_name', '?')}",
                confidence=0.85,
            ))

    # ── /ActualText mismatches ───────────────────────────────────────────────
    if doc.actual_text_spans:
        for item in doc.actual_text_spans:
            findings.append(Finding(
                layer="heuristic",
                severity="high",
                category="actual_text_substitution",
                description="PDF /ActualText attribute substitutes different content from visual rendering",
                evidence=f"visual='{item.get('visual', '')}' | extracted='{item.get('extracted', '')}'",
                location=f"actual_text:page{item.get('page', '?')}",
                confidence=0.9,
            ))

    # ── Clipped text ────────────────────────────────────────────────────────
    if doc.clipped_text:
        total = sum(len(c.get("content", "")) for c in doc.clipped_text)
        findings.append(Finding(
            layer="heuristic",
            severity="high",
            category="clipped_text",
            description=f"Text found in clipped (invisible) regions ({total} chars)",
            evidence=doc.clipped_text[0].get("content", "")[:200],
            location="document",
            confidence=0.8,
        ))

    # ── Transparent text ────────────────────────────────────────────────────
    # Skip spans shorter than 5 chars — these are watermark fragments, copyright
    # symbols, journal abbreviations, and page numbers (e.g. "©", "J.", "1983")
    # produced by OCR software, not injection payloads.
    # Also cap at 20 findings per document to prevent score inflation on scanned
    # PDFs where every watermark span creates a separate "high" finding.
    if doc.transparent_text:
        _MAX_TRANSPARENT_FINDINGS = 20
        _transparent_count = 0
        for item in doc.transparent_text:
            if _transparent_count >= _MAX_TRANSPARENT_FINDINGS:
                break
            content = item.get("content", "").strip()
            if len(content) < 5:
                continue
            findings.append(Finding(
                layer="heuristic",
                severity="high",
                category="transparent_text",
                description=f"Near-invisible text (alpha={item.get('alpha', 0):.3f})",
                evidence=content[:200],
                location=f"transparent:page{item.get('page', '?')}",
                confidence=0.85,
            ))
            _transparent_count += 1

    # ── Font encoding anomalies ──────────────────────────────────────────────
    # Confidence dropped below scoring floor: custom font encodings are present in
    # virtually every professionally typeset PDF (ligatures, kerning, embedded subsets).
    # This check is informational — /ActualText substitution is the real attack signal.
    if doc.font_encoding_anomalies:
        unique_fonts = {f.get("font_name") for f in doc.font_encoding_anomalies}
        findings.append(Finding(
            layer="heuristic",
            severity="medium",
            category="font_encoding_anomaly",
            description=f"Custom/unusual font encoding detected ({len(unique_fonts)} fonts) — glyph-to-text mapping may differ from visual",
            evidence=", ".join(list(unique_fonts)[:5]),
            location="document",
            confidence=0.35,  # below scoring floor — informational only
        ))

    # ── DOCX tracked changes with injection content ──────────────────────────
    for change in doc.tracked_changes:
        content = change.get("content", "")
        if content and _STRICT_INJECTION_RE.search(content):
            findings.append(Finding(
                layer="heuristic",
                severity="high",
                category="tracked_change_injection",
                description=f"Deleted tracked change contains imperative/injection-like content (author: {change.get('author', '?')})",
                evidence=content[:200],
                location=f"tracked_change:{change.get('type', '?')}",
                confidence=0.75,
            ))

    # ── DOCX field codes with injection phrases ──────────────────────────────
    for item in doc.field_codes:
        instr = item.get("instruction", "").strip()
        if not instr:
            continue
        if _STRICT_INJECTION_RE.search(instr):
            findings.append(Finding(
                layer="heuristic",
                severity="medium",
                category="field_code_injection",
                description="DOCX field code contains non-standard imperative instruction",
                evidence=instr[:200],
                location="field_code",
                confidence=0.65,
            ))

    # ── Embedded PDF JavaScript ──────────────────────────────────────────────
    pdf_js = doc.metadata.get("_embedded_js", "")
    if pdf_js:
        findings.append(Finding(
            layer="heuristic",
            severity="high",
            category="embedded_javascript",
            description="PDF contains document-level JavaScript — rarely legitimate, high injection risk",
            evidence=pdf_js[:200],
            location="pdf:/JS",
            confidence=0.9,
        ))

    # ── Macro present ────────────────────────────────────────────────────────
    if doc.macro_present:
        findings.append(Finding(
            layer="heuristic",
            severity="high",
            category="macro_present",
            description="Document contains embedded VBA macros (vbaProject.bin detected)",
            evidence="vbaProject.bin found in DOCX archive",
            location="document",
            confidence=0.95,
        ))

    # ── Metadata with injection phrases ─────────────────────────────────────
    # Skip auto-generated PDF fields — they contain software version strings, ISO dates,
    # and XMP blobs that are never user-authored and can't carry intentional injection.
    _SKIP_META = frozenset({"_xmp", "format", "producer", "creationDate", "modDate", "encryption"})
    for key, val in doc.metadata.items():
        if key in _SKIP_META or not isinstance(val, str) or len(val) < 10:
            continue
        if _STRICT_INJECTION_RE.search(val):
            findings.append(Finding(
                layer="heuristic",
                severity="medium",
                category="metadata_injection",
                description=f"Metadata field '{key}' contains imperative/instruction-like content",
                evidence=val[:200],
                location=f"metadata:{key}",
                confidence=0.6,
            ))

    # ── Form field defaults with long imperative content ────────────────────
    for name, val in doc.form_field_defaults.items():
        val_str = str(val)
        if len(val_str) > 100 and _IMPERATIVE_RE.search(val_str):
            findings.append(Finding(
                layer="heuristic",
                severity="high",
                category="form_field_injection",
                description=f"Form field '{name}' has long imperative default value",
                evidence=val_str[:200],
                location=f"form_field:{name}",
                confidence=0.75,
            ))

    # ── OCR divergence ───────────────────────────────────────────────────────
    # Threshold raised to 500 chars: small divergence (200 chars) is normal for any
    # PDF with ligatures (fi/fl), accented chars, or headers/footers that OCR picks up
    # as extra content. A meaningful attack needs substantial hidden rasterized text.
    if doc.ocr_text:
        ocr_only = [
            h for h in doc.hidden_text if h.get("method") in ("ocr_only", "extraction_only")
        ]
        total_divergence = sum(len(h.get("content", "")) for h in ocr_only)
        if total_divergence > 500:
            sample = " … ".join(
                h.get("content", "")[:120].strip()
                for h in ocr_only[:3]
                if h.get("content", "").strip()
            )
            findings.append(Finding(
                layer="heuristic",
                severity="medium",
                category="ocr_divergence",
                description=f"OCR text diverges significantly from text-layer extraction ({total_divergence} chars differ)",
                evidence=f"{total_divergence} chars differ. Sample: {sample[:300]}" if sample else f"{total_divergence} characters differ between OCR and text extraction",
                location="document",
                confidence=0.65,
            ))

    # ── Annotations with injection phrases ──────────────────────────────────
    for i, ann in enumerate(doc.annotations):
        if _STRICT_INJECTION_RE.search(ann) and len(ann) > 20:
            findings.append(Finding(
                layer="heuristic",
                severity="high",
                category="annotation_injection",
                description="Annotation contains imperative/instruction-like content",
                evidence=ann[:200],
                location=f"annotation:{i}",
                confidence=0.7,
            ))

    # ── QR codes found in embedded images ────────────────────────────────────
    qr_items = [h for h in doc.hidden_text if h.get("method") == "qr_code"]
    for item in qr_items:
        findings.append(Finding(
            layer="heuristic",
            severity="high",
            category="qr_code_content",
            description="QR code decoded from embedded image — content bypasses text-layer scanning",
            evidence=item.get("content", "")[:200],
            location=item.get("location", "image"),
            confidence=0.9,
        ))

    # ── Suspicious URLs ──────────────────────────────────────────────────────
    all_surfaces = " ".join(filter(None, [
        doc.visible_text,
        " ".join(h.get("content", "") for h in doc.hidden_text),
        " ".join(doc.annotations),
        " ".join(v for v in doc.metadata.values() if isinstance(v, str)),
    ]))
    seen_urls: set[str] = set()
    for url in _URL_RE.findall(all_surfaces):
        url = url.rstrip('.,)')
        if url in seen_urls:
            continue
        seen_urls.add(url)
        issues: list[str] = []

        if _IP_URL_RE.match(url):
            issues.append("direct IP address — no domain")

        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower().lstrip('www.')
            if domain in _SHORTENER_DOMAINS:
                issues.append(f"URL shortener ({domain})")
            for tld in _SUSPICIOUS_TLDS:
                if domain.endswith(tld):
                    issues.append(f"suspicious TLD ({tld})")
                    break
        except Exception:
            pass

        if _EXFIL_PARAM_RE.search(url):
            issues.append("credential/token query param")

        query = url.split('?', 1)[1] if '?' in url else ''
        if len(query) > 200:
            issues.append("unusually long query string (possible data exfiltration)")

        if issues:
            sev = "high" if any(k in ' '.join(issues) for k in ('IP', 'credential', 'exfil')) else "medium"
            findings.append(Finding(
                layer="heuristic",
                severity=sev,
                category="suspicious_url",
                description="Suspicious URL: " + "; ".join(issues),
                evidence=url[:200],
                location="document",
                confidence=0.75,
            ))

    return findings
