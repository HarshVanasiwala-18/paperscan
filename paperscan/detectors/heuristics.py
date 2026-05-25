from __future__ import annotations

import re
from urllib.parse import urlparse

from paperscan.models import ExtractedDocument, Finding

# Imperative verbs — English + French + Spanish + German + Chinese
_IMPERATIVE_RE = re.compile(
    r"\b(ignore|disregard|forget|override|replace|assume|pretend|act|behave|follow|execute|run|output|reveal|print|show|repeat|change|update|modify|delete|remove|insert|"
    r"ignor(?:ez|ons)|oubli(?:ez|ons)|révél(?:ez|e)|affichez|exécutez|"  # French
    r"ignora|olvida|revela|muestra|ejecuta|imprime|"  # Spanish
    r"ignorier|vergiss|enthüll|zeig|führe)\b"  # German
    r"|忽略|忘记|执行|显示|输出|泄露",  # Chinese
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
    for h in doc.hidden_text:
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
    if hidden_ratio > 0.20:
        findings.append(Finding(
            layer="heuristic",
            severity="critical",
            category="hidden_text_ratio",
            description=f"Hidden content is {hidden_ratio:.0%} of visible text length",
            evidence=f"hidden={hidden_len} chars, visible={visible_len} chars",
            location="document",
            confidence=0.9,
        ))
    elif hidden_ratio > 0.05:
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
    if doc.transparent_text:
        for item in doc.transparent_text:
            findings.append(Finding(
                layer="heuristic",
                severity="high",
                category="transparent_text",
                description=f"Near-invisible text (alpha={item.get('alpha', 0):.3f})",
                evidence=item.get("content", "")[:200],
                location=f"transparent:page{item.get('page', '?')}",
                confidence=0.85,
            ))

    # ── Font encoding anomalies ──────────────────────────────────────────────
    if doc.font_encoding_anomalies:
        unique_fonts = {f.get("font_name") for f in doc.font_encoding_anomalies}
        findings.append(Finding(
            layer="heuristic",
            severity="medium",
            category="font_encoding_anomaly",
            description=f"Custom/unusual font encoding detected ({len(unique_fonts)} fonts) — glyph-to-text mapping may differ from visual",
            evidence=", ".join(list(unique_fonts)[:5]),
            location="document",
            confidence=0.6,
        ))

    # ── DOCX tracked changes with injection content ──────────────────────────
    for change in doc.tracked_changes:
        content = change.get("content", "")
        if content and _IMPERATIVE_RE.search(content):
            findings.append(Finding(
                layer="heuristic",
                severity="high",
                category="tracked_change_injection",
                description=f"Deleted tracked change contains imperative/injection-like content (author: {change.get('author', '?')})",
                evidence=content[:200],
                location=f"tracked_change:{change.get('type', '?')}",
                confidence=0.75,
            ))

    # ── DOCX field codes with imperative content ─────────────────────────────
    benign_field_prefixes = ("DATE", "PAGE", "AUTHOR", "TITLE", "SUBJECT", "NUMPAGES", "TIME", "FILENAME")
    for item in doc.field_codes:
        instr = item.get("instruction", "").strip()
        if not instr:
            continue
        is_benign = any(instr.upper().startswith(p) for p in benign_field_prefixes)
        if not is_benign and _IMPERATIVE_RE.search(instr):
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

    # ── Metadata with imperative content ────────────────────────────────────
    for key, val in doc.metadata.items():
        if not isinstance(val, str) or len(val) < 10:
            continue
        if _IMPERATIVE_RE.search(val):
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
    if doc.ocr_text:
        ocr_only = [
            h for h in doc.hidden_text if h.get("method") in ("ocr_only", "extraction_only")
        ]
        total_divergence = sum(len(h.get("content", "")) for h in ocr_only)
        if total_divergence > 200:
            findings.append(Finding(
                layer="heuristic",
                severity="medium",
                category="ocr_divergence",
                description=f"OCR text diverges significantly from text-layer extraction ({total_divergence} chars differ)",
                evidence=f"{total_divergence} characters differ between OCR and text extraction",
                location="document",
                confidence=0.7,
            ))

    # ── Annotations with injection patterns ─────────────────────────────────
    for i, ann in enumerate(doc.annotations):
        if _IMPERATIVE_RE.search(ann) and len(ann) > 20:
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
