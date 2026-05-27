from __future__ import annotations

import unicodedata

# Unicode tag block — no legitimate use in document text
_TAG_START = 0xE0000
_TAG_END = 0xE007F

# Zero-width and invisible characters
_ZERO_WIDTH = {0x200B, 0x200C, 0x200D, 0xFEFF}
_SOFT_HYPHEN = {0x00AD}

# Bidirectional override characters
_BIDI_OVERRIDES = set(range(0x202A, 0x202F)) | set(range(0x2066, 0x206A))

# All characters of interest
_SUSPICIOUS = _ZERO_WIDTH | _SOFT_HYPHEN | _BIDI_OVERRIDES
_SUSPICIOUS.update(range(_TAG_START, _TAG_END + 1))

# Count thresholds: small numbers of these chars are common in legitimate documents
# (Word copy-paste, typeset PDFs, multilingual text) and should not generate findings.
_NOISE_THRESHOLDS: dict[int, int] = {
    0x00AD: 40,  # soft hyphen — expected in typeset/hyphenated text
    0x200B: 8,   # zero-width space — common in HTML/Word paste
    0x200C: 6,   # zero-width non-joiner — Indic/Persian scripts
    0x200D: 6,   # zero-width joiner — emoji, Indic scripts
    0xFEFF: 2,   # BOM / ZWNBSP — a single BOM at file start is normal
}

# Unicode letter categories (potential homoglyph targets)
_LETTER_CATS = frozenset({"Ll", "Lu", "Lt", "Lm", "Lo"})

# Typography characters that NFKC-normalize but are NOT homoglyph attacks.
# Word processors, PDFs, and web copy-paste routinely produce these.
_BENIGN_NFKC = frozenset({
    " ",                                        # non-breaking space
    "­",                                        # soft hyphen
    "«", "»",                              # «guillemets»
    "²", "³", "¹",                   # superscript 2, 3, 1
    "¼", "½", "¾",                   # ¼ ½ ¾
    "·", "•", "‣", "․",         # bullets / middle dot
    "‐", "‑", "‒",                   # hyphen variants
    "–", "—", "―",                   # en-dash, em-dash, horizontal bar
    "‘", "’", "‚", "‛",         # single curly quotes
    "“", "”", "„", "‟",         # double curly quotes
    "…",                                        # horizontal ellipsis …
    "′", "″", "‴",                   # prime, double prime, triple prime
    "‹", "›",                              # single angle quotation marks
    "⁠",                                        # word joiner
    "ﬀ", "ﬁ", "ﬂ",                   # ff, fi, fl ligatures
    "ﬃ", "ﬄ", "ﬅ", "ﬆ",         # ffi, ffl, ſt, st ligatures
    # Already tracked separately as zero-width — skip in NFKC loop
    "​", "‌", "‍", "﻿",
})


def _decode_tag_block(text: str) -> str:
    """Decode TAG-block codepoints (U+E0000 range) back to ASCII characters."""
    return "".join(
        chr(ord(ch) - 0xE0000)
        for ch in text
        if _TAG_START <= ord(ch) <= _TAG_END and 0x20 <= ord(ch) - 0xE0000 <= 0x7E
    )


def find_unicode_anomalies(text: str, location: str = "document") -> list[dict]:
    """
    Scan text for Unicode anomalies that indicate steganographic or injection content.

    Returns a list of anomaly dicts:
      {char, codepoint, category, location, count, logical_text?, visual_text?}
    """
    if not text:
        return []

    # Count occurrences per non-TAG codepoint (TAG chars handled separately below
    # so the full sequence can be decoded as one logical string).
    counts: dict[int, int] = {}
    for ch in text:
        cp = ord(ch)
        if cp in _SUSPICIOUS and not (_TAG_START <= cp <= _TAG_END):
            counts[cp] = counts.get(cp, 0) + 1

    anomalies: list[dict] = []
    for cp, count in counts.items():
        # Skip characters whose count is within the normal noise threshold
        threshold = _NOISE_THRESHOLDS.get(cp)
        if threshold is not None and count <= threshold:
            continue

        if cp in _BIDI_OVERRIDES:
            category = "bidi_override"
        elif cp in _ZERO_WIDTH:
            category = "zero_width"
        elif cp in _SOFT_HYPHEN:
            category = "soft_hyphen"
        else:
            category = "other_invisible"

        entry: dict = {
            "char": chr(cp),
            "codepoint": f"U+{cp:04X}",
            "category": category,
            "location": location,
            "count": count,
        }

        # For bidi overrides: capture the logical vs. visual span context
        if category == "bidi_override":
            logical, visual = _extract_bidi_context(text, cp)
            if logical:
                entry["logical_text"] = logical
            if visual:
                entry["visual_text"] = visual

        anomalies.append(entry)

    # TAG block: collect the full sequence and decode in one pass so the pattern
    # detector and semantic model see the readable payload, not per-codepoint noise.
    tag_chars = [ch for ch in text if _TAG_START <= ord(ch) <= _TAG_END]
    if tag_chars:
        decoded = _decode_tag_block(text).strip()
        entry: dict = {
            "char": chr(_TAG_START + 0x41),  # representative printable
            "codepoint": "U+E0000",
            "category": "unicode_tag",
            "location": location,
            "count": len(tag_chars),
        }
        if decoded:
            entry["logical_text"] = decoded
        anomalies.append(entry)

    # NFKC homoglyph check — find LETTER characters that normalise differently.
    # Restricted to Unicode letter categories to avoid noise from normal document
    # typography (curly quotes, em-dashes, ligatures, etc.).
    # Must check per unique character: zip(text, normalised) is wrong when NFKC
    # changes string length (e.g. "ﬁ"→"fi" expands 1 char to 2).
    try:
        normalised_full = unicodedata.normalize("NFKC", text)
        if normalised_full != text:
            differing: list[str] = []
            for ch in dict.fromkeys(text):  # unique chars, insertion order
                if ch in _BENIGN_NFKC:
                    continue  # known-benign typography variant
                cat = unicodedata.category(ch)
                if cat not in _LETTER_CATS:
                    continue  # only flag letters, not punctuation/symbols
                ch_norm = unicodedata.normalize("NFKC", ch)
                if ch_norm != ch:
                    differing.append(f"{repr(ch)}→{repr(ch_norm)}")
            if differing:
                anomalies.append({
                    "char": "(multiple)",
                    "codepoint": "NFKC",
                    "category": "homoglyph",
                    "location": location,
                    "count": len(differing),
                    "examples": differing[:10],
                })
    except Exception:
        pass

    return anomalies


def _extract_bidi_context(text: str, bidi_cp: int, window: int = 60) -> tuple[str, str]:
    """
    For a bidi override codepoint, return the logical string segment and
    a heuristic reversal (visual approximation).  Collects ALL occurrences,
    not just the first (text.find() would miss subsequent ones).
    """
    bidi_char = chr(bidi_cp)
    segments: list[str] = []
    visuals: list[str] = []

    idx = 0
    while True:
        idx = text.find(bidi_char, idx)
        if idx == -1:
            break
        start = max(0, idx - window)
        end = min(len(text), idx + window)
        segment = text[start:end]
        logical_seg = "".join(ch for ch in segment if ord(ch) not in _BIDI_OVERRIDES)
        local_pos = segment.find(bidi_char)
        after = segment[local_pos + 1:]
        visual_seg = logical_seg[:local_pos] + after[::-1]
        segments.append(logical_seg.strip())
        visuals.append(visual_seg.strip())
        idx += 1

    logical = " | ".join(s for s in segments if s)
    visual = " | ".join(v for v in visuals if v)
    return logical, visual
