from __future__ import annotations

import os

import fitz
from PIL import Image, ImageEnhance, ImageFilter

from paperscan.models import ExtractedDocument

_SKIP_ENV = "PAPERSCAN_SKIP_OCR"
_DIVERGENCE_THRESHOLD = 50  # minimum char count to flag a divergence
_OCR_DPI = 300
_TESSERACT_CONFIG = "--oem 3 --psm 6"


def _preprocess_for_ocr(img: Image.Image) -> Image.Image:
    """Enhance image for better accuracy on tiny and blurred text."""
    img = img.convert("L")                       # grayscale — removes colour noise
    img = img.filter(ImageFilter.SHARPEN)        # recover blurred edges
    img = ImageEnhance.Contrast(img).enhance(2.0)  # lift faint/low-contrast ink
    return img.convert("RGB")


def ocr_extract(path: str, extracted: ExtractedDocument) -> ExtractedDocument:
    """
    Render each PDF page to an image, OCR it, then diff against the text-layer
    extraction. Mutates and returns the ExtractedDocument.
    """
    if os.environ.get(_SKIP_ENV) == "1":
        return extracted

    try:
        import pytesseract
    except ImportError:
        return extracted

    doc = fitz.open(path)
    ocr_parts: list[str] = []

    for page in doc:
        pix = page.get_pixmap(dpi=_OCR_DPI)
        img = Image.frombytes("RGB", [pix.width, pix.height], pix.samples)
        img = _preprocess_for_ocr(img)
        try:
            page_ocr = pytesseract.image_to_string(img, lang="eng", config=_TESSERACT_CONFIG)
        except Exception:
            page_ocr = ""
        ocr_parts.append(page_ocr)

    doc.close()

    ocr_text = "\n".join(ocr_parts)
    extracted.ocr_text = ocr_text

    # Token-level diff
    visible_tokens = set(_tokenise(extracted.visible_text))
    ocr_tokens = set(_tokenise(ocr_text))

    # Tokens in OCR but not in visible text → text-as-image (hidden from extraction)
    ocr_only = " ".join(ocr_tokens - visible_tokens)
    if len(ocr_only) >= _DIVERGENCE_THRESHOLD:
        extracted.hidden_text.append({
            "location": "ocr_diff",
            "content": ocr_only[:2000],
            "method": "ocr_only",
        })

    # Tokens in visible text but not in OCR → invisible to renderer
    extraction_only = " ".join(visible_tokens - ocr_tokens)
    if len(extraction_only) >= _DIVERGENCE_THRESHOLD:
        extracted.hidden_text.append({
            "location": "ocr_diff",
            "content": extraction_only[:2000],
            "method": "extraction_only",
        })

    return extracted


def _tokenise(text: str) -> list[str]:
    """Split text into lowercase word tokens, filtering short noise."""
    import re
    return [w.lower() for w in re.findall(r"[a-zA-Z]{3,}", text)]
