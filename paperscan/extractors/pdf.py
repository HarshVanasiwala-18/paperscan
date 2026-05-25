from __future__ import annotations

import base64
import re

import fitz  # PyMuPDF

from paperscan.models import ExtractedDocument
from paperscan.extractors.unicode_utils import find_unicode_anomalies

_BG_COLOUR = (1.0, 1.0, 1.0)
_COLOUR_THRESHOLD = 0.08
_OFFPAGE_MARGIN = 300
_MAX_PAGES = 500  # cap per-page CVE surface; warn on oversized PDFs
_MAX_EMBEDDED_IMAGES = 20   # collect at most this many images for vision analysis
_MIN_IMG_AREA = 100 * 100   # skip tiny decorative images (< 100×100 px)
_EXT_TO_MEDIA_TYPE = {
    "jpg": "image/jpeg", "jpeg": "image/jpeg",
    "png": "image/png", "gif": "image/gif", "webp": "image/webp",
}

# Match text strings in PDF content streams: (string) Tj  or  [(string)] TJ
_PDF_TJ_RE = re.compile(rb"\(([^)\\]*(?:\\.[^)\\]*)*)\)\s*Tj", re.DOTALL)
# Detect q...Q blocks that contain a zero-area or tiny clipping rect before text
_ZERO_CLIP_BLOCK_RE = re.compile(
    rb"q\b"                              # save graphics state
    rb"(?:(?!q\b|Q\b)[\s\S])*?"         # content before clip (non-greedy, no nested q/Q)
    rb"[\d.]+\s+[\d.]+\s+"              # x y
    rb"(?:0|0\.0*)\s+(?:0|0\.0*)"       # width=0  height=0
    rb"\s+re\s+W"                        # re W  (zero-area clip path + clip operator)
    rb"[\s\S]*?"                         # between clip and restore (non-greedy)
    rb"Q\b",                             # restore graphics state
    re.DOTALL,
)


def _extract_clipped_text_from_stream(page: fitz.Page, page_num: int) -> list[dict]:
    """
    Scan the raw PDF content stream for text nested inside a zero-area clipping
    region.  PyMuPDF's get_text() honours clip paths and omits such text; this
    function recovers it by pattern-matching the content-stream bytes directly.
    """
    try:
        raw = page.read_contents()
        if not raw:
            return []
        results = []
        for block_match in _ZERO_CLIP_BLOCK_RE.finditer(raw):
            block = block_match.group(0)
            texts = []
            for m in _PDF_TJ_RE.finditer(block):
                decoded = m.group(1).replace(b"\\n", b"\n").replace(b"\\r", b"\r")
                decoded = re.sub(rb"\\(.)", lambda mo: mo.group(1), decoded)
                text = decoded.decode("latin-1", errors="replace").strip()
                if text:
                    texts.append(text)
            if texts:
                results.append({"page": page_num, "content": " ".join(texts)})
        return results
    except Exception:
        return []


def _colour_to_float(c) -> tuple | None:
    """Normalise a PyMuPDF colour value (packed int or tuple) to (r, g, b) floats 0–1."""
    if c is None:
        return None
    if isinstance(c, (list, tuple)):
        if len(c) >= 3:
            return tuple(float(x) / 255.0 if float(x) > 1.0 else float(x) for x in c[:3])
        if len(c) == 1:
            g = float(c[0])
            g = g / 255.0 if g > 1.0 else g
            return (g, g, g)
        return None
    iv = int(c)
    return (((iv >> 16) & 0xFF) / 255.0, ((iv >> 8) & 0xFF) / 255.0, (iv & 0xFF) / 255.0)


def _is_white(colour: tuple | None) -> bool:
    if not colour:
        return False
    return all(abs(colour[i] - _BG_COLOUR[i]) <= _COLOUR_THRESHOLD for i in range(3))


def _norm_alpha(a) -> float:
    """PyMuPDF 1.27+ returns alpha as int 0-255; normalise to 0.0–1.0."""
    if isinstance(a, int):
        return a / 255.0
    return float(a)


def extract_pdf(path: str) -> ExtractedDocument:
    # Explicit filetype prevents format-confusion attacks where a non-PDF file
    # with a .pdf extension tricks PyMuPDF into parsing it as a different format.
    doc = fitz.open(path, filetype="pdf")
    try:
        if len(doc) > _MAX_PAGES:
            raise ValueError(
                f"PDF has {len(doc)} pages; maximum supported is {_MAX_PAGES}. "
                "Split the document and re-scan each part."
            )
        return _extract_pdf_inner(doc)
    finally:
        doc.close()


def _extract_pdf_inner(doc: fitz.Document) -> ExtractedDocument:
    visible_parts: list[str] = []
    hidden_text: list[dict] = []
    ocg_hidden_text: list[dict] = []
    actual_text_spans: list[dict] = []
    clipped_text: list[dict] = []
    transparent_text: list[dict] = []
    font_encoding_anomalies: list[dict] = []
    annotations: list[str] = []
    form_field_defaults: dict = {}
    embedded_images: list[dict] = []

    # ── Metadata ────────────────────────────────────────────────────────────
    metadata: dict = {}
    if doc.metadata:
        metadata.update({k: v for k, v in doc.metadata.items() if v})
    try:
        xmp = doc.get_xml_metadata()
        if xmp:
            metadata["_xmp"] = xmp
    except Exception:
        pass

    try:
        js = doc.get_js()
        if js:
            metadata["_embedded_js"] = js
    except AttributeError:
        pass

    try:
        toc = doc.get_toc()
        if toc:
            metadata["_outline"] = str([{"level": t[0], "title": t[1]} for t in toc])
    except Exception:
        pass

    # ── OCG / Optional Content Groups ───────────────────────────────────────
    # Toggle each hidden layer on/off to isolate its specific text contribution.
    # Reading all-page text without toggling would attribute ALL page content
    # (including visible text) to every hidden layer — a source of false positives.
    try:
        layer_configs = doc.layer_ui_configs()
        hidden_layers = [
            (i, layer) for i, layer in enumerate(layer_configs)
            if not layer.get("on", True)
        ]
        if hidden_layers:
            # Baseline: text with all currently-off layers still off
            baseline = [page.get_text("text") for page in doc]
            for i, layer in hidden_layers:
                layer_name = layer.get("text", "unnamed_layer")
                # Enable this hidden layer
                doc.set_layer_ui_config(i, action=1)
                enabled = [page.get_text("text") for page in doc]
                # Restore to off
                doc.set_layer_ui_config(i, action=2)
                # Collect text that only appears when the layer is on
                parts = []
                for base_txt, on_txt in zip(baseline, enabled):
                    if on_txt != base_txt:
                        parts.append(on_txt)
                content = "\n".join(parts).strip()
                if content:
                    ocg_hidden_text.append({"layer_name": layer_name, "content": content})
    except Exception:
        pass

    # ── Font encoding anomalies ──────────────────────────────────────────────
    seen_fonts: set[str] = set()
    try:
        for page in doc:
            for font in page.get_fonts(full=True):
                font_name = font[3] or font[4] or "unknown"
                if font_name in seen_fonts:
                    continue
                seen_fonts.add(font_name)
                font_type = font[2]
                if font_type in ("Type3", "CIDFontType0", "CIDFontType2"):
                    font_encoding_anomalies.append({
                        "page": page.number + 1,
                        "font_name": font_name,
                        "note": f"custom_font_type:{font_type}",
                    })
    except Exception:
        pass

    # ── Per-page extraction ─────────────────────────────────────────────────
    for page in doc:
        page_num = page.number + 1
        page_rect = page.rect

        extended_rect = fitz.Rect(
            page_rect.x0 - _OFFPAGE_MARGIN,
            page_rect.y0 - _OFFPAGE_MARGIN,
            page_rect.x1 + _OFFPAGE_MARGIN,
            page_rect.y1 + _OFFPAGE_MARGIN,
        )

        # Form fields / widgets
        try:
            for widget in page.widgets():
                name = widget.field_name or f"field_{page_num}"
                value = widget.field_value or ""
                if value:
                    form_field_defaults[name] = value
                script = getattr(widget, "script", None) or ""
                if script:
                    annotations.append(f"[widget_script:{name}] {script}")
        except Exception:
            pass

        # Annotations
        try:
            for annot in page.annots():
                content = annot.info.get("content", "").strip()
                if content:
                    annotations.append(content)
        except Exception:
            pass

        # Use "dict" format — spans have a "text" key in PyMuPDF 1.27
        try:
            textdict = page.get_text("dict", clip=extended_rect)
        except Exception:
            textdict = page.get_text("dict")

        visible_span_parts: list[str] = []

        for block in textdict.get("blocks", []):
            if block.get("type") != 0:
                continue
            for line in block.get("lines", []):
                for span in line.get("spans", []):
                    text = span.get("text", "").strip()
                    if not text:
                        continue

                    size = float(span.get("size", 12) or 12)
                    colour = _colour_to_float(span.get("color"))
                    origin = span.get("origin", (0.0, 0.0))
                    flags_val = span.get("flags", 0)
                    render_mode = (int(flags_val) >> 8) & 0x0F if flags_val else 0
                    alpha = _norm_alpha(span.get("alpha", 255))

                    ox = origin[0] if isinstance(origin, (list, tuple)) else 0.0
                    oy = origin[1] if isinstance(origin, (list, tuple)) else 0.0
                    is_off_page = not page_rect.contains(fitz.Point(ox, oy))
                    is_zero_font = size < 1.0
                    is_invisible_render = render_mode == 3
                    is_clip_render = render_mode == 7
                    is_white = _is_white(colour)
                    is_transparent = alpha < 0.05

                    if is_zero_font:
                        hidden_text.append({
                            "location": f"page{page_num}",
                            "content": text,
                            "method": "zero_font",
                        })
                    elif is_invisible_render:
                        hidden_text.append({
                            "location": f"page{page_num}",
                            "content": text,
                            "method": "invisible_render",
                        })
                    elif is_clip_render:
                        hidden_text.append({
                            "location": f"page{page_num}",
                            "content": text,
                            "method": "clip_render",
                        })
                    elif is_off_page:
                        hidden_text.append({
                            "location": f"page{page_num}",
                            "content": text,
                            "method": "off_page",
                        })
                    elif is_transparent:
                        transparent_text.append({
                            "page": page_num,
                            "content": text,
                            "alpha": alpha,
                        })
                    elif is_white:
                        hidden_text.append({
                            "location": f"page{page_num}",
                            "content": text,
                            "method": "color_match",
                        })
                    else:
                        visible_span_parts.append(text)

        visible_parts.append(" ".join(visible_span_parts))

        # Zero-area clipping path — text invisible to get_text(); parse stream directly
        clipped_text.extend(_extract_clipped_text_from_stream(page, page_num))

        # QR codes and embedded images for vision analysis
        from paperscan.extractors.qr import scan_image_for_qr
        for img_ref in page.get_images(full=True):
            try:
                base_img = doc.extract_image(img_ref[0])
                img_bytes = base_img.get("image", b"")
                if not img_bytes:
                    continue
                # QR decode (existing)
                for qr_text in scan_image_for_qr(img_bytes):
                    hidden_text.append({
                        "location": f"page{page_num}_image",
                        "content": qr_text,
                        "method": "qr_code",
                    })
                # Collect for vision analysis
                width = base_img.get("width", 0)
                height = base_img.get("height", 0)
                if (width * height >= _MIN_IMG_AREA
                        and len(embedded_images) < _MAX_EMBEDDED_IMAGES):
                    ext = base_img.get("ext", "png").lower()
                    media_type = _EXT_TO_MEDIA_TYPE.get(ext, "image/png")
                    embedded_images.append({
                        "location": f"page{page_num}_image",
                        "image_b64": base64.b64encode(img_bytes).decode(),
                        "media_type": media_type,
                        "width": width,
                        "height": height,
                    })
            except Exception:
                pass

    visible_text = "\n".join(visible_parts).strip()

    # Include metadata in unicode scan so tag chars in metadata are caught
    meta_text = " ".join(str(v) for v in metadata.values() if v and isinstance(v, str))
    all_text_for_unicode = (
        visible_text + " " + meta_text + " " +
        " ".join(h.get("content", "") for h in hidden_text)
    )
    unicode_anomalies = find_unicode_anomalies(all_text_for_unicode)

    return ExtractedDocument(
        visible_text=visible_text,
        hidden_text=hidden_text,
        metadata=metadata,
        annotations=annotations,
        form_field_defaults=form_field_defaults,
        ocr_text="",
        unicode_anomalies=unicode_anomalies,
        ocg_hidden_text=ocg_hidden_text,
        actual_text_spans=actual_text_spans,
        clipped_text=clipped_text,
        transparent_text=transparent_text,
        font_encoding_anomalies=font_encoding_anomalies,
        embedded_images=embedded_images,
    )
