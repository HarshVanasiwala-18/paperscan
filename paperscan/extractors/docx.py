from __future__ import annotations

import base64
import io
import zipfile
from pathlib import Path

from docx import Document as DocxDocument
from lxml import etree

from paperscan.models import ExtractedDocument

# Disable external-entity resolution to prevent XXE attacks when parsing DOCX XML parts
_SAFE_XML_PARSER = etree.XMLParser(resolve_entities=False, no_network=True)
from paperscan.extractors.unicode_utils import find_unicode_anomalies

# OOXML namespace map
NS = {
    "w": "http://schemas.openxmlformats.org/wordprocessingml/2006/main",
    "r": "http://schemas.openxmlformats.org/officeDocument/2006/relationships",
    "cp": "http://schemas.openxmlformats.org/package/2006/metadata/core-properties",
    "dc": "http://purl.org/dc/elements/1.1/",
    "ep": "http://schemas.openxmlformats.org/officeDocument/2006/extended-properties",
}

_W = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"


def _w(tag: str) -> str:
    return f"{{{_W}}}{tag}"


_MAX_ZIP_ENTRY   = 100 * 1024 * 1024  # 100 MB per entry — decompression bomb guard
_MAX_ZIP_ENTRIES = 1_000              # entry count limit — prevents zip-slip / slow-path DoS
_MAX_EMBEDDED_IMAGES = 20
_MIN_IMG_AREA = 100 * 100        # skip tiny decorative images
_MAX_IMG_PIXELS = 25_000_000     # ~25 MP; reject before full decode to prevent memory bombs
_EXT_TO_MEDIA_TYPE = {
    "jpg": "image/jpeg", "jpeg": "image/jpeg",
    "png": "image/png", "gif": "image/gif", "webp": "image/webp",
}


def _safe_zip_read(zf: zipfile.ZipFile, name: str) -> bytes:
    info = zf.getinfo(name)
    if info.file_size > _MAX_ZIP_ENTRY:
        raise ValueError(f"ZIP entry '{name}' exceeds size limit ({info.file_size} bytes)")
    return zf.read(name)


def _check_zip_entry_count(zf: zipfile.ZipFile) -> None:
    count = len(zf.namelist())
    if count > _MAX_ZIP_ENTRIES:
        raise ValueError(f"Archive has too many entries ({count} > {_MAX_ZIP_ENTRIES})")


def extract_docx(path: str) -> ExtractedDocument:
    hidden_text: list[dict] = []
    tracked_changes: list[dict] = []
    field_codes: list[dict] = []
    annotations: list[str] = []
    metadata: dict = {}
    embedded_images: list[dict] = []

    # ── Macro detection ──────────────────────────────────────────────────────
    macro_present = False
    with zipfile.ZipFile(path) as zf:
        _check_zip_entry_count(zf)
        names = zf.namelist()
        macro_present = "word/vbaProject.bin" in names

        # ── Document properties ──────────────────────────────────────────────
        metadata.update(_read_core_props(zf))
        metadata.update(_read_app_props(zf))

        # ── Comments ────────────────────────────────────────────────────────
        if "word/comments.xml" in names:
            with zf.open("word/comments.xml") as f:
                tree = etree.parse(f, _SAFE_XML_PARSER)
                for comment in tree.findall(f".//{_w('comment')}"):
                    texts = [
                        t.text for t in comment.findall(f".//{_w('t')}") if t.text
                    ]
                    combined = " ".join(texts).strip()
                    if combined:
                        author = comment.get(_w("author"), "unknown")
                        annotations.append(f"[comment:{author}] {combined}")

        # ── QR codes and embedded images for vision analysis ─────────────────
        from paperscan.extractors.qr import scan_image_for_qr
        from PIL import Image as _PILImage
        _IMG_EXTS = {'.png', '.jpg', '.jpeg', '.gif', '.bmp', '.webp', '.tiff'}
        for name in names:
            if name.startswith("word/media/") and Path(name).suffix.lower() in _IMG_EXTS:
                try:
                    img_bytes = _safe_zip_read(zf, name)
                    # QR decode (existing)
                    for qr_text in scan_image_for_qr(img_bytes):
                        hidden_text.append({
                            "location": f"docx_image:{Path(name).name}",
                            "content": qr_text,
                            "method": "qr_code",
                        })
                    # Collect for vision analysis
                    if len(embedded_images) < _MAX_EMBEDDED_IMAGES:
                        try:
                            pil_img = _PILImage.open(io.BytesIO(img_bytes))
                            width, height = pil_img.size  # header-only, no pixel decode yet
                            if width * height > _MAX_IMG_PIXELS:
                                pass  # skip — would decompress into too much memory
                            elif width * height >= _MIN_IMG_AREA:
                                ext = Path(name).suffix.lower().lstrip(".")
                                media_type = _EXT_TO_MEDIA_TYPE.get(ext, "image/png")
                                embedded_images.append({
                                    "location": f"docx_image:{Path(name).name}",
                                    "image_b64": base64.b64encode(img_bytes).decode(),
                                    "media_type": media_type,
                                    "width": width,
                                    "height": height,
                                })
                        except Exception:
                            pass
                except Exception:
                    pass

        # ── Main document XML ────────────────────────────────────────────────
        with zf.open("word/document.xml") as f:
            body_tree = etree.parse(f, _SAFE_XML_PARSER)

        # Headers and footers
        header_footer_text: list[str] = []
        for name in names:
            if name.startswith("word/header") or name.startswith("word/footer"):
                with zf.open(name) as f:
                    tree = etree.parse(f, _SAFE_XML_PARSER)
                    parts = [
                        t.text for t in tree.findall(f".//{_w('t')}") if t.text
                    ]
                    header_footer_text.append(" ".join(parts))

    body = body_tree.getroot()

    # ── Visible text via python-docx ─────────────────────────────────────────
    doc = DocxDocument(path)
    visible_parts: list[str] = []
    for para in doc.paragraphs:
        visible_parts.append(para.text)
    for table in doc.tables:
        for row in table.rows:
            for cell in row.cells:
                visible_parts.append(cell.text)
    if header_footer_text:
        visible_parts.extend(header_footer_text)
    visible_text = "\n".join(visible_parts)

    # ── Hidden runs via XML (vanish, tiny_font, color_match) ────────────────
    for run in body.findall(f".//{_w('r')}"):
        rpr = run.find(_w("rPr"))
        if rpr is None:
            continue
        text_nodes = run.findall(_w("t"))
        text = "".join(t.text for t in text_nodes if t.text).strip()
        if not text:
            continue

        # w:vanish — explicitly hidden
        if rpr.find(_w("vanish")) is not None:
            hidden_text.append({
                "location": "docx_body",
                "content": text,
                "method": "vanish",
            })
            continue

        # w:sz — font size near zero (< 2 half-points = 1pt)
        sz = rpr.find(_w("sz"))
        if sz is not None:
            val = sz.get(_w("val"), "")
            try:
                if int(val) < 2:
                    hidden_text.append({
                        "location": "docx_body",
                        "content": text,
                        "method": "tiny_font",
                    })
                    continue
            except ValueError:
                pass

        # w:color — white text (AUTO is normal document text; only flag explicit FFFFFF)
        color_el = rpr.find(_w("color"))
        if color_el is not None:
            color_val = color_el.get(_w("val"), "")
            if color_val.upper() == "FFFFFF":
                hidden_text.append({
                    "location": "docx_body",
                    "content": text,
                    "method": "color_match",
                })

    # ── Tracked changes (gap 6) ──────────────────────────────────────────────
    for del_elem in body.findall(f".//{_w('del')}"):
        texts = [
            t.text for t in del_elem.findall(f".//{_w('delText')}") if t.text
        ]
        content = " ".join(texts).strip()
        if content:
            author = del_elem.get(_w("author"), "unknown")
            tracked_changes.append({"type": "del", "content": content, "author": author})

    for ins_elem in body.findall(f".//{_w('ins')}"):
        texts = [t.text for t in ins_elem.findall(f".//{_w('t')}") if t.text]
        content = " ".join(texts).strip()
        if content:
            author = ins_elem.get(_w("author"), "unknown")
            tracked_changes.append({"type": "ins", "content": content, "author": author})

    # ── Field codes (gap 7) ─────────────────────────────────────────────────
    for instr in body.findall(f".//{_w('instrText')}"):
        instruction = (instr.text or "").strip()
        if instruction:
            field_codes.append({"instruction": instruction})

    all_text = visible_text + " ".join(h["content"] for h in hidden_text)
    unicode_anomalies = find_unicode_anomalies(all_text)

    return ExtractedDocument(
        visible_text=visible_text,
        hidden_text=hidden_text,
        metadata=metadata,
        annotations=annotations,
        form_field_defaults={},
        ocr_text="",
        unicode_anomalies=unicode_anomalies,
        tracked_changes=tracked_changes,
        field_codes=field_codes,
        macro_present=macro_present,
        embedded_images=embedded_images,
    )


def _read_core_props(zf: zipfile.ZipFile) -> dict:
    props: dict = {}
    if "docProps/core.xml" not in zf.namelist():
        return props
    with zf.open("docProps/core.xml") as f:
        tree = etree.parse(f, _SAFE_XML_PARSER)
    root = tree.getroot()
    for child in root:
        tag = etree.QName(child.tag).localname
        if child.text:
            props[f"core:{tag}"] = child.text
    return props


def _read_app_props(zf: zipfile.ZipFile) -> dict:
    props: dict = {}
    if "docProps/app.xml" not in zf.namelist():
        return props
    with zf.open("docProps/app.xml") as f:
        tree = etree.parse(f, _SAFE_XML_PARSER)
    root = tree.getroot()
    for child in root:
        tag = etree.QName(child.tag).localname
        if child.text:
            props[f"app:{tag}"] = child.text
    return props
