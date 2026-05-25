from __future__ import annotations

import base64
import io
import os

from paperscan.models import ExtractedDocument

_EXIF_TAG_NAMES = {
    0x010E: "ImageDescription",
    0x010F: "Make",
    0x0110: "Model",
    0x0131: "Software",
    0x013B: "Artist",
    0x8298: "Copyright",
    0x9286: "UserComment",
    0x9C9B: "XPTitle",
    0x9C9C: "XPComment",
    0x9C9D: "XPAuthor",
    0x9C9E: "XPKeywords",
    0x9C9F: "XPSubject",
}


def _read_exif(img) -> dict:
    metadata: dict[str, str] = {}
    try:
        raw = img._getexif()
        if raw:
            for tag_id, value in raw.items():
                name = _EXIF_TAG_NAMES.get(tag_id)
                if name is None:
                    continue
                if isinstance(value, bytes):
                    try:
                        value = value.decode("utf-16-le", errors="replace").rstrip("\x00")
                    except Exception:
                        value = value.decode("latin-1", errors="replace")
                if isinstance(value, str) and value.strip():
                    metadata[name] = value.strip()
    except Exception:
        pass
    return metadata


def _read_png_text(img) -> dict:
    metadata: dict[str, str] = {}
    try:
        for key, value in img.info.items():
            if isinstance(key, str) and isinstance(value, str) and value.strip():
                metadata[key] = value.strip()
    except Exception:
        pass
    return metadata


def _ocr_image(img) -> str:
    if os.environ.get("PAPERSCAN_SKIP_OCR") == "1":
        return ""
    try:
        import pytesseract
        from PIL import ImageEnhance, ImageFilter
        grey = img.convert("L")
        grey = grey.filter(ImageFilter.SHARPEN)
        grey = ImageEnhance.Contrast(grey).enhance(2.0)
        return pytesseract.image_to_string(grey.convert("RGB"), lang="eng",
                                           config="--oem 3 --psm 6")
    except Exception:
        return ""


_MAX_IMAGE_PIXELS = 25_000_000  # 25 MP — matches PIL's default decompression bomb threshold


def extract_image(path: str) -> ExtractedDocument:
    from PIL import Image

    img = Image.open(path)
    # Validate dimensions before loading full pixel data (decompression bomb guard)
    if img.width * img.height > _MAX_IMAGE_PIXELS:
        raise ValueError(
            f"Image too large ({img.width}×{img.height} = {img.width * img.height:,} px "
            f"> {_MAX_IMAGE_PIXELS:,} limit)"
        )
    img.load()

    fmt = (img.format or "").lower()
    metadata = _read_exif(img) if fmt in ("jpeg", "jpg") else _read_png_text(img)

    ocr_text = _ocr_image(img)

    # Encode image for vision analysis pass
    buf = io.BytesIO()
    rgb = img.convert("RGB")
    rgb.save(buf, format="JPEG", quality=85)
    image_b64 = base64.b64encode(buf.getvalue()).decode()
    embedded_images = [{
        "location": "page1",
        "image_b64": image_b64,
        "media_type": "image/jpeg",
        "width": img.width,
        "height": img.height,
    }]

    hidden_text: list[dict] = []
    if ocr_text.strip():
        hidden_text.append({
            "location": "ocr",
            "content": ocr_text.strip(),
            "method": "ocr_only",
        })

    return ExtractedDocument(
        visible_text=ocr_text.strip(),
        hidden_text=hidden_text,
        metadata=metadata,
        embedded_images=embedded_images,
    )
