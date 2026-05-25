"""Structured data extractors — JSON and XML."""
from __future__ import annotations

import json

from paperscan.models import ExtractedDocument


def extract_json(path: str) -> ExtractedDocument:
    with open(path, encoding="utf-8", errors="replace") as _fh:
        content = _fh.read()
    texts: list[str] = []

    def _walk(obj: object, key_path: str = "root", depth: int = 0) -> None:
        if depth > 50:
            texts.append(f"[{key_path}]: [deeply nested — truncated]")
            return
        if isinstance(obj, str):
            if obj.strip():
                texts.append(f"[{key_path}]: {obj}")
        elif isinstance(obj, dict):
            for k, v in obj.items():
                _walk(v, f"{key_path}.{k}", depth + 1)
        elif isinstance(obj, list):
            for i, v in enumerate(obj):
                _walk(v, f"{key_path}[{i}]", depth + 1)

    try:
        _walk(json.loads(content))
    except json.JSONDecodeError:
        texts = [content]  # not valid JSON — treat as raw text

    return ExtractedDocument(visible_text="\n".join(texts))


def extract_xml(path: str) -> ExtractedDocument:
    try:
        from lxml import etree

        parser = etree.XMLParser(resolve_entities=False, no_network=True)
        tree = etree.parse(path, parser)
        texts: list[str] = []
        annotations: list[str] = []

        for el in tree.iter():
            tag = etree.QName(el.tag).localname if isinstance(el.tag, str) else str(el.tag)
            if el.text and el.text.strip():
                texts.append(f"[{tag}]: {el.text.strip()}")
            for attr, val in el.attrib.items():
                if len(val) > 30:
                    texts.append(f"[{tag}@{attr}]: {val}")

        for comment in tree.xpath("//comment()"):
            text = (comment.text or "").strip()
            if text:
                annotations.append(text)

        return ExtractedDocument(
            visible_text="\n".join(texts),
            annotations=annotations,
        )

    except Exception:
        with open(path, encoding="utf-8", errors="replace") as _fh:
            content = _fh.read()
        return ExtractedDocument(visible_text=content[:20000])
