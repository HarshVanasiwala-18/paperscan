"""HTML extractor — covers webpage poisoning attack surface."""
from __future__ import annotations

import re

from paperscan.models import ExtractedDocument

_CSS_HIDDEN = re.compile(
    r"display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0(?:[^.]|$)",
    re.IGNORECASE,
)


def extract_html(path: str) -> ExtractedDocument:
    with open(path, encoding="utf-8", errors="replace") as _fh:
        content = _fh.read()

    # Pull HTML comments before lxml strips them
    raw_comments = re.findall(r"<!--(.*?)-->", content, re.DOTALL)
    annotations = [c.strip() for c in raw_comments if c.strip()]

    try:
        from lxml import html as lhtml
    except ImportError:
        return ExtractedDocument(
            visible_text=re.sub(r"<[^>]+>", " ", content),
            annotations=annotations,
        )

    # HTMLParser with resolve_entities=False prevents external entity expansion
    _safe = lhtml.HTMLParser(resolve_entities=False)
    try:
        tree = lhtml.fromstring(content, parser=_safe)
    except Exception:
        return ExtractedDocument(
            visible_text=re.sub(r"<[^>]+>", " ", content),
            annotations=annotations,
        )

    # Metadata from <meta> and <title>
    metadata: dict = {}
    for meta in tree.xpath("//meta"):
        name = meta.get("name") or meta.get("property") or meta.get("http-equiv", "")
        val = meta.get("content", "")
        if name and val:
            metadata[name] = val
    for title in tree.xpath("//title/text()"):
        metadata["title"] = title

    # Visible text (strip script/style first)
    tree_clean = lhtml.fromstring(content, parser=_safe)
    for el in tree_clean.xpath("//script|//style|//noscript"):
        parent = el.getparent()
        if parent is not None:
            parent.remove(el)
    visible_text = " ".join(tree_clean.text_content().split())

    hidden_text: list[dict] = []

    # CSS-hidden elements
    for el in tree.xpath("//*[@style]"):
        style = el.get("style", "")
        if _CSS_HIDDEN.search(style):
            text = el.text_content().strip()
            if text:
                hidden_text.append({
                    "location": f"css_hidden:{el.tag}",
                    "content": text,
                    "method": "css_hidden",
                })

    # data-* attributes carrying long text (potential payload)
    for el in tree.iter():
        for attr, val in el.items():
            if attr.startswith("data-") and len(val) > 50:
                hidden_text.append({
                    "location": f"data_attr:{attr}",
                    "content": val,
                    "method": "data_attribute",
                })

    # Inline script content (AI code-review injection vector)
    for script in tree.xpath("//script[not(@src)]"):
        text = (script.text_content() or "").strip()
        if text:
            hidden_text.append({
                "location": "script_tag",
                "content": text[:800],
                "method": "script_content",
            })

    return ExtractedDocument(
        visible_text=visible_text,
        hidden_text=hidden_text,
        metadata=metadata,
        annotations=annotations,
    )
