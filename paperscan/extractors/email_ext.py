"""Email (.eml) extractor — covers email-based agent attack surface."""
from __future__ import annotations

import email as _email
import os
import re
import tempfile
from email import policy

from paperscan.models import ExtractedDocument


def extract_eml(path: str) -> ExtractedDocument:
    with open(path, "rb") as f:
        msg = _email.message_from_binary_file(f, policy=policy.default)

    # Headers → metadata
    metadata: dict = {}
    for key in ["from", "to", "subject", "reply-to", "cc", "bcc",
                "date", "message-id", "x-mailer", "return-path"]:
        val = msg.get(key, "")
        if val:
            metadata[key] = str(val)

    visible_parts: list[str] = []
    hidden_text: list[dict] = []
    annotations: list[str] = []

    def _process_part(part: _email.message.Message) -> None:
        ct = part.get_content_type()
        cd = str(part.get_content_disposition() or "")

        if cd == "attachment":
            fname = part.get_filename() or "unnamed_attachment"
            annotations.append(f"attachment:{fname}")
            return

        if ct == "text/plain":
            try:
                visible_parts.append(part.get_content())
            except Exception:
                pass

        elif ct == "text/html":
            try:
                html_content = part.get_content()
                _parse_html_part(html_content)
            except Exception:
                pass

    def _parse_html_part(html_content: str) -> None:
        from paperscan.extractors.html import extract_html
        with tempfile.NamedTemporaryFile(
            suffix=".html", delete=False, mode="w", encoding="utf-8"
        ) as tmp:
            tmp_path = tmp.name  # capture before write so cleanup always has a path
            tmp.write(html_content)
        try:
            sub = extract_html(tmp_path)
            visible_parts.append(sub.visible_text)
            hidden_text.extend(sub.hidden_text)
            annotations.extend(sub.annotations)
        finally:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass

    if msg.is_multipart():
        for part in msg.walk():
            _process_part(part)
    else:
        _process_part(msg)  # type: ignore[arg-type]

    return ExtractedDocument(
        visible_text="\n\n".join(p for p in visible_parts if p.strip()),
        hidden_text=hidden_text,
        metadata=metadata,
        annotations=annotations,
    )
