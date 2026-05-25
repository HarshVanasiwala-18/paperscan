"""CSV extractor — all cell values fed to the detector pipeline."""
from __future__ import annotations

import csv

from paperscan.models import ExtractedDocument


def extract_csv(path: str) -> ExtractedDocument:
    rows: list[str] = []
    try:
        with open(path, encoding="utf-8-sig", errors="replace", newline="") as f:
            reader = csv.reader(f)
            for row in reader:
                line = "\t".join(cell.strip() for cell in row if cell.strip())
                if line:
                    rows.append(line)
    except Exception as exc:
        return ExtractedDocument(visible_text=f"[CSV parse error: {exc}]")

    return ExtractedDocument(visible_text="\n".join(rows))
