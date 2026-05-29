from __future__ import annotations

from typing import Literal
from pydantic import BaseModel, Field


class Finding(BaseModel):
    layer: Literal["pattern", "heuristic", "semantic"]
    severity: Literal["low", "medium", "high", "critical"]
    category: str
    description: str
    evidence: str
    location: str
    confidence: float = Field(ge=0.0, le=1.0)
    reasoning: str = ""      # LLM chain-of-thought for semantic findings
    attack_vector: str = ""  # e.g. "white_on_white", "ocg_layer", "actual_text_substitution"


class ExtractedDocument(BaseModel):
    # Core content
    visible_text: str = ""
    hidden_text: list[dict] = Field(default_factory=list)
    # [{location: str, content: str, method: str}]
    # methods: zero_font, invisible_render, clip_render, color_match, off_page,
    #          ocr_only, extraction_only, vanish, tiny_font

    metadata: dict = Field(default_factory=dict)
    annotations: list[str] = Field(default_factory=list)
    form_field_defaults: dict = Field(default_factory=dict)
    ocr_text: str = ""
    unicode_anomalies: list[dict] = Field(default_factory=list)
    # [{char, codepoint, category, location, count, logical_text?, visual_text?}]

    # v2 — extended extraction surfaces
    ocg_hidden_text: list[dict] = Field(default_factory=list)
    # [{layer_name: str, content: str}]

    actual_text_spans: list[dict] = Field(default_factory=list)
    # [{page: int, visual: str, extracted: str}]

    clipped_text: list[dict] = Field(default_factory=list)
    # [{page: int, content: str}]

    transparent_text: list[dict] = Field(default_factory=list)
    # [{page: int, content: str, alpha: float}]

    font_encoding_anomalies: list[dict] = Field(default_factory=list)
    # [{page: int, font_name: str, note: str}]

    tracked_changes: list[dict] = Field(default_factory=list)
    # [{type: "del"|"ins", content: str, author: str}]

    field_codes: list[dict] = Field(default_factory=list)
    # [{instruction: str}]

    macro_present: bool = False

    # Embedded images for vision analysis — excluded from serialized output to avoid bloat
    embedded_images: list[dict] = Field(default_factory=list, exclude=True)
    # [{location: str, image_b64: str, media_type: str, width: int, height: int}]


class ScanReport(BaseModel):
    file: str
    file_hash: str
    score: int = Field(ge=0, le=100)
    severity: Literal["clean", "suspicious", "malicious"]
    findings: list[Finding] = Field(default_factory=list)
    extracted: ExtractedDocument
    scan_duration_ms: int
    # Agentic LLM analysis metadata (populated by semantic layer)
    document_type: str = "unknown"
    document_description: str = ""
    risk_narrative: str = ""
    attack_scenario: str = ""
    remediation: list[str] = Field(default_factory=list)
    attack_sophistication: str = ""
    # Pipeline transparency
    semantic_layer_ran: bool = False
    semantic_model: str = ""
    semantic_passes: list[str] = Field(default_factory=list)
    # Sanitized output — visible text with injections neutralized, safe for downstream AI
    sanitized_text: str = ""
    sanitization_changes: list[str] = Field(default_factory=list)
