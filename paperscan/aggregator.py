from __future__ import annotations

from paperscan.models import Finding

_HEURISTIC_WEIGHTS = {"low": 5, "medium": 15, "high": 25, "critical": 40}
_PATTERN_WEIGHTS   = {"low": 5, "medium": 10, "high": 15, "critical": 20}
_SEMANTIC_WEIGHTS  = {"low": 10, "medium": 20, "high": 35, "critical": 50}

# Findings below this confidence threshold are shown in the UI but excluded from scoring.
# Prevents weak / ambiguous signals from driving the verdict.
_CONFIDENCE_FLOOR = 0.50


def aggregate(
    findings: list[Finding],
    macro_present: bool = False,
) -> tuple[int, str]:
    """
    Combine findings from all layers into a single (score, severity) tuple.

    All layers are now confidence-weighted: score += severity_points * confidence.
    Findings below _CONFIDENCE_FLOOR are excluded from scoring (still shown in UI).

    Pattern:    confidence-weighted, capped at 40
    Heuristic:  confidence-weighted, capped at 60
    Semantic:   confidence-weighted, capped at 50

    Returns (score 0–100, severity "clean"|"suspicious"|"malicious")
    """
    scorable = [f for f in findings if f.confidence >= _CONFIDENCE_FLOOR]

    pattern_findings   = [f for f in scorable if f.layer == "pattern"]
    heuristic_findings = [f for f in scorable if f.layer == "heuristic"]
    semantic_findings  = [f for f in scorable if f.layer == "semantic"]

    pattern_score = min(
        sum(_PATTERN_WEIGHTS.get(f.severity, 5) * f.confidence for f in pattern_findings),
        40,
    )

    heuristic_score = min(
        sum(_HEURISTIC_WEIGHTS.get(f.severity, 0) * f.confidence for f in heuristic_findings),
        60,
    )

    raw_semantic = sum(
        _SEMANTIC_WEIGHTS.get(f.severity, 0) * f.confidence
        for f in semantic_findings
    )
    semantic_score = min(raw_semantic, 50)

    total = min(int(pattern_score + heuristic_score + semantic_score), 100)

    if macro_present and total < 21:
        total = 21

    # A critical finding with sufficient confidence must never result in "clean".
    has_critical = any(
        f.severity == "critical" and f.confidence >= _CONFIDENCE_FLOOR
        for f in findings
    )
    if has_critical and total < 21:
        total = 21

    if total <= 20:
        severity = "clean"
    elif total <= 60:
        severity = "suspicious"
    else:
        severity = "malicious"

    return total, severity
