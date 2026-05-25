from __future__ import annotations

from paperscan.models import Finding

_HEURISTIC_WEIGHTS = {"low": 5, "medium": 15, "high": 25, "critical": 40}
_PATTERN_WEIGHTS   = {"low": 5, "medium": 10, "high": 15, "critical": 20}

# Semantic findings now come from the tool-use loop with specific categories.
# Score by severity × confidence, summed and capped at 50.
_SEMANTIC_WEIGHTS  = {"low": 10, "medium": 20, "high": 35, "critical": 50}


def aggregate(
    findings: list[Finding],
    macro_present: bool = False,
) -> tuple[int, str]:
    """
    Combine findings from all layers into a single (score, severity) tuple.

    Pattern:    severity-weighted, capped at 40
    Heuristic:  severity-weighted, capped at 60
    Semantic:   severity × confidence, summed and capped at 50
                (tool-use findings carry specific categories, scored by severity)

    Returns (score 0–100, severity "clean"|"suspicious"|"malicious")
    """
    pattern_findings   = [f for f in findings if f.layer == "pattern"]
    heuristic_findings = [f for f in findings if f.layer == "heuristic"]
    semantic_findings  = [f for f in findings if f.layer == "semantic"]

    pattern_score = min(
        sum(_PATTERN_WEIGHTS.get(f.severity, 5) for f in pattern_findings),
        40,
    )

    heuristic_score = min(
        sum(_HEURISTIC_WEIGHTS.get(f.severity, 0) for f in heuristic_findings),
        60,
    )

    # Sum confidence-weighted semantic scores; a single critical+confident finding
    # contributes 50, multiple findings accumulate but are capped at 50.
    raw_semantic = sum(
        _SEMANTIC_WEIGHTS.get(f.severity, 0) * f.confidence
        for f in semantic_findings
    )
    semantic_score = min(raw_semantic, 50)

    total = min(int(pattern_score + heuristic_score + semantic_score), 100)

    if macro_present and total < 21:
        total = 21

    # A critical finding must never result in "clean" — at minimum suspicious.
    has_critical = any(f.severity == "critical" for f in findings)
    if has_critical and total < 21:
        total = 21

    if total <= 20:
        severity = "clean"
    elif total <= 60:
        severity = "suspicious"
    else:
        severity = "malicious"

    return total, severity
