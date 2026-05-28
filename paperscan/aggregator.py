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
    ai_cleared: bool = False,
) -> tuple[int, str]:
    """
    Combine findings from all layers into a single (score, severity) tuple.

    All layers are now confidence-weighted: score += severity_points * confidence.
    Findings below _CONFIDENCE_FLOOR are excluded from scoring (still shown in UI).

    Pattern:    confidence-weighted, capped at 40
    Heuristic:  confidence-weighted, capped at 60
    Semantic:   confidence-weighted, capped at 50

    Thresholds:  0–20 clean | 21–44 suspicious | 45+ malicious
    The malicious threshold is ≤ 50 so that semantic findings alone can drive
    a malicious verdict (semantic cap = 50; old threshold of 61 made that impossible).

    Critical semantic finding: forces score ≥ 45 (always malicious).
    Critical any-layer finding: forces score ≥ 30 (clearly suspicious).

    ai_cleared=True: AI semantic layer ran and found no injections. Heuristic and
    pattern scores are halved and total is capped at 20 (always clean).

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

    # AI clearance discount: when the semantic layer ran and found nothing,
    # heuristic/pattern noise is halved.
    if ai_cleared:
        pattern_score   *= 0.5
        heuristic_score *= 0.5

    total = min(int(pattern_score + heuristic_score + semantic_score), 100)

    # Minimum-score clamps only apply when the AI has NOT cleared the document.
    # When ai_cleared=True the AI's authoritative judgment overrides heuristic minimums.
    if not ai_cleared:
        if macro_present and total < 30:
            total = 30

        # Any critical finding must never silently produce "clean" or a near-floor score.
        has_critical = any(
            f.severity == "critical" and f.confidence >= _CONFIDENCE_FLOOR
            for f in findings
        )
        if has_critical and total < 30:
            total = 30

        # A critical semantic finding is a confirmed AI-identified injection — must be malicious.
        # The semantic cap (50) sits below the old malicious threshold (61), so without this
        # override a lone critical semantic finding could never reach malicious on score alone.
        has_critical_semantic = any(
            f.severity == "critical" and f.layer == "semantic"
            and f.confidence >= _CONFIDENCE_FLOOR
            for f in findings
        )
        if has_critical_semantic:
            total = max(total, 45)
    else:
        # AI cleared the document — discount heuristic/pattern noise.
        # Hard-cap at 20 (clean) UNLESS there are critical findings from non-semantic
        # layers with high confidence — those may be hidden-surface signals the semantic
        # pass missed (false negative). In that case, allow up to 30 (suspicious) so
        # critical hidden injections are not silently buried by an AI clearance.
        has_non_semantic_critical = any(
            f.severity == "critical"
            and f.confidence >= _CONFIDENCE_FLOOR
            and f.layer != "semantic"
            for f in findings
        )
        total = min(total, 30 if has_non_semantic_critical else 20)

    # Thresholds
    # Semantic cap is 50, so the malicious threshold must be ≤ 50 to allow semantic-only verdicts.
    if total <= 20:
        severity = "clean"
    elif total <= 44:
        severity = "suspicious"
    else:
        severity = "malicious"

    return total, severity
