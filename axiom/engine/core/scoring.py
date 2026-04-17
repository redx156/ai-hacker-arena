"""
AXIOM — Centralized Scoring Engine
═══════════════════════════════════
THE single scoring function used by ALL agents.

Formula:
    final_score = (0.60 × semantic_drift)
                + (0.25 × protocol_signal)
                + (0.15 × exploit_consistency)

NO agent may implement its own scoring formula.
All agents MUST call compute_final_score().
"""


def compute_final_score(
    drift: float,
    protocol: float,
    consistency: float,
) -> float:
    """
    Compute the canonical AXIOM final score.

    Args:
        drift:       Semantic drift score from the fingerprinter (0.0–1.0).
        protocol:    Protocol-level signal from plugins (0.0–1.0).
        consistency: Exploit consistency — how reliably a pattern succeeds (0.0–1.0).

    Returns:
        Composite score in [0.0, 1.0].
    """
    raw = (
        0.60 * drift
        + 0.25 * protocol
        + 0.15 * consistency
    )
    return round(min(max(raw, 0.0), 1.0), 3)


def classify_severity(final_score: float) -> str:
    """
    Classify a final_score into AXIOM severity bands.

    Used by ALL agents for consistent severity labeling.

    Bands:
        > 0.75 → CRITICAL
        > 0.50 → HIGH
        > 0.30 → MEDIUM
        else   → LOW
    """
    if final_score > 0.75:
        return "CRITICAL"
    elif final_score > 0.50:
        return "HIGH"
    elif final_score > 0.30:
        return "MEDIUM"
    else:
        return "LOW"


def classify_verdict(improvement_score: float, critical_remaining: int) -> str:
    """
    Classify the overall system verdict based on improvement and remaining criticals.

    Used by the Judge agent for final verdicts.

    Args:
        improvement_score: Percentage improvement (0.0–1.0).
        critical_remaining: Number of CRITICAL issues still present after defense.

    Returns:
        "SECURE", "WEAK", or "VULNERABLE".
    """
    if critical_remaining > 0:
        return "VULNERABLE"
    elif improvement_score >= 0.7:
        return "SECURE"
    elif improvement_score >= 0.3:
        return "WEAK"
    else:
        return "VULNERABLE"
