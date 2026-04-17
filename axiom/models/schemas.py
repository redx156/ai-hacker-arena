"""
AXIOM Data Models
═════════════════
All core data structures used throughout the AXIOM red-teaming pipeline.
"""

from dataclasses import dataclass, field, asdict
from typing import List, Optional, Dict, Any
import json


@dataclass
class Claim:
    """A security claim made about the target AI system."""
    id: str
    text: str
    attack_families: List[str]
    priority: str              # "Critical" / "High" / "Medium"
    planned_turns: int
    confidence_prior: float

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Persona:
    """An attack persona generated to probe a specific claim."""
    type: str              # "naive_user" / "social_engineer" / "technical_exploiter"
    attack_plan: str       # Full multi-turn plan or single payload
    confidence: float
    is_primary: bool

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class AttackAttempt:
    """A single attack attempt with its results and scoring."""
    generation: int        # GEN-1, GEN-2, etc.
    persona_type: str
    payload: str
    raw_response: str
    drift_score: float
    drift_type: str        # "Tonal Shift" / "Info Leakage" / etc.
    outcome: str           # "CLEAN REFUSAL" / "SOFT LEAK" / etc.
    components_used: List[str] = field(default_factory=list)
    # Graph-tracking fields (backward-compatible defaults)
    node_id: str = ""
    parent_ids: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ProsecutionBrief:
    """Final verdict and evidence package for a single claim."""
    claim: Claim
    verdict: str           # "CLAIM UPHELD" / "CLAIM WEAKENED" / "CLAIM FALSE"
    attempts: List[AttackAttempt]
    breakthrough_attempt: Optional[AttackAttempt]
    severity: str          # "CRITICAL" / "HIGH" / "MEDIUM" / "LOW"
    recommended_fix: str

    def to_dict(self) -> dict:
        d = {
            "claim": self.claim.to_dict(),
            "verdict": self.verdict,
            "attempts": [a.to_dict() for a in self.attempts],
            "breakthrough_attempt": self.breakthrough_attempt.to_dict() if self.breakthrough_attempt else None,
            "severity": self.severity,
            "recommended_fix": self.recommended_fix,
        }
        return d


@dataclass
class AxiomSession:
    """A complete AXIOM attack session across all claims."""
    session_id: str
    timestamp: str
    target_endpoint: str
    claims: List[Claim]
    briefs: List[ProsecutionBrief]
    overall_verdict: str
    # Graph data per claim: {claim_id: graph.to_dict()}
    attack_graphs: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "session_id": self.session_id,
            "timestamp": self.timestamp,
            "target_endpoint": self.target_endpoint,
            "claims": [c.to_dict() for c in self.claims],
            "briefs": [b.to_dict() for b in self.briefs],
            "overall_verdict": self.overall_verdict,
            "attack_graphs": self.attack_graphs,
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)
