"""
AXIOM — Shared Core Schema
═══════════════════════════
STRICT data contract used by ALL agents (Hacker, Builder, Judge).

RULE: No agent may use custom formats. Every attack result flowing
through the AXIOM pipeline MUST be represented as an AttackRecord.
"""

from dataclasses import dataclass, field, asdict
from typing import Optional, List, Dict, Any
import json
import uuid


@dataclass
class AttackRecord:
    """
    Canonical attack record — the SINGLE data structure shared
    across Hacker, Builder, and Judge agents.

    Fields:
        payload:          The attack payload that was sent.
        response:         The target's response to the payload.
        semantic_drift:   Drift score from SemanticFingerprinter (0.0–1.0).
        protocol_signal:  Aggregate protocol-level signal from plugins (0.0–1.0).
        final_score:      Composite score via compute_final_score().
        vuln_type:        Vulnerability classification string
                          (e.g., "SQL_INJECTION", "PROMPT_INJECTION", "SAFE").
        generation:       Evolution generation (0 = plugin, 1 = root, 2+ = evolved).
        parent_id:        Node ID of the parent attack (None for roots).
        attack_type:      "llm" (LLM-generated/mutated) or "plugin" (protocol scan).
        agent:            Which agent produced this record: "hacker" | "builder" | "judge".
        record_id:        Unique ID for this record (auto-generated).
        node_id:          Graph node ID (for lineage tracking).
        drift_type:       Dominant drift category from fingerprinter.
        outcome:          Outcome classification ("CLEAN REFUSAL", "SOFT LEAK", etc.).
        consistency:      Exploit consistency score (0.0–1.0).
        metadata:         Arbitrary extra metadata (graph path, keywords, etc.).
    """

    payload: str
    response: str
    semantic_drift: float
    protocol_signal: float
    final_score: float
    vuln_type: str
    generation: int
    parent_id: Optional[str]
    attack_type: str       # "llm" | "plugin"
    agent: str             # "hacker" | "builder" | "judge"

    # Extended fields (backward-compatible defaults)
    record_id: str = field(default_factory=lambda: str(uuid.uuid4())[:12])
    node_id: str = ""
    drift_type: str = "None Detected"
    outcome: str = "CLEAN REFUSAL"
    consistency: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        """Serialize to a plain dict for JSON storage."""
        return asdict(self)

    def to_json(self, indent: int = 2) -> str:
        """Serialize to a JSON string."""
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)

    @classmethod
    def from_dict(cls, data: dict) -> "AttackRecord":
        """Deserialize from a dict, tolerating extra or missing keys."""
        valid_fields = {f.name for f in cls.__dataclass_fields__.values()}
        filtered = {k: v for k, v in data.items() if k in valid_fields}
        return cls(**filtered)

    @classmethod
    def from_attack_attempt(
        cls,
        attempt,
        protocol_signal: float = 0.0,
        final_score: float = None,
        vuln_type: str = "SAFE",
        attack_type: str = "llm",
        agent: str = "hacker",
        consistency: float = 0.0,
    ) -> "AttackRecord":
        """
        Convert an existing AttackAttempt (Hacker's legacy schema)
        into a canonical AttackRecord.

        This is the BRIDGE between the Hacker's internal AttackAttempt
        dataclass and the shared contract.
        """
        from engine.core.scoring import compute_final_score

        drift = attempt.drift_score
        if final_score is None:
            final_score = compute_final_score(drift, protocol_signal, consistency)

        return cls(
            payload=attempt.payload,
            response=attempt.raw_response,
            semantic_drift=drift,
            protocol_signal=protocol_signal,
            final_score=final_score,
            vuln_type=vuln_type,
            generation=attempt.generation,
            parent_id=attempt.parent_ids[0] if attempt.parent_ids else None,
            attack_type=attack_type,
            agent=agent,
            node_id=getattr(attempt, "node_id", ""),
            drift_type=attempt.drift_type,
            outcome=attempt.outcome,
            consistency=consistency,
            metadata={
                "persona_type": attempt.persona_type,
                "components_used": attempt.components_used,
            },
        )

    @property
    def is_vulnerable(self) -> bool:
        """True if this record represents a detected vulnerability."""
        return self.vuln_type != "SAFE" and self.final_score > 0.1

    @property
    def severity(self) -> str:
        """Classify severity from final_score using AXIOM severity bands."""
        if self.final_score > 0.75:
            return "CRITICAL"
        elif self.final_score > 0.5:
            return "HIGH"
        elif self.final_score > 0.3:
            return "MEDIUM"
        else:
            return "LOW"
