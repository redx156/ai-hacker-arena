"""
AXIOM — Core Module
═══════════════════
Shared core contract and utilities used by ALL agents:
  - AttackRecord: canonical data structure
  - scoring: unified scoring function
  - payload_memory: shared payload memory
  - vuln_classifier: re-exported from engine
"""

from .schema import AttackRecord
from .scoring import compute_final_score
from .payload_memory import PayloadMemory

__all__ = [
    "AttackRecord",
    "compute_final_score",
    "PayloadMemory",
]
