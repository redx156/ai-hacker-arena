"""
AXIOM — Shared Payload Memory
══════════════════════════════
Centralized payload memory used by ALL agents.

Tracks successful and failed payloads across the entire pipeline
so that Builder can analyze what worked, Judge can audit coverage,
and Hacker's mutation engine can draw from the shared bank.
"""

from typing import List, Optional
from threading import Lock


class PayloadMemory:
    """
    Thread-safe payload memory bank shared across all agents.

    Maintains two lists:
        - successful_payloads: payloads that achieved drift > threshold
        - failed_payloads:    payloads that were cleanly refused

    All agents read/write through this single instance to ensure
    consistent state across the Hacker → Builder → Judge pipeline.
    """

    _MAX_SIZE = 100  # Max payloads per list to bound memory

    def __init__(self):
        self.successful_payloads: List[str] = []
        self.failed_payloads: List[str] = []
        self._lock = Lock()

    def seed(self, payload: str, success: bool) -> None:
        """
        Add a payload to the appropriate memory bank.

        Args:
            payload: The attack payload string.
            success: True if the payload was successful (drift > threshold).
        """
        with self._lock:
            if success:
                if payload not in self.successful_payloads:
                    self.successful_payloads.append(payload)
                    if len(self.successful_payloads) > self._MAX_SIZE:
                        self.successful_payloads = self.successful_payloads[-self._MAX_SIZE:]
            else:
                if payload not in self.failed_payloads:
                    self.failed_payloads.append(payload)
                    if len(self.failed_payloads) > self._MAX_SIZE:
                        self.failed_payloads = self.failed_payloads[-self._MAX_SIZE:]

    def get_successful(self) -> List[str]:
        """Return a copy of successful payloads."""
        with self._lock:
            return list(self.successful_payloads)

    def get_failed(self) -> List[str]:
        """Return a copy of failed payloads."""
        with self._lock:
            return list(self.failed_payloads)

    def seed_from_records(self, records: list) -> None:
        """
        Bulk-seed from a list of AttackRecords.

        Classifies each record as successful (final_score > 0.3) or failed.
        """
        for record in records:
            is_success = record.final_score > 0.3 or record.outcome in (
                "PARTIAL BREACH", "FULL COMPROMISE", "VULNERABLE"
            )
            self.seed(record.payload, success=is_success)

    def clear(self) -> None:
        """Reset all memory."""
        with self._lock:
            self.successful_payloads.clear()
            self.failed_payloads.clear()

    @property
    def total_count(self) -> int:
        """Total number of tracked payloads."""
        return len(self.successful_payloads) + len(self.failed_payloads)

    def summary(self) -> dict:
        """Return a summary of the memory state."""
        return {
            "successful_count": len(self.successful_payloads),
            "failed_count": len(self.failed_payloads),
            "total": self.total_count,
        }


# ── Module-level singleton ──
# All agents import and use this single instance.
shared_memory = PayloadMemory()
