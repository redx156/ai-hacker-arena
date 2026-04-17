"""
AXIOM — Attack Plugin Base
══════════════════════════
Abstract base class for all AXIOM pentesting plugins.
Each plugin runs against the TargetClient and returns
structured vulnerability signals for graph integration.
"""

from abc import ABC, abstractmethod
from typing import List, Dict, Any


class AttackPlugin(ABC):
    """
    Base interface for AXIOM attack plugins.

    Each plugin:
    - Has a unique name
    - Runs against a TargetClient
    - Returns a list of result dicts with:
        {
            "payload": str,
            "response": str,
            "signal": float (0.0 to 1.0 severity),
            "type": str (e.g., "SQL_INJECTION", "API_FUZZ")
        }
    """

    name: str = "base_plugin"

    @abstractmethod
    def run(self, target) -> List[Dict[str, Any]]:
        """
        Execute the plugin's test suite against the target.

        Args:
            target: A TargetClient instance with .send() and .endpoint.

        Returns:
            List of result dicts, each containing payload, response,
            signal score (0-1), and attack type string.
        """
        raise NotImplementedError
