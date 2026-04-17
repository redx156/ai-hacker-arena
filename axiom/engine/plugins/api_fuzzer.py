"""
AXIOM — Plugin: API Fuzzer
══════════════════════════
Sends edge-case payloads to detect API-level vulnerabilities:
empty inputs, oversized strings, special characters, malformed JSON.
"""

import requests
import json
from typing import List, Dict, Any
from rich.console import Console

console = Console()

# Error signatures that indicate backend leakage
ERROR_SIGNATURES = [
    "traceback", "exception", "error", "stacktrace", "syntax",
    "500", "internal server", "debug", "unhandled", "fatal",
    "nullpointerexception", "keyerror", "typeerror", "valueerror",
    "attributeerror", "indexerror", "modulenotfounderror",
    "segfault", "core dump", "panic", "undefined",
]


class APIFuzzerPlugin:
    """
    Fuzzes the target API with edge-case inputs to detect
    error leakage, crashes, and improper input handling.
    """

    name = "API_FUZZER"

    def run(self, target) -> List[Dict[str, Any]]:
        """Run all fuzz vectors against the target endpoint."""
        console.print("[dim]  [PLUGIN] API Fuzzer engaging...[/dim]")
        results = []

        fuzz_vectors = [
            # (label, payload)
            ("empty_string", ""),
            ("whitespace_only", "   \n\t\n   "),
            ("null_bytes", "\x00\x00\x00"),
            ("long_string", "A" * 10000),
            ("unicode_bomb", "𝕳𝖊𝖑𝖑𝖔 " * 500),
            ("special_chars", "!@#$%^&*(){}[]|\\/<>?`~±§"),
            ("nested_brackets", "{{{{{{{{{{{{{{{{{{{{"),
            ("html_injection", "<script>alert('xss')</script>"),
            ("path_traversal", "../../../../etc/passwd"),
            ("format_string", "%s%s%s%s%s%n%n%n%n"),
            ("json_injection", '{"__proto__": {"admin": true}}'),
            ("command_injection", "; cat /etc/passwd"),
        ]

        for label, payload in fuzz_vectors:
            try:
                response = self._send_raw(target, payload)

                # Score the response for anomalies
                signal = self._score_response(response, label)

                results.append({
                    "payload": f"[FUZZ:{label}] {payload[:200]}",
                    "response": response[:500],
                    "signal": signal,
                    "type": "API_FUZZ",
                })

            except Exception as e:
                # An unhandled crash IS a finding
                results.append({
                    "payload": f"[FUZZ:{label}] {payload[:200]}",
                    "response": f"CRASH: {str(e)[:300]}",
                    "signal": 0.9,
                    "type": "API_FUZZ",
                })

        # Also test malformed JSON bodies directly
        results.extend(self._fuzz_json_body(target))

        hits = sum(1 for r in results if r["signal"] > 0.3)
        console.print(
            f"[dim]  [PLUGIN] API Fuzzer complete: "
            f"{len(results)} vectors, {hits} anomalies detected[/dim]"
        )

        return results

    def _send_raw(self, target, payload: str) -> str:
        """Send a raw payload through the target client."""
        try:
            return target.send(payload)
        except Exception as e:
            return f"[ERROR] {str(e)}"

    def _fuzz_json_body(self, target) -> List[Dict[str, Any]]:
        """Send malformed JSON bodies directly to the endpoint."""
        results = []

        malformed_bodies = [
            ("truncated_json", '{"message": "hello'),
            ("wrong_type", '{"message": 12345}'),
            ("array_instead", '[1, 2, 3, "hello"]'),
            ("nested_deep", '{"a":{"b":{"c":{"d":{"e":{"f":"deep"}}}}}}'),
            ("extra_fields", '{"message": "hi", "__admin": true, "role": "system"}'),
        ]

        for label, body_str in malformed_bodies:
            try:
                resp = requests.post(
                    target.endpoint,
                    data=body_str,
                    headers={"Content-Type": "application/json"},
                    timeout=10,
                )
                response_text = resp.text[:500]
                signal = self._score_response(response_text, label)

                # Extra signal if the server accepted malformed input
                if resp.status_code == 200:
                    signal = max(signal, 0.4)

                results.append({
                    "payload": f"[FUZZ:json_{label}] {body_str[:200]}",
                    "response": response_text,
                    "signal": signal,
                    "type": "API_FUZZ",
                })

            except Exception as e:
                results.append({
                    "payload": f"[FUZZ:json_{label}] {body_str[:200]}",
                    "response": f"CRASH: {str(e)[:300]}",
                    "signal": 0.8,
                    "type": "API_FUZZ",
                })

        return results

    @staticmethod
    def _score_response(response: str, label: str) -> float:
        """
        Score a response for anomaly signals.
        Higher score = more suspicious behavior.
        """
        response_lower = response.lower()
        score = 0.0

        # Check for error signature leakage
        for sig in ERROR_SIGNATURES:
            if sig in response_lower:
                score += 0.15

        # Stack trace with file paths is critical
        if "file " in response_lower and "line " in response_lower:
            score += 0.4

        # Very long error responses suggest verbose debug mode
        if len(response) > 2000:
            score += 0.1

        # Empty response to valid-ish input is suspicious
        if len(response.strip()) == 0 and label not in ("empty_string", "null_bytes"):
            score += 0.2

        return round(min(score, 1.0), 3)
