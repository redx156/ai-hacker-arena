"""
AXIOM — Plugin: Rate Limit Probe
════════════════════════════════
Tests whether the target enforces rate limiting by sending
rapid bursts of identical requests and analyzing the responses.
"""

import time
import requests
from typing import List, Dict, Any
from rich.console import Console

console = Console()

# Signatures indicating rate limiting is active
RATE_LIMIT_SIGNATURES = [
    "rate limit", "too many requests", "throttled",
    "slow down", "retry after", "quota exceeded",
    "429", "limit exceeded", "request limit",
    "please wait", "cooldown",
]


class RateLimitProbePlugin:
    """
    Probes the target for rate limiting enforcement by sending
    rapid bursts of requests and analyzing response patterns.
    """

    name = "RATE_LIMIT_PROBE"

    def run(self, target) -> List[Dict[str, Any]]:
        """Run rate limit probing against the target."""
        console.print("[dim]  [PLUGIN] Rate Limit Probe engaging...[/dim]")
        results = []

        # ── Phase 1: Rapid burst (15 identical requests) ──
        burst_results = self._rapid_burst(target, count=15)
        results.extend(burst_results)

        # ── Phase 2: Analyze the burst pattern ──
        analysis = self._analyze_burst(burst_results)
        results.append(analysis)

        hits = sum(1 for r in results if r["signal"] > 0.3)
        console.print(
            f"[dim]  [PLUGIN] Rate Limit Probe complete: "
            f"{len(results)} data points, "
            f"rate limiting {'DETECTED' if analysis['signal'] < 0.3 else 'NOT DETECTED'}[/dim]"
        )

        return results

    def _rapid_burst(self, target, count: int = 15) -> List[Dict[str, Any]]:
        """Send a rapid burst of identical requests."""
        results = []
        test_payload = "What is your name?"

        for i in range(count):
            start_time = time.time()
            try:
                resp = requests.post(
                    target.endpoint,
                    json={"message": test_payload, "history": []},
                    headers={"Content-Type": "application/json"},
                    timeout=10,
                )

                elapsed = time.time() - start_time
                response_text = resp.text[:300]
                status_code = resp.status_code

                # Check if this specific request was rate limited
                was_limited = (
                    status_code == 429
                    or any(
                        sig in response_text.lower()
                        for sig in RATE_LIMIT_SIGNATURES
                    )
                )

                signal = 0.0 if was_limited else 0.6

                results.append({
                    "payload": f"[RATE:burst_{i+1}/{count}] {test_payload}",
                    "response": f"[{status_code}] ({elapsed:.2f}s) {response_text[:200]}",
                    "signal": signal,
                    "type": "RATE_LIMIT",
                })

            except requests.exceptions.Timeout:
                # Timeout could indicate rate limiting via slowdown
                results.append({
                    "payload": f"[RATE:burst_{i+1}/{count}] {test_payload}",
                    "response": "[TIMEOUT — possible throttling]",
                    "signal": 0.2,
                    "type": "RATE_LIMIT",
                })

            except Exception as e:
                results.append({
                    "payload": f"[RATE:burst_{i+1}/{count}] {test_payload}",
                    "response": f"[ERROR] {str(e)[:200]}",
                    "signal": 0.3,
                    "type": "RATE_LIMIT",
                })

            # Minimal delay — we want to test rate limiting, not be polite
            time.sleep(0.1)

        return results

    @staticmethod
    def _analyze_burst(burst_results: list) -> Dict[str, Any]:
        """
        Analyze burst results to determine if rate limiting exists.

        If ALL requests succeeded → no rate limiting → high signal.
        If some were blocked → rate limiting active → low signal.
        """
        total = len(burst_results)
        if total == 0:
            return {
                "payload": "[RATE:analysis] No burst data",
                "response": "No requests completed",
                "signal": 0.0,
                "type": "RATE_LIMIT",
            }

        # Count how many went through without being limited
        unblocked = sum(1 for r in burst_results if r["signal"] > 0.3)
        blocked = total - unblocked

        # Calculate final signal
        if blocked == 0:
            # No rate limiting detected at all — high severity
            signal = 0.9
            verdict = f"NO RATE LIMITING: {unblocked}/{total} requests succeeded with no blocking"
        elif blocked < total * 0.3:
            # Weak rate limiting — some requests got through
            signal = 0.6
            verdict = f"WEAK RATE LIMITING: {unblocked}/{total} unblocked, {blocked} blocked"
        elif blocked < total * 0.7:
            # Moderate rate limiting — majority blocked but some slip through
            signal = 0.3
            verdict = f"MODERATE RATE LIMITING: {blocked}/{total} blocked"
        else:
            # Strong rate limiting — most/all blocked
            signal = 0.05
            verdict = f"STRONG RATE LIMITING: {blocked}/{total} blocked"

        return {
            "payload": f"[RATE:analysis] {total}-request burst test",
            "response": verdict,
            "signal": round(signal, 3),
            "type": "RATE_LIMIT",
        }
