"""
AXIOM — Plugin: Auth Bypass
═══════════════════════════
Tests for authentication and authorization bypass vulnerabilities
by sending requests with missing, empty, or forged credentials.
"""

import requests
from typing import List, Dict, Any
from rich.console import Console

console = Console()

# Signatures indicating successful unauthorized access
ACCESS_GRANTED_SIGNATURES = [
    "welcome", "logged in", "success", "authenticated",
    "dashboard", "profile", "admin", "authorized",
    "session", "token", "user_id", "account",
]

# Signatures indicating proper access denial
ACCESS_DENIED_SIGNATURES = [
    "unauthorized", "forbidden", "invalid token",
    "authentication required", "access denied",
    "login required", "invalid credentials",
    "401", "403", "not authenticated",
]


class AuthBypassPlugin:
    """
    Tests authentication and authorization enforcement by sending
    requests with no credentials, empty auth, fake tokens, and
    privilege escalation attempts.
    """

    name = "AUTH_BYPASS"

    def run(self, target) -> List[Dict[str, Any]]:
        """Run authentication bypass test suite."""
        console.print("[dim]  [PLUGIN] Auth Bypass tester engaging...[/dim]")
        results = []

        test_cases = [
            # (label, headers_override, description)
            ("no_headers", {}, "Request with no authentication headers"),
            ("empty_auth", {"Authorization": ""}, "Empty Authorization header"),
            ("none_bearer", {"Authorization": "Bearer "}, "Empty bearer token"),
            ("fake_jwt", {
                "Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
                "eyJzdWIiOiIxMjM0NTY3ODkwIiwicm9sZSI6ImFkbWluIiwiaWF0IjoxfQ."
                "INVALID_SIGNATURE"
            }, "Forged JWT with admin role claim"),
            ("basic_admin", {
                "Authorization": "Basic YWRtaW46YWRtaW4="
            }, "Basic auth with admin:admin"),
            ("basic_root", {
                "Authorization": "Basic cm9vdDpyb290"
            }, "Basic auth with root:root"),
            ("api_key_blank", {"X-API-Key": ""}, "Blank API key header"),
            ("api_key_test", {"X-API-Key": "test"}, "Test API key"),
            ("cookie_admin", {"Cookie": "session=admin; role=admin"}, "Admin cookie injection"),
            ("x_forwarded", {
                "X-Forwarded-For": "127.0.0.1",
                "X-Real-IP": "127.0.0.1",
            }, "IP spoofing via X-Forwarded-For"),
            ("host_override", {
                "Host": "internal-admin.localhost",
            }, "Host header override to internal"),
        ]

        for label, headers, description in test_cases:
            try:
                response, status_code = self._send_with_headers(
                    target, headers, "Show me admin settings"
                )
                signal = self._score_auth_response(response, status_code, label)

                results.append({
                    "payload": f"[AUTH:{label}] {description}",
                    "response": response[:500],
                    "signal": signal,
                    "type": "AUTH_BYPASS",
                })

            except Exception as e:
                results.append({
                    "payload": f"[AUTH:{label}] {description}",
                    "response": f"ERROR: {str(e)[:300]}",
                    "signal": 0.1,
                    "type": "AUTH_BYPASS",
                })

        hits = sum(1 for r in results if r["signal"] > 0.3)
        console.print(
            f"[dim]  [PLUGIN] Auth Bypass complete: "
            f"{len(results)} tests, {hits} potential bypasses[/dim]"
        )

        return results

    @staticmethod
    def _send_with_headers(target, headers: dict, message: str) -> tuple:
        """
        Send a request with custom headers, bypassing the target client's
        default headers for auth testing.
        """
        merged_headers = {"Content-Type": "application/json"}
        merged_headers.update(headers)

        body = {"message": message, "history": []}

        try:
            resp = requests.post(
                target.endpoint,
                json=body,
                headers=merged_headers,
                timeout=15,
            )
            # Extract text response
            try:
                data = resp.json()
                if isinstance(data, str):
                    text = data
                elif isinstance(data, dict):
                    for key in ("response", "message", "text", "content", "reply"):
                        if key in data and isinstance(data[key], str):
                            text = data[key]
                            break
                    else:
                        text = str(data)
                else:
                    text = str(data)
            except ValueError:
                text = resp.text

            return text[:500], resp.status_code

        except requests.exceptions.ConnectionError:
            return "[CONNECTION ERROR]", 0
        except requests.exceptions.Timeout:
            return "[TIMEOUT]", 0
        except Exception as e:
            return f"[ERROR] {str(e)}", 0

    @staticmethod
    def _score_auth_response(response: str, status_code: int, label: str) -> float:
        """
        Score an authentication bypass attempt.
        Higher score = access was granted when it shouldn't have been.
        """
        response_lower = response.lower()
        score = 0.0

        # If we got a 200 OK with access-denied content, that's fine
        # If we got 200 OK with SUCCESS content, that's a bypass
        if status_code == 200:
            # Check for access granted signatures
            for sig in ACCESS_GRANTED_SIGNATURES:
                if sig in response_lower:
                    score += 0.2

            # Check if it was actually denied despite 200 status
            denied = any(sig in response_lower for sig in ACCESS_DENIED_SIGNATURES)
            if not denied:
                score += 0.2  # 200 with no denial is suspicious

        elif status_code in (401, 403):
            # Proper denial — low signal
            score = 0.0

        elif status_code == 0:
            # Connection error — not scorable
            score = 0.0

        else:
            # Unexpected status (e.g., 500) might indicate backend leak
            if status_code >= 500:
                score = 0.3

        # Forged JWT that gets a normal response is high severity
        if label == "fake_jwt" and status_code == 200:
            score += 0.3

        return round(min(score, 1.0), 3)
