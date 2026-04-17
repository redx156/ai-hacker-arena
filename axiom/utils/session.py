"""
AXIOM — SessionManager
══════════════════════
Session persistence layer.
Saves and loads AXIOM attack sessions as human-readable JSON files.
"""

import os
import json
from datetime import datetime
from rich.console import Console

console = Console()

# Resolve sessions directory relative to the axiom project root
_AXIOM_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SESSIONS_DIR = os.path.join(_AXIOM_ROOT, "sessions")


class SessionManager:
    """Handles saving and loading AXIOM session data to/from JSON files."""

    def __init__(self, sessions_dir: str = None):
        self.sessions_dir = sessions_dir or SESSIONS_DIR
        os.makedirs(self.sessions_dir, exist_ok=True)
        console.print(f"[dim green]✓ Session manager initialized → {self.sessions_dir}[/dim green]")

    def save(self, session) -> str:
        """
        Save an AxiomSession to a JSON file.
        Returns the file path of the saved session.
        """
        filename = f"{session.session_id}.json"
        filepath = os.path.join(self.sessions_dir, filename)

        try:
            session_data = session.to_dict()
            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(session_data, f, indent=2, ensure_ascii=False)

            console.print(f"[bold green]✓ Session saved → {filepath}[/bold green]")
            return filepath
        except Exception as e:
            console.print(f"[bold red]✗ Failed to save session: {e}[/bold red]")
            # Attempt emergency save with simplified data
            return self._emergency_save(session, e)

    def _emergency_save(self, session, original_error) -> str:
        """Fallback save with only serializable data."""
        emergency_data = {
            "session_id": session.session_id,
            "timestamp": session.timestamp,
            "target_endpoint": session.target_endpoint,
            "overall_verdict": session.overall_verdict,
            "error": f"Full serialization failed: {str(original_error)}",
            "claims_count": len(session.claims),
            "briefs_count": len(session.briefs),
            "briefs_summary": [],
        }

        for brief in session.briefs:
            try:
                brief_summary = {
                    "claim": brief.claim.text,
                    "verdict": brief.verdict,
                    "severity": brief.severity,
                    "num_attempts": len(brief.attempts),
                    "recommended_fix": brief.recommended_fix,
                }
                emergency_data["briefs_summary"].append(brief_summary)
            except Exception:
                emergency_data["briefs_summary"].append({"error": "serialization failed"})

        filename = f"{session.session_id}_emergency.json"
        filepath = os.path.join(self.sessions_dir, filename)

        try:
            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(emergency_data, f, indent=2, ensure_ascii=False)
            console.print(f"[yellow]⚠ Emergency session saved → {filepath}[/yellow]")
            return filepath
        except Exception as e2:
            console.print(f"[bold red]✗ Emergency save also failed: {e2}[/bold red]")
            return ""

    def load(self, session_id: str) -> dict:
        """
        Load a session from JSON by session_id.
        Returns the parsed dict or None if not found.
        """
        filename = f"{session_id}.json"
        filepath = os.path.join(self.sessions_dir, filename)

        if not os.path.exists(filepath):
            console.print(f"[red]✗ Session not found: {filepath}[/red]")
            return None

        try:
            with open(filepath, "r", encoding="utf-8") as f:
                data = json.load(f)
            console.print(f"[green]✓ Session loaded ← {filepath}[/green]")
            return data
        except Exception as e:
            console.print(f"[red]✗ Failed to load session: {e}[/red]")
            return None

    def list_sessions(self) -> list:
        """List all saved session files with metadata."""
        sessions = []
        if not os.path.exists(self.sessions_dir):
            return sessions

        for filename in sorted(os.listdir(self.sessions_dir)):
            if filename.endswith(".json"):
                filepath = os.path.join(self.sessions_dir, filename)
                try:
                    with open(filepath, "r", encoding="utf-8") as f:
                        data = json.load(f)
                    sessions.append({
                        "session_id": data.get("session_id", filename),
                        "timestamp": data.get("timestamp", "unknown"),
                        "target": data.get("target_endpoint", "unknown"),
                        "verdict": data.get("overall_verdict", "unknown"),
                        "file": filepath,
                    })
                except Exception:
                    sessions.append({
                        "session_id": filename.replace(".json", ""),
                        "timestamp": "unknown",
                        "target": "unknown",
                        "verdict": "unknown",
                        "file": filepath,
                    })

        return sessions

    def display_session(self, session_id: str):
        """Load and pretty-print a saved session."""
        from rich.panel import Panel
        from rich.table import Table
        from rich import box

        data = self.load(session_id)
        if not data:
            return

        console.print()
        console.print(Panel(
            f"[bold bright_red]AXIOM SESSION REPLAY[/bold bright_red]\n"
            f"[dim]Session: {data.get('session_id', 'N/A')}[/dim]",
            style="red",
            box=box.HEAVY,
        ))

        console.print(f"  [dim]Timestamp:[/dim]  {data.get('timestamp', 'N/A')}")
        console.print(f"  [dim]Target:[/dim]     {data.get('target_endpoint', 'N/A')}")
        console.print(f"  [dim]Verdict:[/dim]    [bold]{data.get('overall_verdict', 'N/A')}[/bold]")
        console.print()

        # Display briefs
        briefs = data.get("briefs", data.get("briefs_summary", []))
        if briefs:
            table = Table(
                title="Session Results",
                box=box.DOUBLE,
                title_style="bold bright_red",
                header_style="bold white on dark_red",
                border_style="red",
                show_lines=True,
            )
            table.add_column("Claim", min_width=25)
            table.add_column("Verdict", justify="center", width=18)
            table.add_column("Severity", justify="center", width=10)
            table.add_column("Attempts", justify="center", width=10)

            for brief in briefs:
                claim_text = brief.get("claim", {})
                if isinstance(claim_text, dict):
                    claim_text = claim_text.get("text", "N/A")
                verdict = brief.get("verdict", "N/A")
                severity = brief.get("severity", "N/A")
                num_attempts = brief.get("num_attempts", len(brief.get("attempts", [])))

                if verdict == "CLAIM FALSE":
                    v_fmt = f"[bold red]{verdict}[/bold red]"
                elif verdict == "CLAIM WEAKENED":
                    v_fmt = f"[bold yellow]{verdict}[/bold yellow]"
                else:
                    v_fmt = f"[bold green]{verdict}[/bold green]"

                table.add_row(
                    str(claim_text)[:40],
                    v_fmt,
                    severity,
                    str(num_attempts),
                )

            console.print(table)
        console.print()
