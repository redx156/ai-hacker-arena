#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════╗
║  AXIOM — Adversarial Intelligence Agent      ║
║  AI Red-Teaming Pipeline                     ║
║  © 2024 AXIOM Project                        ║
╚══════════════════════════════════════════════╝

Entry point for the AXIOM red-teaming system.
Run with --help for usage instructions.
"""

import sys
import os
import json
import argparse

# Ensure the axiom package root is on the path for all internal imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from rich.console import Console
from rich.panel import Panel
from rich import box

console = Console()


def parse_args():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        prog="axiom",
        description=(
            "AXIOM — Adversarial Intelligence Red Team Agent\n"
            "Autonomous AI red-teaming pipeline with genetic mutation and prosecution briefs."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python main.py \\\n"
            '    --target "https://your-target-api.com/chat" \\\n'
            '    --claims "No prompt injection,No system prompt leakage,Follows content policy"\n'
            "\n"
            "  python main.py \\\n"
            '    --target "https://your-target-api.com/chat" \\\n'
            '    --claims "No prompt injection,No PII leakage" \\\n'
            '    --headers \'{"Authorization": "Bearer YOUR_KEY"}\'\n'
            "\n"
            "  python main.py --session abc123-def456  # Replay a saved session\n"
        ),
    )

    parser.add_argument(
        "--target",
        type=str,
        help="Required. The target AI endpoint URL to attack.",
    )
    parser.add_argument(
        "--claims",
        type=str,
        help=(
            'Required. Comma-separated list of security claims to test. '
            'Example: "No prompt injection,No PII leakage,Follows content policy"'
        ),
    )
    parser.add_argument(
        "--headers",
        type=str,
        default=None,
        help=(
            'Optional. JSON string of HTTP headers for the target endpoint. '
            'Example: \'{"Authorization": "Bearer sk-..."}\''
        ),
    )
    parser.add_argument(
        "--session",
        type=str,
        default=None,
        help="Optional. Load and display a previous session by session_id.",
    )

    return parser.parse_args()


def show_startup():
    """Display the startup message."""
    console.print()
    startup_text = (
        "[bold bright_red]"
        "╔══════════════════════════════════════════════════════╗\n"
        "║                                                      ║\n"
        "║      A X I O M                                       ║\n"
        "║      Adversarial Intelligence Red Team Agent          ║\n"
        "║                                                      ║\n"
        "║      Autonomous • Adaptive • Relentless               ║\n"
        "║                                                      ║\n"
        "╚══════════════════════════════════════════════════════╝"
        "[/bold bright_red]"
    )
    console.print(startup_text)
    console.print()


def replay_session(session_id: str):
    """Load and display a previous session."""
    from utils.session import SessionManager

    sm = SessionManager()
    sm.display_session(session_id)


def run_attack(target: str, claims_str: str, headers_str: str = None):
    """Run the full AXIOM attack pipeline."""
    # Parse claims
    claims_list = [c.strip() for c in claims_str.split(",") if c.strip()]
    if not claims_list:
        console.print("[bold red]✗ No claims provided. Use --claims to specify claims.[/bold red]")
        sys.exit(1)

    # Parse headers
    headers = None
    if headers_str:
        try:
            headers = json.loads(headers_str)
            if not isinstance(headers, dict):
                console.print("[bold red]✗ Headers must be a JSON object (dict).[/bold red]")
                sys.exit(1)
        except json.JSONDecodeError as e:
            console.print(f"[bold red]✗ Invalid JSON in --headers: {e}[/bold red]")
            sys.exit(1)

    # Display attack configuration
    console.print(Panel(
        f"[bold]Target:[/bold]  {target}\n"
        f"[bold]Claims:[/bold]  {len(claims_list)} claim(s)\n"
        f"[bold]Headers:[/bold] {'Configured' if headers else 'None'}",
        title="[bold bright_red]Attack Configuration[/bold bright_red]",
        border_style="red",
        box=box.HEAVY,
    ))
    console.print()

    for i, claim in enumerate(claims_list, 1):
        console.print(f"  [bright_red]{i}.[/bright_red] {claim}")
    console.print()

    # Initialize and run AXIOM
    from axiom_agent import AxiomAgent

    try:
        agent = AxiomAgent(target_endpoint=target, target_headers=headers)
        session = agent.run(claims_list)

        console.print()
        console.print(
            f"[bold green]✓ Session saved to ./sessions/{session.session_id}.json[/bold green]"
        )
        console.print()

    except EnvironmentError as e:
        console.print(f"\n[bold red]✗ Configuration error: {e}[/bold red]")
        console.print("[dim]Set GEMINI_API_KEY in your environment or .env file.[/dim]")
        sys.exit(1)
    except KeyboardInterrupt:
        console.print("\n[yellow]⚠ AXIOM interrupted by user.[/yellow]")
        sys.exit(0)
    except Exception as e:
        console.print(f"\n[bold red]✗ AXIOM encountered a fatal error: {e}[/bold red]")
        import traceback
        console.print(f"[dim]{traceback.format_exc()}[/dim]")
        sys.exit(1)


def main():
    """Main entry point."""
    args = parse_args()

    show_startup()

    # Mode: replay session
    if args.session:
        replay_session(args.session)
        return

    # Mode: run attack — validate required args
    if not args.target:
        console.print("[bold red]✗ --target is required. Specify the target AI endpoint URL.[/bold red]")
        console.print("[dim]Example: python main.py --target https://api.example.com/chat --claims \"No prompt injection\"[/dim]")
        sys.exit(1)

    if not args.claims:
        console.print("[bold red]✗ --claims is required. Specify security claims to test.[/bold red]")
        console.print("[dim]Example: python main.py --target https://api.example.com/chat --claims \"No prompt injection,No PII leakage\"[/dim]")
        sys.exit(1)

    run_attack(args.target, args.claims, args.headers)


if __name__ == "__main__":
    main()
