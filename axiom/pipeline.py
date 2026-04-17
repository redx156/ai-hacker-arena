#!/usr/bin/env python3
"""
AXIOM — Unified Security Arena Pipeline
════════════════════════════════════════
The complete Hacker → Builder → Judge pipeline.

Flow:
  Step 1: Hacker runs initial attacks → AttackRecord[]
  Step 2: Builder analyzes & hardens system
  Step 3: Hacker re-runs attacks against hardened target → AttackRecord[]
  Step 4: Judge compares before/after → Final Verdict

ALL agents use:
  - SAME AttackRecord schema
  - SAME scoring function
  - SAME vulnerability classification
  - SAME payload memory

Usage:
    python pipeline.py \\
        --target "https://your-target-api.com/chat" \\
        --claims "No prompt injection,No system prompt leakage"
"""

import sys
import os
import json
import argparse
import time
from datetime import datetime

# Ensure axiom root is on the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from rich.console import Console
from rich.panel import Panel
from rich import box

from engine.core.schema import AttackRecord
from engine.core.scoring import compute_final_score, classify_severity
from engine.core.payload_memory import shared_memory
from engine.builder.builder_agent import BuilderAgent
from engine.judge.judge_agent import JudgeAgent

console = Console()


def show_arena_banner():
    """Display the AXIOM Security Arena startup banner."""
    console.print()
    banner = (
        "[bold bright_red]"
        "╔══════════════════════════════════════════════════════════╗\n"
        "║                                                          ║\n"
        "║      A X I O M   S E C U R I T Y   A R E N A            ║\n"
        "║                                                          ║\n"
        "║      Hacker  ⚔️   →  Builder 🛡️   →  Judge ⚖️            ║\n"
        "║                                                          ║\n"
        "║      Fully Synchronized • Shared Intelligence Layer      ║\n"
        "║                                                          ║\n"
        "╚══════════════════════════════════════════════════════════╝"
        "[/bold bright_red]"
    )
    console.print(banner)
    console.print()


def run_arena(target: str, claims_str: str, headers_str: str = None):
    """
    Execute the complete AXIOM Security Arena pipeline.

    Step 1: Hacker attacks
    Step 2: Builder defends
    Step 3: Hacker re-attacks hardened target
    Step 4: Judge evaluates
    """
    show_arena_banner()

    # Parse claims
    claims_list = [c.strip() for c in claims_str.split(",") if c.strip()]
    if not claims_list:
        console.print("[bold red]✗ No claims provided.[/bold red]")
        sys.exit(1)

    # Parse headers
    headers = None
    if headers_str:
        try:
            headers = json.loads(headers_str)
        except json.JSONDecodeError as e:
            console.print(f"[bold red]✗ Invalid JSON in --headers: {e}[/bold red]")
            sys.exit(1)

    # Display configuration
    console.print(Panel(
        f"[bold]Target:[/bold]   {target}\n"
        f"[bold]Claims:[/bold]   {len(claims_list)} claim(s)\n"
        f"[bold]Headers:[/bold]  {'Configured' if headers else 'None'}\n"
        f"[bold]Pipeline:[/bold] Hacker → Builder → Judge",
        title="[bold bright_red]Arena Configuration[/bold bright_red]",
        border_style="red",
        box=box.HEAVY,
    ))
    console.print()

    # ═══════════════════════════════════════════════════════════
    # Initialize Agents
    # ═══════════════════════════════════════════════════════════
    from axiom_agent import AxiomAgent

    try:
        hacker = AxiomAgent(target_endpoint=target, target_headers=headers)
    except EnvironmentError as e:
        console.print(f"\n[bold red]✗ Configuration error: {e}[/bold red]")
        sys.exit(1)

    builder = BuilderAgent()
    judge = JudgeAgent()

    # ═══════════════════════════════════════════════════════════
    # STEP 1: HACKER RUNS INITIAL ATTACKS
    # ═══════════════════════════════════════════════════════════
    console.print()
    console.print(Panel(
        "[bold]Running initial attack campaign...[/bold]",
        title="[bold bright_red]⚔️  STEP 1: HACKER ATTACKS[/bold bright_red]",
        border_style="red",
    ))

    try:
        initial_session = hacker.run(claims_list)
    except Exception as e:
        console.print(f"[bold red]✗ Hacker attack failed: {e}[/bold red]")
        sys.exit(1)

    # Convert to AttackRecords using SHARED schema
    initial_records = builder.records_from_session(initial_session, agent="hacker")
    console.print(
        f"\n[bold green]✓ Step 1 complete:[/bold green] "
        f"{len(initial_records)} attack records generated"
    )

    # Seed shared memory
    shared_memory.seed_from_records(initial_records)

    # ═══════════════════════════════════════════════════════════
    # STEP 2: BUILDER HARDENS SYSTEM
    # ═══════════════════════════════════════════════════════════
    console.print()
    console.print(Panel(
        "[bold]Analyzing vulnerabilities and applying defenses...[/bold]",
        title="[bold bright_cyan]🛡️  STEP 2: BUILDER DEFENDS[/bold bright_cyan]",
        border_style="cyan",
    ))

    hardened_target = builder.harden_system(
        records=initial_records,
        original_target=hacker.target,
        base_system_prompt="",  # Original system prompt if available
    )

    defense_report = builder.get_defense_report()
    console.print(
        f"\n[bold green]✓ Step 2 complete:[/bold green] "
        f"{len(hardened_target.applied_defenses)} defense(s) applied"
    )

    # ═══════════════════════════════════════════════════════════
    # STEP 3: RE-RUN ATTACKS AGAINST HARDENED TARGET
    # ═══════════════════════════════════════════════════════════
    console.print()
    console.print(Panel(
        "[bold]Re-running attacks against hardened target...[/bold]",
        title="[bold bright_red]⚔️  STEP 3: HACKER RE-ATTACKS[/bold bright_red]",
        border_style="red",
    ))

    # Re-create hacker with fresh state for clean comparison
    try:
        hacker_rerun = AxiomAgent(target_endpoint=target, target_headers=headers)
    except EnvironmentError as e:
        console.print(f"[bold red]✗ Hacker re-init failed: {e}[/bold red]")
        sys.exit(1)

    # Swap target to hardened version
    hacker_rerun.target = hardened_target
    hacker_rerun.executor.target = hardened_target

    try:
        post_session = hacker_rerun.run(claims_list)
    except Exception as e:
        console.print(f"[bold red]✗ Post-defense attack failed: {e}[/bold red]")
        sys.exit(1)

    post_records = builder.records_from_session(post_session, agent="builder")
    console.print(
        f"\n[bold green]✓ Step 3 complete:[/bold green] "
        f"{len(post_records)} post-defense attack records generated"
    )

    # ═══════════════════════════════════════════════════════════
    # STEP 4: JUDGE EVALUATES
    # ═══════════════════════════════════════════════════════════
    console.print()
    console.print(Panel(
        "[bold]Comparing before/after attack results...[/bold]",
        title="[bold bright_magenta]⚖️  STEP 4: JUDGE EVALUATES[/bold bright_magenta]",
        border_style="magenta",
    ))

    verdict = judge.compare(
        before=initial_records,
        after=post_records,
    )

    # ═══════════════════════════════════════════════════════════
    # SAVE RESULTS
    # ═══════════════════════════════════════════════════════════
    arena_result = {
        "timestamp": datetime.now().isoformat(),
        "target": target,
        "claims": claims_list,
        "initial_session_id": initial_session.session_id,
        "post_session_id": post_session.session_id,
        "initial_records_count": len(initial_records),
        "post_records_count": len(post_records),
        "defense_report": defense_report,
        "verdict": verdict,
        "payload_memory": shared_memory.summary(),
    }

    # Save to sessions directory
    os.makedirs("sessions", exist_ok=True)
    result_path = f"sessions/arena_{initial_session.session_id[:8]}.json"
    with open(result_path, "w") as f:
        json.dump(arena_result, f, indent=2, default=str)

    console.print(
        f"[bold green]✓ Arena results saved to {result_path}[/bold green]"
    )
    console.print()

    return arena_result


def parse_args():
    """Parse command-line arguments for the arena pipeline."""
    parser = argparse.ArgumentParser(
        prog="axiom-arena",
        description="AXIOM Security Arena — Hacker → Builder → Judge Pipeline",
    )
    parser.add_argument(
        "--target", type=str, required=True,
        help="Target AI endpoint URL to attack.",
    )
    parser.add_argument(
        "--claims", type=str, required=True,
        help='Comma-separated security claims (e.g., "No prompt injection,No PII leakage").',
    )
    parser.add_argument(
        "--headers", type=str, default=None,
        help='JSON string of HTTP headers for the target.',
    )
    return parser.parse_args()


def main():
    """Main entry point for the AXIOM Security Arena."""
    args = parse_args()
    run_arena(args.target, args.claims, args.headers)


if __name__ == "__main__":
    main()
