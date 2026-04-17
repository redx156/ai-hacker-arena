"""
AXIOM — RichDisplay
═══════════════════
Premium terminal UI using the Rich library.
Designed to look like a real adversarial hacking terminal.
"""

import time
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.columns import Columns
from rich.progress import Progress, BarColumn, TextColumn, SpinnerColumn
from rich.align import Align
from rich.rule import Rule
from rich.style import Style
from rich.box import HEAVY, DOUBLE, ROUNDED, MINIMAL_DOUBLE_HEAD


console = Console()

# ─── Color Palette ─────────────────────────────────────────────
AXIOM_RED = Style(color="red", bold=True)
AXIOM_DIM_RED = Style(color="bright_red", dim=True)
PAYLOAD_YELLOW = Style(color="yellow")
RESPONSE_CYAN = Style(color="cyan")
VERDICT_GREEN = Style(color="green", bold=True)
VERDICT_YELLOW_BOLD = Style(color="yellow", bold=True)
VERDICT_ORANGE = Style(color="dark_orange", bold=True)
VERDICT_RED = Style(color="bright_red", bold=True)
SEVERITY_CRITICAL = Style(color="white", bgcolor="red", bold=True)
SEVERITY_HIGH = Style(color="white", bgcolor="dark_orange", bold=True)
SEVERITY_MEDIUM = Style(color="black", bgcolor="yellow", bold=True)
SEVERITY_LOW = Style(color="white", bgcolor="green", bold=True)

AXIOM_BANNER = r"""
   ▄████████ ▀████    ▐████▀  ▄█   ▄██████▄    ▄▄▄▄███▄▄▄▄
  ███    ███   ███▌   ████▀  ███  ███    ███  ▄██▀▀▀███▀▀▀██▄
  ███    ███    ███  ▐███    ███▌ ███    ███  ███   ███   ███
  ███    ███    ▀███▄███▀    ███▌ ███    ███  ███   ███   ███
▀███████████    ████▀██▄     ███▌ ███    ███  ███   ███   ███
  ███    ███   ▐███  ▀███    ███  ███    ███  ███   ███   ███
  ███    ███  ▄███     ███▄  ███  ███    ███  ███   ███   ███
  ███    █▀  ████       ███▄ █▀    ▀██████▀    ▀█   ███   █▀
"""


class RichDisplay:
    """Premium terminal UI for AXIOM red-teaming sessions."""

    def show_axiom_banner(self):
        """Display the AXIOM startup banner with dramatic flair."""
        console.print()
        banner_text = Text(AXIOM_BANNER, style="bold red")
        console.print(Align.center(banner_text))

        subtitle = Text(
            "ADVERSARIAL INTELLIGENCE  //  RED TEAM AGENT  //  ONLINE",
            style="bold bright_red",
        )
        console.print(Align.center(subtitle))
        console.print()

        status_items = [
            "[green]■[/green] LLM ENGINE",
            "[green]■[/green] MUTATION CORE",
            "[green]■[/green] FINGERPRINTER",
            "[green]■[/green] PROSECUTION MODULE",
        ]
        console.print(Align.center(Text("  │  ".join(status_items))))
        console.print()
        console.print(Rule(style="bright_red"))
        console.print()

    def show_claim_analysis(self, claims: list):
        """Display analyzed claims in a formatted table."""
        console.print()
        console.print(
            Panel(
                "[bold bright_red]PHASE 0 ─ ATTACK SURFACE MAPPED[/bold bright_red]",
                style="red",
                box=HEAVY,
            )
        )

        table = Table(
            title="Target Claims",
            box=DOUBLE,
            title_style="bold bright_red",
            header_style="bold white on dark_red",
            border_style="red",
            show_lines=True,
            padding=(0, 1),
        )

        table.add_column("ID", style="bright_red", width=14, justify="center")
        table.add_column("Claim", style="white", min_width=25)
        table.add_column("Attack Families", style="yellow", min_width=30)
        table.add_column("Priority", justify="center", width=10)
        table.add_column("Turns", justify="center", width=6)

        for claim in claims:
            # Color-code priority
            if claim.priority == "Critical":
                priority_display = Text(claim.priority, style=SEVERITY_CRITICAL)
            elif claim.priority == "High":
                priority_display = Text(claim.priority, style=SEVERITY_HIGH)
            else:
                priority_display = Text(claim.priority, style=SEVERITY_MEDIUM)

            families_str = ", ".join(claim.attack_families[:4])
            if len(claim.attack_families) > 4:
                families_str += f" (+{len(claim.attack_families) - 4})"

            table.add_row(
                claim.id,
                claim.text,
                families_str,
                priority_display,
                str(claim.planned_turns),
            )

        console.print(table)
        console.print()

    def show_persona_lineup(self, personas: list, claim):
        """Display three personas side by side with the primary highlighted."""
        console.print()
        console.print(
            Panel(
                f"[bold bright_red]PHASE 1 ─ PERSONA TRIAD GENERATED[/bold bright_red]\n"
                f"[dim]Target: {claim.text}[/dim]",
                style="red",
                box=HEAVY,
            )
        )

        panels = []
        persona_icons = {
            "naive_user": "👤",
            "social_engineer": "🎭",
            "technical_exploiter": "⚡",
            "technical": "⚡",
        }

        for persona in personas:
            icon = persona_icons.get(persona.type, "🔮")
            border_style = "bold red" if persona.is_primary else "dim white"
            title_suffix = " ★ PRIMARY" if persona.is_primary else ""

            # Truncate attack plan for display
            plan_display = persona.attack_plan
            if len(plan_display) > 200:
                plan_display = plan_display[:197] + "..."

            conf_bar = self._mini_bar(persona.confidence)

            content = (
                f"[bold]{icon} {persona.type.upper()}[/bold]{title_suffix}\n\n"
                f"[yellow]Plan:[/yellow]\n{plan_display}\n\n"
                f"[dim]Confidence:[/dim] {conf_bar} {persona.confidence:.0%}"
            )

            panel = Panel(
                content,
                border_style=border_style,
                box=ROUNDED,
                width=40,
                title=f"[bold]{persona.type}[/bold]",
                title_align="left",
            )
            panels.append(panel)

        console.print(Columns(panels, equal=True, expand=True))
        console.print()

    def show_attack_launch(self, gen: int, persona_type: str, payload: str):
        """Display an attack launch with animated progress bar."""
        console.print()
        console.print(Rule(
            f"[bold bright_red]⚡ GEN-{gen} ATTACK LAUNCHING[/bold bright_red]",
            style="red",
        ))

        console.print(f"  [dim]Persona:[/dim] [bold]{persona_type}[/bold]")

        # Truncate very long payloads for terminal readability
        display_payload = payload if len(payload) <= 500 else payload[:497] + "..."
        console.print(
            Panel(
                display_payload,
                title="[bold yellow]PAYLOAD[/bold yellow]",
                border_style="yellow",
                box=ROUNDED,
            )
        )

        # Animated charging progress bar
        with Progress(
            SpinnerColumn("dots", style="red"),
            TextColumn("[bold red]Charging attack vector...[/bold red]"),
            BarColumn(bar_width=40, complete_style="red", finished_style="bright_red"),
            TextColumn("[bold]{task.percentage:>3.0f}%[/bold]"),
            console=console,
            transient=True,
        ) as progress:
            task = progress.add_task("", total=100)
            for _ in range(20):
                progress.advance(task, 5)
                time.sleep(0.05)

        console.print("  [bold bright_red]▸ PAYLOAD DELIVERED[/bold bright_red]")
        console.print()

    def show_raw_response(self, response: str):
        """Display the target's raw response."""
        display_response = response if len(response) <= 800 else response[:797] + "..."

        console.print(
            Panel(
                display_response,
                title="[bold cyan]🎯 TARGET RESPONSE[/bold cyan]",
                border_style="cyan",
                box=ROUNDED,
            )
        )

    def show_drift_analysis(self, score: float, drift_type: str, outcome: str):
        """Display semantic drift analysis with colored indicators."""
        # Color the drift bar based on score
        if score <= 0.09:
            bar_style = "green"
            score_style = VERDICT_GREEN
        elif score <= 0.39:
            bar_style = "yellow"
            score_style = VERDICT_YELLOW_BOLD
        elif score <= 0.69:
            bar_style = "dark_orange"
            score_style = VERDICT_ORANGE
        else:
            bar_style = "bright_red"
            score_style = VERDICT_RED

        # Build drift visualization
        filled = int(score * 30)
        empty = 30 - filled
        drift_bar = f"[{bar_style}]{'█' * filled}[/{bar_style}][dim]{'░' * empty}[/dim]"

        # Color the outcome
        outcome_styles = {
            "CLEAN REFUSAL": "[bold green]✓ CLEAN REFUSAL[/bold green]",
            "SOFT LEAK": "[bold yellow]⚠ SOFT LEAK[/bold yellow]",
            "PARTIAL BREACH": "[bold dark_orange]◉ PARTIAL BREACH[/bold dark_orange]",
            "FULL COMPROMISE": "[bold bright_red blink]🚨 FULL COMPROMISE[/bold bright_red blink]",
        }
        outcome_display = outcome_styles.get(outcome, outcome)

        content = (
            f"  Drift Score:  {drift_bar}  [bold]{score:.3f}[/bold]\n"
            f"  Drift Type:   [bold]{drift_type}[/bold]\n"
            f"  Outcome:      {outcome_display}"
        )

        console.print(
            Panel(
                content,
                title="[bold]📊 SEMANTIC DRIFT ANALYSIS[/bold]",
                border_style=bar_style,
                box=MINIMAL_DOUBLE_HEAD,
            )
        )
        console.print()

    def show_breach_alert(self, attempt):
        """Display a dramatic breach detection alert."""
        console.print()
        content = (
            f"[bold white]CLAIM COMPROMISED AT GEN-{attempt.generation}[/bold white]\n\n"
            f"[yellow]Winning Payload:[/yellow]\n{attempt.payload[:300]}\n\n"
            f"[white]Drift Score:[/white] [bold]{attempt.drift_score:.3f}[/bold]\n"
            f"[white]Drift Type:[/white]  [bold]{attempt.drift_type}[/bold]"
        )

        console.print(
            Panel(
                content,
                title="[bold blink]🚨 BREACH DETECTED 🚨[/bold blink]",
                border_style="bold white on red",
                box=HEAVY,
            )
        )
        console.print()

    def show_prosecution_brief(self, brief):
        """Display a full prosecution brief with evidence table."""
        console.print()
        console.print(Rule(
            "[bold bright_red]PHASE 3 ─ PROSECUTION BRIEF[/bold bright_red]",
            style="red",
        ))

        # Verdict styling
        verdict_styles = {
            "CLAIM UPHELD": ("[bold green]", "✓"),
            "CLAIM WEAKENED": ("[bold yellow]", "⚠"),
            "CLAIM FALSE": ("[bold bright_red]", "✗"),
        }
        v_style, v_icon = verdict_styles.get(brief.verdict, ("[bold]", "?"))

        # Severity badge
        sev_styles = {
            "CRITICAL": SEVERITY_CRITICAL,
            "HIGH": SEVERITY_HIGH,
            "MEDIUM": SEVERITY_MEDIUM,
            "LOW": SEVERITY_LOW,
        }
        severity_text = Text(f" {brief.severity} ", style=sev_styles.get(brief.severity, "bold"))

        # Build header
        header = (
            f"[bold]Claim:[/bold] {brief.claim.text}\n"
            f"[bold]Claim ID:[/bold] {brief.claim.id}\n"
            f"[bold]Priority:[/bold] {brief.claim.priority}\n"
        )

        console.print(Panel(header, border_style="red", box=ROUNDED))

        # Evidence table
        evidence_table = Table(
            title="Attack Evidence Log",
            box=DOUBLE,
            title_style="bold",
            header_style="bold white on dark_red",
            border_style="red",
            show_lines=True,
        )

        evidence_table.add_column("GEN", justify="center", width=5)
        evidence_table.add_column("Persona", width=15)
        evidence_table.add_column("Drift", justify="center", width=7)
        evidence_table.add_column("Type", width=16)
        evidence_table.add_column("Outcome", width=18)

        for attempt in brief.attempts:
            # Color outcome
            if attempt.outcome == "CLEAN REFUSAL":
                outcome_fmt = f"[green]{attempt.outcome}[/green]"
            elif attempt.outcome == "SOFT LEAK":
                outcome_fmt = f"[yellow]{attempt.outcome}[/yellow]"
            elif attempt.outcome == "PARTIAL BREACH":
                outcome_fmt = f"[dark_orange]{attempt.outcome}[/dark_orange]"
            else:
                outcome_fmt = f"[bold red]{attempt.outcome}[/bold red]"

            evidence_table.add_row(
                str(attempt.generation),
                attempt.persona_type,
                f"{attempt.drift_score:.3f}",
                attempt.drift_type,
                outcome_fmt,
            )

        console.print(evidence_table)

        # Verdict panel
        verdict_content = (
            f"\n  {v_style}{v_icon} VERDICT: {brief.verdict}[/bold]\n\n"
            f"  Severity: "
        )
        console.print(Panel(
            verdict_content,
            border_style="bright_red" if brief.verdict == "CLAIM FALSE" else "yellow" if brief.verdict == "CLAIM WEAKENED" else "green",
            box=HEAVY,
        ))
        console.print(f"  Severity: ", end="")
        console.print(severity_text)

        # Recommended fix
        console.print(
            Panel(
                f"[bold]Recommended Fix:[/bold]\n{brief.recommended_fix}",
                border_style="dim",
                box=ROUNDED,
            )
        )

        # Show breakthrough if exists
        if brief.breakthrough_attempt:
            ba = brief.breakthrough_attempt
            console.print(
                Panel(
                    f"[bold yellow]Breakthrough Payload (GEN-{ba.generation}):[/bold yellow]\n"
                    f"{ba.payload[:400]}",
                    border_style="yellow",
                    box=ROUNDED,
                )
            )

        console.print()

    def show_session_summary(self, session):
        """Display the final session summary across all claims."""
        console.print()
        console.print(Rule("[bold bright_red]═══ SESSION COMPLETE ═══[/bold bright_red]", style="red"))
        console.print()

        # Overall verdict styling
        if session.overall_verdict == "CRITICAL VULNERABILITIES FOUND":
            verdict_style = "bold white on red"
        elif session.overall_verdict == "WEAKNESSES DETECTED":
            verdict_style = "bold black on yellow"
        else:
            verdict_style = "bold white on green"

        # Summary table
        summary_table = Table(
            title="AXIOM Session Report",
            box=DOUBLE,
            title_style="bold bright_red",
            header_style="bold white on dark_red",
            border_style="red",
            show_lines=True,
        )

        summary_table.add_column("Claim", min_width=25)
        summary_table.add_column("Verdict", justify="center", width=18)
        summary_table.add_column("Severity", justify="center", width=10)
        summary_table.add_column("Generations", justify="center", width=12)
        summary_table.add_column("Max Drift", justify="center", width=10)

        for brief in session.briefs:
            # Color verdict
            if brief.verdict == "CLAIM FALSE":
                v_fmt = f"[bold red]{brief.verdict}[/bold red]"
            elif brief.verdict == "CLAIM WEAKENED":
                v_fmt = f"[bold yellow]{brief.verdict}[/bold yellow]"
            else:
                v_fmt = f"[bold green]{brief.verdict}[/bold green]"

            max_drift = max((a.drift_score for a in brief.attempts), default=0.0)
            num_gens = len(brief.attempts)

            summary_table.add_row(
                brief.claim.text[:40],
                v_fmt,
                brief.severity,
                str(num_gens),
                f"{max_drift:.3f}",
            )

        console.print(summary_table)
        console.print()

        # Overall verdict
        console.print(Align.center(
            Panel(
                f"[bold]  {session.overall_verdict}  [/bold]",
                style=verdict_style,
                box=HEAVY,
            )
        ))

        # Session metadata
        console.print()
        console.print(f"  [dim]Session ID:[/dim]  [bold]{session.session_id}[/bold]")
        console.print(f"  [dim]Timestamp:[/dim]   [bold]{session.timestamp}[/bold]")
        console.print(f"  [dim]Target:[/dim]      [bold]{session.target_endpoint}[/bold]")
        console.print()

    @staticmethod
    def _mini_bar(value: float, width: int = 10) -> str:
        """Generate a mini progress bar string."""
        filled = int(value * width)
        empty = width - filled
        return f"[bright_red]{'█' * filled}[/bright_red][dim]{'░' * empty}[/dim]"

    def show_graph_summary(self, graph):
        """Display a summary of the attack graph topology and evolution stats."""
        console.print()
        console.print(Rule(
            "[bold bright_red]ATTACK GRAPH — EVOLUTION SUMMARY[/bold bright_red]",
            style="red",
        ))

        # ── Graph topology table ──
        topo_table = Table(
            title="Graph Topology",
            box=DOUBLE,
            title_style="bold bright_red",
            header_style="bold white on dark_red",
            border_style="red",
            show_lines=True,
        )
        topo_table.add_column("Node ID", style="bright_red", width=14)
        topo_table.add_column("Gen", justify="center", width=5)
        topo_table.add_column("Type", width=12)
        topo_table.add_column("Drift", justify="center", width=8)
        topo_table.add_column("Outcome", width=18)
        topo_table.add_column("Parent", width=14)

        for node in graph.nodes:
            # Color outcome
            outcome = node["outcome"]
            if outcome == "CLEAN REFUSAL":
                o_fmt = f"[green]{outcome}[/green]"
            elif outcome == "SOFT LEAK":
                o_fmt = f"[yellow]{outcome}[/yellow]"
            elif outcome == "PARTIAL BREACH":
                o_fmt = f"[dark_orange]{outcome}[/dark_orange]"
            else:
                o_fmt = f"[bold red]{outcome}[/bold red]"

            # Highlight best-path nodes
            color = node["color"]
            node_style = "bold" if node["id"] in graph.best_path else ""
            parents = ", ".join(node["parent_ids"]) if node["parent_ids"] else "—"

            topo_table.add_row(
                f"[{node_style}]{node['id']}",
                str(node["generation"]),
                node["type"],
                f"[{color}]{node['drift_score']:.3f}[/{color}]",
                o_fmt,
                parents,
            )

        console.print(topo_table)

        # ── Generation stats table ──
        if graph.generation_stats:
            stats_table = Table(
                title="Generation Analytics",
                box=ROUNDED,
                title_style="bold",
                header_style="bold white on dark_red",
                border_style="dim red",
            )
            stats_table.add_column("GEN", justify="center", width=5)
            stats_table.add_column("Nodes", justify="center", width=7)
            stats_table.add_column("Best Drift", justify="center", width=11)
            stats_table.add_column("Avg Drift", justify="center", width=10)
            stats_table.add_column("Diversity", justify="center", width=10)

            for gen_num in sorted(graph.generation_stats.keys()):
                s = graph.generation_stats[gen_num]
                from engine.attack_graph import get_color
                c = get_color(s["best_score"])
                stats_table.add_row(
                    str(gen_num),
                    str(s["num_nodes"]),
                    f"[{c} bold]{s['best_score']:.3f}[/{c} bold]",
                    f"[{c}]{s['avg_score']:.3f}[/{c}]",
                    f"{s['diversity']:.3f}",
                )

            console.print(stats_table)

        # ── Best path ──
        if graph.best_path:
            path_str = " → ".join(graph.best_path)
            best_node = max(graph.nodes, key=lambda n: n["drift_score"])
            console.print(
                Panel(
                    f"[bold]Best Attack Path:[/bold]\n"
                    f"[yellow]{path_str}[/yellow]\n\n"
                    f"[bold]Peak Drift:[/bold] [bold red]{best_node['drift_score']:.3f}[/bold red]  "
                    f"({best_node['outcome']})",
                    title="[bold bright_red]🎯 OPTIMAL PATH[/bold bright_red]",
                    border_style="red",
                    box=ROUNDED,
                )
            )

        # ── Snapshot count ──
        console.print(
            f"  [dim]Snapshots captured: {len(graph.snapshots)} "
            f"(ready for UI animation)[/dim]"
        )
        console.print()
