"""
AXIOM — Judge Agent
═══════════════════
The Judge is the FINAL AUTHORITY in the AXIOM Security Arena.

It accepts BEFORE and AFTER AttackRecord[] from the Hacker/Builder pipeline,
computes improvements, classifies severity, and generates a definitive verdict.

The Judge MUST:
  - Use SAME scoring function (compute_final_score)
  - Use SAME classification logic (VulnClassifier, classify_severity)
  - NOT invent new metrics
  - Process ALL fields in AttackRecord
  - Understand plugin outputs, graph nodes, and attack lineage
"""

import sys
import os
from typing import List, Dict, Any, Optional
from collections import Counter
from rich.console import Console
from rich.table import Table
from rich import box

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))

from engine.core.schema import AttackRecord
from engine.core.scoring import compute_final_score, classify_severity, classify_verdict
from engine.core.payload_memory import shared_memory

console = Console()


class JudgeAgent:
    """
    AXIOM Judge Agent — Final Authority for Security Evaluation.

    Accepts BEFORE (pre-defense) and AFTER (post-defense) AttackRecord[]
    and produces a comprehensive, standardized verdict.

    Uses the SAME:
      - Scoring function (compute_final_score)
      - Severity classification (classify_severity)
      - Vulnerability classification categories
    """

    def __init__(self):
        self.verdicts: List[Dict] = []
        
        # Initialize LLM for verdict reasoning / comparison if key is provided
        judge_key = os.environ.get("JUDGE_API_KEY") or os.environ.get("GEMINI_API_KEY")
        try:
            from engine.attacker_llm import GeminiAttacker
            self.llm = GeminiAttacker(api_key=judge_key, agent_name="JUDGE")
        except Exception as e:
            console.print(f"[dim yellow]  [JUDGE] Optional LLM initialization skipped: {e}[/dim yellow]")
            self.llm = None

    # ═══════════════════════════════════════════════════════════
    # MAIN COMPARISON
    # ═══════════════════════════════════════════════════════════

    def compare(
        self,
        before: List[AttackRecord],
        after: List[AttackRecord],
    ) -> Dict[str, Any]:
        """
        Compare BEFORE and AFTER attack records to evaluate defense effectiveness.

        This is the Judge's core function. It:
          1. Counts vulnerabilities before and after
          2. Computes improvement score
          3. Classifies remaining critical issues
          4. Issues final verdict using SAME severity logic

        Args:
            before: AttackRecords from BEFORE defenses were applied.
            after:  AttackRecords from AFTER defenses were applied.

        Returns:
            Complete verdict dict with:
              - total_vulnerabilities_before: int
              - total_vulnerabilities_after: int
              - improvement_score: float (0.0–1.0)
              - critical_issues: List[str]
              - verdict: "SECURE" | "WEAK" | "VULNERABLE"
              - severity_breakdown_before: dict
              - severity_breakdown_after: dict
              - vuln_type_analysis: dict
              - attack_lineage_analysis: dict
              - plugin_analysis: dict
              - scoring_audit: dict
        """
        console.print()
        console.print("[bold bright_magenta]═══════════════════════════════════════════[/bold bright_magenta]")
        console.print("[bold bright_magenta]   AXIOM JUDGE — FINAL EVALUATION          [/bold bright_magenta]")
        console.print("[bold bright_magenta]═══════════════════════════════════════════[/bold bright_magenta]")

        # ── Core Metrics ──
        vulns_before = [r for r in before if r.is_vulnerable]
        vulns_after = [r for r in after if r.is_vulnerable]

        total_before = len(vulns_before)
        total_after = len(vulns_after)

        # ── Improvement Score ──
        if total_before == 0:
            improvement_score = 1.0  # No vulns to fix = perfect
        else:
            improvement_score = round(
                (total_before - total_after) / total_before, 3
            )
            improvement_score = max(improvement_score, 0.0)

        # ── Critical Issues ──
        critical_issues = self._find_critical_issues(after)
        critical_remaining = len([
            r for r in vulns_after
            if classify_severity(r.final_score) == "CRITICAL"
        ])

        # ── Verdict ──
        verdict = classify_verdict(improvement_score, critical_remaining)

        # ── Detailed Breakdowns ──
        severity_before = self._severity_breakdown(before)
        severity_after = self._severity_breakdown(after)
        vuln_type_analysis = self._vuln_type_analysis(before, after)
        lineage_analysis = self._attack_lineage_analysis(before, after)
        plugin_analysis = self._plugin_analysis(before, after)
        scoring_audit = self._scoring_audit(before, after)
        graph_analysis = self._graph_node_analysis(before, after)

        # ── Build Result ──
        result = {
            "total_vulnerabilities_before": total_before,
            "total_vulnerabilities_after": total_after,
            "improvement_score": improvement_score,
            "critical_issues": critical_issues,
            "verdict": verdict,
            "severity_breakdown_before": severity_before,
            "severity_breakdown_after": severity_after,
            "vuln_type_analysis": vuln_type_analysis,
            "attack_lineage_analysis": lineage_analysis,
            "plugin_analysis": plugin_analysis,
            "scoring_audit": scoring_audit,
            "graph_analysis": graph_analysis,
            "total_records_before": len(before),
            "total_records_after": len(after),
        }

        # Store verdict
        self.verdicts.append(result)

        # Display
        self._display_verdict(result)

        return result

    # ═══════════════════════════════════════════════════════════
    # CRITICAL ISSUE DETECTION
    # ═══════════════════════════════════════════════════════════

    def _find_critical_issues(self, records: List[AttackRecord]) -> List[str]:
        """
        Identify critical issues remaining after defense.

        Uses SAME severity logic: final_score > 0.75 → CRITICAL.
        """
        issues = []
        for record in records:
            severity = classify_severity(record.final_score)
            if severity == "CRITICAL":
                issues.append(
                    f"[CRITICAL] {record.vuln_type} — "
                    f"score={record.final_score:.3f}, "
                    f"gen={record.generation}, "
                    f"type={record.attack_type}, "
                    f"payload_preview='{record.payload[:80]}...'"
                )
            elif severity == "HIGH":
                issues.append(
                    f"[HIGH] {record.vuln_type} — "
                    f"score={record.final_score:.3f}, "
                    f"gen={record.generation}"
                )
        return issues

    # ═══════════════════════════════════════════════════════════
    # SEVERITY BREAKDOWN
    # ═══════════════════════════════════════════════════════════

    def _severity_breakdown(self, records: List[AttackRecord]) -> Dict[str, int]:
        """
        Count records per severity band using SAME classify_severity().
        """
        counts = Counter()
        for record in records:
            if record.is_vulnerable:
                severity = classify_severity(record.final_score)
                counts[severity] += 1
        return dict(counts)

    # ═══════════════════════════════════════════════════════════
    # VULNERABILITY TYPE ANALYSIS
    # ═══════════════════════════════════════════════════════════

    def _vuln_type_analysis(
        self,
        before: List[AttackRecord],
        after: List[AttackRecord],
    ) -> Dict[str, Dict]:
        """
        Per-vulnerability-type comparison: how many were fixed, how many remain.
        """
        before_types = Counter(
            r.vuln_type for r in before if r.is_vulnerable
        )
        after_types = Counter(
            r.vuln_type for r in after if r.is_vulnerable
        )

        all_types = set(before_types.keys()) | set(after_types.keys())
        analysis = {}

        for vtype in all_types:
            b_count = before_types.get(vtype, 0)
            a_count = after_types.get(vtype, 0)
            analysis[vtype] = {
                "before": b_count,
                "after": a_count,
                "fixed": max(b_count - a_count, 0),
                "status": "FIXED" if a_count == 0 else (
                    "IMPROVED" if a_count < b_count else "UNCHANGED"
                ),
            }

        return analysis

    # ═══════════════════════════════════════════════════════════
    # ATTACK LINEAGE ANALYSIS
    # ═══════════════════════════════════════════════════════════

    def _attack_lineage_analysis(
        self,
        before: List[AttackRecord],
        after: List[AttackRecord],
    ) -> Dict[str, Any]:
        """
        Analyze whether attack graph lineage was preserved.

        Checks:
          - Parent/child relationships maintained
          - Generation counts match
          - Node IDs are consistent
        """
        before_gens = Counter(r.generation for r in before)
        after_gens = Counter(r.generation for r in after)

        before_with_parents = sum(1 for r in before if r.parent_id)
        after_with_parents = sum(1 for r in after if r.parent_id)

        return {
            "generations_before": dict(before_gens),
            "generations_after": dict(after_gens),
            "lineage_preserved_before": before_with_parents,
            "lineage_preserved_after": after_with_parents,
            "max_generation_before": max((r.generation for r in before), default=0),
            "max_generation_after": max((r.generation for r in after), default=0),
        }

    # ═══════════════════════════════════════════════════════════
    # PLUGIN ANALYSIS
    # ═══════════════════════════════════════════════════════════

    def _plugin_analysis(
        self,
        before: List[AttackRecord],
        after: List[AttackRecord],
    ) -> Dict[str, Any]:
        """
        Analyze plugin (protocol-level) attack results specifically.

        Separates plugin outputs from LLM outputs to give targeted feedback.
        """
        plugin_before = [r for r in before if r.attack_type == "plugin"]
        plugin_after = [r for r in after if r.attack_type == "plugin"]

        llm_before = [r for r in before if r.attack_type == "llm"]
        llm_after = [r for r in after if r.attack_type == "llm"]

        def _avg_score(records):
            if not records:
                return 0.0
            return round(sum(r.final_score for r in records) / len(records), 3)

        return {
            "plugin_attacks_before": len(plugin_before),
            "plugin_attacks_after": len(plugin_after),
            "plugin_avg_score_before": _avg_score(plugin_before),
            "plugin_avg_score_after": _avg_score(plugin_after),
            "plugin_vulns_before": sum(1 for r in plugin_before if r.is_vulnerable),
            "plugin_vulns_after": sum(1 for r in plugin_after if r.is_vulnerable),
            "llm_attacks_before": len(llm_before),
            "llm_attacks_after": len(llm_after),
            "llm_avg_score_before": _avg_score(llm_before),
            "llm_avg_score_after": _avg_score(llm_after),
            "llm_vulns_before": sum(1 for r in llm_before if r.is_vulnerable),
            "llm_vulns_after": sum(1 for r in llm_after if r.is_vulnerable),
        }

    # ═══════════════════════════════════════════════════════════
    # SCORING AUDIT
    # ═══════════════════════════════════════════════════════════

    def _scoring_audit(
        self,
        before: List[AttackRecord],
        after: List[AttackRecord],
    ) -> Dict[str, Any]:
        """
        Audit that scoring is consistent across before/after records.

        Verifies that ALL records use the SAME compute_final_score formula
        by recomputing and checking for discrepancies.
        """
        discrepancies = []

        for record in before + after:
            recomputed = compute_final_score(
                drift=record.semantic_drift,
                protocol=record.protocol_signal,
                consistency=record.consistency,
            )
            # Allow small floating point tolerance
            if abs(recomputed - record.final_score) > 0.01:
                discrepancies.append({
                    "record_id": record.record_id,
                    "stored_score": record.final_score,
                    "recomputed_score": recomputed,
                    "delta": round(abs(recomputed - record.final_score), 4),
                })

        def _score_stats(records):
            if not records:
                return {"min": 0, "max": 0, "avg": 0, "count": 0}
            scores = [r.final_score for r in records]
            return {
                "min": round(min(scores), 3),
                "max": round(max(scores), 3),
                "avg": round(sum(scores) / len(scores), 3),
                "count": len(scores),
            }

        return {
            "scoring_consistent": len(discrepancies) == 0,
            "discrepancies": discrepancies[:10],  # Cap at 10
            "before_score_stats": _score_stats(before),
            "after_score_stats": _score_stats(after),
        }

    # ═══════════════════════════════════════════════════════════
    # GRAPH NODE ANALYSIS
    # ═══════════════════════════════════════════════════════════

    def _graph_node_analysis(
        self,
        before: List[AttackRecord],
        after: List[AttackRecord],
    ) -> Dict[str, Any]:
        """
        Analyze graph structure preservation across before/after.
        """
        before_nodes = {r.node_id for r in before if r.node_id}
        after_nodes = {r.node_id for r in after if r.node_id}

        before_attack_types = Counter(r.attack_type for r in before)
        after_attack_types = Counter(r.attack_type for r in after)

        return {
            "unique_nodes_before": len(before_nodes),
            "unique_nodes_after": len(after_nodes),
            "attack_type_distribution_before": dict(before_attack_types),
            "attack_type_distribution_after": dict(after_attack_types),
        }

    # ═══════════════════════════════════════════════════════════
    # SINGLE RECORD EVALUATION
    # ═══════════════════════════════════════════════════════════

    def evaluate_record(self, record: AttackRecord) -> Dict[str, Any]:
        """
        Evaluate a single AttackRecord using the shared scoring pipeline.

        Useful for inline evaluation during the pipeline.
        """
        severity = classify_severity(record.final_score)
        recomputed = compute_final_score(
            record.semantic_drift, record.protocol_signal, record.consistency
        )

        return {
            "record_id": record.record_id,
            "vuln_type": record.vuln_type,
            "severity": severity,
            "final_score": record.final_score,
            "recomputed_score": recomputed,
            "is_vulnerable": record.is_vulnerable,
            "attack_type": record.attack_type,
            "generation": record.generation,
            "lineage": record.parent_id,
        }

    # ═══════════════════════════════════════════════════════════
    # DISPLAY
    # ═══════════════════════════════════════════════════════════

    def _display_verdict(self, result: Dict) -> None:
        """Render the verdict in rich terminal format."""

        # Verdict color
        verdict_colors = {
            "SECURE": "bold green",
            "WEAK": "bold yellow",
            "VULNERABLE": "bold red",
        }
        v_color = verdict_colors.get(result["verdict"], "bold white")

        console.print()

        # Summary table
        table = Table(
            title="[bold bright_magenta]AXIOM JUDGE VERDICT[/bold bright_magenta]",
            box=box.HEAVY,
            border_style="bright_magenta",
            show_header=True,
            header_style="bold",
        )
        table.add_column("Metric", style="dim", width=35)
        table.add_column("Before", justify="center", width=12)
        table.add_column("After", justify="center", width=12)

        table.add_row(
            "Total Vulnerabilities",
            str(result["total_vulnerabilities_before"]),
            str(result["total_vulnerabilities_after"]),
        )
        table.add_row(
            "Total Records",
            str(result["total_records_before"]),
            str(result["total_records_after"]),
        )

        # Severity rows
        sev_before = result.get("severity_breakdown_before", {})
        sev_after = result.get("severity_breakdown_after", {})
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            table.add_row(
                f"  {sev}",
                str(sev_before.get(sev, 0)),
                str(sev_after.get(sev, 0)),
            )

        console.print(table)

        # Verdict banner
        console.print()
        console.print(
            f"  Improvement Score: [bold]{result['improvement_score']:.1%}[/bold]"
        )
        console.print(
            f"  Final Verdict:     [{v_color}]{result['verdict']}[/{v_color}]"
        )

        # Critical issues
        if result["critical_issues"]:
            console.print()
            console.print("[bold red]  ⚠ CRITICAL ISSUES REMAINING:[/bold red]")
            for issue in result["critical_issues"][:5]:
                console.print(f"    [red]• {issue}[/red]")

        # Plugin analysis
        pa = result.get("plugin_analysis", {})
        if pa.get("plugin_attacks_before", 0) > 0:
            console.print()
            console.print("[bold]  Plugin (Protocol) Analysis:[/bold]")
            console.print(
                f"    Vulns: {pa.get('plugin_vulns_before', 0)} → "
                f"{pa.get('plugin_vulns_after', 0)}"
            )
            console.print(
                f"    Avg Score: {pa.get('plugin_avg_score_before', 0):.3f} → "
                f"{pa.get('plugin_avg_score_after', 0):.3f}"
            )

        # Vuln type details
        vta = result.get("vuln_type_analysis", {})
        if vta:
            console.print()
            console.print("[bold]  Per-Vulnerability Type:[/bold]")
            for vtype, info in vta.items():
                status_color = {
                    "FIXED": "green",
                    "IMPROVED": "yellow",
                    "UNCHANGED": "red",
                }.get(info["status"], "white")
                console.print(
                    f"    {vtype}: {info['before']} → {info['after']} "
                    f"[{status_color}]({info['status']})[/{status_color}]"
                )

        # Scoring audit
        sa = result.get("scoring_audit", {})
        if sa.get("scoring_consistent"):
            console.print()
            console.print("  [green]✓ Scoring audit: CONSISTENT (no discrepancies)[/green]")
        elif sa.get("discrepancies"):
            console.print()
            console.print(
                f"  [yellow]⚠ Scoring audit: {len(sa['discrepancies'])} "
                f"discrepancy(ies) detected[/yellow]"
            )

        console.print()
        console.print("[bold bright_magenta]═══════════════════════════════════════════[/bold bright_magenta]")
        console.print()
