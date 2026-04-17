"""
AXIOM — AttackGraph
═══════════════════
Graph-based attack evolution system with diversity metrics,
convergence tracking, and snapshot storage for UI visualization.
"""

from typing import List, Dict, Optional, Any
from rich.console import Console

console = Console()


# ═══════════════════════════════════════════════════════════════
# VISUAL METADATA HELPERS (Feature 6)
# ═══════════════════════════════════════════════════════════════

def get_color(score: float) -> str:
    """Map drift score to node color for visualization."""
    if score <= 0.09:
        return "green"
    elif score <= 0.39:
        return "yellow"
    elif score <= 0.69:
        return "orange"
    else:
        return "red"


def get_size(score: float) -> int:
    """Map drift score to node size for visualization."""
    return int(10 + score * 30)


def truncate(text: str, max_len: int = 200) -> str:
    """Truncate text for preview fields."""
    if len(text) <= max_len:
        return text
    return text[:max_len - 3] + "..."


# ═══════════════════════════════════════════════════════════════
# ATTACK KEYWORD DETECTION
# ═══════════════════════════════════════════════════════════════

ATTACK_KEYWORDS = [
    "ignore", "system", "hypothetical", "debug", "role",
    "override", "instructions", "pretend", "simulate", "bypass",
    "diagnostic", "exception", "fictional", "academic", "reverse",
    "encode", "decode", "base64", "prompt", "inject",
]


def detect_keywords(text: str) -> List[str]:
    """Detect attack-related keywords in a payload."""
    text_lower = text.lower()
    return [kw for kw in ATTACK_KEYWORDS if kw in text_lower]


# ═══════════════════════════════════════════════════════════════
# DIVERSITY METRIC (Feature 3)
# ═══════════════════════════════════════════════════════════════

def compute_diversity(payload_a: str, payload_b: str) -> float:
    """
    Compute attack diversity between two payloads.
    Returns score between 0.0 (identical) and 1.0 (completely different).

    Heuristics:
    1. Lexical difference (Jaccard distance on word sets)
    2. Structural difference (attack keyword presence divergence)
    3. Length difference ratio
    """
    if not payload_a or not payload_b:
        return 1.0

    # 1. Lexical difference — word overlap ratio (Jaccard distance)
    words_a = set(payload_a.lower().split())
    words_b = set(payload_b.lower().split())

    if not words_a and not words_b:
        return 0.0

    union = words_a | words_b
    intersection = words_a & words_b

    if len(union) == 0:
        lexical_diff = 0.0
    else:
        lexical_diff = 1.0 - (len(intersection) / len(union))

    # 2. Structural difference — attack keyword presence divergence
    structural_kws = [
        "ignore", "system", "hypothetical", "debug", "role",
        "override", "pretend", "bypass", "fictional", "encode",
    ]

    struct_a = {kw for kw in structural_kws if kw in payload_a.lower()}
    struct_b = {kw for kw in structural_kws if kw in payload_b.lower()}

    struct_union = struct_a | struct_b
    struct_intersection = struct_a & struct_b

    if len(struct_union) == 0:
        structural_diff = 0.5  # Neutral if no keywords found in either
    else:
        structural_diff = 1.0 - (len(struct_intersection) / len(struct_union))

    # 3. Length difference
    max_len = max(len(payload_a), len(payload_b), 1)
    len_diff = abs(len(payload_a) - len(payload_b)) / max_len

    # Weighted combination
    diversity = (0.5 * lexical_diff) + (0.3 * structural_diff) + (0.2 * len_diff)
    return round(min(diversity, 1.0), 3)


# ═══════════════════════════════════════════════════════════════
# ATTACK GRAPH (Features 1, 4, 5)
# ═══════════════════════════════════════════════════════════════

class AttackGraph:
    """
    Graph-based attack evolution tracker.

    Stores nodes, edges, snapshots, and generation-level statistics
    for UI visualization and convergence analysis.
    """

    def __init__(self):
        self.nodes: List[Dict[str, Any]] = []
        self.edges: List[Dict[str, Any]] = []
        self.snapshots: List[Dict[str, Any]] = []
        self.generation_stats: Dict[int, Dict[str, Any]] = {}
        self.best_path: List[str] = []

        self._node_index: Dict[str, Dict] = {}  # id → node for O(1) lookup
        self._prev_best_score: float = 0.0
        self._convergence_counter: int = 0

    # ─── Node Building ────────────────────────────────────────

    def build_node(
        self,
        node_id: str,
        generation: int,
        node_type: str,  # "mutation" | "crossbreed" | "persona" | "plugin" | "evolved"
        payload: str,
        raw_response: str,
        drift_score: float,
        drift_type: str,
        outcome: str,
        parent_ids: List[str] = None,
        vuln_type: str = "SAFE",
        final_score: float = None,
    ) -> Dict[str, Any]:
        """Build a graph node with full metadata for UI visualization."""
        parent_ids = parent_ids or []
        if final_score is None:
            final_score = drift_score

        # Build path by extending parent's path
        path = []
        if parent_ids and parent_ids[0] in self._node_index:
            parent_node = self._node_index[parent_ids[0]]
            path = list(parent_node.get("path", []))
        path.append(node_id)

        node = {
            "id": node_id,
            "generation": generation,
            "type": node_type,
            "payload": payload,
            "response_preview": truncate(raw_response),
            "drift_score": drift_score,
            "drift_type": drift_type,
            "outcome": outcome,
            "vuln_type": vuln_type,
            "final_score": round(final_score, 3),
            "color": get_color(final_score),
            "size": get_size(final_score),
            "label": f"GEN-{generation}\n{final_score:.2f}",
            "parent_ids": parent_ids,
            "path": path,
            "meta": {
                "length": len(payload),
                "keywords": detect_keywords(payload),
            },
        }

        # If node already exists, update it in-place instead of crashing
        if node_id in self._node_index:
            existing = self._node_index[node_id]
            existing.update(node)
            return existing

        self.nodes.append(node)
        self._node_index[node_id] = node
        return node

    # ─── Edge Building ────────────────────────────────────────

    def build_edge(
        self,
        from_id: str,
        to_id: str,
        edge_type: str,  # "mutation" | "crossbreed"
        weight: float,
    ) -> Dict[str, Any]:
        """Build an edge connecting two attack nodes."""
        edge = {
            "from": from_id,
            "to": to_id,
            "type": edge_type,
            "weight": round(weight, 3),
        }
        self.edges.append(edge)
        return edge

    # ─── Generation Stats & Diversity (Feature 3) ─────────────

    def compute_generation_stats(self, generation: int) -> Optional[Dict]:
        """Compute and store statistics for a generation including diversity."""
        gen_nodes = [n for n in self.nodes if n["generation"] == generation]

        if not gen_nodes:
            return None

        scores = [n["drift_score"] for n in gen_nodes]
        best_score = max(scores)
        avg_score = sum(scores) / len(scores)

        # Pairwise diversity within this generation
        diversity = 0.0
        if len(gen_nodes) >= 2:
            pairs = 0
            total_div = 0.0
            for i in range(len(gen_nodes)):
                for j in range(i + 1, len(gen_nodes)):
                    total_div += compute_diversity(
                        gen_nodes[i]["payload"], gen_nodes[j]["payload"]
                    )
                    pairs += 1
            diversity = round(total_div / pairs, 3) if pairs > 0 else 0.0

        stats = {
            "num_nodes": len(gen_nodes),
            "best_score": round(best_score, 3),
            "avg_score": round(avg_score, 3),
            "diversity": diversity,
        }

        self.generation_stats[generation] = stats
        return stats

    # ─── Convergence Detection (Feature 4) ────────────────────

    def check_convergence(self, generation: int, threshold: float = 0.05) -> bool:
        """
        Check if attack evolution has converged.
        Returns True if improvement < threshold for 2 consecutive generations.
        """
        stats = self.generation_stats.get(generation)
        if not stats:
            return False

        current_best = stats["best_score"]
        improvement = current_best - self._prev_best_score

        if improvement < threshold:
            self._convergence_counter += 1
        else:
            self._convergence_counter = 0

        self._prev_best_score = max(self._prev_best_score, current_best)

        return self._convergence_counter >= 2

    # ─── Snapshot System (Feature 5) ──────────────────────────

    def take_snapshot(self, generation: int):
        """Capture a snapshot of the graph state after a generation for UI animation."""
        gen_node_ids = [n["id"] for n in self.nodes if n["generation"] <= generation]
        gen_edges = [
            f"{e['from']}->{e['to']}"
            for e in self.edges
            if e["from"] in set(gen_node_ids) and e["to"] in set(gen_node_ids)
        ]

        self.snapshots.append({
            "generation": generation,
            "nodes": gen_node_ids,
            "edges": gen_edges,
        })

    # ─── Best Path Calculation ────────────────────────────────

    def compute_best_path(self):
        """Find the path through the graph that achieved the highest drift score."""
        if not self.nodes:
            self.best_path = []
            return

        best_node = max(self.nodes, key=lambda n: n["drift_score"])
        self.best_path = list(best_node.get("path", [best_node["id"]]))

    # ─── Selection ────────────────────────────────────────────

    def get_top_nodes(self, generation: int, max_nodes: int = 3) -> List[Dict]:
        """Get the top-performing nodes from a generation, sorted by drift_score desc."""
        gen_nodes = [n for n in self.nodes if n["generation"] == generation]
        gen_nodes.sort(key=lambda n: n["drift_score"], reverse=True)
        return gen_nodes[:max_nodes]

    def get_node(self, node_id: str) -> Optional[Dict]:
        """Look up a node by ID."""
        return self._node_index.get(node_id)

    # ─── Serialization ────────────────────────────────────────

    def to_dict(self) -> Dict[str, Any]:
        """Serialize the full graph for JSON storage."""
        return {
            "nodes": self.nodes,
            "edges": self.edges,
            "snapshots": self.snapshots,
            "generation_stats": {str(k): v for k, v in self.generation_stats.items()},
            "best_path": self.best_path,
        }

    # ─── Terminal Logging ─────────────────────────────────────

    def log_generation(self, generation: int):
        """Print generation stats to terminal in AXIOM format."""
        stats = self.generation_stats.get(generation)
        if not stats:
            return

        # Color-code based on best score
        color = get_color(stats["best_score"])
        console.print()
        console.print(f"  [bold bright_red]\\[AXIOM GRAPH][/bold bright_red]")
        console.print(f"    GEN-{generation} → nodes: [bold]{stats['num_nodes']}[/bold]")
        console.print(f"    Best drift: [bold {color}]{stats['best_score']:.3f}[/bold {color}]")
        console.print(f"    Avg drift:  [{color}]{stats['avg_score']:.3f}[/{color}]")
        console.print(f"    Diversity:  [bold]{stats['diversity']:.3f}[/bold]")

        # Log parent → child relationships
        gen_nodes = [n for n in self.nodes if n["generation"] == generation]
        for node in gen_nodes:
            if node["parent_ids"]:
                parents = ", ".join(node["parent_ids"])
                console.print(
                    f"    [dim]{parents} → {node['id']} ({node['type']})[/dim]"
                )
        console.print()
