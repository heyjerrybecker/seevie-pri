from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import networkx as nx


@dataclass
class Component:
    name: str
    version: str
    ecosystem: str
    purl: str | None = None
    direct: bool = False


@dataclass
class CVEMatch:
    cve_id: str
    severity: str
    affected_component: Component
    fixed_version: str | None = None
    source: str = "osv"


@dataclass
class ScoredMatch:
    match: CVEMatch
    topology_score: float = 0.0
    compatibility_score: float = 0.0
    combined_score: float = 0.0


@dataclass
class RankedFinding:
    rank: int
    scored: ScoredMatch
    action: str = ""
    upgrade_path: str = "unknown"


@dataclass
class TriageContext:
    sbom_path: Path | None = None
    components: list[Component] = field(default_factory=list)
    graph: nx.DiGraph = field(default_factory=nx.DiGraph)
    root_node: str = ""
    matches: list[CVEMatch] = field(default_factory=list)
    scores: list[ScoredMatch] = field(default_factory=list)
    rankings: list[RankedFinding] = field(default_factory=list)
    options: dict = field(default_factory=dict)
