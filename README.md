# SeeviePri

**Vulnerability triage engine** — mathematical risk prioritization for CVEs.

When a CVE drops, scanners tell you *what's vulnerable*. SeeviePri tells you *what to do about it, in what order, and why*.

## How It Works

SeeviePri applies graph topology analysis and version constraint algebra to your dependency graphs, producing ranked, context-aware risk scores. The math is validated across 5 real CVEs with an average Spearman correlation (rho) of 0.91.

**Two mathematical lenses:**
- **Graph Topology** — betweenness centrality, reverse reachability, depth, fan-in. Measures how structurally exposed a vulnerable component is.
- **Version Compatibility** — assesses upgrade path difficulty based on dependency structure and fix availability.

**Combined:** `risk = topology_score * (1 - compatibility_score)`

## Quick Start

```bash
pip install -e .

# One-shot triage
seevie-pri triage --sbom bom.json

# Index services for persistent monitoring
seevie-pri index --sbom services/payment-api/bom.json --name payment-api
seevie-pri index --sbom services/order-service/bom.json --name order-service

# Re-triage everything against fresh CVE data
seevie-pri rescan

# Start the dashboard + API
seevie-pri serve --port 8080
# Open http://localhost:8080/dashboard/
```

## Features

- **4 ecosystems** — Maven, npm, PyPI, Go
- **2 SBOM formats** — CycloneDX (JSON + XML), SPDX (JSON)
- **CVE matching** — OSV (primary), NVD (fallback), offline mode for air-gapped environments
- **Persistent indexing** — SQLite storage, index once, rescan on demand
- **REST API** — 5 endpoints for programmatic access
- **Web dashboard** — dark-themed UI with severity breakdown, service drill-down, findings filters
- **CI-friendly** — exit code 1 when high-risk findings are present

## CLI Commands

| Command | Description |
|---------|-------------|
| `seevie-pri triage --sbom <path>` | One-shot triage (no persistence) |
| `seevie-pri index --sbom <path> --name <label>` | Index an SBOM for persistent monitoring |
| `seevie-pri rescan` | Re-triage all indexed SBOMs |
| `seevie-pri serve --port 8080` | Start REST API + web dashboard |

## Output Example

```
org.apache.logging.log4j:log4j-core @ 2.14.1 — CRITICAL
  7 CVE(s) affecting this component

 #  CVE                     Severity   Risk   Fix          Action
 1  GHSA-7rjr-3q55-vv33     CRITICAL   0.06   2.16.0       SCHEDULE FOR NEXT SPRINT
 2  GHSA-jfh8-c2jp-5v3q     CRITICAL   0.06   2.15.0       SCHEDULE FOR NEXT SPRINT
 ...
```

## Architecture

Pipeline of 5 swappable stages:

```
SBOM → [Parse] → [Match] → [Score] → [Rank] → [Output]
```

Each stage is a plain function that transforms a shared `TriageContext`. Swap any stage for your own implementation — different SBOM parser, different CVE source, different scoring model, different output format.

## License

MIT
