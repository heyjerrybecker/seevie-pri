# SeeviePri

**Vulnerability triage engine** — mathematical risk prioritization for CVEs.

When a CVE drops, scanners tell you *what's vulnerable*. SeeviePri tells you *what to do about it, in what order, and why — in dollars*.

## How It Works

SeeviePri applies **graph topology analysis** to your dependency graphs, producing ranked, context-aware risk scores with financial exposure estimates. The math is validated across 5 real CVEs with an average Spearman correlation (rho) of 0.91.

**Graph Topology Scoring** — treats your dependency tree as a directed graph and computes structural properties of each vulnerable component: betweenness centrality (blast radius), reverse reachability (how many things depend on it), depth from root (exposure), and fan-in (connectivity). Components that are more structurally central score higher risk.

**Version Compatibility** — assesses upgrade path difficulty based on whether the vulnerable component is a direct or transitive dependency and whether a fix version is available.

**Financial Risk** — combines EPSS exploit probability (from FIRST.org) with the topology risk score and a per-service business value to estimate dollar exposure: `financial_risk = EPSS × topology_risk × business_value`

**Combined risk score:** `risk = topology_score × (1 - compatibility_score)`

## Quick Start

```bash
pip install -e .

# One-shot triage
seevie-pri triage --sbom bom.json

# Index services for persistent monitoring
seevie-pri index --sbom services/payment-api/bom.json --name payment-api --business-value 5000000
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
- **Financial risk quantification** — EPSS exploit probability × topology risk × business value per service
- **Blast radius** — cross-service impact analysis (how many services does each CVE affect?)
- **Persistent indexing** — SQLite storage, index once, rescan on demand, SBOM upsert on re-index
- **REST API** — 5 endpoints for programmatic access
- **Web dashboard** — Security Pro dark theme with Chart.js severity/service charts, executive summary banner, interactive vis.js dependency graph, editable business values, findings filters, and rescan button
- **CI-friendly** — exit code 1 when high-risk findings are present

## CLI Commands

| Command | Description |
|---------|-------------|
| `seevie-pri triage --sbom <path>` | One-shot triage (no persistence) |
| `seevie-pri index --sbom <path> --name <label>` | Index an SBOM for persistent monitoring |
| `seevie-pri rescan` | Re-triage all indexed SBOMs against fresh CVE data |
| `seevie-pri serve --port 8080` | Start REST API + web dashboard |

## Dashboard

The web dashboard (`seevie-pri serve`) provides:

- **Executive summary** — one-sentence security posture with total dollar exposure
- **Summary cards** — total findings, high/critical count, services indexed, estimated exposure
- **Severity donut chart** — interactive breakdown of findings by severity
- **Risk by service bar chart** — visual comparison across services
- **Findings table** — sortable by blast radius and financial exposure, filterable by severity
- **Service detail** — interactive dependency graph (vulnerable nodes in red) + per-service findings
- **SBOM upload** — drag-and-drop indexing from the browser
- **Editable business values** — set dollar value per service directly on the services page
- **Rescan button** — re-triage all services with spinning animation and auto-refresh

## Output Example (CLI)

```
org.apache.logging.log4j:log4j-core @ 2.14.1 — CRITICAL
  7 CVE(s) affecting this component

 #  CVE                     Severity   Risk   Fix          Action
 1  GHSA-7rjr-3q55-vv33     CRITICAL   0.06   2.16.0       SCHEDULE FOR NEXT SPRINT
 2  GHSA-jfh8-c2jp-5v3q     CRITICAL   0.06   2.15.0       SCHEDULE FOR NEXT SPRINT
 ...

23 finding(s) across 5 component(s). 0 high-risk.
```

## Generating SBOMs

SeeviePri consumes SBOMs — it doesn't generate them. Use any standard tool:

```bash
# Syft (Anchore) — scans directories, containers, archives
brew install syft
syft /path/to/project -o cyclonedx-json > bom.json

# Trivy (Aqua) — similar capabilities
brew install trivy
trivy fs /path/to/project --format cyclonedx --output bom.json

# CycloneDX CLI — language-specific, deeper dependency resolution
pip install cyclonedx-bom
cyclonedx-py environment -o bom.json
```

**SBOM quality matters.** Tools like `syft` produce flat component lists (good for detection), while build-tool-integrated generators (like `cyclonedx-py`, `cyclonedx-maven-plugin`, or `@cyclonedx/cdxgen`) include full dependency trees. SeeviePri's topology scoring is most valuable with dependency tree data — a flat SBOM still works, but the risk differentiation between components will be limited.

## CI Integration

SeeviePri fits into your CI pipeline with two lines. Re-indexing the same service name automatically updates the existing entry — no duplicates.

**GitLab CI:**

```yaml
vulnerability_triage:
  script:
    - syft . -o cyclonedx-json > bom.json
    - seevie-pri index --sbom bom.json --name $CI_PROJECT_NAME
    - seevie-pri rescan --format json --output triage-results.json
  artifacts:
    paths:
      - triage-results.json
```

**GitHub Actions:**

```yaml
- name: Vulnerability triage
  run: |
    syft . -o cyclonedx-json > bom.json
    seevie-pri index --sbom bom.json --name ${{ github.event.repository.name }}
    seevie-pri rescan --format json --output triage-results.json
```

**Or hit the API directly** (if `seevie-pri serve` is running):

```bash
curl -X POST http://seevie-pri:8080/sbom \
  -F file=@bom.json \
  -F name=payment-api

curl -X POST http://seevie-pri:8080/rescan
```

## Architecture

Pipeline of 5 swappable stages:

```
SBOM → [Parse] → [Match] → [Score] → [Rank] → [Output]
```

Each stage is a plain function that transforms a shared `TriageContext`. Swap any stage for your own implementation — different SBOM parser, different CVE source, different scoring model, different output format.

## The Math

The topology scoring is validated against 5 real CVEs with different blast patterns:

| CVE | Vulnerability | Spearman rho |
|-----|--------------|-------------|
| Guava (CVE-2020-8908) | Temp dir access | +0.99 |
| Log4Shell (CVE-2021-44228) | Remote code execution | +0.99 |
| Spring4Shell (CVE-2022-22965) | RCE via data binding | +0.63 |
| Text4Shell (CVE-2022-42889) | RCE via string interpolation | +1.00 |
| Jackson (CVE-2022-42003) | Deserialization DoS | +0.95 |

Average correlation: **0.91**. The math correctly ranks projects by vulnerability risk across every vulnerability shape tested.

## License

MIT
