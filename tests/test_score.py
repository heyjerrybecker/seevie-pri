import networkx as nx

from seevie_pri.context import Component, CVEMatch, TriageContext
from seevie_pri.stages.score import score, score_topology, score_version_compatibility
from seevie_pri.version import parse_version


def _build_fixture_graph():
    """Build the same graph as cyclonedx_sample.json fixture.

    my-app (root)
    ├── starter-web (direct)
    │   └── spring-webmvc
    │       └── spring-beans (depth 3)
    ├── log4j-core (direct)
    │   └── log4j-api
    └── jackson-databind (direct)
    """
    g = nx.DiGraph()
    nodes = [
        ("my-app", Component("my-app", "1.0.0", "maven", direct=True)),
        ("starter-web", Component("starter-web", "2.6.5", "maven", direct=True)),
        ("spring-webmvc", Component("spring-webmvc", "5.3.17", "maven")),
        ("spring-beans", Component("spring-beans", "5.3.17", "maven")),
        ("log4j-core", Component("org.apache.logging.log4j:log4j-core", "2.14.1", "maven", direct=True)),
        ("log4j-api", Component("log4j-api", "2.14.1", "maven")),
        ("jackson-databind", Component("jackson-databind", "2.13.2", "maven", direct=True)),
    ]
    for ref, comp in nodes:
        g.add_node(ref, component=comp)

    g.add_edge("my-app", "starter-web")
    g.add_edge("my-app", "log4j-core")
    g.add_edge("my-app", "jackson-databind")
    g.add_edge("starter-web", "spring-webmvc")
    g.add_edge("spring-webmvc", "spring-beans")
    g.add_edge("log4j-core", "log4j-api")

    return g


def test_parse_version():
    assert parse_version("2.14.1") == (2, 14, 1)
    assert parse_version("5.3") == (5, 3, 0)
    assert parse_version("invalid") == (0, 0, 0)


def test_topology_scores_in_range():
    g = _build_fixture_graph()
    s = score_topology(g, ["log4j-core"], "my-app")
    assert 0.0 <= s <= 1.0


def test_topology_central_node_scores_higher():
    g = _build_fixture_graph()
    # log4j-core has a child (log4j-api), jackson-databind is a leaf
    s_central = score_topology(g, ["log4j-core"], "my-app")
    s_leaf = score_topology(g, ["jackson-databind"], "my-app")
    assert s_central > s_leaf


def test_topology_no_vuln_nodes():
    g = _build_fixture_graph()
    s = score_topology(g, [], "my-app")
    assert s == 0.0


def test_version_compatibility_direct_with_fix():
    comp = Component("lib", "1.0", "maven", direct=True)
    m = CVEMatch(cve_id="CVE-1", severity="HIGH", affected_component=comp,
                 fixed_version="2.0")
    assert score_version_compatibility(m) == 0.8


def test_version_compatibility_transitive_with_fix():
    comp = Component("lib", "1.0", "maven", direct=False)
    m = CVEMatch(cve_id="CVE-1", severity="HIGH", affected_component=comp,
                 fixed_version="2.0")
    assert score_version_compatibility(m) == 0.3


def test_version_compatibility_no_fix():
    comp = Component("lib", "1.0", "maven", direct=True)
    m = CVEMatch(cve_id="CVE-1", severity="HIGH", affected_component=comp,
                 fixed_version=None)
    assert score_version_compatibility(m) == 0.0


def test_score_stage_populates_context():
    g = _build_fixture_graph()
    comp = Component("org.apache.logging.log4j:log4j-core", "2.14.1", "maven",
                     direct=True)
    match_obj = CVEMatch(cve_id="CVE-2021-44228", severity="CRITICAL",
                         affected_component=comp, fixed_version="2.16.0")

    ctx = TriageContext(
        graph=g,
        root_node="my-app",
        matches=[match_obj],
    )
    ctx = score(ctx)

    assert len(ctx.scores) == 1
    scored = ctx.scores[0]
    assert scored.topology_score > 0
    assert scored.compatibility_score == 0.8  # direct + fix
    assert scored.combined_score == round(
        scored.topology_score * (1 - 0.8) * 0.7, 4
    )
