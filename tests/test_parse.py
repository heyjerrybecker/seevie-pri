from pathlib import Path

from seevie_pri.purl import parse_purl
from seevie_pri.stages.parse import parse
from seevie_pri.context import TriageContext

FIXTURES = Path(__file__).parent / "fixtures"


def test_parse_purl_maven():
    eco, name, ver = parse_purl(
        "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"
    )
    assert eco == "maven"
    assert name == "org.apache.logging.log4j:log4j-core"
    assert ver == "2.14.1"


def test_parse_purl_npm_scoped():
    eco, name, ver = parse_purl("pkg:npm/%40angular/core@12.0.0")
    assert eco == "npm"
    assert name == "@angular/core"
    assert ver == "12.0.0"


def test_parse_purl_pypi():
    eco, name, ver = parse_purl("pkg:pypi/requests@2.28.0")
    assert eco == "pypi"
    assert name == "requests"
    assert ver == "2.28.0"


def test_parse_cyclonedx_json_components():
    ctx = TriageContext(sbom_path=FIXTURES / "cyclonedx_sample.json")
    ctx = parse(ctx)

    assert len(ctx.components) == 7  # root + 6 libraries
    names = {c.name for c in ctx.components}
    assert "org.apache.logging.log4j:log4j-core" in names
    assert "org.springframework:spring-beans" in names


def test_parse_cyclonedx_json_graph():
    ctx = TriageContext(sbom_path=FIXTURES / "cyclonedx_sample.json")
    ctx = parse(ctx)

    assert ctx.root_node == "my-app"
    assert len(ctx.graph.nodes) == 7
    assert len(ctx.graph.edges) == 6
    assert ctx.graph.has_edge("my-app", "log4j-core")
    assert ctx.graph.has_edge("starter-web", "spring-webmvc")
    assert ctx.graph.has_edge("spring-webmvc", "spring-beans")


def test_parse_cyclonedx_json_direct_flag():
    ctx = TriageContext(sbom_path=FIXTURES / "cyclonedx_sample.json")
    ctx = parse(ctx)

    comp_by_name = {c.name: c for c in ctx.components}
    assert comp_by_name["org.apache.logging.log4j:log4j-core"].direct is True
    assert comp_by_name["org.springframework:spring-beans"].direct is False
    assert comp_by_name["org.apache.logging.log4j:log4j-api"].direct is False


def test_parse_cyclonedx_json_ecosystem():
    ctx = TriageContext(sbom_path=FIXTURES / "cyclonedx_sample.json")
    ctx = parse(ctx)

    for comp in ctx.components:
        if comp.purl:
            assert comp.ecosystem == "maven"
