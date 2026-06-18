from pathlib import Path

import pytest

from seevie_pri.purl import parse_purl
from seevie_pri.stages.parse import parse, detect_format
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


def test_parse_purl_golang():
    eco, name, ver = parse_purl(
        "pkg:golang/github.com/gin-gonic/gin@1.9.1"
    )
    assert eco == "golang"
    assert name == "github.com/gin-gonic/gin"
    assert ver == "1.9.1"


def test_parse_purl_golang_stdlib():
    eco, name, ver = parse_purl(
        "pkg:golang/golang.org/x/text@0.3.7"
    )
    assert eco == "golang"
    assert name == "golang.org/x/text"
    assert ver == "0.3.7"


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


def test_detect_format_cyclonedx_json():
    raw = (FIXTURES / "cyclonedx_sample.json").read_bytes()
    assert detect_format(raw) == "cyclonedx-json"


def test_detect_format_cyclonedx_xml():
    raw = (FIXTURES / "cyclonedx_sample.xml").read_bytes()
    assert detect_format(raw) == "cyclonedx-xml"


def test_detect_format_spdx_json():
    raw = (FIXTURES / "spdx_sample.json").read_bytes()
    assert detect_format(raw) == "spdx-json"


def test_parse_cyclonedx_xml_components():
    ctx = TriageContext(sbom_path=FIXTURES / "cyclonedx_sample.xml")
    ctx = parse(ctx)

    assert len(ctx.components) == 7
    names = {c.name for c in ctx.components}
    assert "org.apache.logging.log4j:log4j-core" in names


def test_parse_cyclonedx_xml_graph():
    ctx = TriageContext(sbom_path=FIXTURES / "cyclonedx_sample.xml")
    ctx = parse(ctx)

    assert ctx.root_node == "my-app"
    assert len(ctx.graph.nodes) == 7
    assert len(ctx.graph.edges) == 6
    assert ctx.graph.has_edge("my-app", "log4j-core")


def test_parse_spdx_raises():
    ctx = TriageContext(sbom_path=FIXTURES / "spdx_sample.json")
    with pytest.raises(NotImplementedError, match="SPDX"):
        parse(ctx)
