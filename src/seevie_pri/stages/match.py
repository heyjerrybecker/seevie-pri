from __future__ import annotations

import json
import logging
import os
import time
from pathlib import Path

import httpx

from seevie_pri.context import CVEMatch, Component, TriageContext

logger = logging.getLogger(__name__)

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns"
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def match(ctx: TriageContext) -> TriageContext:
    cve_data_path = ctx.options.get("cve_data")

    if cve_data_path:
        matches = offline_match(ctx.components, Path(cve_data_path))
    else:
        matches = osv_match(ctx.components)
        if not ctx.options.get("no_nvd"):
            nvd_matches = nvd_match(ctx.components, matches)
            matches.extend(nvd_matches)

    ctx.matches = deduplicate(matches)
    return ctx


def osv_match(components: list[Component]) -> list[CVEMatch]:
    queries = []
    comp_by_index: dict[int, Component] = {}

    for comp in components:
        if not comp.purl:
            logger.debug("Skipping %s: no PURL", comp.name)
            continue
        comp_by_index[len(queries)] = comp
        queries.append({"package": {"purl": comp.purl}})

    if not queries:
        return []

    resp = httpx.post(OSV_BATCH_URL, json={"queries": queries}, timeout=30)
    resp.raise_for_status()
    results = resp.json().get("results", [])

    vuln_ids: set[str] = set()
    vuln_to_comps: dict[str, list[Component]] = {}

    for i, result in enumerate(results):
        comp = comp_by_index.get(i)
        if not comp:
            continue
        for vuln in result.get("vulns", []):
            vid = vuln["id"]
            vuln_ids.add(vid)
            vuln_to_comps.setdefault(vid, []).append(comp)

    matches = []
    for vid in vuln_ids:
        detail = _fetch_osv_detail(vid)
        if not detail:
            continue
        severity = _extract_severity(detail)
        fixed_version = _extract_fixed_version(detail)
        for comp in vuln_to_comps[vid]:
            matches.append(CVEMatch(
                cve_id=vid,
                severity=severity,
                affected_component=comp,
                fixed_version=fixed_version,
                source="osv",
            ))

    return matches


def _fetch_osv_detail(vuln_id: str) -> dict | None:
    try:
        resp = httpx.get(f"{OSV_VULN_URL}/{vuln_id}", timeout=10)
        resp.raise_for_status()
        return resp.json()
    except httpx.HTTPError:
        logger.warning("Failed to fetch OSV details for %s", vuln_id)
        return None


def _extract_severity(detail: dict) -> str:
    for affected in detail.get("affected", []):
        for key in ("database_specific", "ecosystem_specific"):
            sev = affected.get(key, {}).get("severity")
            if sev:
                return sev
    return "UNKNOWN"


def _extract_fixed_version(detail: dict) -> str | None:
    for affected in detail.get("affected", []):
        for range_obj in affected.get("ranges", []):
            if range_obj.get("type") in ("ECOSYSTEM", "SEMVER"):
                for event in range_obj.get("events", []):
                    if "fixed" in event:
                        return event["fixed"]
    return None


def nvd_match(
    components: list[Component], existing: list[CVEMatch]
) -> list[CVEMatch]:
    api_key = os.environ.get("NVD_API_KEY")
    if not api_key:
        logger.info("NVD fallback skipped (no NVD_API_KEY set)")
        return []

    already_matched = {m.affected_component.name for m in existing}
    unmatched = [c for c in components if c.name not in already_matched]
    if not unmatched:
        return []

    matches = []
    for comp in unmatched:
        artifact = comp.name.split(":")[-1]
        try:
            resp = httpx.get(
                NVD_API_URL,
                params={"keywordSearch": artifact, "resultsPerPage": 5},
                headers={"apiKey": api_key},
                timeout=10,
            )
            resp.raise_for_status()
        except httpx.HTTPError:
            logger.warning("NVD query failed for %s", artifact)
            continue

        for vuln_entry in resp.json().get("vulnerabilities", []):
            cve_data = vuln_entry["cve"]
            severity = _extract_nvd_severity(cve_data)
            matches.append(CVEMatch(
                cve_id=cve_data["id"],
                severity=severity,
                affected_component=comp,
                fixed_version=None,
                source="nvd",
            ))
        time.sleep(0.7)

    return matches


def _extract_nvd_severity(cve_data: dict) -> str:
    metrics = cve_data.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30"):
        entries = metrics.get(key, [])
        if entries:
            return entries[0].get("cvssData", {}).get("baseSeverity", "UNKNOWN")
    return "UNKNOWN"


def offline_match(
    components: list[Component], cve_data_path: Path
) -> list[CVEMatch]:
    with open(cve_data_path) as f:
        cve_entries = json.load(f)

    comp_by_purl = {c.purl: c for c in components if c.purl}
    comp_by_name = {c.name: c for c in components}
    matches = []

    for entry in cve_entries:
        vid = entry["id"]
        severity = _extract_severity(entry)
        fixed_version = _extract_fixed_version(entry)

        for affected in entry.get("affected", []):
            pkg = affected.get("package", {})
            pkg_purl = pkg.get("purl", "")
            pkg_name = pkg.get("name", "")

            matched_comp = comp_by_purl.get(pkg_purl) or comp_by_name.get(pkg_name)
            if matched_comp:
                matches.append(CVEMatch(
                    cve_id=vid,
                    severity=severity,
                    affected_component=matched_comp,
                    fixed_version=fixed_version,
                    source="manual",
                ))

    return matches


def deduplicate(matches: list[CVEMatch]) -> list[CVEMatch]:
    seen: dict[tuple[str, str], CVEMatch] = {}
    for m in matches:
        key = (m.cve_id, m.affected_component.name)
        if key not in seen or m.source == "osv":
            seen[key] = m
    return list(seen.values())
