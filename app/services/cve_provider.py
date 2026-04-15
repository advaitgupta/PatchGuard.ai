"""Live CVE / KEV / EPSS data providers.

Fetches real vulnerability intelligence from public APIs:
  - NVD (National Vulnerability Database) for CVE details
  - CISA KEV (Known Exploited Vulnerabilities) catalog
  - FIRST EPSS (Exploit Prediction Scoring System) scores
"""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Any

import httpx

from app.config import get_settings

logger = logging.getLogger(__name__)

# ──────────────────────────────── CISA KEV ────────────────────────────────

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

async def fetch_kev_catalog() -> list[dict[str, Any]]:
    """Fetch the full CISA KEV catalog (JSON).  Returns list of vulnerability dicts."""
    try:
        async with httpx.AsyncClient(timeout=20.0) as client:
            resp = await client.get(KEV_URL)
            resp.raise_for_status()
            data = resp.json()
            vulns = data.get("vulnerabilities", [])
            logger.info("Fetched %d KEV entries", len(vulns))
            return vulns
    except Exception as exc:
        logger.warning("KEV fetch failed: %s", exc)
        return []


def parse_kev_entry(entry: dict) -> dict[str, Any]:
    """Normalize a single KEV entry to our internal format."""
    return {
        "cve_id": entry.get("cveID", ""),
        "vendor": entry.get("vendorProject", ""),
        "product": entry.get("product", ""),
        "vulnerability_name": entry.get("vulnerabilityName", ""),
        "date_added": entry.get("dateAdded", ""),
        "due_date": entry.get("dueDate", ""),
        "short_description": entry.get("shortDescription", ""),
        "required_action": entry.get("requiredAction", ""),
        "known_ransomware_use": entry.get("knownRansomwareCampaignUse", "Unknown"),
    }


# ──────────────────────────────── EPSS ────────────────────────────────────

EPSS_URL = "https://api.first.org/data/v1/epss"

async def fetch_epss_scores(cve_ids: list[str]) -> dict[str, float]:
    """Fetch EPSS scores for a list of CVE IDs.  Returns {cve_id: probability}."""
    if not cve_ids:
        return {}
    results: dict[str, float] = {}
    # EPSS API accepts comma-separated CVEs (max ~100 per request)
    batches = [cve_ids[i:i + 50] for i in range(0, len(cve_ids), 50)]
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            for batch in batches:
                params = {"cve": ",".join(batch)}
                resp = await client.get(EPSS_URL, params=params)
                resp.raise_for_status()
                data = resp.json().get("data", [])
                for item in data:
                    cve = item.get("cve", "")
                    prob = float(item.get("epss", 0.0))
                    results[cve] = prob
        logger.info("Fetched EPSS scores for %d CVEs", len(results))
    except Exception as exc:
        logger.warning("EPSS fetch failed: %s", exc)
    return results


# ──────────────────────────────── NVD CVE ─────────────────────────────────

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

async def fetch_recent_cves(days: int = 30, keyword: str | None = None) -> list[dict[str, Any]]:
    """Fetch recent CVEs from NVD (last N days), optionally filtered by keyword."""
    now = datetime.utcnow()
    start = (now - timedelta(days=days)).strftime("%Y-%m-%dT00:00:00.000")
    end = now.strftime("%Y-%m-%dT23:59:59.999")
    params: dict[str, Any] = {
        "pubStartDate": start,
        "pubEndDate": end,
        "resultsPerPage": 50,
    }
    if keyword:
        params["keywordSearch"] = keyword
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.get(NVD_URL, params=params)
            resp.raise_for_status()
            data = resp.json()
            vulns = data.get("vulnerabilities", [])
            logger.info("Fetched %d CVEs from NVD", len(vulns))
            return vulns
    except Exception as exc:
        logger.warning("NVD fetch failed: %s", exc)
        return []


def parse_nvd_cve(item: dict) -> dict[str, Any]:
    """Normalize a single NVD CVE item to our internal vulnerability format."""
    cve = item.get("cve", {})
    cve_id = cve.get("id", "")
    descriptions = cve.get("descriptions", [])
    desc = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")

    # CVSS: try v3.1, then v3.0, then v2
    metrics = cve.get("metrics", {})
    cvss = 0.0
    if "cvssMetricV31" in metrics:
        cvss = metrics["cvssMetricV31"][0].get("cvssData", {}).get("baseScore", 0.0)
    elif "cvssMetricV30" in metrics:
        cvss = metrics["cvssMetricV30"][0].get("cvssData", {}).get("baseScore", 0.0)
    elif "cvssMetricV2" in metrics:
        cvss = metrics["cvssMetricV2"][0].get("cvssData", {}).get("baseScore", 0.0)

    published = cve.get("published", "")[:10]

    # Affected products (CPE)
    affected_products: list[str] = []
    configs = cve.get("configurations", [])
    for conf in configs:
        for node in conf.get("nodes", []):
            for match in node.get("cpeMatch", []):
                cpe = match.get("criteria", "")
                affected_products.append(cpe)

    return {
        "cve_id": cve_id,
        "summary": desc[:300] if desc else "",
        "cvss": cvss,
        "published_date": published,
        "affected_products": affected_products,
        "references": [r.get("url", "") for r in cve.get("references", [])],
    }


# ───────────────────── Combined enrichment ─────────────────────

async def enrich_vulnerabilities(
    cve_ids: list[str],
) -> dict[str, dict[str, Any]]:
    """Enrich a set of CVE IDs with KEV status and EPSS scores."""
    kev_task = fetch_kev_catalog()
    epss_task = fetch_epss_scores(cve_ids)
    kev_entries, epss_scores = await asyncio.gather(kev_task, epss_task)

    kev_set = {e.get("cveID", "") for e in kev_entries}
    kev_details = {e.get("cveID", ""): parse_kev_entry(e) for e in kev_entries}

    result: dict[str, dict[str, Any]] = {}
    for cve_id in cve_ids:
        result[cve_id] = {
            "kev": cve_id in kev_set,
            "kev_details": kev_details.get(cve_id),
            "epss": epss_scores.get(cve_id, 0.0),
        }
    return result
