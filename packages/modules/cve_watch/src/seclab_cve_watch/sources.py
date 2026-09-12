from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from seclab.core.config import Settings
from seclab.core.http import HttpProvider

from seclab_cve_watch.models import TrackedCve

logger = logging.getLogger(__name__)

DATA_DIR = Path(__file__).resolve().parent / "data" / "mock"

NVD_API_URL = "https://services.nvd.nih.gov/rest/json/cves/2.0"
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def _parse_datetime(raw: str | None) -> datetime:
    if not raw:
        return datetime.now(UTC)
    try:
        parsed = datetime.fromisoformat(raw)
    except ValueError:
        return datetime.now(UTC)
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def _extract_cvss_score(cve: dict[str, Any]) -> float | None:
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key)
        if entries:
            cvss_data = entries[0].get("cvssData", {})
            score = cvss_data.get("baseScore")
            if score is not None:
                return float(score)
    return None


def _extract_description(cve: dict[str, Any]) -> str:
    for description in cve.get("descriptions", []):
        if description.get("lang") == "en":
            return str(description.get("value", ""))
    return ""


def parse_nvd_response(payload: dict[str, Any]) -> list[TrackedCve]:
    """Parses an NVD CVE API 2.0 JSON response into TrackedCve records.
    Tolerant of a malformed/partial entry: skipped rather than raising,
    since this runs over content from an external feed."""
    cves: list[TrackedCve] = []
    for item in payload.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = cve.get("id")
        if not cve_id:
            continue
        cves.append(
            TrackedCve(
                cve_id=cve_id,
                description=_extract_description(cve),
                cvss_score=_extract_cvss_score(cve),
                published_at=_parse_datetime(cve.get("published")),
                is_actively_exploited=False,
                matched_products=[],
                source="NVD",
            )
        )
    return cves


def parse_cisa_kev_response(payload: dict[str, Any]) -> list[TrackedCve]:
    """Parses the CISA KEV catalog JSON into TrackedCve records. Every
    entry in this feed is, by definition, actively exploited."""
    cves: list[TrackedCve] = []
    for item in payload.get("vulnerabilities", []):
        cve_id = item.get("cveID")
        if not cve_id:
            continue
        vendor = str(item.get("vendorProject", "")).strip()
        product = str(item.get("product", "")).strip()
        matched_products = [p for p in (vendor, product) if p]
        cves.append(
            TrackedCve(
                cve_id=cve_id,
                description=str(item.get("shortDescription", "")),
                cvss_score=None,
                published_at=_parse_datetime(item.get("dateAdded")),
                is_actively_exploited=True,
                matched_products=matched_products,
                source="CISA KEV",
            )
        )
    return cves


def merge_cves(nvd_cves: list[TrackedCve], kev_cves: list[TrackedCve]) -> list[TrackedCve]:
    """Combines NVD and KEV records by CVE ID. When a CVE appears in both
    feeds, the KEV record's exploited/product data wins but the NVD
    record's CVSS score and description are kept (KEV rarely has a CVSS
    score, NVD rarely has product/vendor names)."""
    by_id: dict[str, TrackedCve] = {cve.cve_id: cve for cve in nvd_cves}
    for kev_cve in kev_cves:
        existing = by_id.get(kev_cve.cve_id)
        if existing is None:
            by_id[kev_cve.cve_id] = kev_cve
            continue
        by_id[kev_cve.cve_id] = existing.model_copy(
            update={
                "is_actively_exploited": True,
                "matched_products": list(
                    dict.fromkeys(existing.matched_products + kev_cve.matched_products)
                ),
                "description": existing.description or kev_cve.description,
                "source": "NVD + CISA KEV",
            }
        )
    return sorted(by_id.values(), key=lambda c: c.published_at, reverse=True)


def mock_nvd_cves() -> dict[str, Any]:
    return json.loads((DATA_DIR / "nvd_cves.json").read_text())


def mock_cisa_kev() -> dict[str, Any]:
    return json.loads((DATA_DIR / "cisa_kev.json").read_text())


class CveIngestionService:
    def __init__(self, settings: Settings, offline_mode: bool) -> None:
        self.settings = settings
        self.offline_mode = offline_mode
        self.http = HttpProvider(settings)

    async def fetch_all(
        self, *, pub_start_date: str | None = None, pub_end_date: str | None = None
    ) -> list[TrackedCve]:
        if self.offline_mode:
            return merge_cves(
                parse_nvd_response(mock_nvd_cves()),
                parse_cisa_kev_response(mock_cisa_kev()),
            )

        nvd_cves: list[TrackedCve] = []
        kev_cves: list[TrackedCve] = []
        try:
            params = {}
            if pub_start_date:
                params["pubStartDate"] = pub_start_date
            if pub_end_date:
                params["pubEndDate"] = pub_end_date
            nvd_payload = await self.http.get_json(NVD_API_URL, params=params or None)
            if isinstance(nvd_payload, dict):
                nvd_cves = parse_nvd_response(nvd_payload)
        except Exception as exc:
            logger.warning("nvd_fetch_failed", extra={"error": str(exc)})

        try:
            kev_payload = await self.http.get_json(CISA_KEV_URL)
            if isinstance(kev_payload, dict):
                kev_cves = parse_cisa_kev_response(kev_payload)
        except Exception as exc:
            logger.warning("cisa_kev_fetch_failed", extra={"error": str(exc)})

        return merge_cves(nvd_cves, kev_cves)
