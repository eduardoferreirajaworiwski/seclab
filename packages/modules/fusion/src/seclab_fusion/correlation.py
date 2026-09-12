from __future__ import annotations

import hashlib

from seclab_cve_watch.models import TrackedCve
from seclab_monitor.models import MonitorMatch
from seclab_threatlens.models import ThreatArticle

from seclab_fusion.models import FusionFinding, FusionSignal

# Scoring weights: named, small, and documented (mirrors the
# "named, weighted, explainable signal" philosophy already used
# throughout the repo, e.g. seclab.reporting.scoring.RiskSignal).
WEIGHT_EXPLOITED_CVE = 3
WEIGHT_CVE_MATCH = 1
WEIGHT_THREAT_VECTOR = 1
MAX_THREAT_VECTOR_SIGNALS = 5  # cap so one noisy digest can't dominate a score


def _finding_id(domain: str) -> str:
    """Deterministic id derived from the (lowercased) domain - stable
    across requests since fusion computes everything fresh each time."""
    return hashlib.sha256(domain.strip().lower().encode("utf-8")).hexdigest()[:16]


def _keyword_in_text(keyword: str, text: str) -> bool:
    if not keyword or not text:
        return False
    return keyword.lower() in text.lower()


def _cve_signals(match: MonitorMatch, tracked_cves: list[TrackedCve]) -> list[FusionSignal]:
    signals: list[FusionSignal] = []
    needles = [n for n in {match.matched_keyword, match.domain} if n]
    for cve in tracked_cves:
        matched_product = next(
            (
                product
                for product in cve.matched_products
                for needle in needles
                if _keyword_in_text(needle, product)
            ),
            None,
        )
        if matched_product is None:
            continue
        if cve.is_actively_exploited:
            signals.append(
                FusionSignal(
                    source_module="cve_watch",
                    kind="exploited_cve",
                    label=f"Actively exploited CVE matches product '{matched_product}'",
                    detail=(
                        f"{cve.cve_id} (CISA KEV) matches product '{matched_product}', "
                        f"correlated via monitor keyword/domain."
                    ),
                    severity="critical",
                )
            )
        else:
            signals.append(
                FusionSignal(
                    source_module="cve_watch",
                    kind="cve_match",
                    label=f"Tracked CVE matches product '{matched_product}'",
                    detail=(
                        f"{cve.cve_id} matches product '{matched_product}', "
                        f"correlated via monitor keyword/domain."
                    ),
                    severity="medium",
                )
            )
    return signals


def _threat_vector_signals(
    match: MonitorMatch, threatlens_articles: list[ThreatArticle]
) -> list[FusionSignal]:
    signals: list[FusionSignal] = []
    for article in threatlens_articles:
        if not article.vectors:
            continue
        text = f"{article.title} {article.summary}"
        if not _keyword_in_text(match.matched_keyword, text):
            continue
        vector_names = ", ".join(str(v) for v in article.vectors)
        signals.append(
            FusionSignal(
                source_module="threatlens",
                kind="threat_vector",
                label=f"Trending vector(s): {vector_names}",
                detail=(
                    f"Article '{article.title}' ({article.source}) tags vector(s) "
                    f"{vector_names}, matched via monitor keyword '{match.matched_keyword}'."
                ),
                severity="medium",
            )
        )
        if len(signals) >= MAX_THREAT_VECTOR_SIGNALS:
            break
    return signals


def correlate(
    monitor_matches: list[MonitorMatch],
    threatlens_articles: list[ThreatArticle],
    tracked_cves: list[TrackedCve],
) -> list[FusionFinding]:
    """Pure function: joins already-fetched data from the three source
    modules into a prioritized, explainable list of FusionFinding. A
    MonitorMatch with zero correlation signals produces no finding -
    fusion surfaces only genuinely correlated activity."""
    findings: list[FusionFinding] = []
    for match in monitor_matches:
        signals = _cve_signals(match, tracked_cves) + _threat_vector_signals(
            match, threatlens_articles
        )
        if not signals:
            continue

        base_score = round(match.score / 10)
        weight_by_kind = {
            "exploited_cve": WEIGHT_EXPLOITED_CVE,
            "cve_match": WEIGHT_CVE_MATCH,
            "threat_vector": WEIGHT_THREAT_VECTOR,
        }
        score = base_score + sum(weight_by_kind[s.kind] for s in signals)

        rationale_parts = [f"monitor_score/10 ({base_score})"] + [
            f"{s.kind} ({weight_by_kind[s.kind]}): {s.detail}" for s in signals
        ]
        findings.append(
            FusionFinding(
                id=_finding_id(match.domain),
                title=f"{match.domain} (keyword '{match.matched_keyword}')",
                score=score,
                signals=signals,
                rationale=" + ".join(rationale_parts),
            )
        )

    findings.sort(key=lambda f: f.score, reverse=True)
    return findings
