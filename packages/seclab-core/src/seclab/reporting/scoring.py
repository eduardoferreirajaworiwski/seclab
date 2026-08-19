from pydantic import BaseModel, Field


class RiskSignal(BaseModel):
    """A single named, weighted contribution to a risk score. Ported
    verbatim from phantomscope/src/phantomscope/models/schemas.py::RiskSignal
    - already fully generic (code/severity/reason/weight/evidence), so every
    module's scoring rules (phantom's lookalike-domain rules, future OSINT
    modules' rules) can emit the same explainable signal shape."""

    code: str
    severity: str
    reason: str
    weight: int
    evidence: list[str] = Field(default_factory=list)


def score_and_prioritize(
    signals: list[RiskSignal],
    *,
    high_threshold: int = 70,
    medium_threshold: int = 40,
    max_score: int = 100,
) -> tuple[int, str, str]:
    """Sum signal weights into a bounded 0-100 score, derive a priority
    label, and build a human-readable rationale string. Factored out of
    phantomscope/src/phantomscope/scoring/rules.py::score_asset so every
    module's rule-set (which decides *which* signals fire) can share the
    same aggregation/priority/rationale logic instead of reimplementing it.

    Returns (bounded_score, priority, rationale).
    """
    raw_score = sum(signal.weight for signal in signals)
    bounded_score = min(raw_score, max_score)

    priority = "low"
    if bounded_score >= high_threshold:
        priority = "high"
    elif bounded_score >= medium_threshold:
        priority = "medium"

    rationale = (
        " + ".join(f"{signal.code} ({signal.weight})" for signal in signals) or "no triggered rules"
    )
    return bounded_score, priority, rationale
