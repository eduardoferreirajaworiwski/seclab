import asyncio

from seclab.core.config import Settings
from seclab_phantom.models import TargetRequest
from seclab_phantom.service import AnalysisService


def test_analysis_service_returns_ranked_assets(db_session) -> None:
    settings = Settings(offline_mode=True)
    service = AnalysisService(settings, db_session)
    request = TargetRequest(target="acme", target_type="brand", offline_mode=True, max_variants=8)
    result = asyncio.run(service.analyze(request))
    assert result.assets
    assert result.summary.headline
    assert result.report_markdown.startswith("# PhantomScope Report")
    assert result.metadata["mock_assets"] >= 1
    assert all(asset.score_rationale for asset in result.assets)
    assert result.summary.grounding_notes
    assert any(asset.infrastructure.origin.value == "mock" for asset in result.assets)


def test_analysis_can_be_retrieved_and_listed(db_session) -> None:
    settings = Settings(offline_mode=True)
    service = AnalysisService(settings, db_session)
    request = TargetRequest(target="acme", target_type="brand", offline_mode=True, max_variants=8)
    result = asyncio.run(service.analyze(request))

    fetched = service.get_analysis(result.analysis_id)
    assert fetched is not None
    assert fetched.analysis_id == result.analysis_id

    recent = service.list_recent_analyses(limit=5)
    assert any(item.analysis_id == result.analysis_id for item in recent)
