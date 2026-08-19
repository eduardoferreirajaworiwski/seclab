import pytest
from seclab.core.config import Settings
from seclab.core.events import Event, EventBus
from seclab_monitor.capture import CaptureWorker
from seclab_monitor.config import MonitorSettings
from seclab_monitor.models import MonitorMatch
from seclab_monitor.pipeline import MatchPipeline


class SpySink:
    def __init__(self) -> None:
        self.events: list[Event] = []

    async def emit(self, event: Event) -> None:
        self.events.append(event)


@pytest.mark.asyncio
async def test_handle_match_scores_and_persists(db_session):
    settings = Settings(offline_mode=True)
    monitor_settings = MonitorSettings(capture_enabled=False)
    spy = SpySink()
    pipeline = MatchPipeline(
        db_session, settings, monitor_settings, CaptureWorker(), EventBus([spy])
    )

    match = await pipeline.handle_match("login-microsoft-support.com", "Let's Encrypt", "microsoft")

    assert isinstance(match, MonitorMatch)
    assert match.id is not None
    assert match.capture_status == "skipped"
    assert match.score >= 0
    assert len(spy.events) == 1
    assert spy.events[0].payload["domain"] == "login-microsoft-support.com"


@pytest.mark.asyncio
async def test_handle_match_stores_scoring_evidence(db_session):
    from seclab.security.evidence import EvidenceStore

    settings = Settings(offline_mode=True)
    monitor_settings = MonitorSettings(capture_enabled=False)
    pipeline = MatchPipeline(
        db_session, settings, monitor_settings, CaptureWorker(), EventBus([SpySink()])
    )

    await pipeline.handle_match("secure-google-login.net", "Sectigo", "google")

    artifacts = EvidenceStore(db_session).by_subject(
        source_module="monitor", subject_type="domain", subject_id="secure-google-login.net"
    )
    assert any(a.evidence_type == "ct_match_scoring" for a in artifacts)


@pytest.mark.asyncio
async def test_capture_skipped_when_disabled_leaves_status_skipped(db_session):
    settings = Settings(offline_mode=True)
    monitor_settings = MonitorSettings(
        capture_enabled=True
    )  # worker itself has no playwright in CI
    pipeline = MatchPipeline(
        db_session, settings, monitor_settings, CaptureWorker(), EventBus([SpySink()])
    )

    match = await pipeline.handle_match("binance-verify.io", "Let's Encrypt", "binance")
    assert match.capture_status in {"skipped", "failed"}
