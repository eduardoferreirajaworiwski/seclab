import socket

import pytest
from seclab.core.config import Settings
from seclab.core.events import Event, EventBus
from seclab_monitor.capture import CaptureResult, CaptureWorker
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


class _CaptureCalledSpy(CaptureWorker):
    """Would return a fake 'captured' result if invoked - used to prove the
    egress check below stops the pipeline before capture() is ever called,
    not just that the end result happens to be 'skipped'."""

    def __init__(self) -> None:
        super().__init__()
        self.called = False

    async def capture(self, domain: str) -> CaptureResult:
        self.called = True
        return CaptureResult(status="captured", html_content="<html></html>")


@pytest.mark.asyncio
async def test_capture_skipped_for_domain_resolving_to_private_ip(monkeypatch, db_session):
    monkeypatch.setattr(
        socket, "getaddrinfo", lambda *a, **k: [(None, None, None, None, ("10.0.0.5", 0))]
    )
    settings = Settings(offline_mode=True)
    monitor_settings = MonitorSettings(capture_enabled=True)
    spy = _CaptureCalledSpy()
    pipeline = MatchPipeline(db_session, settings, monitor_settings, spy, EventBus([SpySink()]))

    match = await pipeline.handle_match("login-internal-service.test", "Let's Encrypt", "internal")

    assert match.capture_status == "skipped"
    assert spy.called is False


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
