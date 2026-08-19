import pytest
from seclab_monitor.capture import CaptureWorker


@pytest.mark.asyncio
async def test_capture_returns_skipped_result_without_playwright_installed():
    worker = CaptureWorker()
    if worker.available:
        pytest.skip("playwright is installed in this environment; skip-path not exercised")

    await worker.start()
    result = await worker.capture("example.com")
    assert result.status == "skipped"
    await worker.stop()
