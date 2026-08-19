from pathlib import Path

import pytest
from seclab_monitor.capture import CaptureWorker, write_artifact


@pytest.mark.asyncio
async def test_capture_returns_skipped_result_without_playwright_installed():
    worker = CaptureWorker()
    if worker.available:
        pytest.skip("playwright is installed in this environment; skip-path not exercised")

    await worker.start()
    result = await worker.capture("example.com")
    assert result.status == "skipped"
    await worker.stop()


def test_write_artifact_rejects_dot_dot_path_traversal(tmp_path):
    artifact_dir = tmp_path / "captures"
    malicious_name = "../../../../windows/system32/evil.png"

    path = write_artifact(str(artifact_dir), malicious_name, b"payload")

    written = Path(path)
    assert artifact_dir.resolve() in written.resolve().parents
    assert written.read_bytes() == b"payload"


def test_write_artifact_rejects_backslash_path_traversal(tmp_path):
    # A bare .replace("/", "_") leaves this untouched on Windows, the
    # platform this repo targets - backslash is a real path separator here.
    artifact_dir = tmp_path / "captures"
    malicious_name = "..\\..\\..\\evil.png"

    path = write_artifact(str(artifact_dir), malicious_name, b"payload")

    written = Path(path)
    assert artifact_dir.resolve() in written.resolve().parents


def test_write_artifact_caps_filename_length(tmp_path):
    artifact_dir = tmp_path / "captures"
    long_name = ("a" * 500) + ".png"

    path = write_artifact(str(artifact_dir), long_name, b"payload")

    assert len(Path(path).name) <= 100


def test_write_artifact_preserves_ordinary_domain_filenames(tmp_path):
    artifact_dir = tmp_path / "captures"

    path = write_artifact(str(artifact_dir), "login-example.com_20260101_120000.png", b"payload")

    assert Path(path).name == "login-example.com_20260101_120000.png"
