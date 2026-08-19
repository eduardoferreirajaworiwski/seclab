from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger("seclab.monitor.capture")

try:
    from playwright.async_api import Browser, async_playwright

    _PLAYWRIGHT_AVAILABLE = True
except ImportError:  # pragma: no cover - exercised when the optional extra isn't installed
    Browser = None  # type: ignore[assignment,misc]
    _PLAYWRIGHT_AVAILABLE = False


@dataclass
class CaptureResult:
    status: str  # "captured" | "skipped" | "failed"
    screenshot_bytes: bytes | None = None
    html_content: str | None = None
    error: str | None = None


class CaptureWorker:
    """Sandboxed, pooled headless-browser capture.

    Fixes two issues in hydra-mapper's forensics/collector.py:
    - it opened a brand new `sync_playwright()` browser process per domain,
      which will not scale to CertStream's real match volume; this worker
      launches ONE Chromium instance and reuses it across captures.
    - Playwright is an optional dependency here (the "wrapper opcional"
      pattern): if it isn't installed, `capture()` returns a
      status="skipped" result instead of crashing the pipeline.

    Every navigation is treated as visiting an untrusted, possibly
    malicious URL: downloads are blocked, navigation is hard-timed-out, and
    the resulting HTML is only ever stored (via the evidence store), never
    rendered.
    """

    def __init__(self, *, navigation_timeout_ms: int = 30_000) -> None:
        self._navigation_timeout_ms = navigation_timeout_ms
        self._playwright = None
        self._browser: Browser | None = None

    @property
    def available(self) -> bool:
        return _PLAYWRIGHT_AVAILABLE

    async def start(self) -> None:
        if not _PLAYWRIGHT_AVAILABLE:
            logger.warning("capture_disabled_playwright_not_installed")
            return
        self._playwright = await async_playwright().start()
        self._browser = await self._playwright.chromium.launch(headless=True)

    async def stop(self) -> None:
        if self._browser is not None:
            await self._browser.close()
        if self._playwright is not None:
            await self._playwright.stop()

    async def capture(self, domain: str) -> CaptureResult:
        if not _PLAYWRIGHT_AVAILABLE or self._browser is None:
            return CaptureResult(status="skipped", error="playwright not available")

        page = await self._browser.new_page(accept_downloads=False)
        try:
            await page.route(
                "**/*",
                lambda route: (
                    route.abort() if route.request.resource_type == "media" else route.continue_()
                ),
            )
            url = domain if domain.startswith(("http://", "https://")) else f"http://{domain}"
            await page.goto(url, timeout=self._navigation_timeout_ms)
            await page.wait_for_load_state("networkidle", timeout=self._navigation_timeout_ms)

            screenshot_bytes = await page.screenshot()
            html_content = await page.content()
            return CaptureResult(
                status="captured", screenshot_bytes=screenshot_bytes, html_content=html_content
            )
        except Exception as exc:
            logger.warning("capture_failed", extra={"domain": domain, "error": str(exc)})
            return CaptureResult(status="failed", error=str(exc))
        finally:
            await page.close()


def write_artifact(artifact_dir: str, filename: str, content: bytes) -> str:
    directory = Path(artifact_dir)
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / filename
    path.write_bytes(content)
    return str(path)
