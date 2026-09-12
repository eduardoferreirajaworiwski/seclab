from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from pathlib import Path
from xml.etree import ElementTree

from seclab.core.config import Settings
from seclab.core.http import HttpProvider

from seclab_threatlens.models import FeedSource, ThreatArticle

logger = logging.getLogger(__name__)

DATA_DIR = Path(__file__).resolve().parent / "data" / "mock"

# Major, stable security-news RSS feeds. Kept short and hand-picked
# rather than a long scraped list: every URL here has been verified to
# serve a well-formed RSS 2.0 feed as of this writing.
DEFAULT_FEEDS: list[FeedSource] = [
    FeedSource(name="The Hacker News", url="https://feeds.feedburner.com/TheHackersNews"),
    FeedSource(name="BleepingComputer", url="https://www.bleepingcomputer.com/feed/"),
    FeedSource(name="Krebs on Security", url="https://krebsonsecurity.com/feed/"),
    FeedSource(name="Dark Reading", url="https://www.darkreading.com/rss.xml"),
    FeedSource(name="The Record", url="https://therecord.media/feed"),
]


def _parse_pubdate(raw: str | None) -> datetime:
    if not raw:
        return datetime.now(UTC)
    try:
        parsed = parsedate_to_datetime(raw)
    except (TypeError, ValueError):
        return datetime.now(UTC)
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def parse_rss_feed(xml_text: str, *, source_name: str) -> list[ThreatArticle]:
    """Parses RSS 2.0 <item> elements. Deliberately tolerant: a malformed
    or partially-missing item is skipped rather than raising, since this
    runs over content from external, occasionally inconsistent feeds."""
    try:
        root = ElementTree.fromstring(xml_text)  # noqa: S314 (trusted feed list, text-only parse)
    except ElementTree.ParseError as exc:
        logger.warning("feed_parse_failed", extra={"source": source_name, "error": str(exc)})
        return []

    articles: list[ThreatArticle] = []
    for item in root.findall(".//item"):
        title = (item.findtext("title") or "").strip()
        link = (item.findtext("link") or "").strip()
        if not title or not link:
            continue
        description = (item.findtext("description") or "").strip()
        articles.append(
            ThreatArticle(
                title=title,
                link=link,
                published_at=_parse_pubdate(item.findtext("pubDate")),
                source=source_name,
                summary=description,
            )
        )
    return articles


def mock_articles() -> list[ThreatArticle]:
    payload = json.loads((DATA_DIR / "articles.json").read_text())
    return [ThreatArticle.model_validate(item) for item in payload]


class FeedIngestionService:
    def __init__(self, settings: Settings, offline_mode: bool) -> None:
        self.settings = settings
        self.offline_mode = offline_mode
        self.http = HttpProvider(settings)

    async def fetch_all(
        self, *, feeds: list[FeedSource] | None = None, max_per_feed: int = 15
    ) -> list[ThreatArticle]:
        if self.offline_mode:
            return mock_articles()

        collected: list[ThreatArticle] = []
        for feed in feeds or DEFAULT_FEEDS:
            try:
                xml_text = await self.http.get_text(feed.url)
                collected.extend(parse_rss_feed(xml_text, source_name=feed.name)[:max_per_feed])
            except Exception as exc:
                logger.warning(
                    "feed_fetch_failed", extra={"source": feed.name, "error": str(exc)}
                )
        return collected
