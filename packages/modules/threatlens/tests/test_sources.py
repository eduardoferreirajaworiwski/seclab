from seclab_threatlens.sources import DEFAULT_FEEDS, mock_articles, parse_rss_feed

SAMPLE_RSS = """<?xml version="1.0"?>
<rss version="2.0"><channel>
  <title>Example Security Feed</title>
  <item>
    <title>Ransomware gang exploits zero-day in VPN appliance</title>
    <link>https://example.com/a1</link>
    <pubDate>Mon, 08 Sep 2026 12:00:00 GMT</pubDate>
    <description>Attackers used a zero-day RCE to deploy ransomware.</description>
  </item>
  <item>
    <title>Phishing campaign targets finance teams</title>
    <link>https://example.com/a2</link>
    <pubDate>Tue, 09 Sep 2026 08:30:00 GMT</pubDate>
    <description>Business email compromise via credential phishing.</description>
  </item>
</channel></rss>"""


def test_parse_rss_feed_extracts_articles():
    articles = parse_rss_feed(SAMPLE_RSS, source_name="Example Security Feed")
    assert len(articles) == 2
    assert articles[0].title == "Ransomware gang exploits zero-day in VPN appliance"
    assert articles[0].link == "https://example.com/a1"
    assert articles[0].source == "Example Security Feed"


def test_parse_rss_feed_skips_items_missing_a_link():
    broken = SAMPLE_RSS.replace(
        "<link>https://example.com/a1</link>", ""
    )
    articles = parse_rss_feed(broken, source_name="Example Security Feed")
    assert len(articles) == 1


def test_default_feeds_are_all_https():
    assert DEFAULT_FEEDS
    assert all(feed.url.startswith("https://") for feed in DEFAULT_FEEDS)


def test_mock_articles_returns_offline_fixture_data():
    articles = mock_articles()
    assert articles
    assert all(article.source for article in articles)
