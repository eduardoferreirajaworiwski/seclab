from seclab_sensor_chimera.detection import is_suspicious_ua, sanitize_input, touches_sensitive_path


def test_detects_known_scanner_user_agents():
    assert is_suspicious_ua("sqlmap/1.6")
    assert is_suspicious_ua("Mozilla/5.0 (compatible; Nmap Scripting Engine)")
    assert not is_suspicious_ua("Mozilla/5.0 (Windows NT 10.0; Win64; x64)")


def test_touches_sensitive_path_matches_known_markers():
    assert touches_sensitive_path("/.env")
    assert touches_sensitive_path("/.aws/credentials")
    assert touches_sensitive_path("/.git/config")
    assert not touches_sensitive_path("/index.html")


def test_sanitize_input_strips_non_printable_and_truncates():
    dirty = "abc\x00def" + "x" * 600
    cleaned = sanitize_input(dirty)
    assert "\x00" not in cleaned
    assert len(cleaned) <= 500
