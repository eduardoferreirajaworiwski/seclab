from seclab_monitor.listener import _extract_matches

HEARTBEAT = {"message_type": "heartbeat"}


def _cert_message(domains: list[str], issuer: str = "Let's Encrypt") -> dict:
    return {
        "message_type": "certificate_update",
        "data": {"leaf_cert": {"all_domains": domains, "issuer": {"O": issuer}}},
    }


def test_heartbeat_produces_no_matches():
    assert _extract_matches(HEARTBEAT, keywords=["microsoft"]) == []


def test_matches_keyword_case_insensitively_but_preserves_original_casing():
    message = _cert_message(["login-Microsoft-support.com"])
    matches = _extract_matches(message, keywords=["microsoft"])
    assert matches == [("login-Microsoft-support.com", "Let's Encrypt", "microsoft")]


def test_wildcard_prefix_is_stripped_exactly_once():
    message = _cert_message(["*.microsoft.com"])
    matches = _extract_matches(message, keywords=["microsoft"])
    assert matches[0][0] == "microsoft.com"


def test_leading_dots_that_are_not_the_wildcard_marker_are_preserved():
    # hydra-mapper's original used domain.lstrip("*."), which strips a
    # *character set* - it keeps eating any leading '*' or '.' characters,
    # not just one literal "*." prefix. A malformed/unusual CT entry with an
    # extra leading dot would be silently mangled by lstrip but is left
    # intact here since removeprefix only removes the exact "*." prefix once.
    message = _cert_message(["*..microsoft.com"])
    matches = _extract_matches(message, keywords=["microsoft"])
    assert matches[0][0] == ".microsoft.com"


def test_non_matching_domain_is_ignored():
    message = _cert_message(["example.com"])
    assert _extract_matches(message, keywords=["microsoft", "google"]) == []


def test_multiple_domains_only_matching_ones_returned():
    message = _cert_message(["example.com", "secure-google-login.net"])
    matches = _extract_matches(message, keywords=["google"])
    assert len(matches) == 1
    assert matches[0][0] == "secure-google-login.net"
