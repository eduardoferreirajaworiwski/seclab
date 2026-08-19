import pytest
from seclab.core.http import EgressBlockedError, EgressPolicy


def test_blocks_loopback_ip_literal():
    policy = EgressPolicy()
    with pytest.raises(EgressBlockedError):
        policy.check("http://127.0.0.1/secret")


def test_blocks_private_range_ip_literal():
    policy = EgressPolicy()
    with pytest.raises(EgressBlockedError):
        policy.check("http://10.0.0.5/internal")


def test_blocks_link_local_ip_literal():
    policy = EgressPolicy()
    with pytest.raises(EgressBlockedError):
        policy.check("http://169.254.169.254/latest/meta-data/")


def test_allows_public_ip_literal():
    policy = EgressPolicy()
    policy.check("http://8.8.8.8/")  # should not raise


def test_rejects_non_http_scheme():
    policy = EgressPolicy()
    with pytest.raises(EgressBlockedError):
        policy.check("file:///etc/passwd")


def test_allowlist_rejects_host_not_listed():
    policy = EgressPolicy(allowlist=["crt.sh"])
    with pytest.raises(EgressBlockedError):
        policy.check("https://evil.example.com/")


def test_allowlist_permits_listed_host():
    policy = EgressPolicy(allowlist=["crt.sh"])
    policy.check("https://crt.sh/?q=example.com")  # should not raise
