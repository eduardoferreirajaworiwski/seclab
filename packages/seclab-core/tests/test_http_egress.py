import socket

import pytest
from seclab.core.http import EgressBlockedError, EgressPolicy


def test_check_returns_the_validated_ip_literal():
    policy = EgressPolicy()
    assert policy.check("http://8.8.8.8/") == "8.8.8.8"


def test_unresolvable_host_is_blocked_not_allowed_through(monkeypatch):
    # Used to `return` (allow the request) when getaddrinfo raised
    # gaierror - the one case where nothing had actually been validated.
    def _raise(*args, **kwargs):
        raise socket.gaierror("name or service not known")

    monkeypatch.setattr(socket, "getaddrinfo", _raise)
    policy = EgressPolicy()
    with pytest.raises(EgressBlockedError):
        policy.check("https://this-host-does-not-resolve.invalid/")


def test_blocks_multicast_address():
    policy = EgressPolicy()
    with pytest.raises(EgressBlockedError):
        policy.check("http://224.0.0.1/")


def test_blocks_cgnat_shared_address_space():
    # 100.64.0.0/10 (RFC 6598): not is_private, not is_loopback, but not
    # publicly routable either - a range the original enumerated check
    # missed entirely. "not is_global" catches it by construction.
    policy = EgressPolicy()
    with pytest.raises(EgressBlockedError):
        policy.check("http://100.64.0.1/")


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
