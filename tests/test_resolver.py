"""Tests for nftpol/resolver.py"""
import socket
from unittest.mock import MagicMock, patch

import pytest

from nftpol.policy import EgressRule, Policy
from nftpol.resolver import (
    ResolverError,
    collect_dynamic_ips,
    resolve_cidr_url,
    resolve_fqdn,
    resolve_service,
)


def _make_addrinfo(ips: list[str]):
    return [(None, None, None, None, (ip, 0)) for ip in ips]


def test_fqdn_resolution_returns_deduplicated_ipv4():
    with patch("socket.getaddrinfo") as mock_gai:
        mock_gai.return_value = _make_addrinfo(["1.2.3.4", "1.2.3.4", "5.6.7.8"])
        result = resolve_fqdn("example.com")
    assert result == ["1.2.3.4", "5.6.7.8"]


def test_fqdn_resolution_failure_returns_empty_list_no_exception():
    with patch("socket.getaddrinfo", side_effect=socket.gaierror("nxdomain")):
        result = resolve_fqdn("nonexistent.invalid")
    assert result == []


def test_service_with_running_container_returns_ips():
    mock_container = MagicMock()
    mock_container.attrs = {
        "NetworkSettings": {
            "Networks": {
                "net1": {"IPAddress": "172.17.0.2"},
                "net2": {"IPAddress": "10.0.0.5"},
            }
        }
    }
    mock_client = MagicMock()
    mock_client.containers.list.return_value = [mock_container]

    with patch.dict("sys.modules", {"docker": MagicMock(from_env=lambda: mock_client)}):
        import importlib
        import nftpol.resolver as res_mod
        importlib.reload(res_mod)
        result = res_mod.resolve_service("myproject", "myservice")

    assert "172.17.0.2" in result
    assert "10.0.0.5" in result


def test_service_with_no_containers_returns_empty_list_no_exception():
    mock_client = MagicMock()
    mock_client.containers.list.return_value = []

    with patch.dict("sys.modules", {"docker": MagicMock(from_env=lambda: mock_client)}):
        import importlib
        import nftpol.resolver as res_mod
        importlib.reload(res_mod)
        result = res_mod.resolve_service("myproject", "missing")

    assert result == []


def test_collect_dynamic_ips_deduplicates():
    policy = Policy(
        egress_rules=[
            EgressRule(fqdn="example.com"),
            EgressRule(fqdn="example.com"),
        ]
    )
    with patch("nftpol.resolver.resolve_fqdn", return_value=["1.2.3.4"]):
        result = collect_dynamic_ips(policy)
    assert result == {"egress": ["1.2.3.4"]}


def test_collect_dynamic_ips_skips_cidr():
    policy = Policy(egress_rules=[EgressRule(cidr="10.0.0.0/8")])
    with patch("nftpol.resolver.resolve_fqdn") as mock_fqdn:
        result = collect_dynamic_ips(policy)
    mock_fqdn.assert_not_called()
    assert result == {}


def _mock_url_response(body: bytes):
    mock_resp = MagicMock()
    mock_resp.read.return_value = body
    mock_resp.__enter__ = lambda s: s
    mock_resp.__exit__ = MagicMock(return_value=False)
    return mock_resp


def test_resolve_cidr_url_returns_valid_cidrs():
    body = b"103.21.244.0/22\n103.22.200.0/22\n# comment\n\n198.41.128.0/17\n"
    with patch("urllib.request.urlopen", return_value=_mock_url_response(body)):
        result = resolve_cidr_url("https://example.com/ips-v4")
    assert result == ["103.21.244.0/22", "103.22.200.0/22", "198.41.128.0/17"]


def test_resolve_cidr_url_skips_invalid_entries():
    body = b"103.21.244.0/22\nnot-an-ip\n256.0.0.1\n"
    with patch("urllib.request.urlopen", return_value=_mock_url_response(body)):
        result = resolve_cidr_url("https://example.com/ips-v4")
    assert result == ["103.21.244.0/22"]


def test_resolve_cidr_url_deduplicates():
    body = b"103.21.244.0/22\n103.21.244.0/22\n"
    with patch("urllib.request.urlopen", return_value=_mock_url_response(body)):
        result = resolve_cidr_url("https://example.com/ips-v4")
    assert result == ["103.21.244.0/22"]


def test_resolve_cidr_url_network_error_returns_empty_list():
    import urllib.error
    with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("timeout")):
        result = resolve_cidr_url("https://example.com/ips-v4")
    assert result == []


def test_resolve_cidr_url_skips_comments_and_blank_lines():
    body = b"# Cloudflare IPs\n\n103.21.244.0/22\n"
    with patch("urllib.request.urlopen", return_value=_mock_url_response(body)):
        result = resolve_cidr_url("https://example.com/ips-v4")
    assert result == ["103.21.244.0/22"]


def test_collect_dynamic_ips_includes_cidr_url():
    policy = Policy(egress_rules=[EgressRule(cidr_url="https://example.com/ips")])
    with patch("nftpol.resolver.resolve_cidr_url", return_value=["103.21.244.0/22"]):
        result = collect_dynamic_ips(policy)
    assert result == {"egress": ["103.21.244.0/22"]}


def test_collect_dynamic_ips_plain_cidr_does_not_trigger_cidr_url():
    policy = Policy(egress_rules=[EgressRule(cidr="10.0.0.0/8")])
    with patch("nftpol.resolver.resolve_cidr_url") as mock_curl:
        collect_dynamic_ips(policy)
    mock_curl.assert_not_called()


def test_collect_dynamic_ips_groups_by_via():
    """Rules with different via values produce separate groups."""
    policy = Policy(
        egress_rules=[
            EgressRule(fqdn="ext.example.com"),            # no via → egress
            EgressRule(fqdn="db.example.com", via="backend"),
        ]
    )
    def fake_resolve(fqdn):
        return ["1.2.3.4"] if "ext" in fqdn else ["10.0.0.5"]

    with patch("nftpol.resolver.resolve_fqdn", side_effect=fake_resolve):
        result = collect_dynamic_ips(policy)
    assert result == {"egress": ["1.2.3.4"], "backend": ["10.0.0.5"]}
