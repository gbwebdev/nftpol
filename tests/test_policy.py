"""Tests for nftpol/policy.py"""
import textwrap
from pathlib import Path

import pytest
import yaml

from nftpol.policy import (
    EgressRule,
    Policy,
    PolicyError,
    load_policy,
    validate_fqdn_domains,
)


def _write_policy(tmp_path: Path, data: dict) -> Path:
    p = tmp_path / "firewall-policy.yml"
    p.write_text(yaml.dump(data))
    return p


def test_valid_policy_parses(tmp_path):
    p = _write_policy(
        tmp_path,
        {
            "egress": {
                "allow": [
                    {"cidr": "1.2.3.0/24", "proto": "tcp", "port": 443, "comment": "test"},
                    {"fqdn": "vpn.example.com", "proto": "tcp", "port": 443},
                    {"service": "proj/svc", "proto": "tcp", "port": 5432},
                ],
                "default": "deny",
            }
        },
    )
    policy = load_policy(p)
    assert len(policy.egress_rules) == 3
    assert policy.egress_default == "deny"
    assert policy.egress_rules[0].cidr == "1.2.3.0/24"
    assert policy.egress_rules[1].fqdn == "vpn.example.com"
    assert policy.egress_rules[2].service == "proj/svc"


def test_default_accept(tmp_path):
    p = _write_policy(tmp_path, {"egress": {"allow": [], "default": "accept"}})
    policy = load_policy(p)
    assert policy.egress_default == "accept"


def test_invalid_proto_raises(tmp_path):
    p = _write_policy(
        tmp_path,
        {"egress": {"allow": [{"cidr": "1.2.3.0/24", "proto": "icmp"}]}},
    )
    with pytest.raises(PolicyError, match="proto"):
        load_policy(p)


def test_port_out_of_range_raises(tmp_path):
    p = _write_policy(
        tmp_path,
        {"egress": {"allow": [{"cidr": "1.2.3.0/24", "port": 99999}]}},
    )
    with pytest.raises(PolicyError, match="port"):
        load_policy(p)


def test_port_zero_raises(tmp_path):
    p = _write_policy(
        tmp_path,
        {"egress": {"allow": [{"cidr": "1.2.3.0/24", "port": 0}]}},
    )
    with pytest.raises(PolicyError, match="port"):
        load_policy(p)


def test_fqdn_under_trusted_domain_passes():
    policy = Policy(egress_rules=[EgressRule(fqdn="vpn.example.com")])
    validate_fqdn_domains(policy, ["example.com"])  # should not raise


def test_fqdn_exact_trusted_domain_passes():
    policy = Policy(egress_rules=[EgressRule(fqdn="example.com")])
    validate_fqdn_domains(policy, ["example.com"])  # should not raise


def test_fqdn_under_untrusted_domain_raises():
    policy = Policy(egress_rules=[EgressRule(fqdn="hub.docker.com")])
    with pytest.raises(PolicyError, match="hub.docker.com"):
        validate_fqdn_domains(policy, ["example.com"])


def test_multiple_untrusted_fqdns_reported_together():
    policy = Policy(
        egress_rules=[
            EgressRule(fqdn="hub.docker.com"),
            EgressRule(fqdn="github.com"),
            EgressRule(fqdn="vpn.example.com"),
        ]
    )
    with pytest.raises(PolicyError) as exc_info:
        validate_fqdn_domains(policy, ["example.com"])
    msg = str(exc_info.value)
    assert "hub.docker.com" in msg
    assert "github.com" in msg
    assert "vpn.example.com" not in msg  # this one is trusted


def test_no_trusted_domains_with_fqdn_raises():
    policy = Policy(egress_rules=[EgressRule(fqdn="example.com")])
    with pytest.raises(PolicyError, match="trusted_fqdn_domains"):
        validate_fqdn_domains(policy, [])


def test_no_trusted_domains_without_fqdn_passes():
    policy = Policy(egress_rules=[EgressRule(cidr="1.2.3.0/24")])
    validate_fqdn_domains(policy, [])  # should not raise


def test_invalid_default_raises(tmp_path):
    p = _write_policy(tmp_path, {"egress": {"default": "reject"}})
    with pytest.raises(PolicyError, match="default"):
        load_policy(p)


def test_missing_file_raises():
    with pytest.raises(PolicyError, match="not found"):
        load_policy(Path("/nonexistent/firewall-policy.yml"))


def test_cidr_url_valid_parses(tmp_path):
    p = _write_policy(
        tmp_path,
        {
            "egress": {
                "allow": [
                    {
                        "cidr_url": "https://www.cloudflare.com/ips-v4/#",
                        "proto": "tcp",
                        "port": 443,
                        "comment": "Cloudflare IPs",
                    }
                ],
                "default": "deny",
            }
        },
    )
    policy = load_policy(p)
    assert len(policy.egress_rules) == 1
    assert policy.egress_rules[0].cidr_url == "https://www.cloudflare.com/ips-v4/#"
    assert policy.egress_rules[0].proto == "tcp"
    assert policy.egress_rules[0].port == 443


def test_cidr_url_http_scheme_also_valid(tmp_path):
    p = _write_policy(
        tmp_path,
        {"egress": {"allow": [{"cidr_url": "http://example.com/ips.txt"}]}},
    )
    policy = load_policy(p)
    assert policy.egress_rules[0].cidr_url == "http://example.com/ips.txt"


def test_cidr_url_invalid_scheme_raises(tmp_path):
    p = _write_policy(
        tmp_path,
        {"egress": {"allow": [{"cidr_url": "ftp://example.com/ips.txt"}]}},
    )
    with pytest.raises(PolicyError, match="cidr_url"):
        load_policy(p)


def test_cidr_url_non_string_raises(tmp_path):
    p = _write_policy(
        tmp_path,
        {"egress": {"allow": [{"cidr_url": 12345}]}},
    )
    with pytest.raises(PolicyError, match="cidr_url"):
        load_policy(p)


def test_cidr_url_cannot_combine_with_cidr(tmp_path):
    p = _write_policy(
        tmp_path,
        {
            "egress": {
                "allow": [
                    {"cidr": "1.2.3.0/24", "cidr_url": "https://example.com/ips"}
                ]
            }
        },
    )
    with pytest.raises(PolicyError, match="exactly one of"):
        load_policy(p)
