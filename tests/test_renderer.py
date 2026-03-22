"""Tests for nftpol/renderer.py"""
import pytest

from nftpol.policy import EgressRule, Policy
from nftpol.renderer import render_block, render_host_ipsets_file, render_set


def _policy(*rules, default="deny"):
    return Policy(egress_rules=list(rules), egress_default=default)


# --- render_set ---


def test_render_set_with_ips():
    out = render_set("myapp", ["1.2.3.4", "5.6.7.8"])
    assert "set myapp-egress-dynamic {" in out
    assert "1.2.3.4" in out
    assert "5.6.7.8" in out
    assert 'comment "managed: myapp"' in out


def test_render_set_empty():
    out = render_set("myapp", [])
    assert "set myapp-egress-dynamic {" in out
    assert "elements" not in out


# --- render_block ---


def test_render_block_cidr_tcp_port():
    rule = EgressRule(cidr="185.125.190.0/24", proto="tcp", port=443, comment="apt")
    out = render_block("myapp", _policy(rule), [], "eth0")
    assert 'iifname "br-myapp-egress"' in out
    assert "tcp dport 443" in out
    assert "185.125.190.0/24" in out
    assert "return" in out
    assert 'comment "apt"' in out


def test_render_block_cidr_groups_by_proto_port():
    rules = [
        EgressRule(cidr="1.0.0.0/8", proto="tcp", port=443),
        EgressRule(cidr="2.0.0.0/8", proto="tcp", port=443),
        EgressRule(cidr="3.0.0.0/8", proto="tcp", port=80),
    ]
    out = render_block("myapp", _policy(*rules), [], "eth0")
    # Should have one rule for port 443 containing both CIDRs, one for port 80
    lines = [l for l in out.splitlines() if "tcp dport 443" in l]
    assert len(lines) == 1
    assert "1.0.0.0/8" in lines[0] and "2.0.0.0/8" in lines[0]
    lines80 = [l for l in out.splitlines() if "tcp dport 80" in l]
    assert len(lines80) == 1


def test_render_block_proto_only():
    rule = EgressRule(cidr="10.0.0.0/8", proto="tcp")
    out = render_block("myapp", _policy(rule), [], "eth0")
    assert "tcp dport" in out
    assert "port" not in out.replace("tcp dport", "")  # no port number after "tcp dport"


def test_render_block_port_only():
    rule = EgressRule(cidr="10.0.0.0/8", port=443)
    out = render_block("myapp", _policy(rule), [], "eth0")
    assert "th dport 443" in out


def test_render_block_neither_proto_nor_port():
    rule = EgressRule(cidr="10.0.0.0/8")
    out = render_block("myapp", _policy(rule), [], "eth0")
    assert "10.0.0.0/8" in out
    assert "return" in out
    assert "dport" not in out


def test_render_block_default_deny_emits_drop():
    out = render_block("myapp", _policy(default="deny"), [], "eth0")
    assert "drop" in out
    assert "br-myapp-egress" in out


def test_render_block_default_accept_no_drop():
    rule = EgressRule(cidr="10.0.0.0/8")
    out = render_block("myapp", _policy(rule, default="accept"), [], "eth0")
    assert "drop" not in out


def test_render_block_empty_allow_default_deny():
    out = render_block("myapp", _policy(default="deny"), [], "eth0")
    lines = [l.strip() for l in out.splitlines() if l.strip()]
    assert len(lines) == 1
    assert "drop" in lines[0]


def test_render_block_dynamic_rule_references_set():
    rule = EgressRule(fqdn="vpn.example.com", proto="tcp", port=443)
    out = render_block("myapp", _policy(rule), ["1.2.3.4"], "eth0")
    assert "@myapp-egress-dynamic" in out
    assert "tcp dport 443" in out
    assert "return" in out


def test_render_block_dynamic_no_ips_skips_dynamic_rule():
    rule = EgressRule(fqdn="vpn.example.com", proto="tcp", port=443)
    out = render_block("myapp", _policy(rule), [], "eth0")
    assert "@myapp-egress-dynamic" not in out


def test_render_block_cidr_url_dynamic_rule_references_set():
    rule = EgressRule(cidr_url="https://example.com/ips", proto="tcp", port=443)
    out = render_block("myapp", _policy(rule), ["103.21.244.0/22"], "eth0")
    assert "@myapp-egress-dynamic" in out
    assert "tcp dport 443" in out
    assert "return" in out


def test_render_block_cidr_url_no_ips_skips_dynamic_rule():
    rule = EgressRule(cidr_url="https://example.com/ips", proto="tcp", port=443)
    out = render_block("myapp", _policy(rule), [], "eth0")
    assert "@myapp-egress-dynamic" not in out


def test_render_block_cidr_url_and_fqdn_same_proto_port_emit_one_rule():
    rules = [
        EgressRule(fqdn="vpn.example.com", proto="tcp", port=443),
        EgressRule(cidr_url="https://example.com/ips", proto="tcp", port=443),
    ]
    out = render_block("myapp", _policy(*rules), ["1.2.3.4", "103.21.244.0/22"], "eth0")
    dyn_lines = [l for l in out.splitlines() if "@myapp-egress-dynamic" in l and "443" in l]
    assert len(dyn_lines) == 1


def test_render_set_accepts_cidr_notation():
    out = render_set("myapp", ["1.2.3.4", "103.21.244.0/22"])
    assert "103.21.244.0/22" in out
    assert "1.2.3.4" in out


# --- render_host_ipsets_file ---


def test_render_host_ipsets_file_structure():
    out = render_host_ipsets_file({"cloudflare-ipv4": ["103.21.244.0/22", "103.22.200.0/22"]})
    assert "table inet fw-host {" in out
    assert "set cloudflare-ipv4 {" in out
    assert "type ipv4_addr" in out
    assert "flags interval" in out
    assert "103.21.244.0/22" in out
    assert "103.22.200.0/22" in out
    assert 'comment "managed: cloudflare-ipv4"' in out
    assert "MANAGED BY nftpol" in out


def test_render_host_ipsets_file_empty_set():
    out = render_host_ipsets_file({"cloudflare-ipv4": []})
    assert "set cloudflare-ipv4 {" in out
    assert "elements" not in out


def test_render_host_ipsets_file_multiple_sets():
    out = render_host_ipsets_file({
        "cloudflare-ipv4": ["1.2.3.0/24"],
        "my-set": ["10.0.0.1"],
    })
    assert "set cloudflare-ipv4 {" in out
    assert "set my-set {" in out


def test_render_host_ipsets_file_elements_sorted():
    out = render_host_ipsets_file({"s": ["200.0.0.0/8", "100.0.0.0/8"]})
    idx_100 = out.index("100.0.0.0/8")
    idx_200 = out.index("200.0.0.0/8")
    assert idx_100 < idx_200
