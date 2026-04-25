"""Tests for nftpol/renderer.py"""
import pytest

from nftpol.config import TransverseNetwork
from nftpol.policy import EgressRule, Policy
from nftpol.renderer import (
    render_block,
    render_host_ipsets_file,
    render_set,
    render_static_section,
    render_transverse_block,
)


def _policy(*rules, default="deny"):
    return Policy(egress_rules=list(rules), egress_default=default)


# --- render_set ---


def test_render_set_with_ips():
    out = render_set("myapp", "egress", ["1.2.3.4", "5.6.7.8"])
    assert "set myapp-egress-dynamic {" in out
    assert "1.2.3.4" in out
    assert "5.6.7.8" in out


def test_render_set_empty():
    out = render_set("myapp", "egress", [])
    assert "set myapp-egress-dynamic {" in out
    assert "elements" not in out


def test_render_set_custom_key():
    out = render_set("myapp", "backend", ["10.0.0.1"])
    assert "set myapp-backend-dynamic {" in out
    assert "set myapp-egress-dynamic {" not in out


# --- render_block ---


def test_render_block_cidr_tcp_port():
    rule = EgressRule(cidr="185.125.190.0/24", proto="tcp", port=443, comment="apt")
    out = render_block("myapp", "abc1234", _policy(rule), {}, "eth0")
    assert 'iifname "b.abc1234.egs"' in out
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
    out = render_block("myapp", "abc1234", _policy(*rules), {}, "eth0")
    # Should have one rule for port 443 containing both CIDRs, one for port 80
    lines = [l for l in out.splitlines() if "tcp dport 443" in l]
    assert len(lines) == 1
    assert "1.0.0.0/8" in lines[0] and "2.0.0.0/8" in lines[0]
    lines80 = [l for l in out.splitlines() if "tcp dport 80" in l]
    assert len(lines80) == 1


def test_render_block_proto_only():
    rule = EgressRule(cidr="10.0.0.0/8", proto="tcp")
    out = render_block("myapp", "abc1234", _policy(rule), {}, "eth0")
    assert "tcp dport" in out
    assert "port" not in out.replace("tcp dport", "")  # no port number after "tcp dport"


def test_render_block_port_only():
    rule = EgressRule(cidr="10.0.0.0/8", port=443)
    out = render_block("myapp", "abc1234", _policy(rule), {}, "eth0")
    assert "th dport 443" in out


def test_render_block_neither_proto_nor_port():
    rule = EgressRule(cidr="10.0.0.0/8")
    out = render_block("myapp", "abc1234", _policy(rule), {}, "eth0")
    assert "10.0.0.0/8" in out
    assert "return" in out
    assert "dport" not in out


def test_render_block_default_deny_emits_drop():
    out = render_block("myapp", "abc1234", _policy(default="deny"), {}, "eth0")
    assert "drop" in out
    assert "b.abc1234.egs" in out


def test_render_block_default_accept_no_drop():
    rule = EgressRule(cidr="10.0.0.0/8")
    out = render_block("myapp", "abc1234", _policy(rule, default="accept"), {}, "eth0")
    assert "drop" not in out


def test_render_block_empty_allow_default_deny():
    out = render_block("myapp", "abc1234", _policy(default="deny"), {}, "eth0")
    lines = [l.strip() for l in out.splitlines() if l.strip()]
    assert len(lines) == 1
    assert "drop" in lines[0]


def test_render_block_dynamic_rule_references_set():
    rule = EgressRule(fqdn="vpn.example.com", proto="tcp", port=443)
    out = render_block("myapp", "abc1234", _policy(rule), {"egress": ["1.2.3.4"]}, "eth0")
    assert "@myapp-egress-dynamic" in out
    assert "tcp dport 443" in out
    assert "return" in out


def test_render_block_dynamic_no_ips_skips_dynamic_rule():
    rule = EgressRule(fqdn="vpn.example.com", proto="tcp", port=443)
    out = render_block("myapp", "abc1234", _policy(rule), {}, "eth0")
    assert "@myapp-egress-dynamic" not in out


def test_render_block_cidr_url_dynamic_rule_references_set():
    rule = EgressRule(cidr_url="https://example.com/ips", proto="tcp", port=443)
    out = render_block("myapp", "abc1234", _policy(rule), {"egress": ["103.21.244.0/22"]}, "eth0")
    assert "@myapp-egress-dynamic" in out
    assert "tcp dport 443" in out
    assert "return" in out


def test_render_block_cidr_url_no_ips_skips_dynamic_rule():
    rule = EgressRule(cidr_url="https://example.com/ips", proto="tcp", port=443)
    out = render_block("myapp", "abc1234", _policy(rule), {}, "eth0")
    assert "@myapp-egress-dynamic" not in out


def test_render_block_cidr_url_and_fqdn_same_proto_port_emit_one_rule():
    rules = [
        EgressRule(fqdn="vpn.example.com", proto="tcp", port=443),
        EgressRule(cidr_url="https://example.com/ips", proto="tcp", port=443),
    ]
    out = render_block(
        "myapp", "abc1234", _policy(*rules),
        {"egress": ["1.2.3.4", "103.21.244.0/22"]}, "eth0",
    )
    dyn_lines = [l for l in out.splitlines() if "@myapp-egress-dynamic" in l and "443" in l]
    assert len(dyn_lines) == 1


def test_render_set_plain_ips_no_interval_flag():
    out = render_set("myapp", "egress", ["1.2.3.4", "5.6.7.8"])
    assert "flags interval" not in out


def test_render_set_accepts_cidr_notation():
    out = render_set("myapp", "egress", ["1.2.3.4", "103.21.244.0/22"])
    assert "103.21.244.0/22" in out
    assert "1.2.3.4" in out
    assert "flags interval" in out


def test_render_set_empty_no_interval_flag():
    out = render_set("myapp", "egress", [])
    assert "flags interval" not in out


def test_render_block_via_uses_bridge_map():
    """Rules with via: use the mapped bridge; default deny still uses default egress bridge."""
    rule = EgressRule(cidr="10.0.0.0/8", proto="tcp", port=5432, via="backend")
    bridge_map = {"backend": "b.abc1234.bck"}
    out = render_block("myapp", "abc1234", _policy(rule), {}, "eth0", bridge_map=bridge_map)
    # The explicit CIDR rule uses the backend bridge
    cidr_lines = [l for l in out.splitlines() if "10.0.0.0/8" in l]
    assert len(cidr_lines) == 1
    assert 'iifname "b.abc1234.bck"' in cidr_lines[0]
    # The default deny drop uses the default egress bridge
    drop_lines = [l for l in out.splitlines() if "drop" in l]
    assert len(drop_lines) == 1
    assert 'iifname "b.abc1234.egs"' in drop_lines[0]


def test_render_block_via_missing_from_bridge_map_skips_rule():
    """Rules with via: that is not in bridge_map are silently skipped."""
    rule = EgressRule(cidr="10.0.0.0/8", proto="tcp", port=5432, via="unknown-net")
    out = render_block("myapp", "abc1234", _policy(rule), {}, "eth0", bridge_map={})
    assert "10.0.0.0/8" not in out


def test_render_block_via_dynamic_rule_references_via_set():
    """Dynamic rule with via uses {app_id}-{via}-dynamic set name."""
    rule = EgressRule(fqdn="db.example.com", proto="tcp", port=5432, via="backend")
    bridge_map = {"backend": "b.abc1234.bck"}
    out = render_block(
        "myapp", "abc1234", _policy(rule),
        {"backend": ["10.0.0.5"]}, "eth0", bridge_map=bridge_map,
    )
    assert "@myapp-backend-dynamic" in out
    assert "@myapp-egress-dynamic" not in out
    assert 'iifname "b.abc1234.bck"' in out


def test_render_block_mixed_via_and_default():
    """Rules with and without via coexist on their respective bridges."""
    rules = [
        EgressRule(cidr="1.0.0.0/8", proto="tcp", port=443),          # default egress
        EgressRule(cidr="10.0.0.0/8", proto="tcp", port=5432, via="backend"),  # backend
    ]
    bridge_map = {"backend": "b.abc1234.bck"}
    out = render_block("myapp", "abc1234", _policy(*rules), {}, "eth0", bridge_map=bridge_map)
    assert 'iifname "b.abc1234.egs"' in out
    assert 'iifname "b.abc1234.bck"' in out


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


# --- render_transverse_block ---


def _outbound(name="edge_rp", bridge="br-edge-rp", ip="172.26.48.1", comment=""):
    return TransverseNetwork(name=name, bridge=bridge, privileged_ip=ip,
                             direction="outbound", comment=comment)


def _inbound(name="shared_db", bridge="br-db", ip="172.26.48.65", comment=""):
    return TransverseNetwork(name=name, bridge=bridge, privileged_ip=ip,
                             direction="inbound", comment=comment)


def test_render_transverse_block_outbound_saddr_initiates():
    """Outbound: privileged_ip initiates → saddr match + ct state for replies + drop."""
    out = render_transverse_block(_outbound())
    assert 'iifname "br-edge-rp" oifname "br-edge-rp" ip saddr 172.26.48.1 return' in out
    assert 'iifname "br-edge-rp" oifname "br-edge-rp" ip daddr 172.26.48.1 ct state { established, related } return' in out
    assert 'iifname "br-edge-rp" oifname "br-edge-rp" drop' in out


def test_render_transverse_block_inbound_daddr_initiates():
    """Inbound: others initiate toward privileged_ip → daddr match + ct state + drop."""
    out = render_transverse_block(_inbound())
    assert 'iifname "br-db" oifname "br-db" ip daddr 172.26.48.65 return' in out
    assert 'iifname "br-db" oifname "br-db" ip saddr 172.26.48.65 ct state { established, related } return' in out
    assert 'iifname "br-db" oifname "br-db" drop' in out


def test_render_transverse_block_comment_included():
    out = render_transverse_block(_outbound(comment="Traefik RP"))
    assert "Traefik RP" in out


def test_render_transverse_block_no_comment_no_extra_noise():
    out = render_transverse_block(_outbound(comment=""))
    # Comment line should just be the name, no trailing noise
    comment_lines = [l for l in out.splitlines() if l.strip().startswith("#")]
    assert len(comment_lines) == 1
    assert "edge_rp" in comment_lines[0]


def test_render_transverse_block_uses_indent():
    """All rule lines must start with 8 spaces to match nftables file indentation."""
    out = render_transverse_block(_outbound())
    rule_lines = [l for l in out.splitlines() if "iifname" in l]
    assert all(l.startswith("        ") for l in rule_lines)


# --- render_static_section ---


def test_render_static_section_empty():
    out = render_static_section([])
    assert "# === STATIC BEGIN ===" in out
    assert "# === STATIC END ===" in out
    assert "iifname" not in out


def test_render_static_section_single_network():
    out = render_static_section([_outbound()])
    assert "# === STATIC BEGIN ===" in out
    assert "# === STATIC END ===" in out
    assert "br-edge-rp" in out
    assert out.index("# === STATIC BEGIN ===") < out.index("# === STATIC END ===")


def test_render_static_section_two_networks():
    out = render_static_section([_outbound(), _inbound()])
    assert "br-edge-rp" in out
    assert "br-db" in out
    assert out.index("# === STATIC BEGIN ===") < out.index("# === STATIC END ===")


def test_render_static_section_markers_indented():
    """BEGIN/END markers must have 8-space indent."""
    out = render_static_section([])
    for line in out.splitlines():
        if "STATIC BEGIN" in line or "STATIC END" in line:
            assert line.startswith("        "), f"marker not indented: {line!r}"
