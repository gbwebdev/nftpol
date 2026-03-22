"""Render nftables named-set and chain-rule blocks."""
from __future__ import annotations

from collections import defaultdict

from .config import HostRestrictedPort
from .policy import EgressRule, Policy

_INDENT = "        "  # 8 spaces — matches marker indentation in managed file


def render_set(app_id: str, ips: list[str]) -> str:
    """Render the named set block for dynamic IPs (docker egress)."""
    lines = [
        f"    # managed: {app_id}",
        f"    set {app_id}-egress-dynamic {{",
        f"        type ipv4_addr",
        f"        flags interval",
        f'        comment "managed: {app_id}"',
    ]
    if ips:
        elements = ", ".join(sorted(ips))
        lines.append(f"        elements = {{ {elements} }}")
    lines.append("    }")
    return "\n".join(lines) + "\n"


def render_host_ipsets_file(
    ipsets: dict[str, list[str]],
    restricted_ports: list[HostRestrictedPort] | None = None,
) -> str:
    """Render the full /etc/nftables.d/05-host-ipsets.nft managed file.

    ipsets: mapping of set_name → list of CIDRs/IPs fetched from configured URLs.
    restricted_ports: ports whose access is gated by an ipset.

    The file defines named sets and a host-restrict chain (priority filter - 1) inside
    table inet fw-host.  The restrict chain accepts matching traffic before the main input
    chain sees it, and drops everything else on restricted ports.  10-host.nft is therefore
    completely standalone — it simply opens the port to all, but the restrict chain runs
    first and gates it.
    """
    if restricted_ports is None:
        restricted_ports = []

    lines = [
        "# THIS FILE IS MANAGED BY nftpol - DO NOT EDIT MANUALLY",
        "",
        "table inet fw-host {",
    ]

    # --- named sets ---
    for name, entries in sorted(ipsets.items()):
        lines.append("")
        lines.append(f"    # managed: {name}")
        lines.append(f"    set {name} {{")
        lines.append(f"        type ipv4_addr")
        lines.append(f"        flags interval")
        lines.append(f'        comment "managed: {name}"')
        if entries:
            elements = ", ".join(sorted(entries))
            lines.append(f"        elements = {{ {elements} }}")
        lines.append(f"    }}")

    # --- host-restrict chain (only when there are port restrictions) ---
    if restricted_ports:
        lines.append("")
        lines.append("    chain host-restrict {")
        lines.append("        type filter hook input priority filter - 1;")
        lines.append("")
        for rp in restricted_ports:
            comment = f' comment "{rp.comment}"' if rp.comment else ""
            lines.append(
                f"        ip saddr @{rp.ipset} tcp dport {rp.port} accept{comment}"
            )
            lines.append(
                f'        tcp dport {rp.port} drop comment "block non-{rp.ipset} on {rp.port}"'
            )
        lines.append("    }")

    lines.append("}")
    lines.append("")
    return "\n".join(lines)


def _proto_port_key(rule: EgressRule) -> tuple[str | None, int | None]:
    return (rule.proto, rule.port)


def render_block(
    app_id: str,
    instance_id: str,
    policy: Policy,
    dynamic_ips: list[str],
    wan_iface: str,
) -> str:
    """Render the per-app chain rules block (between BEGIN_APP / END_APP markers)."""
    bridge = f"b.{instance_id}.egs"
    has_dynamic = any(r.fqdn or r.service or r.cidr_url for r in policy.egress_rules)

    lines: list[str] = []

    # --- static CIDR rules grouped by (proto, port) ---
    cidr_groups: dict[tuple, list[str]] = defaultdict(list)
    cidr_comments: dict[tuple, list[str]] = {}
    for rule in policy.egress_rules:
        if rule.cidr is None:
            continue
        key = _proto_port_key(rule)
        cidr_groups[key].append(rule.cidr)
        if rule.comment and key not in cidr_comments:
            cidr_comments[key] = rule.comment

    for key, cidrs in cidr_groups.items():
        proto, port = key
        match_parts = [f'iifname "{bridge}"']
        if proto:
            match_parts.append(f"{proto} dport")
            if port:
                match_parts.append(str(port))
        elif port:
            match_parts.append(f"th dport {port}")
        addr_set = "{ " + ", ".join(sorted(set(cidrs))) + " }"
        match_parts.append(f"ip daddr {addr_set}")
        match_parts.append("return")
        comment = cidr_comments.get(key)
        if comment:
            match_parts.append(f'comment "{comment}"')
        lines.append(_INDENT + " ".join(match_parts))

    # --- dynamic set rules grouped by (proto, port) ---
    if has_dynamic and dynamic_ips:
        dyn_keys: set[tuple] = set()
        for rule in policy.egress_rules:
            if rule.fqdn or rule.service or rule.cidr_url:
                dyn_keys.add(_proto_port_key(rule))

        for proto, port in sorted(dyn_keys, key=lambda k: (k[0] or "", k[1] or 0)):
            match_parts = [f'iifname "{bridge}"']
            if proto:
                match_parts.append(f"{proto} dport")
                if port:
                    match_parts.append(str(port))
            elif port:
                match_parts.append(f"th dport {port}")
            match_parts.append(f"ip daddr @{app_id}-egress-dynamic")
            match_parts.append("return")
            match_parts.append(f'comment "dynamic: {app_id}"')
            lines.append(_INDENT + " ".join(match_parts))

    # --- default deny ---
    if policy.egress_default == "deny":
        lines.append(_INDENT + f'iifname "{bridge}" drop comment "default deny: {app_id}"')

    return "\n".join(lines) + "\n" if lines else ""
