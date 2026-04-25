"""Render nftables named-set and chain-rule blocks."""
from __future__ import annotations

import logging
from collections import defaultdict

from .config import HostRestrictedPort, TransverseNetwork
from .policy import EgressRule, Policy

log = logging.getLogger("nftpol")
_PREFIX = "[nftpol]"

_INDENT = "        "  # 8 spaces — matches marker indentation in managed file


def render_set(app_id: str, set_key: str, ips: list[str]) -> str:
    """Render the named set block for dynamic IPs (docker egress).

    set_key is the via key (e.g. "egress", "backend") — the set name becomes
    {app_id}-{set_key}-dynamic.
    """
    # flags interval is only needed (and safe) when the set contains CIDR prefixes.
    # Plain IPs from FQDN/service resolution don't require it, and some older nft
    # versions mis-parse plain IPs inside an interval-flagged elements block.
    set_name = f"{app_id}-{set_key}-dynamic"
    has_prefix = any("/" in ip for ip in ips)
    lines = [
        f"    # managed: {app_id}",
        f"    set {set_name} {{",
        f"        type ipv4_addr",
    ]
    if has_prefix:
        lines.append(f"        flags interval")
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


def render_transverse_block(network: TransverseNetwork) -> str:
    """Render the 3-line isolation block for a single transverse network.

    outbound: privileged_ip initiates (Traefik, Prometheus) → saddr match.
    inbound:  others initiate toward privileged_ip (DB) → daddr match.
    """
    b = network.bridge
    ip = network.privileged_ip
    name = network.name
    comment_part = f" — {network.comment}" if network.comment else ""

    lines = [f"{_INDENT}# {name} isolation{comment_part}"]
    if network.direction == "outbound":
        lines.append(
            f'{_INDENT}iifname "{b}" oifname "{b}" ip saddr {ip} return'
            f' comment "{name} egress ok"'
        )
        lines.append(
            f'{_INDENT}iifname "{b}" oifname "{b}" ip daddr {ip}'
            f' ct state {{ established, related }} return comment "{name} replies ok"'
        )
    else:  # inbound
        lines.append(
            f'{_INDENT}iifname "{b}" oifname "{b}" ip daddr {ip} return'
            f' comment "{name} ingress ok"'
        )
        lines.append(
            f'{_INDENT}iifname "{b}" oifname "{b}" ip saddr {ip}'
            f' ct state {{ established, related }} return comment "{name} replies ok"'
        )
    lines.append(
        f'{_INDENT}iifname "{b}" oifname "{b}" drop'
        f' comment "block lateral movement on {name}"'
    )
    return "\n".join(lines) + "\n"


def render_static_section(networks: list[TransverseNetwork]) -> str:
    """Render the full STATIC section (BEGIN/END markers + all transverse blocks)."""
    lines = [f"{_INDENT}# === STATIC BEGIN ==="]
    for i, net in enumerate(networks):
        if i > 0:
            lines.append("")
        # render_transverse_block already ends with \n; strip it to join cleanly
        lines.append(render_transverse_block(net).rstrip("\n"))
    lines.append(f"{_INDENT}# === STATIC END ===")
    return "\n".join(lines) + "\n"


def _proto_port_key(rule: EgressRule) -> tuple[str | None, int | None]:
    return (rule.proto, rule.port)


def render_block(
    app_id: str,
    instance_id: str,
    policy: Policy,
    dynamic_ips_by_key: dict[str, list[str]],
    wan_iface: str,
    bridge_map: dict[str, str] | None = None,
) -> str:
    """Render the per-app chain rules block (between BEGIN_APP / END_APP markers).

    dynamic_ips_by_key: {via_key: [ips]} from collect_dynamic_ips().
    bridge_map: {compose_network_name: bridge_iface} from get_bridge_map().
      Rules without via use the default egress bridge b.{instance_id}.egs.
      Rules with via use the corresponding bridge from bridge_map; if the via
      key is missing from bridge_map, a warning is logged and the rule is skipped.
    """
    if bridge_map is None:
        bridge_map = {}

    default_bridge = f"b.{instance_id}.egs"

    def get_bridge(via: str | None) -> str | None:
        if via is None:
            return default_bridge
        bridge = bridge_map.get(via)
        if bridge is None:
            log.warning("%s via: %r not found in bridge_map, skipping rule", _PREFIX, via)
        return bridge

    lines: list[str] = []

    # --- static CIDR rules grouped by (via_key, proto, port) ---
    # Key: (via, proto, port) — via preserved as-is (None or string)
    cidr_groups: dict[tuple, list[str]] = defaultdict(list)
    cidr_comments: dict[tuple, str] = {}
    for rule in policy.egress_rules:
        if rule.cidr is None:
            continue
        key = (rule.via, rule.proto, rule.port)
        cidr_groups[key].append(rule.cidr)
        if rule.comment and key not in cidr_comments:
            cidr_comments[key] = rule.comment

    for key, cidrs in cidr_groups.items():
        via, proto, port = key
        bridge = get_bridge(via)
        if bridge is None:
            continue
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

    # --- dynamic set rules grouped by (via_key, proto, port) ---
    # Collect which (via, proto, port) tuples have dynamic rules
    dyn_by_via: dict[str | None, set[tuple]] = defaultdict(set)
    for rule in policy.egress_rules:
        if rule.fqdn or rule.service or rule.cidr_url:
            dyn_by_via[rule.via].add((rule.proto, rule.port))

    for via, proto_port_set in sorted(
        dyn_by_via.items(), key=lambda kv: (kv[0] or "", kv[0] or "")
    ):
        via_key = via or "egress"
        ips = dynamic_ips_by_key.get(via_key, [])
        if not ips:
            continue  # no resolved IPs for this key, skip
        bridge = get_bridge(via)
        if bridge is None:
            continue
        for proto, port in sorted(proto_port_set, key=lambda k: (k[0] or "", k[1] or 0)):
            match_parts = [f'iifname "{bridge}"']
            if proto:
                match_parts.append(f"{proto} dport")
                if port:
                    match_parts.append(str(port))
            elif port:
                match_parts.append(f"th dport {port}")
            match_parts.append(f"ip daddr @{app_id}-{via_key}-dynamic")
            match_parts.append("return")
            match_parts.append(f'comment "dynamic: {app_id}"')
            lines.append(_INDENT + " ".join(match_parts))

    # --- default deny (on default egress bridge) ---
    if policy.egress_default == "deny":
        lines.append(
            _INDENT + f'iifname "{default_bridge}" drop comment "default deny: {app_id}"'
        )

    return "\n".join(lines) + "\n" if lines else ""
