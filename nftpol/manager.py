"""File manipulation: init, upsert, remove, refresh, refresh_all, list_apps."""
from __future__ import annotations

import logging
import re
from pathlib import Path

from .config import Config
from .nft import validate_and_write
from .policy import Policy, load_policy, validate_fqdn_domains
from .renderer import render_block, render_host_ipsets_file, render_set
from .resolver import collect_dynamic_ips, resolve_cidr_url

log = logging.getLogger("nftpol")
PREFIX = "[nftpol]"

# Marker patterns — anchored to 8-space indentation
_RE_APP_BLOCK = re.compile(
    r"        # === BEGIN_APP (?P<id>\S+) ===\n.*?        # === END_APP (?P=id) ===\n",
    re.DOTALL,
)
_RE_APP_BLOCK_FOR_ID = lambda app_id: re.compile(  # noqa: E731
    rf"        # === BEGIN_APP {re.escape(app_id)} ===\n.*?        # === END_APP {re.escape(app_id)} ===\n",
    re.DOTALL,
)
_ANCHOR = "        # === APP_ANCHOR ==="
_RE_NAMED_SET = lambda app_id: re.compile(  # noqa: E731
    rf"    # managed: {re.escape(app_id)}\n    set {re.escape(app_id)}-egress-dynamic \{{.*?^    \}}\n",
    re.DOTALL | re.MULTILINE,
)

SKELETON = """\
# THIS FILE IS MANAGED BY nftpol - DO NOT EDIT MANUALLY

table ip fw-docker {{

    chain isolation {{
        type filter hook forward priority filter - 1;

        # === STATIC BEGIN ===
        # edge-rp inter-container isolation
        iifname "{edge_rp_bridge}" oifname "{edge_rp_bridge}" ip saddr {traefik_ip} return comment "traefik egress ok"
        iifname "{edge_rp_bridge}" oifname "{edge_rp_bridge}" ip daddr {traefik_ip} ct state {{ established, related }} return comment "traefik replies ok"
        iifname "{edge_rp_bridge}" oifname "{edge_rp_bridge}" drop comment "block lateral movement"
        # === STATIC END ===

        # === APP_ANCHOR ===
    }}
}}
"""


def init(config: Config, dry_run: bool = False) -> None:
    """Create the isolation nft file from skeleton. No-op if already exists."""
    path = config.nft_isolation_file
    if path.exists():
        log.info("%s %s already exists, skipping init", PREFIX, path)
        return
    content = SKELETON.format(
        edge_rp_bridge=config.edge_rp_bridge,
        traefik_ip=config.traefik_ip,
    )
    if dry_run:
        print(f"[nftpol] DRY-RUN: would write {path}:")
        print(content)
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    validate_and_write(content, path)
    log.info("%s Initialized %s", PREFIX, path)


def list_apps(config: Config) -> list[str]:
    """Return all app IDs currently managed in the isolation file."""
    content = config.nft_isolation_file.read_text()
    return re.findall(r"# === BEGIN_APP (\S+) ===", content)


def upsert(
    app_id: str,
    instance_id: str,
    policy: Policy,
    config: Config,
    dry_run: bool = False,
) -> None:
    """Full upsert: resolve dynamic IPs, render and insert/replace app block + set."""
    validate_fqdn_domains(policy, config.trusted_fqdn_domains)

    dynamic_ips = collect_dynamic_ips(policy)
    has_dynamic = any(r.fqdn or r.service or r.cidr_url for r in policy.egress_rules)

    content = config.nft_isolation_file.read_text()

    # Build new block
    block_body = render_block(app_id, instance_id, policy, dynamic_ips, config.wan_iface)
    new_block = (
        f"        # === BEGIN_APP {app_id} ===\n"
        f"{block_body}"
        f"        # === END_APP {app_id} ===\n"
    )

    # Replace or insert chain block
    pat = _RE_APP_BLOCK_FOR_ID(app_id)
    if pat.search(content):
        content = pat.sub(new_block, content)
    else:
        content = content.replace(_ANCHOR, new_block + _ANCHOR)

    # Replace or insert named set (only if app has dynamic entries)
    set_pat = _RE_NAMED_SET(app_id)
    if has_dynamic:
        new_set = render_set(app_id, dynamic_ips)
        if set_pat.search(content):
            content = set_pat.sub(new_set, content)
        else:
            # Insert before "chain isolation {"
            content = content.replace(
                "    chain isolation {",
                new_set + "\n    chain isolation {",
                1,
            )
    else:
        # Remove set if it exists but is no longer needed
        content = set_pat.sub("", content)

    if dry_run:
        print(f"[nftpol] DRY-RUN: would write {config.nft_isolation_file}:")
        print(content)
        return

    validate_and_write(content, config.nft_isolation_file)
    log.info("%s upsert %s done (dynamic IPs: %s)", PREFIX, app_id, dynamic_ips)


def remove(app_id: str, config: Config, dry_run: bool = False) -> None:
    """Remove the app's chain block and named set."""
    content = config.nft_isolation_file.read_text()

    block_pat = _RE_APP_BLOCK_FOR_ID(app_id)
    if not block_pat.search(content):
        log.info("%s remove %s: not found, no-op", PREFIX, app_id)
        return

    content = block_pat.sub("", content)
    content = _RE_NAMED_SET(app_id).sub("", content)

    if dry_run:
        print(f"[nftpol] DRY-RUN: would write {config.nft_isolation_file}:")
        print(content)
        return

    validate_and_write(content, config.nft_isolation_file)
    log.info("%s remove %s done", PREFIX, app_id)


def refresh(
    app_id: str,
    policy: Policy,
    config: Config,
    dry_run: bool = False,
    instance_id: str | None = None,
) -> None:
    """Re-resolve dynamic entries and update named set in-place.

    Falls back to full upsert if set is missing and instance_id is provided.
    No-op if no dynamic entries.
    """
    has_dynamic = any(r.fqdn or r.service or r.cidr_url for r in policy.egress_rules)
    if not has_dynamic:
        log.info("%s refresh %s: no dynamic entries, no-op", PREFIX, app_id)
        return

    content = config.nft_isolation_file.read_text()
    set_pat = _RE_NAMED_SET(app_id)
    if not set_pat.search(content):
        if instance_id is None:
            log.warning("%s refresh %s: set missing but no instance_id, skipping upsert", PREFIX, app_id)
            return
        log.info("%s refresh %s: set missing, falling back to upsert", PREFIX, app_id)
        upsert(app_id, instance_id, policy, config, dry_run=dry_run)
        return

    validate_fqdn_domains(policy, config.trusted_fqdn_domains)
    dynamic_ips = collect_dynamic_ips(policy)
    new_set = render_set(app_id, dynamic_ips)
    content = set_pat.sub(new_set, content)

    if dry_run:
        print(f"[nftpol] DRY-RUN: would write {config.nft_isolation_file}:")
        print(content)
        return

    validate_and_write(content, config.nft_isolation_file)
    log.info("%s refresh %s done (IPs: %s)", PREFIX, app_id, dynamic_ips)


def refresh_host_sets(config: Config, dry_run: bool = False) -> None:
    """Fetch all host_ipsets URLs and update the host ipsets file.

    No-op if no host_ipsets are configured.
    """
    if not config.host_ipsets:
        log.info("%s refresh-host-sets: no host_ipsets configured, no-op", PREFIX)
        return

    resolved: dict[str, list[str]] = {}
    for name, ipset in config.host_ipsets.items():
        log.info("%s refresh-host-sets: resolving %s from %s", PREFIX, name, ipset.url)
        entries = resolve_cidr_url(ipset.url)
        resolved[name] = entries

    content = render_host_ipsets_file(resolved, config.host_restricted_ports)

    if dry_run:
        print(f"[nftpol] DRY-RUN: would write {config.host_ipsets_file}:")
        print(content)
        return

    config.host_ipsets_file.parent.mkdir(parents=True, exist_ok=True)
    validate_and_write(content, config.host_ipsets_file)
    log.info(
        "%s refresh-host-sets: wrote %s (%d sets)",
        PREFIX,
        config.host_ipsets_file,
        len(resolved),
    )


def refresh_all(policy_dir: Path, config: Config, dry_run: bool = False) -> None:
    """Discover and refresh all apps, then refresh host IP sets."""
    for policy_file in sorted(policy_dir.glob("*/firewall-policy.yml")):
        app_id = policy_file.parent.name
        log.info("%s refresh-all: processing %s", PREFIX, app_id)
        try:
            policy = load_policy(policy_file)
            refresh(app_id, policy, config, dry_run=dry_run)
        except Exception as e:
            log.error("%s refresh-all: %s failed: %s", PREFIX, app_id, e)

    try:
        refresh_host_sets(config, dry_run=dry_run)
    except Exception as e:
        log.error("%s refresh-all: host-sets failed: %s", PREFIX, e)
