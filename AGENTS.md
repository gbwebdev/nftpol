# nftpol — Agent Guide

## Purpose
nftables manager for Docker Compose. Implements container egress filtering + transverse network isolation (no Kubernetes/Calico required).

## Module map
```
cli.py       → subcommands: init | upsert | remove | refresh | refresh-all | refresh-host-sets | validate | list
config.py    → /etc/nftpol.conf.yml loader → Config, HostIpset, HostRestrictedPort
policy.py    → firewall-policy.yml loader → Policy, EgressRule; bridge map from rendered compose
resolver.py  → dynamic IP resolution: FQDN (DNS) | service (Docker API) | cidr_url (HTTP)
manager.py   → marker-based insert/replace in nft files; orchestrates upsert/remove/refresh
renderer.py  → nftables syntax: render_set(), render_block(), render_host_ipsets_file()
nft.py       → subprocess wrapper: validate() | validate_and_write() | _reload()
```

## Managed nftables files
| File | Table | Owner |
|------|-------|-------|
| `/etc/nftables.d/05-host-ipsets.nft` | `inet fw-host` | nftpol (refresh-host-sets) |
| `/etc/nftables.d/20-docker-isolation.nft` | `ip fw-docker` | nftpol (init/upsert/remove) |

## Key formats

**Global config** (`/etc/nftpol.conf.yml`):
```yaml
wan_iface: eth0
traefik_ip: 172.26.48.1
edge_rp_bridge: br-edge-rp
nft_isolation_file: /etc/nftables.d/20-docker-isolation.nft
trusted_fqdn_domains: [example.com]
host_ipsets_file: /etc/nftables.d/05-host-ipsets.nft
host_ipsets:
  cloudflare-ipv4: {url: "https://www.cloudflare.com/ips-v4/#"}
host_restricted_ports:
  - {port: 443, ipset: cloudflare-ipv4}
```

**App policy** (`firewall-policy.yml`):
```yaml
egress:
  allow:
    - cidr: 1.2.3.0/24     # static
    - fqdn: vpn.example.com # DNS (must be in trusted_fqdn_domains)
    - service: proj/svc     # Docker API → container IP
    - cidr_url: https://…   # HTTP CIDR list
    # all rules accept: proto, port, via (network name), comment
  default: deny
```

## File markers (20-docker-isolation.nft)
- `# === STATIC BEGIN/END ===` — managed by `apply_transverse()`, rewritten on config change
- `# === BEGIN_APP <id> === … # === END_APP <id> ===` — per-app block
- `# === APP_ANCHOR ===` — insertion point, always preserved

## Tests
```bash
uv run --python 3.11 --with pytest --project nftpol pytest tests/ -v
```
All external calls mocked (nft subprocess, Docker socket, DNS, HTTP).

## Exit codes
0=ok · 1=validation/config error · 2=nft syntax error · 3=system error

---

## Transverse networks (implemented in feat/transverse-networks)

Configurable transverse network isolation. Replaces hardcoded Traefik/edge_rp pattern.

**New dataclass** `TransverseNetwork` in `config.py`: `name`, `bridge`, `privileged_ip`, `direction` ("outbound"|"inbound"), `comment`.

**Config** (`nftpol.conf.yml`):
```yaml
transverse_networks:
  - name: edge_rp
    bridge: br-edge-rp
    privileged_ip: 172.26.48.1
    direction: outbound   # privileged component initiates (Traefik, Prometheus)
  - name: shared_db
    bridge: br-shared-db
    privileged_ip: 172.26.48.65
    direction: inbound    # others initiate toward privileged (DB)
```

**Backward compat**: if `traefik_ip` + `edge_rp_bridge` present and `transverse_networks` absent → auto-generates `edge_rp` entry in `load_config()`.

**New renderer functions**: `render_transverse_block(net)` · `render_static_section(nets)` in `renderer.py`.

**New manager function**: `apply_transverse(config, dry_run)` — replaces STATIC section via `_RE_STATIC` regex. Called automatically by `refresh-all`.

**New CLI command**: `nftpol refresh-transverse [--dry-run]`
