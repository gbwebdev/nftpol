# nftpol

nftables firewall manager for Docker Compose servers. Provides per-app egress control and
host perimeter IP restrictions without Calico, etcd, or any CNI overhead.

**Ansible is the source of truth.** This tool is installed and configured by Ansible. Its
config file (`/etc/nftpol.conf.yml`) is deployed by the `setup_root_stack` role via
Jinja2 template. Never edit it manually.

---

## nftables architecture

Two tables are managed. Docker's own chains (`DOCKER`, `DOCKER-USER`, etc.) are never touched.

```
inet fw-host        host perimeter — INPUT/OUTPUT
ip   fw-docker      container isolation + per-app egress — FORWARD (priority filter-1)
```

### Host perimeter (`inet fw-host`)

Three files contribute to this table, written independently:

| File | Written by | Content |
|------|-----------|---------|
| `/etc/nftables.d/10-host.nft` | Ansible (`setup_server`) | `input` chain — SSH + any `host_public_ports` |
| `/etc/nftables.d/05-host-ipsets.nft` | nftpol (`refresh-host-sets`) | named IP sets + `host-restrict` chain (priority filter-1) |

The `host-restrict` chain runs before `input`. It accepts traffic from trusted IP sets on
restricted ports (e.g. Cloudflare → 443) and drops everything else on those ports. The
`input` chain never references any IP sets — it is fully standalone.

### Container isolation (`ip fw-docker`)

Managed entirely by nftpol in `/etc/nftables.d/20-docker-isolation.nft`:

- **STATIC block**: Traefik bridge rules (written once by `init`, never overwritten)
- **Per-app blocks**: one `# === BEGIN_APP <id> ===` … `# === END_APP <id> ===` block per app
- **Named sets**: one `set <app_id>-egress-dynamic` per app with dynamic IPs (FQDN/service/cidr_url)
- **`# === APP_ANCHOR ===`**: insertion point for new apps, always preserved at chain end

Hook priority `filter - 1` runs before Docker's chains. Always use `return` for allowed traffic
(so Docker's chains still process it) and `drop` for denied. Never use `accept` in FORWARD.

---

## Configuration

The tool reads `/etc/nftpol.conf.yml` by default. Override with `--config <path>` or
the `NFTPOL_CONF` environment variable.

See `nftpol.conf.yml.example` for the full schema. Key fields:

```yaml
wan_iface: eth0                                        # outbound interface
traefik_ip: 172.26.63.2                                # Traefik container IP
edge_rp_bridge: br-edge-rp                             # Traefik's bridge
trusted_fqdn_domains: [example.com]                    # allowed FQDN suffixes in policies
nft_isolation_file: /etc/nftables.d/20-docker-isolation.nft

# Host IP sets fetched from URLs at refresh-host-sets time
host_ipsets_file: /etc/nftables.d/05-host-ipsets.nft
host_ipsets:
  cloudflare-ipv4:
    url: https://www.cloudflare.com/ips-v4/#
    comment: Cloudflare IPv4 ranges

# Ports gated by an IP set (handled by host-restrict chain, not 10-host.nft)
host_restricted_ports:
  - port: 443
    ipset: cloudflare-ipv4
    comment: "HTTPS - Cloudflare only"
```

---

## CLI reference

All commands accept `--config <path>` and (where applicable) `--dry-run`.

```
nftpol init
    Write the 20-docker-isolation.nft skeleton. No-op if file already exists.

nftpol upsert <app_id> <policy_file>
    Resolve all dynamic entries, render and insert/replace the app block and named set.
    Validates with `nft -c -f` before writing, reloads nftables on success.

nftpol remove <app_id>
    Remove the app block and named set. No-op for unknown app IDs.

nftpol refresh <app_id> <policy_file>
    Re-resolve dynamic IPs only. Updates the named set in-place.
    Falls back to full upsert if the set is missing.

nftpol refresh-all <policy_dir>
    Discover all firewall-policy.yml files under <policy_dir>/<app_id>/ and refresh each.
    Also calls refresh-host-sets to update host IP sets.

nftpol refresh-host-sets
    Fetch all host_ipsets URLs, render 05-host-ipsets.nft with updated IP sets and
    the host-restrict chain. Reloads nftables.

nftpol validate <policy_file>
    Parse and validate a policy file, print resolved IPs. No disk writes.

nftpol list
    Print all app IDs currently managed in the isolation file.
```

Exit codes: `0` = ok, `1` = validation/config error, `2` = nft syntax error, `3` = system error.

---

## Per-app policy (`firewall-policy.yml`)

Lives in each app's own repository. Passed to `nftpol upsert` at deploy time.

```yaml
egress:
  allow:
    # Static CIDR — always safe
    - cidr: 185.125.190.0/24
      proto: tcp
      port: 443
      comment: Ubuntu apt HTTPS

    # CIDR list from URL — fetched at upsert/refresh time
    # Use for well-known published ranges (Cloudflare, AWS, etc.)
    - cidr_url: https://www.cloudflare.com/ips-v4/#
      proto: tcp
      port: 443
      comment: Cloudflare egress

    # FQDN — ONLY for domains you own (pseudo-static IPs).
    # Never use for CDN-backed or third-party hosts.
    # Must be under a domain listed in trusted_fqdn_domains.
    - fqdn: vpn.example.com
      proto: tcp
      port: 1194
      comment: Internal VPN

    # Docker service reference — resolved via Docker socket at upsert/refresh.
    # Format: {compose_project}/{service}
    - service: sharedservices/postgres
      proto: tcp
      port: 5432
      comment: Shared Postgres

  default: deny   # or: accept
```

Rules may mix all four types. `proto` and `port` are optional but recommended.

**FQDN trust rule**: FQDNs must be under a domain listed in `trusted_fqdn_domains` in the
global config. For third-party hosts (GitHub, Docker Hub, apt mirrors, CDNs) always use
`cidr` or `cidr_url` instead — their DNS resolves to constantly-changing CDN IPs.

---

## Docker Compose conventions

Each app should use this network layout so bridge names match the app ID:

```yaml
services:
  app:
    networks:
      - backend    # internal: app ↔ db only
      - edge-rp    # Traefik reaches app here
      - egress     # controlled outbound (gated by nftpol)

  db:
    networks:
      - backend    # isolated: no Traefik, no egress

networks:
  backend:
    internal: true          # Docker blocks all routing out — no nftables rules needed

  edge-rp:
    external: true          # shared Traefik network, managed centrally

  egress:
    driver: bridge
    driver_opts:
      com.docker.network.bridge.name: br-<app_id>-egress   # must match app_id
```

The bridge name `br-<app_id>-egress` is the key that links the Compose file to the
nftpol policy. The `app_id` passed to `nftpol upsert` must match.

---

## Development and testing

Tests use `pytest` with mocked nft/Docker calls. Run with `uv`:

```bash
uv run --python 3.11 --with pytest --project nftpol pytest nftpol/tests/ -v
```

No system dependencies needed — all nft and Docker calls are mocked in tests.
