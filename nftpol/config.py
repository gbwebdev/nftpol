"""Load and validate global nftpol configuration."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

import yaml

DEFAULT_CONF_PATH = Path("/etc/nftpol.conf.yml")
REQUIRED_FIELDS = ("wan_iface", "nft_isolation_file")
VALID_DIRECTIONS = ("outbound", "inbound")


class ConfigError(Exception):
    pass


@dataclass
class HostIpset:
    url: str
    comment: str = ""


@dataclass
class HostRestrictedPort:
    port: int
    ipset: str
    comment: str = ""


@dataclass
class TransverseNetwork:
    """A transverse Docker network with one privileged component.

    direction="outbound": the privileged component initiates (Traefik, Prometheus).
    direction="inbound":  other containers initiate toward the privileged one (DB).
    """
    name: str            # logical name, e.g. "edge_rp", "shared_db"
    bridge: str          # Docker bridge interface, e.g. "br-edge-rp"
    privileged_ip: str   # IP of the central component (first IP of /26)
    direction: str       # "outbound" or "inbound"
    comment: str = ""


@dataclass
class Config:
    wan_iface: str
    nft_isolation_file: Path
    # Legacy fields — kept for backward compat; use transverse_networks instead.
    traefik_ip: str | None = None
    edge_rp_bridge: str | None = None
    transverse_networks: list[TransverseNetwork] = field(default_factory=list)
    trusted_fqdn_domains: list[str] = field(default_factory=list)
    refresh_interval_seconds: int = 300
    host_ipsets: dict[str, HostIpset] = field(default_factory=dict)
    host_ipsets_file: Path = field(default_factory=lambda: Path("/etc/nftables.d/05-host-ipsets.nft"))
    host_restricted_ports: list[HostRestrictedPort] = field(default_factory=list)


def _parse_transverse_networks(raw_list: list, path: Path) -> list[TransverseNetwork]:
    networks: list[TransverseNetwork] = []
    for i, entry in enumerate(raw_list):
        if not isinstance(entry, dict):
            raise ConfigError(f"transverse_networks[{i}]: must be a mapping")
        for required in ("name", "bridge", "privileged_ip", "direction"):
            if required not in entry:
                raise ConfigError(
                    f"transverse_networks[{i}]: missing required field '{required}'"
                )
        direction = entry["direction"]
        if direction not in VALID_DIRECTIONS:
            raise ConfigError(
                f"transverse_networks[{i}]: direction must be one of "
                f"{VALID_DIRECTIONS}, got {direction!r}"
            )
        networks.append(TransverseNetwork(
            name=str(entry["name"]),
            bridge=str(entry["bridge"]),
            privileged_ip=str(entry["privileged_ip"]),
            direction=direction,
            comment=str(entry.get("comment", "")),
        ))
    return networks


def load_config(path: Path | None = None) -> Config:
    if path is None:
        env = os.environ.get("NFTPOL_CONF")
        path = Path(env) if env else DEFAULT_CONF_PATH

    try:
        raw = yaml.safe_load(path.read_text())
    except FileNotFoundError:
        raise ConfigError(f"Config file not found: {path}")
    except yaml.YAMLError as e:
        raise ConfigError(f"Config parse error in {path}: {e}")

    if not isinstance(raw, dict):
        raise ConfigError(f"Config file {path} must be a YAML mapping")

    missing = [f for f in REQUIRED_FIELDS if f not in raw]
    if missing:
        raise ConfigError(f"Missing required config fields: {', '.join(missing)}")

    # Parse transverse_networks
    transverse_networks: list[TransverseNetwork] = []
    if "transverse_networks" in raw and raw["transverse_networks"]:
        transverse_networks = _parse_transverse_networks(
            raw["transverse_networks"], path
        )
    elif raw.get("traefik_ip") and raw.get("edge_rp_bridge"):
        # Backward compat: auto-convert legacy Traefik fields
        transverse_networks = [
            TransverseNetwork(
                name="edge_rp",
                bridge=str(raw["edge_rp_bridge"]),
                privileged_ip=str(raw["traefik_ip"]),
                direction="outbound",
                comment="Traefik reverse proxy (legacy config)",
            )
        ]

    host_ipsets: dict[str, HostIpset] = {}
    for name, cfg in (raw.get("host_ipsets") or {}).items():
        if not isinstance(cfg, dict) or "url" not in cfg:
            raise ConfigError(f"host_ipsets.{name}: must be a mapping with a 'url' key")
        if not isinstance(cfg["url"], str) or not cfg["url"].startswith(("http://", "https://")):
            raise ConfigError(
                f"host_ipsets.{name}.url must start with http:// or https://, got {cfg['url']!r}"
            )
        host_ipsets[name] = HostIpset(url=cfg["url"], comment=cfg.get("comment", ""))

    host_restricted_ports: list[HostRestrictedPort] = []
    for i, entry in enumerate(raw.get("host_restricted_ports") or []):
        if not isinstance(entry, dict):
            raise ConfigError(f"host_restricted_ports[{i}]: must be a mapping")
        if "port" not in entry or "ipset" not in entry:
            raise ConfigError(f"host_restricted_ports[{i}]: requires 'port' and 'ipset' keys")
        try:
            port = int(entry["port"])
            if not (1 <= port <= 65535):
                raise ValueError
        except (ValueError, TypeError):
            raise ConfigError(f"host_restricted_ports[{i}].port: must be 1-65535")
        host_restricted_ports.append(
            HostRestrictedPort(
                port=port,
                ipset=str(entry["ipset"]),
                comment=str(entry.get("comment", "")),
            )
        )

    return Config(
        wan_iface=raw["wan_iface"],
        nft_isolation_file=Path(raw["nft_isolation_file"]),
        traefik_ip=raw.get("traefik_ip"),
        edge_rp_bridge=raw.get("edge_rp_bridge"),
        transverse_networks=transverse_networks,
        trusted_fqdn_domains=raw.get("trusted_fqdn_domains") or [],
        refresh_interval_seconds=int(raw.get("refresh_interval_seconds", 300)),
        host_ipsets=host_ipsets,
        host_ipsets_file=Path(
            raw.get("host_ipsets_file", "/etc/nftables.d/05-host-ipsets.nft")
        ),
        host_restricted_ports=host_restricted_ports,
    )
