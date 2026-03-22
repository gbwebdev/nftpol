"""Load and validate global nftpol configuration."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

import yaml

DEFAULT_CONF_PATH = Path("/etc/nftpol.conf.yml")
REQUIRED_FIELDS = ("wan_iface", "traefik_ip", "edge_rp_bridge", "nft_isolation_file")


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
class Config:
    wan_iface: str
    traefik_ip: str
    edge_rp_bridge: str
    nft_isolation_file: Path
    trusted_fqdn_domains: list[str] = field(default_factory=list)
    refresh_interval_seconds: int = 300
    host_ipsets: dict[str, HostIpset] = field(default_factory=dict)
    host_ipsets_file: Path = field(default_factory=lambda: Path("/etc/nftables.d/05-host-ipsets.nft"))
    host_restricted_ports: list[HostRestrictedPort] = field(default_factory=list)


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
        traefik_ip=raw["traefik_ip"],
        edge_rp_bridge=raw["edge_rp_bridge"],
        nft_isolation_file=Path(raw["nft_isolation_file"]),
        trusted_fqdn_domains=raw.get("trusted_fqdn_domains") or [],
        refresh_interval_seconds=int(raw.get("refresh_interval_seconds", 300)),
        host_ipsets=host_ipsets,
        host_ipsets_file=Path(
            raw.get("host_ipsets_file", "/etc/nftables.d/05-host-ipsets.nft")
        ),
        host_restricted_ports=host_restricted_ports,
    )
