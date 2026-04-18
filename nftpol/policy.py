"""Load and validate per-app firewall-policy.yml."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml

VALID_PROTOS = ("tcp", "udp")


class PolicyError(Exception):
    pass


@dataclass
class EgressRule:
    # exactly one of cidr/fqdn/service/cidr_url must be set
    cidr: str | None = None
    fqdn: str | None = None
    service: str | None = None
    cidr_url: str | None = None
    proto: str | None = None
    port: int | None = None
    comment: str | None = None
    via: str | None = None  # Docker Compose network name to route through


@dataclass
class Policy:
    egress_rules: list[EgressRule] = field(default_factory=list)
    egress_default: str = "deny"  # "deny" or "accept"


def load_policy(path: Path) -> Policy:
    try:
        raw = yaml.safe_load(path.read_text())
    except FileNotFoundError:
        raise PolicyError(f"Policy file not found: {path}")
    except yaml.YAMLError as e:
        raise PolicyError(f"Policy parse error in {path}: {e}")

    if not isinstance(raw, dict):
        raise PolicyError(f"Policy file {path} must be a YAML mapping")

    errors: list[str] = []
    egress_block = raw.get("egress", {}) or {}

    default = egress_block.get("default", "deny")
    if default not in ("deny", "accept"):
        errors.append(f"egress.default must be 'deny' or 'accept', got: {default!r}")

    rules: list[EgressRule] = []
    for i, entry in enumerate(egress_block.get("allow") or []):
        if not isinstance(entry, dict):
            errors.append(f"egress.allow[{i}]: must be a mapping")
            continue

        type_keys = [k for k in ("cidr", "fqdn", "service", "cidr_url") if k in entry]
        if len(type_keys) != 1:
            errors.append(
                f"egress.allow[{i}]: exactly one of cidr/fqdn/service/cidr_url required, got {type_keys}"
            )
            continue

        cidr_url_val = entry.get("cidr_url")
        if cidr_url_val is not None:
            if not isinstance(cidr_url_val, str) or not cidr_url_val.startswith(("http://", "https://")):
                errors.append(
                    f"egress.allow[{i}]: cidr_url must be a string starting with http:// or https://, got {cidr_url_val!r}"
                )


        proto = entry.get("proto")
        if proto is not None and proto not in VALID_PROTOS:
            errors.append(
                f"egress.allow[{i}]: invalid proto {proto!r}, must be one of {VALID_PROTOS}"
            )

        port = entry.get("port")
        if port is not None:
            try:
                port = int(port)
                if not (1 <= port <= 65535):
                    raise ValueError
            except (ValueError, TypeError):
                errors.append(
                    f"egress.allow[{i}]: port must be an integer 1-65535, got {entry['port']!r}"
                )
                port = None

        via = entry.get("via")
        if via is not None and not isinstance(via, str):
            errors.append(f"egress.allow[{i}]: via must be a string, got {via!r}")
            via = None

        rules.append(
            EgressRule(
                cidr=entry.get("cidr"),
                fqdn=entry.get("fqdn"),
                service=entry.get("service"),
                cidr_url=entry.get("cidr_url"),
                proto=proto,
                port=port,
                comment=entry.get("comment"),
                via=via,
            )
        )

    if errors:
        raise PolicyError("Policy validation failed:\n" + "\n".join(f"  - {e}" for e in errors))

    return Policy(egress_rules=rules, egress_default=default)


def get_bridge_map(compose_path: Path) -> dict[str, str]:
    """Read bridge name mappings from a rendered compose file.

    Returns {compose_network_name: bridge_interface_name} for networks that have
    com.docker.network.bridge.name set in driver_opts.
    """
    try:
        raw = yaml.safe_load(compose_path.read_text())
    except FileNotFoundError:
        raise PolicyError(f"Rendered compose file not found: {compose_path}")
    except yaml.YAMLError as e:
        raise PolicyError(f"Compose file parse error in {compose_path}: {e}")

    if not isinstance(raw, dict):
        return {}

    bridge_map: dict[str, str] = {}
    for net_name, net_cfg in (raw.get("networks") or {}).items():
        if not isinstance(net_cfg, dict):
            continue
        driver_opts = net_cfg.get("driver_opts") or {}
        bridge = driver_opts.get("com.docker.network.bridge.name")
        if bridge:
            bridge_map[net_name] = bridge
    return bridge_map


def validate_fqdn_domains(policy: Policy, trusted_domains: list[str]) -> None:
    """Raise PolicyError listing all FQDNs that don't match a trusted domain."""
    if not trusted_domains:
        violations = [r.fqdn for r in policy.egress_rules if r.fqdn]
        if violations:
            raise PolicyError(
                "FQDN entries require trusted_fqdn_domains to be configured.\n"
                "Use 'cidr' for third-party hosts (Docker Hub, GitHub, apt repos).\n"
                "Offending FQDNs: " + ", ".join(violations)
            )
        return

    violations = []
    for rule in policy.egress_rules:
        if rule.fqdn is None:
            continue
        fqdn = rule.fqdn.rstrip(".")
        if not any(fqdn == d or fqdn.endswith("." + d) for d in trusted_domains):
            violations.append(rule.fqdn)

    if violations:
        raise PolicyError(
            "The following FQDNs are not under a trusted domain.\n"
            "Use 'cidr' instead for third-party hosts (Docker Hub, GitHub, apt repos).\n"
            "Trusted domains: " + ", ".join(trusted_domains) + "\n"
            "Offending FQDNs: " + ", ".join(violations)
        )
