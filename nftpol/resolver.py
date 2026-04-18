"""FQDN and Docker service resolution."""
from __future__ import annotations

import ipaddress
import logging
import socket
import urllib.request

from .policy import EgressRule, Policy

log = logging.getLogger("nftpol")

PREFIX = "[nftpol]"


class ResolverError(Exception):
    pass


def resolve_fqdn(fqdn: str) -> list[str]:
    """Resolve an FQDN to a deduplicated list of IPv4 addresses."""
    try:
        results = socket.getaddrinfo(fqdn, None, socket.AF_INET)
        ips = list(dict.fromkeys(r[4][0] for r in results))
        log.info("%s FQDN %s → %s", PREFIX, fqdn, ips)
        return ips
    except socket.gaierror as e:
        log.warning("%s FQDN %s could not be resolved: %s", PREFIX, fqdn, e)
        return []


def resolve_service(project: str, service: str) -> list[str]:
    """Resolve a Docker Compose service reference to its container IPs."""
    try:
        import docker  # type: ignore[import-untyped]
    except ImportError:
        raise ResolverError(
            "The 'docker' Python package is required to resolve service references.\n"
            "Install it with: pip install nftpol[docker]"
        )

    client = docker.from_env()
    label_filter = f"com.docker.compose.project={project}"
    containers = client.containers.list(
        filters={"label": [label_filter, f"com.docker.compose.service={service}"]}
    )

    if not containers:
        log.warning(
            "%s service %s/%s: no running containers found", PREFIX, project, service
        )
        return []

    ips: list[str] = []
    for c in containers:
        nets = c.attrs.get("NetworkSettings", {}).get("Networks", {})
        for net in nets.values():
            ip = net.get("IPAddress")
            if ip:
                ips.append(ip)

    ips = list(dict.fromkeys(ips))
    log.info("%s service %s/%s → %s", PREFIX, project, service, ips)
    return ips


def resolve_cidr_url(url: str) -> list[str]:
    """Fetch a URL returning newline-separated CIDRs/IPs. Returns deduplicated list."""
    try:
        with urllib.request.urlopen(url, timeout=10) as resp:
            body = resp.read().decode("utf-8", errors="replace")
    except Exception as e:
        log.warning("%s cidr_url %s could not be fetched: %s", PREFIX, url, e)
        return []

    results: list[str] = []
    for raw_line in body.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            ipaddress.IPv4Network(line, strict=False)
            results.append(line)
        except ValueError:
            log.warning("%s cidr_url %s: skipping invalid entry %r", PREFIX, url, line)

    deduped = list(dict.fromkeys(results))
    log.info("%s cidr_url %s → %d entries", PREFIX, url, len(deduped))
    return deduped


def collect_dynamic_ips(policy: Policy) -> dict[str, list[str]]:
    """Resolve all fqdn, service, and cidr_url entries, grouped by via key.

    Returns {via_key: [ips]} where via_key is rule.via or "egress" for rules
    without an explicit via. Each group is deduplicated.
    """
    per_key: dict[str, list[str]] = {}
    seen: dict[str, set[str]] = {}

    for rule in policy.egress_rules:
        if not (rule.fqdn or rule.service or rule.cidr_url):
            continue
        key = rule.via or "egress"
        if key not in per_key:
            per_key[key] = []
            seen[key] = set()

        resolved: list[str] = []
        if rule.fqdn:
            resolved = resolve_fqdn(rule.fqdn)
        elif rule.service:
            project, svc = rule.service.split("/", 1)
            resolved = resolve_service(project, svc)
        elif rule.cidr_url:
            resolved = resolve_cidr_url(rule.cidr_url)

        for ip in resolved:
            if ip not in seen[key]:
                seen[key].add(ip)
                per_key[key].append(ip)

    return per_key
