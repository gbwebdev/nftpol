"""Tests for host IP set management (config + manager)."""
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml

from nftpol.config import ConfigError, HostIpset, load_config
from nftpol.manager import refresh_host_sets


# --- config loading ---


def _write_conf(tmp_path: Path, extra: dict = None) -> Path:
    base = {
        "wan_iface": "eth0",
        "traefik_ip": "172.20.0.2",
        "edge_rp_bridge": "br-edge-rp",
        "nft_isolation_file": str(tmp_path / "20-docker-isolation.nft"),
    }
    if extra:
        base.update(extra)
    p = tmp_path / "nftpol.conf.yml"
    p.write_text(yaml.dump(base))
    return p


def test_config_host_ipsets_parses(tmp_path):
    p = _write_conf(tmp_path, {
        "host_ipsets": {
            "cloudflare-ipv4": {
                "url": "https://www.cloudflare.com/ips-v4/#",
                "comment": "Cloudflare IPs",
            }
        }
    })
    cfg = load_config(p)
    assert "cloudflare-ipv4" in cfg.host_ipsets
    assert cfg.host_ipsets["cloudflare-ipv4"].url == "https://www.cloudflare.com/ips-v4/#"
    assert cfg.host_ipsets["cloudflare-ipv4"].comment == "Cloudflare IPs"


def test_config_host_ipsets_empty_by_default(tmp_path):
    p = _write_conf(tmp_path)
    cfg = load_config(p)
    assert cfg.host_ipsets == {}


def test_config_host_ipsets_custom_file(tmp_path):
    p = _write_conf(tmp_path, {"host_ipsets_file": "/etc/nftables.d/05-custom.nft"})
    cfg = load_config(p)
    assert cfg.host_ipsets_file == Path("/etc/nftables.d/05-custom.nft")


def test_config_host_ipsets_invalid_url_raises(tmp_path):
    p = _write_conf(tmp_path, {
        "host_ipsets": {"bad": {"url": "ftp://example.com/ips"}}
    })
    with pytest.raises(ConfigError, match="http"):
        load_config(p)


def test_config_host_ipsets_missing_url_raises(tmp_path):
    p = _write_conf(tmp_path, {
        "host_ipsets": {"bad": {"comment": "no url here"}}
    })
    with pytest.raises(ConfigError, match="url"):
        load_config(p)


# --- refresh_host_sets ---


def _cfg(tmp_path: Path) -> object:
    from nftpol.config import Config
    iso = tmp_path / "20-docker-isolation.nft"
    iso.write_text("# placeholder")
    sets_file = tmp_path / "05-host-ipsets.nft"
    return Config(
        wan_iface="eth0",
        traefik_ip="172.20.0.2",
        edge_rp_bridge="br-edge-rp",
        nft_isolation_file=iso,
        host_ipsets={
            "cloudflare-ipv4": HostIpset(
                url="https://www.cloudflare.com/ips-v4/#",
                comment="Cloudflare IPv4",
            )
        },
        host_ipsets_file=sets_file,
    )


def _mock_nft():
    def fake_vaw(content, path):
        path.write_text(content)
    return patch("nftpol.manager.validate_and_write", side_effect=fake_vaw)


def test_refresh_host_sets_writes_file(tmp_path):
    cfg = _cfg(tmp_path)
    with _mock_nft(), patch(
        "nftpol.manager.resolve_cidr_url",
        return_value=["103.21.244.0/22", "103.22.200.0/22"],
    ):
        refresh_host_sets(cfg)
    content = cfg.host_ipsets_file.read_text()
    assert "set cloudflare-ipv4 {" in content
    assert "103.21.244.0/22" in content
    assert "table inet fw-host" in content


def test_refresh_host_sets_noop_when_no_ipsets(tmp_path):
    from nftpol.config import Config
    cfg = Config(
        wan_iface="eth0",
        traefik_ip="172.20.0.2",
        edge_rp_bridge="br-edge-rp",
        nft_isolation_file=tmp_path / "20.nft",
        host_ipsets={},
        host_ipsets_file=tmp_path / "05.nft",
    )
    with _mock_nft() as mock_vaw:
        refresh_host_sets(cfg)
    mock_vaw.assert_not_called()
    assert not cfg.host_ipsets_file.exists()


def test_refresh_host_sets_dry_run_no_write(tmp_path, capsys):
    cfg = _cfg(tmp_path)
    with _mock_nft() as mock_vaw, patch(
        "nftpol.manager.resolve_cidr_url", return_value=["103.21.244.0/22"]
    ):
        refresh_host_sets(cfg, dry_run=True)
    mock_vaw.assert_not_called()
    assert not cfg.host_ipsets_file.exists()
    out = capsys.readouterr().out
    assert "DRY-RUN" in out


def test_refresh_host_sets_empty_resolution_writes_empty_set(tmp_path):
    cfg = _cfg(tmp_path)
    with _mock_nft(), patch("nftpol.manager.resolve_cidr_url", return_value=[]):
        refresh_host_sets(cfg)
    content = cfg.host_ipsets_file.read_text()
    assert "set cloudflare-ipv4 {" in content
    assert "elements" not in content
