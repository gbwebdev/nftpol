"""Tests for nftpol/config.py — transverse_networks extension."""
from pathlib import Path

import pytest
import yaml

from nftpol.config import ConfigError, TransverseNetwork, load_config


def _write_config(tmp_path: Path, data: dict) -> Path:
    p = tmp_path / "nftpol.conf.yml"
    p.write_text(yaml.dump(data))
    return p


def _base(tmp_path: Path, **kwargs) -> dict:
    return {
        "wan_iface": "eth0",
        "nft_isolation_file": str(tmp_path / "20-docker-isolation.nft"),
        **kwargs,
    }


# --- transverse_networks loading ---


def test_transverse_networks_parsed(tmp_path):
    data = _base(tmp_path, transverse_networks=[
        {"name": "edge_rp", "bridge": "br-edge-rp", "privileged_ip": "172.26.48.1", "direction": "outbound"},
        {"name": "shared_db", "bridge": "br-db", "privileged_ip": "172.26.48.65",
         "direction": "inbound", "comment": "Postgres"},
    ])
    cfg = load_config(_write_config(tmp_path, data))
    assert len(cfg.transverse_networks) == 2
    assert cfg.transverse_networks[0] == TransverseNetwork(
        name="edge_rp", bridge="br-edge-rp", privileged_ip="172.26.48.1", direction="outbound"
    )
    assert cfg.transverse_networks[1].comment == "Postgres"
    assert cfg.transverse_networks[1].direction == "inbound"


def test_transverse_networks_empty_by_default(tmp_path):
    cfg = load_config(_write_config(tmp_path, _base(tmp_path)))
    assert cfg.transverse_networks == []


# --- backward compatibility: traefik_ip + edge_rp_bridge ---


def test_legacy_fields_auto_convert_to_transverse(tmp_path):
    """traefik_ip + edge_rp_bridge without transverse_networks → auto-generate edge_rp entry."""
    data = _base(tmp_path, traefik_ip="172.26.48.1", edge_rp_bridge="br-edge-rp")
    cfg = load_config(_write_config(tmp_path, data))
    assert len(cfg.transverse_networks) == 1
    tn = cfg.transverse_networks[0]
    assert tn.name == "edge_rp"
    assert tn.bridge == "br-edge-rp"
    assert tn.privileged_ip == "172.26.48.1"
    assert tn.direction == "outbound"


def test_explicit_transverse_networks_takes_precedence_over_legacy(tmp_path):
    """When transverse_networks is set, traefik_ip/edge_rp_bridge are ignored."""
    data = _base(tmp_path,
        traefik_ip="172.26.48.1",
        edge_rp_bridge="br-edge-rp",
        transverse_networks=[
            {"name": "my_net", "bridge": "br-my", "privileged_ip": "10.0.0.1", "direction": "inbound"},
        ],
    )
    cfg = load_config(_write_config(tmp_path, data))
    assert len(cfg.transverse_networks) == 1
    assert cfg.transverse_networks[0].name == "my_net"


def test_only_traefik_ip_without_bridge_does_not_auto_convert(tmp_path):
    """Only one of the pair present → no auto-conversion, no error."""
    data = _base(tmp_path, traefik_ip="172.26.48.1")
    cfg = load_config(_write_config(tmp_path, data))
    assert cfg.transverse_networks == []


# --- validation ---


def test_invalid_direction_raises_config_error(tmp_path):
    data = _base(tmp_path, transverse_networks=[
        {"name": "x", "bridge": "br-x", "privileged_ip": "10.0.0.1", "direction": "sideways"},
    ])
    with pytest.raises(ConfigError, match="direction"):
        load_config(_write_config(tmp_path, data))


def test_missing_name_raises_config_error(tmp_path):
    data = _base(tmp_path, transverse_networks=[
        {"bridge": "br-x", "privileged_ip": "10.0.0.1", "direction": "outbound"},
    ])
    with pytest.raises(ConfigError):
        load_config(_write_config(tmp_path, data))


def test_missing_bridge_raises_config_error(tmp_path):
    data = _base(tmp_path, transverse_networks=[
        {"name": "x", "privileged_ip": "10.0.0.1", "direction": "outbound"},
    ])
    with pytest.raises(ConfigError):
        load_config(_write_config(tmp_path, data))


def test_missing_privileged_ip_raises_config_error(tmp_path):
    data = _base(tmp_path, transverse_networks=[
        {"name": "x", "bridge": "br-x", "direction": "outbound"},
    ])
    with pytest.raises(ConfigError):
        load_config(_write_config(tmp_path, data))


def test_missing_required_field_wan_iface(tmp_path):
    data = {"nft_isolation_file": str(tmp_path / "x.nft")}
    with pytest.raises(ConfigError, match="wan_iface"):
        load_config(_write_config(tmp_path, data))


def test_missing_required_field_nft_isolation_file(tmp_path):
    data = {"wan_iface": "eth0"}
    with pytest.raises(ConfigError, match="nft_isolation_file"):
        load_config(_write_config(tmp_path, data))
