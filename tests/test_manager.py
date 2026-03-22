"""Tests for nftpol/manager.py"""
import re
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from nftpol.config import Config
from nftpol.manager import (
    _ANCHOR,
    init,
    list_apps,
    remove,
    upsert,
)
from nftpol.policy import EgressRule, Policy


def _cfg(tmp_path: Path, traefik_ip="172.20.0.2", bridge="br-edge-rp") -> Config:
    iso = tmp_path / "20-docker-isolation.nft"
    return Config(
        wan_iface="eth0",
        traefik_ip=traefik_ip,
        edge_rp_bridge=bridge,
        nft_isolation_file=iso,
        trusted_fqdn_domains=["example.com"],
    )


def _simple_policy(default="deny") -> Policy:
    return Policy(
        egress_rules=[EgressRule(cidr="1.2.3.0/24", proto="tcp", port=443)],
        egress_default=default,
    )


def _mock_nft():
    """Patch validate_and_write to be a plain file write."""
    def fake_vaw(content, path):
        path.write_text(content)
    return patch("nftpol.manager.validate_and_write", side_effect=fake_vaw)


# --- init ---


def test_init_creates_file(tmp_path):
    cfg = _cfg(tmp_path)
    with _mock_nft():
        init(cfg)
    assert cfg.nft_isolation_file.exists()
    content = cfg.nft_isolation_file.read_text()
    assert _ANCHOR in content
    assert "fw-docker" in content
    assert "STATIC BEGIN" in content


def test_init_noop_if_file_exists(tmp_path):
    cfg = _cfg(tmp_path)
    cfg.nft_isolation_file.write_text("existing content")
    with _mock_nft() as mock_vaw:
        init(cfg)
    mock_vaw.assert_not_called()


def test_init_dry_run_no_write(tmp_path, capsys):
    cfg = _cfg(tmp_path)
    with _mock_nft() as mock_vaw:
        init(cfg, dry_run=True)
    mock_vaw.assert_not_called()
    assert not cfg.nft_isolation_file.exists()
    out = capsys.readouterr().out
    assert "DRY-RUN" in out


# --- upsert ---


def _initialized_file(tmp_path: Path) -> Config:
    cfg = _cfg(tmp_path)
    with _mock_nft():
        init(cfg)
    return cfg


def test_upsert_inserts_block_before_anchor(tmp_path):
    cfg = _initialized_file(tmp_path)
    policy = _simple_policy()
    with _mock_nft():
        upsert("myapp", "abc1234", policy, cfg)
    content = cfg.nft_isolation_file.read_text()
    assert "BEGIN_APP myapp" in content
    assert "END_APP myapp" in content
    assert _ANCHOR in content
    # anchor must come after the block
    assert content.index("BEGIN_APP myapp") < content.index(_ANCHOR)


def test_upsert_replaces_existing_block(tmp_path):
    cfg = _initialized_file(tmp_path)
    policy1 = _simple_policy()
    policy2 = Policy(
        egress_rules=[EgressRule(cidr="9.9.9.0/24", proto="tcp", port=53)],
        egress_default="deny",
    )
    with _mock_nft():
        upsert("myapp", "abc1234", policy1, cfg)
        upsert("myapp", "abc1234", policy2, cfg)
    content = cfg.nft_isolation_file.read_text()
    assert content.count("BEGIN_APP myapp") == 1
    assert "9.9.9.0/24" in content


def test_upsert_multiple_apps_coexist(tmp_path):
    cfg = _initialized_file(tmp_path)
    with _mock_nft():
        upsert("app1", "abc1234", _simple_policy(), cfg)
        upsert("app2", "abc1234", _simple_policy(), cfg)
    content = cfg.nft_isolation_file.read_text()
    assert "BEGIN_APP app1" in content
    assert "BEGIN_APP app2" in content
    assert _ANCHOR in content


def test_upsert_one_app_does_not_affect_other(tmp_path):
    cfg = _initialized_file(tmp_path)
    policy_a = Policy(
        egress_rules=[EgressRule(cidr="1.1.1.0/24", proto="tcp", port=80)],
        egress_default="deny",
    )
    policy_b = Policy(
        egress_rules=[EgressRule(cidr="2.2.2.0/24", proto="tcp", port=443)],
        egress_default="deny",
    )
    with _mock_nft():
        upsert("app1", "abc1234", policy_a, cfg)
        upsert("app2", "def5678", policy_b, cfg)
        # Re-upsert app1 only
        upsert("app1", "abc1234", policy_a, cfg)
    content = cfg.nft_isolation_file.read_text()
    assert "2.2.2.0/24" in content  # app2 rules still present


def test_anchor_always_present_after_upsert(tmp_path):
    cfg = _initialized_file(tmp_path)
    with _mock_nft():
        upsert("app1", "abc1234", _simple_policy(), cfg)
        upsert("app2", "abc1234", _simple_policy(), cfg)
        remove("app1", cfg)
    assert _ANCHOR in cfg.nft_isolation_file.read_text()


# --- remove ---


def test_remove_existing_app(tmp_path):
    cfg = _initialized_file(tmp_path)
    with _mock_nft():
        upsert("myapp", "abc1234", _simple_policy(), cfg)
        remove("myapp", cfg)
    content = cfg.nft_isolation_file.read_text()
    assert "BEGIN_APP myapp" not in content
    assert _ANCHOR in content


def test_remove_unknown_app_is_noop(tmp_path):
    cfg = _initialized_file(tmp_path)
    content_before = cfg.nft_isolation_file.read_text()
    with _mock_nft() as mock_vaw:
        remove("ghost", cfg)
    mock_vaw.assert_not_called()
    assert cfg.nft_isolation_file.read_text() == content_before


def test_remove_one_does_not_affect_other(tmp_path):
    cfg = _initialized_file(tmp_path)
    with _mock_nft():
        upsert("app1", "abc1234", _simple_policy(), cfg)
        upsert("app2", "abc1234", _simple_policy(), cfg)
        remove("app1", cfg)
    content = cfg.nft_isolation_file.read_text()
    assert "BEGIN_APP app1" not in content
    assert "BEGIN_APP app2" in content


# --- list_apps ---


def test_list_apps_returns_all_managed(tmp_path):
    cfg = _initialized_file(tmp_path)
    with _mock_nft():
        upsert("alpha", "abc1234", _simple_policy(), cfg)
        upsert("beta", "def5678", _simple_policy(), cfg)
    apps = list_apps(cfg)
    assert set(apps) == {"alpha", "beta"}


def test_list_apps_empty(tmp_path):
    cfg = _initialized_file(tmp_path)
    assert list_apps(cfg) == []
