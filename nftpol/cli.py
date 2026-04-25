"""CLI entrypoint for nftpol."""
from __future__ import annotations

import logging
import sys
from pathlib import Path

from .config import ConfigError, load_config
from .manager import apply_transverse, init, list_apps, refresh, refresh_all, refresh_host_sets, remove, upsert
from .nft import NftError
from .policy import PolicyError, load_policy
from .resolver import ResolverError

logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
    stream=sys.stdout,
)
log = logging.getLogger("nftpol")

EXIT_OK = 0
EXIT_VALIDATION = 1
EXIT_NFT_SYNTAX = 2
EXIT_SYSTEM = 3


def _die(msg: str, code: int = EXIT_SYSTEM) -> None:
    print(f"[nftpol] ERROR: {msg}", file=sys.stderr)
    sys.exit(code)


def cmd_init(args) -> None:
    try:
        cfg = load_config(args.config)
        init(cfg, dry_run=args.dry_run)
    except ConfigError as e:
        _die(str(e), EXIT_VALIDATION)
    except NftError as e:
        _die(str(e), EXIT_NFT_SYNTAX)
    except OSError as e:
        _die(str(e), EXIT_SYSTEM)


def cmd_upsert(args) -> None:
    try:
        cfg = load_config(args.config)
        policy = load_policy(Path(args.policy_file))
        upsert(
            args.app_id, args.instance_id, policy, cfg,
            dry_run=args.dry_run,
            rendered_compose=Path(args.rendered_compose) if args.rendered_compose else None,
        )
    except PolicyError as e:
        _die(str(e), EXIT_VALIDATION)
    except ConfigError as e:
        _die(str(e), EXIT_VALIDATION)
    except ResolverError as e:
        _die(str(e), EXIT_SYSTEM)
    except NftError as e:
        _die(str(e), EXIT_NFT_SYNTAX)
    except OSError as e:
        _die(str(e), EXIT_SYSTEM)


def cmd_remove(args) -> None:
    try:
        cfg = load_config(args.config)
        remove(args.app_id, cfg, dry_run=args.dry_run)
    except ConfigError as e:
        _die(str(e), EXIT_VALIDATION)
    except NftError as e:
        _die(str(e), EXIT_NFT_SYNTAX)
    except OSError as e:
        _die(str(e), EXIT_SYSTEM)


def cmd_refresh(args) -> None:
    try:
        cfg = load_config(args.config)
        policy = load_policy(Path(args.policy_file))
        refresh(
            args.app_id, policy, cfg,
            dry_run=args.dry_run,
            instance_id=args.instance_id,
            rendered_compose=Path(args.rendered_compose) if args.rendered_compose else None,
        )
    except PolicyError as e:
        _die(str(e), EXIT_VALIDATION)
    except ConfigError as e:
        _die(str(e), EXIT_VALIDATION)
    except ResolverError as e:
        _die(str(e), EXIT_SYSTEM)
    except NftError as e:
        _die(str(e), EXIT_NFT_SYNTAX)
    except OSError as e:
        _die(str(e), EXIT_SYSTEM)


def cmd_refresh_all(args) -> None:
    try:
        cfg = load_config(args.config)
        refresh_all(Path(args.policy_dir), cfg, dry_run=args.dry_run)
    except ConfigError as e:
        _die(str(e), EXIT_VALIDATION)
    except NftError as e:
        _die(str(e), EXIT_NFT_SYNTAX)
    except OSError as e:
        _die(str(e), EXIT_SYSTEM)


def cmd_refresh_transverse(args) -> None:
    try:
        cfg = load_config(args.config)
        apply_transverse(cfg, dry_run=args.dry_run)
    except ConfigError as e:
        _die(str(e), EXIT_VALIDATION)
    except NftError as e:
        _die(str(e), EXIT_NFT_SYNTAX)
    except OSError as e:
        _die(str(e), EXIT_SYSTEM)


def cmd_refresh_host_sets(args) -> None:
    try:
        cfg = load_config(args.config)
        refresh_host_sets(cfg, dry_run=args.dry_run)
    except ConfigError as e:
        _die(str(e), EXIT_VALIDATION)
    except NftError as e:
        _die(str(e), EXIT_NFT_SYNTAX)
    except OSError as e:
        _die(str(e), EXIT_SYSTEM)


def cmd_validate(args) -> None:
    """Dry-run: parse policy, print resolved IPs. No disk writes."""
    try:
        cfg = load_config(args.config)
        from .policy import validate_fqdn_domains
        from .resolver import collect_dynamic_ips

        policy = load_policy(Path(args.policy_file))
        validate_fqdn_domains(policy, cfg.trusted_fqdn_domains)
        ips = collect_dynamic_ips(policy)
        print(f"[nftpol] Policy valid.")
        if ips:
            print(f"[nftpol] Resolved dynamic IPs: {', '.join(ips)}")
        else:
            print("[nftpol] No dynamic IPs (fqdn/service entries).")
    except PolicyError as e:
        _die(str(e), EXIT_VALIDATION)
    except ConfigError as e:
        _die(str(e), EXIT_VALIDATION)
    except ResolverError as e:
        _die(str(e), EXIT_SYSTEM)


def cmd_list(args) -> None:
    try:
        cfg = load_config(args.config)
        apps = list_apps(cfg)
        for app in apps:
            print(app)
    except ConfigError as e:
        _die(str(e), EXIT_VALIDATION)
    except OSError as e:
        _die(str(e), EXIT_SYSTEM)


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(
        prog="nftpol",
        description="nftables firewall manager for Docker Compose apps",
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=None,
        metavar="PATH",
        help="Path to nftpol.conf.yml (default: $NFTPOL_CONF or /etc/nftpol.conf.yml)",
    )

    sub = parser.add_subparsers(dest="command", required=True)

    # init
    p_init = sub.add_parser("init", help="Create isolation file skeleton")
    p_init.add_argument("--dry-run", action="store_true")
    p_init.set_defaults(func=cmd_init)

    # upsert
    p_upsert = sub.add_parser("upsert", help="Insert/replace app firewall rules")
    p_upsert.add_argument("app_id")
    p_upsert.add_argument("instance_id")
    p_upsert.add_argument("policy_file")
    p_upsert.add_argument(
        "--rendered-compose", dest="rendered_compose", default=None, metavar="PATH",
        help="Path to rendered compose.yml for bridge name resolution (required for via: rules)",
    )
    p_upsert.add_argument("--dry-run", action="store_true")
    p_upsert.set_defaults(func=cmd_upsert)

    # remove
    p_remove = sub.add_parser("remove", help="Remove app firewall rules")
    p_remove.add_argument("app_id")
    p_remove.add_argument("--dry-run", action="store_true")
    p_remove.set_defaults(func=cmd_remove)

    # refresh
    p_refresh = sub.add_parser("refresh", help="Re-resolve dynamic IPs for app")
    p_refresh.add_argument("app_id")
    p_refresh.add_argument("policy_file")
    p_refresh.add_argument("--instance-id", dest="instance_id", default=None,
                           metavar="INSTANCE_ID",
                           help="Instance short ID (required if chain block is missing)")
    p_refresh.add_argument(
        "--rendered-compose", dest="rendered_compose", default=None, metavar="PATH",
        help="Path to rendered compose.yml for bridge name resolution (required for via: rules)",
    )
    p_refresh.add_argument("--dry-run", action="store_true")
    p_refresh.set_defaults(func=cmd_refresh)

    # refresh-all
    p_refresh_all = sub.add_parser("refresh-all", help="Refresh all apps under a policy dir")
    p_refresh_all.add_argument("policy_dir")
    p_refresh_all.add_argument("--dry-run", action="store_true")
    p_refresh_all.set_defaults(func=cmd_refresh_all)

    # refresh-transverse
    p_rt = sub.add_parser(
        "refresh-transverse",
        help="Re-apply transverse network isolation rules from config",
    )
    p_rt.add_argument("--dry-run", action="store_true")
    p_rt.set_defaults(func=cmd_refresh_transverse)

    # refresh-host-sets
    p_rhs = sub.add_parser("refresh-host-sets", help="Fetch host IP sets from configured URLs")
    p_rhs.add_argument("--dry-run", action="store_true")
    p_rhs.set_defaults(func=cmd_refresh_host_sets)

    # validate
    p_validate = sub.add_parser("validate", help="Validate a policy file (dry-run)")
    p_validate.add_argument("policy_file")
    p_validate.set_defaults(func=cmd_validate)

    # list
    p_list = sub.add_parser("list", help="List managed app IDs")
    p_list.set_defaults(func=cmd_list)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
