"""nft subprocess wrapper: validate + reload."""
from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path


class NftError(Exception):
    pass


def validate(content: str) -> None:
    """Write content to a temp file and validate with nft -c -f. Always cleans up."""
    tmp = tempfile.NamedTemporaryFile(
        mode="w", suffix=".nft", delete=False, prefix="nftpol-"
    )
    tmp_path = Path(tmp.name)
    try:
        # Prepend flush ruleset so nft -c starts from an empty simulated state.
        # This prevents false "File exists" errors when objects already exist in
        # the live kernel — the actual file uses a targeted flush table instead.
        tmp.write("flush ruleset\n" + content)
        tmp.flush()
        tmp.close()
        result = subprocess.run(
            ["nft", "-c", "-f", str(tmp_path)],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            raise NftError(
                f"nft syntax check failed:\n{result.stderr.strip()}"
            )
    finally:
        tmp_path.unlink(missing_ok=True)


def validate_and_write(content: str, path: Path) -> None:
    """Validate content, then write it to path and reload nftables."""
    validate(content)
    # Write to a temp file next to destination, then atomic rename
    tmp = path.with_suffix(".tmp")
    try:
        tmp.write_text(content)
        shutil.copy2(str(tmp), str(path))
    finally:
        tmp.unlink(missing_ok=True)
    _reload(path)


def _reload(path: Path) -> None:
    """Apply the managed file directly with nft -f.

    Using nft -f <path> rather than systemctl reload keeps the operation
    targeted to our table only and avoids interference from the system's
    main nftables.conf (which may flush and reload unrelated rules).
    The flush preamble in the file ensures idempotency.
    """
    result = subprocess.run(
        ["nft", "-f", str(path)],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise NftError(f"nftables reload failed:\n{result.stderr.strip()}")


def current_ruleset() -> str:
    """Return the current nftables ruleset for debugging."""
    result = subprocess.run(
        ["nft", "list", "ruleset"],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise NftError(f"nft list ruleset failed:\n{result.stderr.strip()}")
    return result.stdout
