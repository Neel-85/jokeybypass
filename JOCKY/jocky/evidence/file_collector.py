from datetime import datetime, timezone
from pathlib import Path

from jocky.evidence.hash_utils import calculate_sha256


def collect_files(directory: Path) -> list[dict]:
    """Collect file metadata and SHA-256 hashes."""

    if not directory.exists():
        raise FileNotFoundError(
            f"Directory not found: {directory}"
        )

    if not directory.is_dir():
        raise NotADirectoryError(
            f"Not a directory: {directory}"
        )

    files = []

    for file_path in directory.rglob("*"):
        if not file_path.is_file():
            continue

        try:
            stat = file_path.stat()
            file_hash = calculate_sha256(file_path)

            files.append(
                {
                    "path": str(file_path),
                    "name": file_path.name,
                    "extension": file_path.suffix,
                    "size": stat.st_size,
                    "created_at": datetime.fromtimestamp(
                        stat.st_ctime,
                        timezone.utc,
                    ).isoformat(),
                    "modified_at": datetime.fromtimestamp(
                        stat.st_mtime,
                        timezone.utc,
                    ).isoformat(),
                    "accessed_at": datetime.fromtimestamp(
                        stat.st_atime,
                        timezone.utc,
                    ).isoformat(),
                    "sha256": file_hash,
                }
            )

        except (
            PermissionError,
            OSError,
        ):
            continue

    return files