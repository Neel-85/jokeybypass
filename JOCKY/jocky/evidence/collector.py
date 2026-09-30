import json
import platform
from datetime import datetime, timezone
from pathlib import Path


def collect_system_info() -> dict:
    """Collect basic system information."""
    return {
        "evidence_type": "system_info",
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "operating_system": platform.system(),
        "os_release": platform.release(),
        "architecture": platform.machine(),
        "hostname": platform.node(),
        "python_version": platform.python_version(),
    }


def save_evidence(data: dict, output_path: Path) -> None:
    """Save evidence as JSON."""
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with output_path.open("w", encoding="utf-8") as file:
        json.dump(data, file, indent=4)