import platform
import subprocess
from pathlib import Path


def collect_persistence() -> list[dict]:
    """Collect common persistence mechanisms."""

    system = platform.system()

    if system == "Windows":
        return collect_windows_persistence()

    if system == "Linux":
        return collect_linux_persistence()

    return []


def collect_windows_persistence() -> list[dict]:
    """Collect Windows persistence entries."""

    persistence = []

    registry_paths = [
        r"HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
        r"HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        r"HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
        r"HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    ]

    for registry_path in registry_paths:
        result = subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-Command",
                (
                    f"Get-ItemProperty -Path '{registry_path}' "
                    "-ErrorAction SilentlyContinue | "
                    "ConvertTo-Json"
                ),
            ],
            capture_output=True,
            text=True,
            check=False,
        )

        if result.returncode != 0:
            continue

        if not result.stdout.strip():
            continue

        persistence.append(
            {
                "type": "registry_run",
                "location": registry_path,
                "data": result.stdout.strip(),
            }
        )

    startup_paths = [
        Path.home()
        / "AppData"
        / "Roaming"
        / "Microsoft"
        / "Windows"
        / "Start Menu"
        / "Programs"
        / "Startup",
    ]

    for startup_path in startup_paths:
        if not startup_path.exists():
            continue

        for item in startup_path.iterdir():
            persistence.append(
                {
                    "type": "startup_folder",
                    "location": str(item),
                    "name": item.name,
                }
            )

    return persistence


def collect_linux_persistence() -> list[dict]:
    """Collect common Linux persistence entries."""

    persistence = []

    cron_paths = [
        Path("/etc/crontab"),
        Path("/etc/cron.d"),
        Path("/etc/cron.daily"),
        Path("/etc/cron.hourly"),
        Path("/etc/cron.weekly"),
        Path("/etc/cron.monthly"),
    ]

    for path in cron_paths:
        if not path.exists():
            continue

        persistence.append(
            {
                "type": "cron",
                "location": str(path),
            }
        )

    systemd_path = Path("/etc/systemd/system")

    if systemd_path.exists():
        for item in systemd_path.iterdir():
            persistence.append(
                {
                    "type": "systemd",
                    "location": str(item),
                    "name": item.name,
                }
            )

    autostart_path = (
        Path.home()
        / ".config"
        / "autostart"
    )

    if autostart_path.exists():
        for item in autostart_path.iterdir():
            persistence.append(
                {
                    "type": "user_autostart",
                    "location": str(item),
                    "name": item.name,
                }
            )

    return persistence