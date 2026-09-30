import json
import os
import platform
import subprocess


def collect_users() -> list[dict]:
    """Collect local user account information."""

    system = platform.system()

    if system == "Windows":
        return collect_windows_users()

    if system == "Linux":
        return collect_linux_users()

    return []


def collect_linux_users() -> list[dict]:
    """Collect Linux local user information."""

    import pwd

    users = []

    for entry in pwd.getpwall():
        users.append(
            {
                "username": entry.pw_name,
                "user_id": entry.pw_uid,
                "group_id": entry.pw_gid,
                "home_directory": entry.pw_dir,
                "shell": entry.pw_shell,
                "is_current_user": (
                    entry.pw_uid == os.getuid()
                ),
            }
        )

    return users


def collect_windows_users() -> list[dict]:
    """Collect Windows local user information."""

    users = []

    result = subprocess.run(
        [
            "powershell",
            "-NoProfile",
            "-Command",
            (
                "Get-LocalUser | "
                "Select-Object Name,Enabled,LastLogon,SID | "
                "ConvertTo-Json"
            ),
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    if result.returncode != 0:
        return users

    if not result.stdout.strip():
        return users

    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        return users

    if isinstance(data, dict):
        data = [data]

    for user in data:
        users.append(
            {
                "username": user.get("Name"),
                "enabled": user.get("Enabled"),
                "last_logon": user.get("LastLogon"),
                "sid": user.get("SID"),
            }
        )

    return users