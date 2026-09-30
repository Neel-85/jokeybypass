import psutil


def collect_processes() -> list[dict]:
    """Collect detailed information about running processes."""

    processes = []

    for process in psutil.process_iter(
        [
            "pid",
            "name",
            "exe",
            "username",
            "memory_info",
            "memory_percent",
        ]
    ):
        try:
            cpu_percent = process.cpu_percent(interval=0.1)
            memory_percent = process.info.get("memory_percent") or 0.0

            memory_info = process.info.get("memory_info")

            if memory_info is not None:
                memory_mb = memory_info.rss / (1024 * 1024)
            else:
                memory_mb = 0.0

            processes.append(
                {
                    "pid": process.info.get("pid"),
                    "name": process.info.get("name"),
                    "executable": process.info.get("exe"),
                    "username": process.info.get("username"),
                    "cpu_percent": round(cpu_percent, 2),
                    "memory_percent": round(memory_percent, 2),
                    "memory_mb": round(memory_mb, 2),
                }
            )

        except (
            psutil.NoSuchProcess,
            psutil.AccessDenied,
            psutil.ZombieProcess,
        ):
            continue

    processes.sort(
        key=lambda item: item.get("memory_percent", 0),
        reverse=True,
    )

    return processes