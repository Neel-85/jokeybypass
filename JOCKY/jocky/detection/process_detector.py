SUSPICIOUS_PROCESS_NAMES = {
    "mimikatz.exe",
    "procdump.exe",
    "psexec.exe",
}


def detect_suspicious_processes(processes: list[dict]) -> list[dict]:
    """Detect processes matching known suspicious names."""
    findings = []

    for process in processes:
        name = process.get("name")

        if not name:
            continue

        if name.lower() in SUSPICIOUS_PROCESS_NAMES:
            findings.append({
                "type": "suspicious_process",
                "severity": "high",
                "pid": process.get("pid"),
                "name": name,
                "executable": process.get("executable"),
                "reason": "Process name matched a configured detection rule.",
            })

    return findings