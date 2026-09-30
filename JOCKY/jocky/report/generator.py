import json
from pathlib import Path


def load_json(path: Path) -> dict:
    """Load JSON evidence."""
    with path.open("r", encoding="utf-8") as file:
        return json.load(file)


def generate_report() -> str:
    """Generate a terminal investigation report."""

    system_data = load_json(
        Path("evidence/system_info.json")
    )

    process_data = load_json(
        Path("evidence/processes.json")
    )

    findings_data = load_json(
        Path("evidence/findings.json")
    )

    lines = [
        "========================================",
        "        JOCKY FORENSIC REPORT",
        "========================================",
        "",
        "SYSTEM",
        "------",
        f"Operating System : {system_data.get('operating_system')}",
        f"OS Release      : {system_data.get('os_release')}",
        f"Architecture    : {system_data.get('architecture')}",
        f"Hostname        : {system_data.get('hostname')}",
        "",
        "PROCESS ANALYSIS",
        "----------------",
        f"Processes Found : {process_data.get('process_count', 0)}",
        "",
        "DETECTION",
        "---------",
        f"Findings        : {findings_data.get('finding_count', 0)}",
        "",
    ]

    findings = findings_data.get("findings", [])

    if findings:
        lines.append("FINDINGS")
        lines.append("--------")

        for finding in findings:
            lines.append(
                f"[{finding.get('severity', 'unknown').upper()}] "
                f"{finding.get('name')} "
                f"(PID: {finding.get('pid')})"
            )

            lines.append(
                f"Reason: {finding.get('reason')}"
            )

            lines.append("")

    else:
        lines.append("No configured detection matches found.")

    lines.extend([
        "========================================",
        "        END OF JOCKY REPORT",
        "========================================",
    ])

    return "\n".join(lines)