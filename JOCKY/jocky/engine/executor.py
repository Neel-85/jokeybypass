from pathlib import Path

from rich.console import Console

from jocky.evidence.collector import (
    collect_system_info,
    save_evidence,
)
from jocky.evidence.process_collector import (
    collect_processes,
)
from jocky.evidence.network_collector import (
    collect_network_connections,
)
from jocky.evidence.hash_utils import (
    calculate_sha256,
)
from jocky.detection.process_detector import (
    detect_suspicious_processes,
)
from jocky.report.generator import (
    generate_report,
)
from jocky.ir.instructions import (
    ScanSystemInstruction,
    ScanProcessesInstruction,
    ScanNetworkInstruction,
    ReportInstruction,
    ScanPersistenceInstruction,
    ScanFilesInstruction,
)
from jocky.evidence.persistence_collector import collect_persistence
from jocky.evidence.file_collector import collect_files
from jocky.ir.program import IRProgram
from jocky.evidence.database import (
    initialize_database,
    add_evidence,
)

console = Console()

db_path = Path("evidence/jocky.db")
initialize_database(db_path)

def execute_ir(program: IRProgram) -> None:
    """Execute JOCKY IR instructions."""

    process_list = []

    for instruction in program.instructions:

        if isinstance(instruction, ScanSystemInstruction):
            data = collect_system_info()

            output_path = Path(
                "evidence/system_info.json"
            )

            save_evidence(
                data,
                output_path,
            )

            evidence_hash = calculate_sha256(
                output_path
            )

            console.print(
                "[green][+] System evidence collected[/green]"
            )
            console.print(
                f"    SHA-256: {evidence_hash}"
            )

        elif isinstance(
            instruction,
            ScanProcessesInstruction,
        ):
            process_list = collect_processes()

            output_path = Path(
                "evidence/processes.json"
            )

            save_evidence(
                {
                    "evidence_type": "process_list",
                    "process_count": len(process_list),
                    "processes": process_list,
                },
                output_path,
            )

            evidence_hash = calculate_sha256(
                output_path
            )

            console.print(
                "[green][+] Process evidence collected[/green]"
            )
            console.print(
                f"    Processes: {len(process_list)}"
            )
            console.print(
                f"    SHA-256: {evidence_hash}"
            )

            findings = detect_suspicious_processes(
                process_list
            )

            findings_path = Path(
                "evidence/findings.json"
            )

            save_evidence(
                {
                    "evidence_type": "detection_findings",
                    "finding_count": len(findings),
                    "findings": findings,
                },
                findings_path,
            )

            findings_hash = calculate_sha256(
                findings_path
            )

            console.print(
                "[green][+] Detection completed[/green]"
            )
            console.print(
                f"    Findings: {len(findings)}"
            )
            console.print(
                f"    SHA-256: {findings_hash}"
            )

        elif isinstance(instruction, ScanNetworkInstruction):
            connections = collect_network_connections()

            output_path = Path(
                "evidence/network_connections.json"
            )

            save_evidence(
                {
                    "evidence_type": "network_connections",
                    "connection_count": len(connections),
                    "connections": connections,
                },
                output_path,
            )

            evidence_hash = calculate_sha256(output_path)

    
            console.print(
                "[green][+] Network evidence collected[/green]"
            )
            console.print(
                f"    Connections: {len(connections)}"
            )
            console.print(
                f"    SHA-256: {evidence_hash}"
            )

        elif isinstance(instruction, ScanPersistenceInstruction):
            items = collect_persistence()
            output_path = Path("evidence/persistence.json")
            save_evidence(
                {
                    "evidence_type": "persistence",
                    "entry_count": len(items),
                    "entries": items,
                },
                output_path,
            )
            console.print("[green][+] Persistence evidence collected[/green]")
            console.print(f"    Entries: {len(items)}")
            console.print(f"    SHA-256: {calculate_sha256(output_path)}")

        elif isinstance(instruction, ScanFilesInstruction):
            file_list = collect_files(Path(instruction.path))
            output_path = Path("evidence/file_hashes.json")
            save_evidence(
                {
                    "evidence_type": "file_analysis",
                    "directory": instruction.path,
                    "file_count": len(file_list),
                    "files": file_list,
                },
                output_path,
            )
            console.print("[green][+] File evidence collected[/green]")
            console.print(f"    Directory: {instruction.path}")
            console.print(f"    Files: {len(file_list)}")
            console.print(f"    SHA-256: {calculate_sha256(output_path)}")

        elif isinstance(
            instruction,
            ReportInstruction,
        ):
            report_text = generate_report()

            output_path = Path(
                "reports/forensic_report.txt"
            )

            output_path.parent.mkdir(
                parents=True,
                exist_ok=True,
            )

            output_path.write_text(
                report_text,
                encoding="utf-8",
            )

            report_hash = calculate_sha256(
                output_path
            )

            console.print(
                "[green][+] Report generated[/green]"
            )
            console.print(
                f"    File: {output_path}"
            )
            console.print(
                f"    SHA-256: {report_hash}"
            )

        else:
            raise ValueError(
                f"Unsupported IR instruction: "
                f"{instruction.opcode}"
            )

    console.print("")
    console.print(
        "[bold]JOCKY execution completed.[/bold]"
    )