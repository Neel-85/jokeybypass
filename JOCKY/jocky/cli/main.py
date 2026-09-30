import platform
import typer
from pathlib import Path
from jocky.evidence.collector import collect_system_info, save_evidence
import json
from jocky.evidence.process_collector import collect_processes
from jocky.evidence.hash_utils import calculate_sha256
from jocky.detection.process_detector import detect_suspicious_processes
from jocky.report.generator import generate_report
from jocky.evidence.database import initialize_database, add_evidence
from jocky.evidence.database import (
    initialize_database,
    add_evidence,
    get_evidence,
)
from jocky.compiler.parser import parse_script
from jocky.compiler.ir_compiler import compile_to_ir
from jocky.engine.executor import execute_ir
from jocky.evidence.network_collector import (
    collect_network_connections,
)
from jocky.evidence.file_collector import (
    collect_files,
)
from jocky.evidence.persistence_collector import (
    collect_persistence,
)
from rich.table import Table

app = typer.Typer(
    name="jocky",
    help="JOCKY Digital Forensics Framework",
)


@app.command()
def version():
    """Show JOCKY version."""
    typer.echo("JOCKY v0.1.0")


@app.command()
def status():
    """Show JOCKY system status."""
    typer.echo("JOCKY is ready.")


@app.command("system-info")
def system_info():
    """Collect and save basic system information."""
    data = collect_system_info()

    output_path = Path("evidence/system_info.json")
    save_evidence(data, output_path)
    evidence_hash = calculate_sha256(output_path)

    typer.echo("=== JOCKY System Information ===")
    typer.echo(f"Operating System : {data['operating_system']}")
    typer.echo(f"OS Release      : {data['os_release']}")
    typer.echo(f"Architecture    : {data['architecture']}")
    typer.echo(f"Hostname        : {data['hostname']}")
    typer.echo(f"Python Version  : {data['python_version']}")
    typer.echo("")
    typer.echo(f"Evidence saved  : {output_path}")
    typer.echo(f"SHA-256         : {evidence_hash}")

@app.command()
def processes():
    """Collect and display detailed running process information."""

    process_list = collect_processes()

    output_path = Path("evidence/processes.json")

    save_evidence(
        {
            "evidence_type": "process_list",
            "process_count": len(process_list),
            "processes": process_list,
        },
        output_path,
    )

    evidence_hash = calculate_sha256(output_path)

    typer.echo("")
    typer.echo("========================================")
    typer.echo("       JOCKY PROCESS ANALYSIS")
    typer.echo("========================================")
    typer.echo("")

    typer.echo(
        f"Total running processes : "
        f"{len(process_list)}"
    )

    typer.echo(
        f"Evidence saved          : "
        f"{output_path}"
    )

    typer.echo(
        f"Evidence SHA-256        : "
        f"{evidence_hash}"
    )

    typer.echo("")

    table = Table(
        title="Running Processes",
        show_lines=False,
    )

    table.add_column(
        "PID",
        justify="right",
    )

    table.add_column(
        "PROCESS",
        style="cyan",
    )

    table.add_column(
        "CPU %",
        justify="right",
    )

    table.add_column(
        "MEM %",
        justify="right",
    )

    table.add_column(
        "MEM MB",
        justify="right",
    )

    table.add_column(
        "USER",
    )

    table.add_column(
        "EXECUTABLE",
    )

    for process in process_list:
        table.add_row(
            str(process.get("pid") or "-"),
            str(process.get("name") or "-"),
            f"{process.get('cpu_percent', 0):.2f}",
            f"{process.get('memory_percent', 0):.2f}",
            f"{process.get('memory_mb', 0):.2f}",
            str(process.get("username") or "-"),
            str(process.get("executable") or "-"),
        )

    from rich.console import Console

    console = Console()
    console.print(table)

    typer.echo("")
    typer.echo("========================================")
    typer.echo("       PROCESS ANALYSIS COMPLETED")
    typer.echo("========================================")

@app.command()
def scan():
    
    """Run a basic forensic evidence scan."""
    db_path = Path("evidence/jocky.db")
    initialize_database(db_path)

    typer.echo("=== JOCKY Forensic Scan ===")
    typer.echo("")

    # System information
    system_data = collect_system_info()
    system_path = Path("evidence/system_info.json")
    save_evidence(system_data, system_path)

    system_hash = calculate_sha256(system_path)

    add_evidence(
        db_path,
        "system_info",
        str(system_path),
        system_hash,
        system_data["collected_at"],
    )

    typer.echo("[+] System information collected")
    typer.echo(f"    File : {system_path}")
    typer.echo(f"    SHA-256 : {system_hash}")
    typer.echo("")

    # Process information
    process_list = collect_processes()

    process_path = Path("evidence/processes.json")

    save_evidence(
        {
            "evidence_type": "process_list",
            "process_count": len(process_list),
            "processes": process_list,
        },
        process_path,
    )

    process_hash = calculate_sha256(process_path)

    typer.echo("[+] Process information collected")
    typer.echo(f"    Processes : {len(process_list)}")
    typer.echo(f"    File : {process_path}")
    typer.echo(f"    SHA-256 : {process_hash}")
    typer.echo("")

    findings = detect_suspicious_processes(process_list)

    findings_path = Path("evidence/findings.json")

    findings_data = {
        "evidence_type": "detection_findings",
        "finding_count": len(findings),
        "findings": findings,
    }

    save_evidence(findings_data, findings_path)

    findings_hash = calculate_sha256(findings_path)

    typer.echo("=== Detection Results ===")

    if not findings:
        typer.echo("[+] No configured suspicious process matches found.")
    else:
        typer.echo(f"[!] Findings: {len(findings)}")

        for finding in findings:
            typer.echo(
                f"    [{finding['severity'].upper()}] "
                f"{finding['name']} "
                f"(PID: {finding['pid']})"
            )

    typer.echo("")
    typer.echo(f"Findings saved : {findings_path}")
    typer.echo(f"SHA-256        : {findings_hash}")
    typer.echo("")
    typer.echo("[+] Forensic scan completed.")

@app.command()
def report():
    """Generate and save the latest forensic investigation report."""

    report_text = generate_report()

    output_path = Path("reports/forensic_report.txt")
    output_path.parent.mkdir(parents=True, exist_ok=True)

    output_path.write_text(
        report_text,
        encoding="utf-8",
    )

    report_hash = calculate_sha256(output_path)

    typer.echo(report_text)
    typer.echo("")
    typer.echo(f"Report saved : {output_path}")
    typer.echo(f"SHA-256      : {report_hash}")

@app.command()
def evidence():
    """List collected evidence records."""

    db_path = Path("evidence/jocky.db")

    if not db_path.exists():
        typer.echo(
            "[!] Evidence database not found. "
            "Run 'jocky scan' first."
        )
        raise typer.Exit(code=1)

    records = get_evidence(db_path)

    typer.echo("=== JOCKY Evidence Database ===")
    typer.echo("")

    if not records:
        typer.echo("No evidence records found.")
        return

    for record in records:
        evidence_id, evidence_type, file_path, sha256, collected_at = record

        typer.echo(f"ID          : {evidence_id}")
        typer.echo(f"Type        : {evidence_type}")
        typer.echo(f"File        : {file_path}")
        typer.echo(f"SHA-256     : {sha256}")
        typer.echo(f"Collected   : {collected_at}")
        typer.echo("-" * 50)

@app.command()
def parse(script: Path):
    """Parse a JOCKY script into an AST."""

    try:
        program = parse_script(script)
    except Exception as error:
        typer.echo(f"[!] Parse error: {error}")
        raise typer.Exit(code=1)

    typer.echo("=== JOCKY AST ===")
    typer.echo("")

    for index, statement in enumerate(program.statements, start=1):
        typer.echo(
            f"{index}. {statement.__class__.__name__}"
        )

@app.command()
def compile(script: Path):
    """Compile a JOCKY script into JOCKY IR."""

    try:
        program = parse_script(script)
        ir_program = compile_to_ir(program)

    except Exception as error:
        typer.echo(f"[!] Compilation error: {error}")
        raise typer.Exit(code=1)

    typer.echo("=== JOCKY IR ===")
    typer.echo("")

    for index, instruction in enumerate(
        ir_program.instructions,
        start=1,
    ):
        typer.echo(
            f"{index}. {instruction.opcode}"
        )

@app.command()
def run(script: Path):
    """Compile and execute a JOCKY script."""

    try:
        program = parse_script(script)
        ir_program = compile_to_ir(program)
        execute_ir(ir_program)

    except Exception as error:
        typer.echo(f"[!] Execution error: {error}")
        raise typer.Exit(code=1)

@app.command()
def network():
    """Collect currently active network connections."""
    connections = collect_network_connections()

    output_path = Path("evidence/network_connections.json")

    save_evidence(
        {
            "evidence_type": "network_connections",
            "connection_count": len(connections),
            "connections": connections,
        },
        output_path,
    )

    evidence_hash = calculate_sha256(output_path)

    typer.echo("=== JOCKY Network Evidence ===")
    typer.echo(f"Connections found : {len(connections)}")
    typer.echo(f"Evidence saved    : {output_path}")
    typer.echo(f"SHA-256           : {evidence_hash}")

@app.command()
def files(directory: Path):
    """Collect file metadata and SHA-256 hashes."""

    try:
        file_list = collect_files(directory)
    except (FileNotFoundError, NotADirectoryError) as error:
        typer.echo(f"[!] File collection error: {error}")
        raise typer.Exit(code=1)

    output_path = Path("evidence/file_hashes.json")

    save_evidence(
        {
            "evidence_type": "file_analysis",
            "directory": str(directory),
            "file_count": len(file_list),
            "files": file_list,
        },
        output_path,
    )

    evidence_hash = calculate_sha256(output_path)

    typer.echo("=== JOCKY File Evidence ===")
    typer.echo(f"Directory       : {directory}")
    typer.echo(f"Files examined  : {len(file_list)}")
    typer.echo(f"Evidence saved  : {output_path}")
    typer.echo(f"SHA-256         : {evidence_hash}")

@app.command("investigate")
def investigate(script: Path = Path("scripts/basic.jky")):
    """Run a complete JOCKY forensic investigation."""

    typer.echo("========================================")
    typer.echo("       JOCKY FORENSIC INVESTIGATION")
    typer.echo("========================================")
    typer.echo("")

    typer.echo(f"Script: {script}")
    typer.echo("")

    try:
        program = parse_script(script)
        ir_program = compile_to_ir(program)

        typer.echo("=== Investigation Pipeline ===")
        typer.echo("")

        for index, instruction in enumerate(
            ir_program.instructions,
            start=1,
        ):
            typer.echo(
                f"{index}. {instruction.opcode}"
            )

        typer.echo("")
        typer.echo("=== Evidence Collection ===")
        typer.echo("")

        execute_ir(ir_program)

        typer.echo("")
        typer.echo("========================================")
        typer.echo("      INVESTIGATION COMPLETED")
        typer.echo("========================================")

    except Exception as error:
        typer.echo("")
        typer.echo(f"[!] Investigation error: {error}")
        raise typer.Exit(code=1)

@app.command()
def persistence():
    """Collect persistence mechanism evidence."""

    persistence_items = collect_persistence()

    output_path = Path(
        "evidence/persistence.json"
    )

    save_evidence(
        {
            "evidence_type": "persistence",
            "entry_count": len(persistence_items),
            "entries": persistence_items,
        },
        output_path,
    )

    evidence_hash = calculate_sha256(output_path)

    typer.echo("=== JOCKY Persistence Evidence ===")
    typer.echo(
        f"Persistence entries : "
        f"{len(persistence_items)}"
    )
    typer.echo(f"Evidence saved      : {output_path}")
    typer.echo(f"SHA-256             : {evidence_hash}")

if __name__ == "__main__":
    app()