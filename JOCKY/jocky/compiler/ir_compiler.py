from jocky.compiler.ast import (
    Program,
    ScanSystem,
    ScanProcesses,
    Report,
    ScanPersistence,
    ScanNetwork,
    ScanFiles,
)

from jocky.ir.instructions import (
    ScanSystemInstruction,
    ScanProcessesInstruction,
    ReportInstruction,
    ScanNetworkInstruction,
    ScanPersistenceInstruction,
    ScanFilesInstruction,
)

from jocky.ir.program import IRProgram


def compile_to_ir(program: Program) -> IRProgram:
    """Compile JOCKY AST into JOCKY IR."""

    instructions = []

    for statement in program.statements:

        if isinstance(statement, ScanSystem):
            instructions.append(
                ScanSystemInstruction()
            )

        elif isinstance(statement, ScanProcesses):
            instructions.append(
                ScanProcessesInstruction()
            )

        elif isinstance(statement, ScanNetwork):
            instructions.append(ScanNetworkInstruction())

        elif isinstance(statement, ScanPersistence):
            instructions.append(ScanPersistenceInstruction())

        elif isinstance(statement, ScanFiles):
            instructions.append(ScanFilesInstruction(statement.path))

        elif isinstance(statement, Report):
            instructions.append(
                ReportInstruction()
            )

        else:
            raise ValueError(
                f"Unsupported AST node: "
                f"{type(statement).__name__}"
            )

    return IRProgram(instructions)