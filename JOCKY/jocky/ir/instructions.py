from dataclasses import dataclass


@dataclass
class Instruction:
    """Base JOCKY IR instruction."""
    opcode: str


@dataclass
class ScanSystemInstruction(Instruction):
    """Collect system information."""

    def __init__(self):
        super().__init__("SCAN_SYSTEM")


@dataclass
class ScanProcessesInstruction(Instruction):
    """Collect process information."""

    def __init__(self):
        super().__init__("SCAN_PROCESSES")

@dataclass
class ScanNetworkInstruction(Instruction):
    def __init__(self):
        super().__init__("SCAN_NETWORK")

@dataclass
class ScanPersistenceInstruction(Instruction):
    def __init__(self):
        super().__init__("SCAN_PERSISTENCE")

@dataclass
class ReportInstruction(Instruction):
    """Generate forensic report."""

    def __init__(self):
        super().__init__("REPORT")

@dataclass
class ScanFilesInstruction(Instruction):
    """Collect file metadata + SHA-256 for a directory."""
    path: str = ""

    def __init__(self, path):
        super().__init__("SCAN_FILES")
        self.path = path
