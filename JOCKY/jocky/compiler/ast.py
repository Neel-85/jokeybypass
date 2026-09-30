from dataclasses import dataclass


@dataclass
class ScanSystem:
    """AST node for system scan."""
    pass


@dataclass
class ScanProcesses:
    """AST node for process scan."""
    pass

@dataclass
class ScanNetwork:
    pass

@dataclass
class ScanPersistence:
    pass

@dataclass
class ScanFiles:
    path: str

@dataclass
class Report:
    """AST node for report generation."""
    pass


@dataclass
class Program:
    """Root AST node."""
    statements: list