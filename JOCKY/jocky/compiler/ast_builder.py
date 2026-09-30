from lark import Transformer

from jocky.compiler.ast import (
    Program,
    ScanSystem,
    ScanProcesses,
    ScanNetwork,
    ScanPersistence,
    ScanFiles,
    Report,
)


class JockyASTBuilder(Transformer):
    """Convert JOCKY parse tree into AST."""

    def start(self, statements):
        return Program(statements)

    def scan_system(self, _items):
        return ScanSystem()

    def scan_processes(self, _items):
        return ScanProcesses()

    def scan_network(self, _items):
        return ScanNetwork()

    def scan_persistence(self, _items):
        return ScanPersistence()

    def scan_files(self, items):
        return ScanFiles(str(items[0])[1:-1].replace("\\\\", "\\"))

    def report(self, _items):
        return Report()