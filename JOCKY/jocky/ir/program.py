from dataclasses import dataclass

from jocky.ir.instructions import Instruction


@dataclass
class IRProgram:
    """JOCKY Intermediate Representation."""

    instructions: list[Instruction]