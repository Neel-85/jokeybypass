from pathlib import Path

from lark import Lark

from jocky.compiler.ast_builder import JockyASTBuilder


GRAMMAR_PATH = Path(__file__).with_name("grammar.lark")


parser = Lark.open(
    str(GRAMMAR_PATH),
    parser="lalr",
)


def parse_script(script_path: Path):
    """Parse a JOCKY script into an AST."""

    source = script_path.read_text(encoding="utf-8")

    tree = parser.parse(source)

    return JockyASTBuilder().transform(tree)