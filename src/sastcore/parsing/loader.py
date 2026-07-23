"""Carga perezosa y memoizada de parsers tree-sitter.

Usa ``tree-sitter-language-pack`` (gramáticas precompiladas). El mapeo Language →
nombre de gramática vive aquí para aislar el resto del código del nombre concreto.
"""

from __future__ import annotations

from functools import cache
from typing import TYPE_CHECKING

from tree_sitter_language_pack import get_parser as _get_parser

from sastcore.discovery.languages import Language

if TYPE_CHECKING:
    from tree_sitter import Parser

_GRAMMAR_NAME: dict[Language, str] = {
    Language.python: "python",
    Language.javascript: "javascript",
    Language.typescript: "typescript",
}


@cache
def get_parser(language: Language) -> Parser:
    """Devuelve el parser de tree-sitter para ``language`` (memoizado)."""
    parser: Parser = _get_parser(_GRAMMAR_NAME[language])
    return parser
