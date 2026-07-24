"""IR estrecha para el taint (ADR-0001): clasifica los nodos tree-sitter de cada
lenguaje en las pocas categorías que el análisis necesita (asignación, if, bucle,
try, return, llamada, member, subscript, …), aislando el resto del motor de los
nombres concretos de la gramática.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from sastcore.discovery.languages import Language
from sastcore.parsing.ast import Node


@dataclass(frozen=True)
class LangSpec:
    """Nombres de tipo y de campo de una gramática, para el análisis de taint."""

    function_types: frozenset[str]
    block_types: frozenset[str]
    if_type: str
    while_type: str
    for_types: frozenset[str]
    try_type: str
    catch_types: frozenset[str]
    return_type: str
    assign_types: frozenset[str]
    var_decl_types: frozenset[str]
    expr_stmt_type: str
    call_type: str
    member_type: str
    subscript_type: str
    name_type: str
    binary_types: frozenset[str]
    string_types: frozenset[str]
    interpolation_types: frozenset[str]
    destructure_types: frozenset[str]
    container_methods: frozenset[str]
    body_field: str
    member_object_field: str
    member_prop_field: str
    subscript_object_field: str
    call_func_field: str
    call_args_field: str
    assign_left_field: str
    assign_right_field: str
    paren_type: str | None = None
    name_leaf_types: frozenset[str] = field(default_factory=frozenset)

    # -- helpers -------------------------------------------------------------
    def unwrap_paren(self, node: Node) -> Node:
        while self.paren_type is not None and node.type == self.paren_type:
            named = node.named_children
            if not named:
                break
            node = named[0]
        return node

    def function_params(self, func: Node) -> list[str]:
        params = func.child_by_field_name("parameters")
        if params is None:
            return []
        names: list[str] = []
        for child in params.named_children:
            name = self._first_name(child)
            if name is not None:
                names.append(name)
        return names

    def destructure_names(self, target: Node) -> list[str]:
        names: list[str] = []
        leaf_types = {self.name_type, *self.name_leaf_types}
        for node in target.walk_preorder():
            if node.type in leaf_types:
                names.append(node.text)
        return names

    def _first_name(self, node: Node) -> str | None:
        if node.type == self.name_type:
            return node.text
        for descendant in node.walk_preorder():
            if descendant.type == self.name_type:
                return descendant.text
        return None


_PYTHON = LangSpec(
    function_types=frozenset({"function_definition"}),
    block_types=frozenset({"block", "module"}),
    if_type="if_statement",
    while_type="while_statement",
    for_types=frozenset({"for_statement"}),
    try_type="try_statement",
    catch_types=frozenset({"except_clause"}),
    return_type="return_statement",
    assign_types=frozenset({"assignment", "augmented_assignment"}),
    var_decl_types=frozenset(),
    expr_stmt_type="expression_statement",
    call_type="call",
    member_type="attribute",
    subscript_type="subscript",
    name_type="identifier",
    binary_types=frozenset({"binary_operator", "boolean_operator", "comparison_operator"}),
    string_types=frozenset({"string"}),
    interpolation_types=frozenset({"interpolation"}),
    destructure_types=frozenset({"pattern_list", "tuple_pattern", "list_pattern"}),
    container_methods=frozenset({"append", "add", "update", "extend", "insert"}),
    body_field="body",
    member_object_field="object",
    member_prop_field="attribute",
    subscript_object_field="value",
    call_func_field="function",
    call_args_field="arguments",
    assign_left_field="left",
    assign_right_field="right",
    paren_type="parenthesized_expression",
)

_JAVASCRIPT = LangSpec(
    function_types=frozenset(
        {
            "function_declaration",
            "function_expression",
            "arrow_function",
            "method_definition",
            "generator_function_declaration",
        }
    ),
    block_types=frozenset({"statement_block", "program"}),
    if_type="if_statement",
    while_type="while_statement",
    for_types=frozenset({"for_statement", "for_in_statement"}),
    try_type="try_statement",
    catch_types=frozenset({"catch_clause"}),
    return_type="return_statement",
    assign_types=frozenset({"assignment_expression", "augmented_assignment_expression"}),
    var_decl_types=frozenset({"lexical_declaration", "variable_declaration"}),
    expr_stmt_type="expression_statement",
    call_type="call_expression",
    member_type="member_expression",
    subscript_type="subscript_expression",
    name_type="identifier",
    binary_types=frozenset({"binary_expression"}),
    string_types=frozenset({"string"}),
    interpolation_types=frozenset({"template_substitution"}),
    destructure_types=frozenset({"object_pattern", "array_pattern"}),
    container_methods=frozenset({"push", "unshift", "splice", "add", "set"}),
    body_field="body",
    member_object_field="object",
    member_prop_field="property",
    subscript_object_field="object",
    call_func_field="function",
    call_args_field="arguments",
    assign_left_field="left",
    assign_right_field="right",
    paren_type="parenthesized_expression",
    name_leaf_types=frozenset({"shorthand_property_identifier_pattern", "property_identifier"}),
)

_SPECS: dict[Language, LangSpec] = {
    Language.python: _PYTHON,
    Language.javascript: _JAVASCRIPT,
    Language.typescript: _JAVASCRIPT,
}


def spec_for(language: Language) -> LangSpec:
    return _SPECS[language]
