"""Carga y validación de rulepacks YAML.

Una regla sin fixtures ``bad`` y ``good`` no se carga cuando ``require_fixtures`` está
activo (contrato de calidad de las reglas). En tiempo de ejecución (escaneo) se carga
con ``require_fixtures=False``, ya que los fixtures son un artefacto de desarrollo.
"""

from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import ValidationError

from sastcore.rules.model import Rule


class RuleLoadError(ValueError):
    """Un rulepack no se pudo cargar o validar."""


def default_rulepacks_dir() -> Path:
    """Directorio de rulepacks empaquetados con sastcore."""
    return Path(__file__).resolve().parent.parent / "rulepacks"


def _check_fixtures(rule: Rule, fixtures_root: Path, source: Path) -> None:
    for kind, rel in (("bad", rule.tests.bad), ("good", rule.tests.good)):
        if not (fixtures_root / rel).is_file():
            raise RuleLoadError(f"{source}: regla '{rule.id}': falta el fixture {kind}: {rel}")


def load_rulepack_file(
    path: Path, *, fixtures_root: Path, require_fixtures: bool = True
) -> list[Rule]:
    """Carga y valida un único fichero de rulepack."""
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(raw, list):
        raise RuleLoadError(f"{path}: se esperaba una lista de reglas")

    rules: list[Rule] = []
    for entry in raw:
        try:
            rule = Rule.model_validate(entry)
        except ValidationError as exc:
            raise RuleLoadError(f"{path}: regla inválida: {exc}") from exc
        if require_fixtures:
            _check_fixtures(rule, fixtures_root, path)
        rules.append(rule)
    return rules


def load_rulepacks(root: Path, *, fixtures_root: Path, require_fixtures: bool = True) -> list[Rule]:
    """Carga todos los ``*.yml`` bajo ``root``, rechazando ids duplicados."""
    rules: list[Rule] = []
    seen: set[str] = set()
    for yml in sorted(root.rglob("*.yml")):
        for rule in load_rulepack_file(
            yml, fixtures_root=fixtures_root, require_fixtures=require_fixtures
        ):
            if rule.id in seen:
                raise RuleLoadError(f"id de regla duplicado: {rule.id}")
            seen.add(rule.id)
            rules.append(rule)
    return rules
