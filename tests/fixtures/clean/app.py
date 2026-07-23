"""Módulo limpio de control: no debe producir ningún hallazgo."""

DEFAULT_TIMEOUT = 30
REQUEST_ID = "550e8400-e29b-41d4-a716-446655440000"
password = "changeme"  # entropía y longitud bajas: no es un secreto


def greet(name: str) -> str:
    return f"Hello, {name}!"


def build_config() -> dict[str, int]:
    return {"retries": 3, "timeout": DEFAULT_TIMEOUT}
