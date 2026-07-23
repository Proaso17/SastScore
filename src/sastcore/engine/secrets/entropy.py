"""Entropía de Shannon, para distinguir secretos de alta entropía de texto normal."""

from __future__ import annotations

import math
from collections import Counter


def shannon_entropy(data: str) -> float:
    """Entropía de Shannon (en bits por carácter) de una cadena.

    Devuelve 0.0 para la cadena vacía o para cadenas de un solo carácter repetido.
    Una cadena con N caracteres equiprobables tiene entropía ``log2(N)``.
    """
    if not data:
        return 0.0
    length = len(data)
    counts = Counter(data)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())
