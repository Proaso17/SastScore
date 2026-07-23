"""Tests de la entropía de Shannon."""

from __future__ import annotations

import math

from sastcore.engine.secrets.entropy import shannon_entropy


def test_empty_string_is_zero() -> None:
    assert shannon_entropy("") == 0.0


def test_single_repeated_char_is_zero() -> None:
    assert shannon_entropy("aaaaaa") == 0.0


def test_two_equiprobable_symbols_is_one_bit() -> None:
    assert math.isclose(shannon_entropy("0101"), 1.0)


def test_four_equiprobable_symbols_is_two_bits() -> None:
    assert math.isclose(shannon_entropy("abcd"), 2.0)


def test_high_entropy_greater_than_low() -> None:
    assert shannon_entropy("aB3$xZ9!qL2#") > shannon_entropy("aaaaaaaaaaaa")
