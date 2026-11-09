"""pt-BR number formatting used by insights and the HTML report."""
from __future__ import annotations

from decimal import Decimal, InvalidOperation
from typing import Any


def _dec(value: Any) -> Decimal | None:
    if value is None or value == "":
        return None
    try:
        return value if isinstance(value, Decimal) else Decimal(str(value))
    except (InvalidOperation, ValueError):
        return None


def _br(text: str) -> str:
    return text.replace(",", "X").replace(".", ",").replace("X", ".")


def money(value: Any, symbol: str = "R$") -> str:
    d = _dec(value)
    if d is None:
        return "–"
    sign = "-" if d < 0 else ""
    return f"{sign}{symbol} {_br(f'{abs(d):,.2f}')}"


def number(value: Any, decimals: int | None = None) -> str:
    d = _dec(value)
    if d is None:
        return "–"
    if decimals is None:
        decimals = 0 if d == d.to_integral_value() else 2
    return _br(f"{d:,.{decimals}f}")


def percent(value: Any, decimals: int = 2) -> str:
    d = _dec(value)
    if d is None:
        return "–"
    return _br(f"{d * 100:,.{decimals}f}") + "%"


def pp(value: Any, decimals: int = 2) -> str:
    """Percentage-point difference with explicit sign."""
    d = _dec(value)
    if d is None:
        return "–"
    sign = "+" if d > 0 else ""
    return f"{sign}{_br(f'{d * 100:,.{decimals}f}')} p.p."
