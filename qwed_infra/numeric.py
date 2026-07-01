from decimal import Decimal, InvalidOperation
from typing import Any


def parse_decimal_input(value: Any, field_name: str) -> Decimal:
    if isinstance(value, bool):
        raise ValueError(f"{field_name} must be a numeric value.")
    try:
        parsed = Decimal(str(value))
    except (InvalidOperation, ValueError) as exc:
        raise ValueError(f"{field_name} must be a numeric value.") from exc
    if not parsed.is_finite():
        raise ValueError(f"{field_name} must be a finite numeric value.")
    return parsed


def decimal_text(value: Decimal) -> str:
    return format(value, "f")
