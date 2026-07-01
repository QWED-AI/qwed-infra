import pytest
from decimal import Decimal
from qwed_infra.numeric import parse_decimal_input, decimal_text


class TestParseDecimalInput:
    def test_valid_int(self):
        result = parse_decimal_input(42, "value")
        assert result == Decimal("42")

    def test_valid_float_string(self):
        result = parse_decimal_input("0.0104", "value")
        assert result == Decimal("0.0104")

    def test_raises_on_bool(self):
        with pytest.raises(ValueError, match="must be a numeric value"):
            parse_decimal_input(True, "budget")

    def test_raises_on_invalid_string(self):
        with pytest.raises(ValueError, match="must be a numeric value"):
            parse_decimal_input("not-a-number", "value")

    def test_raises_on_infinity(self):
        with pytest.raises(ValueError, match="must be a finite numeric value"):
            parse_decimal_input("Infinity", "value")

    def test_raises_on_nan(self):
        with pytest.raises(ValueError, match="must be a finite numeric value"):
            parse_decimal_input("NaN", "value")


class TestDecimalText:
    def test_format(self):
        assert decimal_text(Decimal("15.184")) == "15.184"
        assert decimal_text(Decimal("0.00")) == "0.00"
        assert decimal_text(Decimal("7.59")) == "7.59"
