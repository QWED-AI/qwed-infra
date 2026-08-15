"""
QWED-Infra Verification Context v1.0 Model Types.

Independent implementation of the Verification Context contract,
following the same pattern as InfraDiagnosticResult (no dependency
on qwed-verification, mirrors the VC contract exactly).

See: qwed-verification/spec/v1.0/verification-context.md
"""

from __future__ import annotations

import copy
import hashlib
import json
import math
import re
from dataclasses import dataclass, replace
from enum import Enum
from functools import lru_cache
from types import MappingProxyType
from typing import Any, Dict, Mapping, Optional, Tuple

SPEC_VERSION = "1.0"
_PROOF_REF_PATTERN = re.compile(r"sha256:[a-f0-9]{64}")


class VerificationContextValidationError(ValueError):
    pass


class Verdict(str, Enum):
    VERIFIED = "VERIFIED"
    UNVERIFIABLE = "UNVERIFIABLE"
    BLOCKED = "BLOCKED"


class Admission(str, Enum):
    ADMIT = "ADMIT"
    DENY = "DENY"


def _freeze_value(value: Any) -> Any:
    if isinstance(value, Mapping):
        return MappingProxyType(
            {key: _freeze_value(item) for key, item in value.items()}
        )
    if isinstance(value, (list, tuple)):
        return tuple(_freeze_value(item) for item in value)
    return value


def _thaw_value(value: Any) -> Any:
    if isinstance(value, MappingProxyType):
        return {key: _thaw_value(item) for key, item in value.items()}
    if isinstance(value, Mapping):
        return {key: _thaw_value(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_thaw_value(item) for item in value]
    return value


@dataclass(frozen=True)
class Formalization:
    source_query: str
    translator: str

    def __post_init__(self) -> None:
        if not isinstance(self.source_query, str) or not self.source_query.strip():
            raise VerificationContextValidationError(
                "Formalization.source_query must be a non-empty string"
            )
        if not isinstance(self.translator, str) or not self.translator.strip():
            raise VerificationContextValidationError(
                "Formalization.translator must be a non-empty string"
            )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source_query": self.source_query,
            "translator": self.translator,
        }


@dataclass(frozen=True)
class Interpretation:
    theory: str
    logic: str = "deterministic pattern matching"

    def __post_init__(self) -> None:
        if not isinstance(self.theory, str) or not self.theory.strip():
            raise VerificationContextValidationError(
                "Interpretation.theory must be a non-empty string"
            )
        if not isinstance(self.logic, str) or not self.logic.strip():
            raise VerificationContextValidationError(
                "Interpretation.logic must be a non-empty string"
            )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "theory": self.theory,
            "logic": self.logic,
        }


@dataclass(frozen=True)
class Proof:
    verifier: str
    verifier_version: str
    configuration: Dict[str, Any]
    theory_scope: str
    trusted_dependencies: Tuple[str, ...]
    outcome_treatment: str

    def __post_init__(self) -> None:
        for field_name in ("verifier", "verifier_version", "theory_scope", "outcome_treatment"):
            value = getattr(self, field_name)
            if not isinstance(value, str) or not value.strip():
                raise VerificationContextValidationError(
                    f"Proof.{field_name} must be a non-empty string"
                )
        if not isinstance(self.configuration, dict):
            raise VerificationContextValidationError(
                "Proof.configuration must be a dict"
            )
        if not isinstance(self.trusted_dependencies, tuple):
            raise VerificationContextValidationError(
                "Proof.trusted_dependencies must be a tuple of strings"
            )
        for dep in self.trusted_dependencies:
            if not isinstance(dep, str):
                raise VerificationContextValidationError(
                    "Proof.trusted_dependencies must contain only strings"
                )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "verifier": self.verifier,
            "verifier_version": self.verifier_version,
            "configuration": self.configuration,
            "theory_scope": self.theory_scope,
            "trusted_dependencies": list(self.trusted_dependencies),
            "outcome_treatment": self.outcome_treatment,
        }


@dataclass(frozen=True)
class Evidence:
    payload: Dict[str, Any]
    proof_ref: Optional[str] = None

    def __post_init__(self) -> None:
        if not isinstance(self.payload, dict):
            raise VerificationContextValidationError(
                "Evidence.payload must be a dict"
            )
        if self.proof_ref is not None:
            if not isinstance(self.proof_ref, str) or not _PROOF_REF_PATTERN.fullmatch(self.proof_ref):
                raise VerificationContextValidationError(
                    "Evidence.proof_ref must match sha256:<64-hex> or be None"
                )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "payload": self.payload,
            "proof_ref": self.proof_ref,
        }


@dataclass(frozen=True)
class Decision:
    admission: Admission

    def __post_init__(self) -> None:
        if not isinstance(self.admission, Admission):
            raise VerificationContextValidationError(
                "Decision.admission must be an Admission enum value"
            )

    def to_dict(self) -> Dict[str, Any]:
        return {"admission": self.admission.value}


@dataclass(frozen=True)
class VerificationContext:
    interpretation: Interpretation
    proof: Proof
    evidence: Evidence
    decision: Decision

    def __post_init__(self) -> None:
        for field_name, expected_type in (
            ("interpretation", Interpretation),
            ("proof", Proof),
            ("evidence", Evidence),
            ("decision", Decision),
        ):
            value = getattr(self, field_name)
            if not isinstance(value, expected_type):
                raise VerificationContextValidationError(
                    f"VerificationContext.{field_name} must be a {expected_type.__name__}"
                )
        if self.evidence.proof_ref is not None and self.decision.admission is Admission.DENY:
            raise VerificationContextValidationError(
                "DENY admission requires proof_ref is None — "
                "fail-closed contract: UNVERIFIABLE/BLOCKED never admit"
            )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "interpretation": self.interpretation.to_dict(),
            "proof": self.proof.to_dict(),
            "evidence": self.evidence.to_dict(),
            "decision": self.decision.to_dict(),
        }


def _canonical_json(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        try:
            as_float = float(value)
        except OverflowError as exc:
            raise VerificationContextValidationError(
                f"integer not representable as IEEE-754 double: {value!r}"
            ) from exc
        if int(as_float) != value:
            raise VerificationContextValidationError(
                f"integer not representable as IEEE-754 double: {value!r}"
            )
        return _es_number_to_string(as_float)
    if isinstance(value, float):
        if not math.isfinite(value):
            raise VerificationContextValidationError(
                f"non-finite number not allowed in proof_ref payload: {value!r}"
            )
        return _es_number_to_string(value)
    if isinstance(value, str):
        _reject_unpaired_surrogates(value)
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(_canonical_json(item) for item in value) + "]"
    if isinstance(value, Mapping):
        for key in value:
            if not isinstance(key, str):
                raise VerificationContextValidationError(
                    f"non-string object key not allowed in proof_ref payload: {key!r}"
                )
            _reject_unpaired_surrogates(key)
        items = sorted(value.items(), key=lambda kv: kv[0].encode("utf-16-be"))
        return (
            "{"
            + ",".join(
                json.dumps(k, ensure_ascii=False) + ":" + _canonical_json(v)
                for k, v in items
            )
            + "}"
        )
    raise VerificationContextValidationError(
        f"unsupported type in proof_ref payload: {type(value).__name__}"
    )


def _es_number_to_string(value: float) -> str:
    neg = value < 0
    coeff, e10 = _parse_es_decimal(value)
    out = _format_es_decimal(coeff, e10)
    if neg and out != "0":
        return "-" + out
    return out


def _parse_es_decimal(value: float) -> Tuple[int, int]:
    if not math.isfinite(value):
        raise VerificationContextValidationError(
            f"non-finite number not allowed: {value!r}"
        )
    import decimal
    d = decimal.Decimal(repr(value))
    sign, digits, exponent = d.as_tuple()
    coeff = int("".join(str(i) for i in digits))
    return coeff, exponent


def _format_es_decimal(coeff: int, exponent: int) -> str:
    if coeff == 0:
        return "0"
    s = str(coeff)
    if exponent >= 0:
        return s + "0" * exponent
    if len(s) > abs(exponent):
        point = len(s) + exponent
        return s[:point] + "." + s[point:]
    return "0." + "0" * abs(exponent + len(s)) + s


def _reject_unpaired_surrogates(value: str) -> None:
    for i, ch in enumerate(value):
        cp = ord(ch)
        if 0xD800 <= cp <= 0xDBFF:  # high surrogate
            if i + 1 >= len(value) or not (0xDC00 <= ord(value[i + 1]) <= 0xDFFF):
                raise VerificationContextValidationError(
                    f"unpaired high surrogate at position {i}: {value!r}"
                )
        elif 0xDC00 <= cp <= 0xDFFF:  # low surrogate
            if i == 0 or not (0xD800 <= ord(value[i - 1]) <= 0xDBFF):
                raise VerificationContextValidationError(
                    f"unpaired low surrogate at position {i}: {value!r}"
                )


def compute_document_proof_ref(document: Mapping[str, Any]) -> str:
    formal_statement = document["object"]["formal_statement"]
    context_dict = document["context"]
    evidence_dict = {
        key: value
        for key, value in context_dict["evidence"].items()
        if key != "proof_ref"
    }
    bound = {
        "formal_statement": formal_statement,
        "context": {**context_dict, "evidence": evidence_dict},
    }
    payload = _canonical_json(bound)
    return "sha256:" + hashlib.sha256(payload.encode("utf-8")).hexdigest()


def resolve_document_proof_ref(document: Mapping[str, Any]) -> bool:
    try:
        if not isinstance(document, Mapping):
            return False
        if document.get("verdict") != Verdict.VERIFIED.value:
            return False
        expected = compute_document_proof_ref(document)
        stored = document["context"]["evidence"]["proof_ref"]
        return isinstance(stored, str) and stored == expected
    except (VerificationContextValidationError, KeyError, TypeError, AttributeError):
        return False


def is_valid_document(document: Mapping[str, Any]) -> bool:
    try:
        if not isinstance(document, Mapping):
            return False
        if document.get("spec_version") != SPEC_VERSION:
            return False
        if document.get("verdict") not in {"VERIFIED", "UNVERIFIABLE", "BLOCKED"}:
            return False
        return True
    except (KeyError, TypeError, AttributeError):
        return False


@dataclass(frozen=True)
class VerificationContextDocument:
    spec_version: str
    object: Dict[str, Any]
    context: VerificationContext
    verdict: Verdict
    formalization: Optional[Formalization] = None

    def __post_init__(self) -> None:
        if self.spec_version != SPEC_VERSION:
            raise VerificationContextValidationError(
                f"spec_version must be {SPEC_VERSION}"
            )
        if not isinstance(self.object, dict):
            raise VerificationContextValidationError(
                "object must be a dict with formal_statement"
            )
        formal_statement = self.object.get("formal_statement")
        if not isinstance(formal_statement, str) or not formal_statement.strip():
            raise VerificationContextValidationError(
                "object.formal_statement must be a non-empty string"
            )
        if not isinstance(self.verdict, Verdict):
            raise VerificationContextValidationError(
                "verdict must be VERIFIED, UNVERIFIABLE, or BLOCKED"
            )
        if self.verdict is Verdict.VERIFIED and self.context.evidence.proof_ref is None:
            raise VerificationContextValidationError(
                "VERIFIED verdict requires context.evidence.proof_ref to be non-null"
            )
        if self.verdict is not Verdict.VERIFIED and self.context.evidence.proof_ref is not None:
            raise VerificationContextValidationError(
                f"{self.verdict.value} verdict requires proof_ref to be null"
            )
        if self.verdict is Verdict.VERIFIED and self.context.decision.admission is Admission.DENY:
            raise VerificationContextValidationError(
                "VERIFIED verdict requires ADMIT admission"
            )
        if self.verdict is not Verdict.VERIFIED and self.context.decision.admission is Admission.ADMIT:
            raise VerificationContextValidationError(
                f"{self.verdict.value} verdict requires DENY admission"
            )

    def to_dict(self) -> Dict[str, Any]:
        doc = {
            "spec_version": self.spec_version,
            "object": self.object,
            "context": self.context.to_dict(),
            "verdict": self.verdict.value,
        }
        if self.formalization is not None:
            doc["object"]["formalization"] = self.formalization.to_dict()
        return doc