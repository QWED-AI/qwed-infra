"""
Tests for qwed_infra.verification_context model and verification_context_bridge.
"""

import pytest

from qwed_infra.diagnostics import InfraDiagnosticResult, InfraDiagnosticStatus
from qwed_infra.verification_context import (
    Admission,
    Decision,
    Evidence,
    Formalization,
    Interpretation,
    Proof,
    Verdict,
    VerificationContext,
    VerificationContextDocument,
    VerificationContextValidationError,
    compute_document_proof_ref,
    is_valid_document,
    resolve_document_proof_ref,
)
from qwed_infra.verification_context_bridge import (
    verification_context_from_diagnostic_result,
)


# =============================================================================
# Model type tests
# =============================================================================

class TestFormalization:
    def test_valid(self):
        f = Formalization(source_query="test", translator="TestVerifier")
        assert f.source_query == "test"
        assert f.translator == "TestVerifier"

    def test_dict_serialization(self):
        f = Formalization(source_query="test", translator="TestVerifier")
        d = f.to_dict()
        assert d == {"source_query": "test", "translator": "TestVerifier"}

    def test_empty_source_query_rejected(self):
        with pytest.raises(VerificationContextValidationError):
            Formalization(source_query="", translator="TestVerifier")

    def test_empty_translator_rejected(self):
        with pytest.raises(VerificationContextValidationError):
            Formalization(source_query="test", translator="")


class TestInterpretation:
    def test_valid(self):
        i = Interpretation(theory="TestGuard verification")
        assert i.theory == "TestGuard verification"
        assert i.logic == "deterministic pattern matching"

    def test_dict_serialization(self):
        i = Interpretation(theory="Test", logic="custom logic")
        d = i.to_dict()
        assert d == {"theory": "Test", "logic": "custom logic"}

    def test_empty_theory_rejected(self):
        with pytest.raises(VerificationContextValidationError):
            Interpretation(theory="")

    def test_empty_logic_rejected(self):
        with pytest.raises(VerificationContextValidationError):
            Interpretation(theory="test", logic="")


class TestProof:
    def _proof(self):
        return Proof(
            verifier="TestGuard", verifier_version="1.0.0",
            configuration={}, theory_scope="TestGuard tests",
            trusted_dependencies=("qwed-infra",),
            outcome_treatment="fail-closed",
        )

    def test_valid(self):
        p = self._proof()
        assert p.verifier == "TestGuard"

    def test_dict_serialization(self):
        p = self._proof()
        d = p.to_dict()
        assert d["verifier"] == "TestGuard"
        assert d["verifier_version"] == "1.0.0"

    def test_non_dict_config_rejected(self):
        with pytest.raises(VerificationContextValidationError):
            Proof(
                verifier="Test", verifier_version="1.0.0",
                configuration="not-a-dict", theory_scope="scope",
                trusted_dependencies=("qwed-infra",), outcome_treatment="fail-closed",
            )

    def test_non_tuple_trusted_deps_rejected(self):
        with pytest.raises(VerificationContextValidationError):
            Proof(
                verifier="Test", verifier_version="1.0.0",
                configuration={}, theory_scope="scope",
                trusted_dependencies=["qwed-infra"], outcome_treatment="fail-closed",
            )


class TestEvidence:
    def test_valid(self):
        e = Evidence(payload={"test": True}, proof_ref="sha256:" + "a" * 64)
        assert e.payload == {"test": True}
        assert e.proof_ref == "sha256:" + "a" * 64

    def test_none_proof_ref(self):
        e = Evidence(payload={"test": True}, proof_ref=None)
        assert e.proof_ref is None

    def test_dict_serialization(self):
        e = Evidence(payload={"test": True}, proof_ref=None)
        d = e.to_dict()
        assert d == {"payload": {"test": True}, "proof_ref": None}

    def test_non_dict_payload_rejected(self):
        bad_payload = "not-a-dict"
        with pytest.raises(VerificationContextValidationError):
            Evidence(payload=bad_payload, proof_ref=None)

    def test_invalid_proof_ref_format_rejected(self):
        bad_ref = "not-sha256"
        with pytest.raises(VerificationContextValidationError):
            Evidence(payload={"test": True}, proof_ref=bad_ref)


class TestDecision:
    def test_valid(self):
        d = Decision(admission=Admission.ADMIT)
        assert d.admission == Admission.ADMIT

    def test_dict_serialization(self):
        d = Decision(admission=Admission.DENY)
        assert d.to_dict() == {"admission": "DENY"}

    def test_non_admission_rejected(self):
        bad_admission = "not-admission"
        with pytest.raises(VerificationContextValidationError):
            Decision(admission=bad_admission)


class TestVerificationContext:
    def _context(self, admitted=True, proof_ref=None):
        return VerificationContext(
            interpretation=Interpretation(theory="Test theory"),
            proof=Proof(
                verifier="TestGuard", verifier_version="1.0.0",
                configuration={}, theory_scope="test",
                trusted_dependencies=("qwed-infra",),
                outcome_treatment="fail-closed",
            ),
            evidence=Evidence(payload={"test": True}, proof_ref=proof_ref),
            decision=Decision(admission=Admission.ADMIT if admitted else Admission.DENY),
        )

    def test_valid_admit(self):
        ctx = self._context(admitted=True, proof_ref="sha256:" + "a" * 64)
        assert ctx.decision.admission == Admission.ADMIT

    def test_valid_deny_without_proof_ref(self):
        ctx = self._context(admitted=False, proof_ref=None)
        assert ctx.decision.admission == Admission.DENY

    def test_deny_with_proof_ref_rejected(self):
        proof_ref = "sha256:" + "a" * 64
        with pytest.raises(VerificationContextValidationError):
            self._context(admitted=False, proof_ref=proof_ref)

    def test_dict_serialization(self):
        ctx = self._context()
        d = ctx.to_dict()
        assert "interpretation" in d
        assert "proof" in d
        assert "evidence" in d
        assert "decision" in d


# =============================================================================
# Document model tests
# =============================================================================

class TestVerificationContextDocument:
    def _doc(self, verdict=Verdict.VERIFIED, proof_ref="sha256:" + "a" * 64):
        return VerificationContextDocument(
            spec_version="1.0",
            object={"formal_statement": "test claim"},
            context=VerificationContext(
                interpretation=Interpretation(theory="Test"),
                proof=Proof(
                    verifier="Test", verifier_version="1.0",
                    configuration={}, theory_scope="test",
                    trusted_dependencies=(), outcome_treatment="fail-closed",
                ),
                evidence=Evidence(payload={"test": True}, proof_ref=proof_ref),
                decision=Decision(admission=Admission.ADMIT),
            ),
            verdict=verdict,
        )

    def test_valid_verified(self):
        doc = self._doc()
        assert doc.verdict == Verdict.VERIFIED
        assert doc.context.decision.admission == Admission.ADMIT

    def test_valid_unverifiable(self):
        doc = VerificationContextDocument(
            spec_version="1.0",
            object={"formal_statement": "test claim"},
            context=VerificationContext(
                interpretation=Interpretation(theory="Test"),
                proof=Proof(
                    verifier="Test", verifier_version="1.0",
                    configuration={}, theory_scope="test",
                    trusted_dependencies=(), outcome_treatment="fail-closed",
                ),
                evidence=Evidence(payload={"test": True}, proof_ref=None),
                decision=Decision(admission=Admission.DENY),
            ),
            verdict=Verdict.UNVERIFIABLE,
        )
        assert doc.verdict == Verdict.UNVERIFIABLE

    def test_invalid_spec_version_rejected(self):
        doc = self._doc()
        with pytest.raises(VerificationContextValidationError):
            VerificationContextDocument(
                spec_version="2.0",
                object={"formal_statement": "test"},
                context=doc.context,
                verdict=Verdict.VERIFIED,
            )

    def test_verified_without_proof_ref_rejected(self):
        with pytest.raises(VerificationContextValidationError):
            self._doc(verdict=Verdict.VERIFIED, proof_ref=None)

    def test_unverified_with_proof_ref_rejected(self):
        proof_ref = "sha256:" + "a" * 64
        with pytest.raises(VerificationContextValidationError):
            self._doc(verdict=Verdict.UNVERIFIABLE, proof_ref=proof_ref)

    def test_admit_with_unverified_verdict_rejected(self):
        # UNVERIFIABLE verdict requires DENY admission; ADMIT with non-VERIFIED
        # verdict must fail in VerificationContextDocument.__post_init__.
        context = VerificationContext(
            interpretation=Interpretation(theory="Test"),
            proof=Proof(
                verifier="Test", verifier_version="1.0",
                configuration={}, theory_scope="test",
                trusted_dependencies=(), outcome_treatment="fail-closed",
            ),
            evidence=Evidence(payload={"test": True}, proof_ref=None),
            decision=Decision(admission=Admission.ADMIT),
        )
        with pytest.raises(VerificationContextValidationError):
            VerificationContextDocument(
                spec_version="1.0",
                object={"formal_statement": "test"},
                context=context,
                verdict=Verdict.UNVERIFIABLE,
            )

    def test_dict_serialization(self):
        doc = self._doc()
        d = doc.to_dict()
        assert d["spec_version"] == "1.0"
        assert d["object"]["formal_statement"] == "test claim"
        assert d["verdict"] == "VERIFIED"


# =============================================================================
# Canonical proof functions
# =============================================================================

class TestComputeDocumentProofRef:
    def _doc(self):
        return {
            "spec_version": "1.0",
            "object": {"formal_statement": "test claim"},
            "context": {
                "interpretation": {"theory": "Test", "logic": "deterministic"},
                "proof": {"verifier": "Test", "verifier_version": "1.0", "configuration": {}, "theory_scope": "test", "trusted_dependencies": [], "outcome_treatment": "fail-closed"},
                "evidence": {"payload": {"test": True}, "proof_ref": None},
                "decision": {"admission": "ADMIT"},
            },
            "verdict": "VERIFIED",
        }

    def test_computes_valid_sha256(self):
        ref = compute_document_proof_ref(self._doc())
        assert ref.startswith("sha256:")
        assert len(ref) == len("sha256:") + 64

    def test_excludes_proof_ref_from_bound_payload(self):
        doc = self._doc()
        doc["context"]["evidence"]["proof_ref"] = "sha256:" + "b" * 64
        ref1 = compute_document_proof_ref(doc)
        assert ref1 != "sha256:" + "b" * 64


class TestResolveDocumentProofRef:
    def _valid_doc(self):
        return {
            "spec_version": "1.0",
            "object": {"formal_statement": "test claim"},
            "context": {
                "interpretation": {"theory": "Test", "logic": "deterministic"},
                "proof": {"verifier": "Test", "verifier_version": "1.0", "configuration": {}, "theory_scope": "test", "trusted_dependencies": [], "outcome_treatment": "fail-closed"},
                "evidence": {"payload": {"test": True}, "proof_ref": None},
                "decision": {"admission": "ADMIT"},
            },
            "verdict": "VERIFIED",
        }

    def test_valid_doc_resolves(self):
        doc = self._valid_doc()
        doc["context"]["evidence"]["proof_ref"] = compute_document_proof_ref(doc)
        assert resolve_document_proof_ref(doc) is True

    def test_wrong_proof_ref_rejected(self):
        doc = self._valid_doc()
        doc["context"]["evidence"]["proof_ref"] = "sha256:" + "c" * 64
        assert resolve_document_proof_ref(doc) is False

    def test_non_verified_rejected(self):
        doc = self._valid_doc()
        doc["verdict"] = "BLOCKED"
        assert resolve_document_proof_ref(doc) is False


class TestIsValidDocument:
    def test_valid_verified(self):
        # Build a document and resolve its actual proof_ref
        doc = self._full_doc(verdict="VERIFIED", admission="ADMIT", proof_ref=None)
        doc["context"]["evidence"]["proof_ref"] = compute_document_proof_ref(doc)
        assert is_valid_document(doc) is True

    def test_valid_unverifiable(self):
        doc = self._full_doc(verdict="UNVERIFIABLE", admission="DENY", proof_ref=None)
        assert is_valid_document(doc) is True

    def test_valid_blocked(self):
        doc = self._full_doc(verdict="BLOCKED", admission="DENY", proof_ref=None)
        assert is_valid_document(doc) is True

    def test_invalid_missing_object_rejected(self):
        doc = {"spec_version": "1.0", "verdict": "VERIFIED"}
        assert is_valid_document(doc) is False

    def test_invalid_missing_context_rejected(self):
        doc = {"spec_version": "1.0", "object": {"formal_statement": "test"}, "verdict": "VERIFIED"}
        assert is_valid_document(doc) is False

    def test_invalid_missing_evidence_rejected(self):
        doc = {
            "spec_version": "1.0",
            "object": {"formal_statement": "test"},
            "context": {
                "interpretation": {},
                "proof": {},
                "decision": {"admission": "ADMIT"},
            },
            "verdict": "VERIFIED",
        }
        assert is_valid_document(doc) is False

    def test_invalid_verified_without_proof_ref_rejected(self):
        doc = self._full_doc(verdict="VERIFIED", admission="ADMIT", proof_ref=None)
        assert is_valid_document(doc) is False

    def test_invalid_non_verified_with_proof_ref_rejected(self):
        doc = self._full_doc(verdict="BLOCKED", admission="DENY", proof_ref="sha256:" + "a" * 64)
        assert is_valid_document(doc) is False

    def test_invalid_spec_version_rejected(self):
        doc = self._full_doc()
        doc["spec_version"] = "2.0"
        assert is_valid_document(doc) is False

    def test_invalid_verdict_rejected(self):
        doc = self._full_doc()
        doc["verdict"] = "INVALID"
        assert is_valid_document(doc) is False

    def test_non_dict_rejected(self):
        assert is_valid_document("not-a-dict") is False

    def _full_doc(self, verdict="VERIFIED", admission="ADMIT", proof_ref="sha256:" + "a" * 64):
        return {
            "spec_version": "1.0",
            "object": {"formal_statement": "test claim"},
            "context": {
                "interpretation": {"theory": "Test", "logic": "deterministic"},
                "proof": {"verifier": "Test", "verifier_version": "1.0", "configuration": {}, "theory_scope": "test", "trusted_dependencies": [], "outcome_treatment": "fail-closed"},
                "evidence": {"payload": {"test": True}, "proof_ref": proof_ref},
                "decision": {"admission": admission},
            },
            "verdict": verdict,
        }

    def test_empty_trusted_dependency_rejected(self):
        doc = self._full_doc(verdict="BLOCKED", admission="DENY", proof_ref=None)
        doc["context"]["proof"]["trusted_dependencies"] = [""]
        assert is_valid_document(doc) is False

    def test_whitespace_trusted_dependency_rejected(self):
        doc = self._full_doc(verdict="BLOCKED", admission="DENY", proof_ref=None)
        doc["context"]["proof"]["trusted_dependencies"] = [" "]
        assert is_valid_document(doc) is False

    def test_unserializable_config_rejected(self):
        doc = self._full_doc(verdict="BLOCKED", admission="DENY", proof_ref=None)
        doc["context"]["proof"]["configuration"] = {"bad": object()}
        assert is_valid_document(doc) is False

    def test_unserializable_payload_rejected(self):
        doc = self._full_doc(verdict="BLOCKED", admission="DENY", proof_ref=None)
        doc["context"]["evidence"]["payload"] = {"bad": object()}
        assert is_valid_document(doc) is False

    def test_unserializable_object_rejected(self):
        doc = self._full_doc(verdict="BLOCKED", admission="DENY", proof_ref=None)
        doc["object"]["formal_statement"] = {"bad": object()}
        assert is_valid_document(doc) is False

    def test_unserializable_formalization_rejected(self):
        doc = self._full_doc(verdict="BLOCKED", admission="DENY", proof_ref=None)
        doc["object"]["formalization"] = {"source_query": object(), "translator": "Test"}
        assert is_valid_document(doc) is False


class TestConstructorRejectsUnsupportedLeaves:
    def test_proof_rejects_set(self):
        with pytest.raises(VerificationContextValidationError):
            Proof(
                verifier="Test", verifier_version="1.0",
                configuration={"mode": {"a", "b"}},
                theory_scope="test", trusted_dependencies=(),
                outcome_treatment="fail-closed",
            )

    def test_evidence_rejects_bytearray(self):
        with pytest.raises(VerificationContextValidationError):
            Evidence(payload={"data": bytearray(b"x")}, proof_ref=None)

    def test_document_rejects_object_leaf(self):
        with pytest.raises(VerificationContextValidationError):
            VerificationContextDocument(
                spec_version="1.0",
                object={"formal_statement": "test", "extra": object()},
                context=VerificationContext(
                    interpretation=Interpretation(theory="Test"),
                    proof=Proof(
                        verifier="Test", verifier_version="1.0",
                        configuration={}, theory_scope="test",
                        trusted_dependencies=(), outcome_treatment="fail-closed",
                    ),
                    evidence=Evidence(payload={"test": True}, proof_ref=None),
                    decision=Decision(admission=Admission.DENY),
                ),
                verdict=Verdict.BLOCKED,
            )


# =============================================================================
# Canonical JSON tests (RFC 8785)
# =============================================================================

class TestCanonicalJson:
    def test_simple_object(self):
        result = _canonical_json({"b": 1, "a": 2})
        # Integer-valued floats serialize as integers per ECMAScript
        assert '"a":2' in result
        assert result.index('"a"') < result.index('"b"')

    def test_nested_object(self):
        result = _canonical_json({"outer": {"inner": [1, 2]}})
        # Integer-valued floats serialize as integers per ECMAScript
        assert '"outer":{"inner":[1,2]}' in result

    def test_null(self):
        assert _canonical_json(None) == "null"

    def test_bool(self):
        assert _canonical_json(True) == "true"
        assert _canonical_json(False) == "false"

    def test_int(self):
        # ECMAScript Number::toString: integer-valued float -> integer-form digits
        assert _canonical_json(42) == "42"
        assert _canonical_json(0) == "0"
        assert _canonical_json(-42) == "-42"

    def test_float(self):
        assert _canonical_json(4.5) == "4.5"
        # zero serializes as plain "0" in RFC 8785
        assert _canonical_json(0.0) == "0"

    def test_string(self):
        assert _canonical_json("test") == '"test"'
        assert _canonical_json("café") == '"café"'

    def test_list(self):
        result = _canonical_json([3, 1, 2])
        # ECMAScript: integer-valued floats serialize as integers
        assert result == "[3,1,2]"

    def test_tuple_converts_to_list(self):
        result = _canonical_json((1, 2))
        assert result == "[1,2]"

    def test_large_int_rejected(self):
        val = 2**53 + 1
        with pytest.raises(VerificationContextValidationError):
            _canonical_json(val)

    def test_nan_rejected(self):
        val = float("nan")
        with pytest.raises(VerificationContextValidationError):
            _canonical_json(val)

    def test_inf_rejected(self):
        val = float("inf")
        with pytest.raises(VerificationContextValidationError):
            _canonical_json(val)

    def test_unsupported_type_rejected(self):
        val = object()
        with pytest.raises(VerificationContextValidationError):
            _canonical_json(val)

    def test_unordered_dict_keys(self):
        result = _canonical_json({"zebra": 1, "apple": 2})
        assert result.index('"apple"') < result.index('"zebra"')

    def test_nested_list(self):
        result = _canonical_json([[1, 2], [3, 4]])
        assert result == "[[1,2],[3,4]]"


# =============================================================================
# Helpers
# =============================================================================

def _canonical_json(value):
    from qwed_infra.verification_context import _canonical_json
    return _canonical_json(value)


# =============================================================================
# Freeze-thaw tests
# =============================================================================

class TestFreezeThaw:
    def test_freeze_mapping(self):
        f = _freeze_value({"a": 1, "b": [2, 3]})
        assert f["a"] == 1

    def test_freeze_tuple(self):
        f = _freeze_value([1, 2, (3, 4)])
        assert f == (1, 2, (3, 4))

    def test_freeze_scalar(self):
        assert _freeze_value("test") == "test"

    def test_thaw_mappingproxy(self):
        f = _freeze_value({"a": 1})
        t = _thaw_value(f)
        assert t == {"a": 1}

    def test_thaw_dict(self):
        t = _thaw_value({"a": 1})
        assert t == {"a": 1}

    def test_thaw_tuple(self):
        t = _thaw_value((1, 2, (3, 4)))
        assert t == [1, 2, [3, 4]]

    def test_thaw_scalar(self):
        assert _thaw_value("test") == "test"


def _freeze_value(value):
    from qwed_infra.verification_context import _freeze_value
    return _freeze_value(value)

def _thaw_value(value):
    from qwed_infra.verification_context import _thaw_value
    return _thaw_value(value)


# =============================================================================
# Numeric formatting tests
# =============================================================================

class TestEsNumberFormatting:
    def test_positive_integer(self):
        assert _es_number_to_string(42.0) == "42"

    def test_negative_integer(self):
        assert _es_number_to_string(-42.0) == "-42"

    def test_zero(self):
        assert _es_number_to_string(0.0) == "0"

    def test_decimal(self):
        assert _es_number_to_string(4.5) == "4.5"

    def test_large_integer_float(self):
        # ECMAScript: 1e16 is within fixed-point range -> "10000000000000000"
        assert _es_number_to_string(1e16) == "10000000000000000"

    def test_exponential_threshold_upper(self):
        # ECMAScript: >= 1e21 uses exponential -> "1e+21"
        assert _es_number_to_string(1e21) == "1e+21"

    def test_exponential_threshold_lower(self):
        # ECMAScript: < 1e-6 uses exponential -> "1e-7"
        assert _es_number_to_string(1e-7) == "1e-7"

    def test_within_threshold_fixed(self):
        # ECMAScript: 1e-5 is >= 1e-6, uses fixed -> "0.00001"
        assert _es_number_to_string(1e-5) == "0.00001"

    def test_nan_rejected(self):
        val = float("nan")
        with pytest.raises(VerificationContextValidationError):
            _es_number_to_string(val)

    def test_infinity_rejected(self):
        val = float("inf")
        with pytest.raises(VerificationContextValidationError):
            _es_number_to_string(val)


def _es_number_to_string(value):
    from qwed_infra.verification_context import _es_number_to_string
    return _es_number_to_string(value)


# =============================================================================
# Surrogate validation tests
# =============================================================================

class TestRejectUnpairedSurrogates:
    def test_valid_string(self):
        _reject_unpaired_surrogates("hello world")

    def test_valid_unicode(self):
        _reject_unpaired_surrogates("café 東京")

    def test_valid_surrogate_pair(self):
        _reject_unpaired_surrogates("🚀 rocket")


def _reject_unpaired_surrogates(value):
    from qwed_infra.verification_context import _reject_unpaired_surrogates
    return _reject_unpaired_surrogates(value)


# =============================================================================
# Bridge tests
# =============================================================================

class TestBridge:
    def _verified_result(self):
        return InfraDiagnosticResult.verified(
            agent_message="test verified",
            developer_fields={"audit_trace": {"rule": "test.deny"}, "data": 1},
            evidence={"rule": "test.deny"},
        )

    def test_verified_with_attestation(self):
        result = self._verified_result()
        vc = verification_context_from_diagnostic_result(
            result,
            formal_statement="test claim",
            verifier="IamGuard",
            attestation_token="fake-jwt",
        )
        assert vc.verdict == Verdict.VERIFIED
        assert vc.context.decision.admission == Admission.ADMIT
        # Bridge now computes document-bound proof_ref, NOT diagnostic proof_ref
        assert vc.context.evidence.proof_ref.startswith("sha256:")
        assert len(vc.context.evidence.proof_ref) == 71  # sha256: + 64 hex chars
        doc_dict = vc.to_dict()
        # The document's own proof_ref must resolve against itself
        assert resolve_document_proof_ref(doc_dict) is True

    def test_verified_without_attestation(self):
        result = self._verified_result()
        vc = verification_context_from_diagnostic_result(
            result,
            formal_statement="test claim",
            verifier="IamGuard",
        )
        assert vc.verdict == Verdict.UNVERIFIABLE
        assert vc.context.decision.admission == Admission.DENY
        assert vc.context.evidence.proof_ref is None

    def test_unverifiable(self):
        result = InfraDiagnosticResult.unverifiable(
            agent_message="unverified test",
            developer_fields={"reason": "unknown"},
        )
        vc = verification_context_from_diagnostic_result(
            result,
            formal_statement="test claim",
            verifier="IamGuard",
        )
        assert vc.verdict == Verdict.UNVERIFIABLE
        assert vc.context.decision.admission == Admission.DENY
        assert vc.context.evidence.proof_ref is None

    def test_blocked(self):
        result = InfraDiagnosticResult.blocked(
            agent_message="blocked test",
            developer_fields={"reason": "violation"},
        )
        vc = verification_context_from_diagnostic_result(
            result,
            formal_statement="test claim",
            verifier="IamGuard",
        )
        assert vc.verdict == Verdict.BLOCKED
        assert vc.context.decision.admission == Admission.DENY
        assert vc.context.evidence.proof_ref is None

    def test_empty_formal_statement_rejected(self):
        result = self._verified_result()
        with pytest.raises(VerificationContextValidationError):
            verification_context_from_diagnostic_result(
                result,
                formal_statement="",
                verifier="IamGuard",
            )

    def test_malformed_status_blocked_fail_closed(self):
        # Malformed string status ("VERIFIED" as string) must produce BLOCKED
        # as fail-closed protection (no AttributeError through the bridge).
        result = object.__new__(InfraDiagnosticResult)
        object.__setattr__(result, 'status', "VERIFIED")  # string, not enum
        object.__setattr__(result, 'agent_message', "test")
        object.__setattr__(result, 'developer_fields', {"test": 1})
        object.__setattr__(result, 'proof_ref', "sha256:" + "a" * 64)

        vc = verification_context_from_diagnostic_result(
            result,
            formal_statement="test claim",
            verifier="IamGuard",
        )
        # Malformed status demotes to BLOCKED, not ADMIT
        assert vc.verdict == Verdict.BLOCKED
        assert vc.context.decision.admission == Admission.DENY

    def test_empty_verifier_rejected(self):
        result = self._verified_result()
        with pytest.raises(VerificationContextValidationError):
            verification_context_from_diagnostic_result(
                result,
                formal_statement="test claim",
                verifier="",
            )

    def test_evidence_preserves_developer_fields(self):
        result = InfraDiagnosticResult.verified(
            agent_message="test",
            developer_fields={"test": 1, "audit_trace": {"rule": "x"}},
            evidence={"test": 1},
        )
        vc = verification_context_from_diagnostic_result(
            result,
            formal_statement="test",
            verifier="TestGuard",
            attestation_token="fake-jwt",
        )
        assert "developer_fields" in vc.context.evidence.payload
        assert "audit_trace" in vc.context.evidence.payload["developer_fields"]


class TestBridgeEdgeCases:
    def test_malformed_developer_fields_via_bypass(self):
        # Post-init rejects non-dict; bypass constructor via object.__new__
        result = object.__new__(InfraDiagnosticResult)
        object.__setattr__(result, 'status', InfraDiagnosticStatus.UNVERIFIABLE)
        object.__setattr__(result, 'agent_message', "test")
        object.__setattr__(result, 'developer_fields', "not-a-dict")
        object.__setattr__(result, 'proof_ref', None)

        vc = verification_context_from_diagnostic_result(
            result,
            formal_statement="test claim",
            verifier="IamGuard",
        )
        assert vc.verdict == Verdict.BLOCKED

    def test_evidence_excludes_proof_ref_from_payload(self):
        result = InfraDiagnosticResult.verified(
            agent_message="test",
            developer_fields={"test": 1, "audit_trace": {"rule": "x"}},
            evidence={"test": 1},
        )
        vc = verification_context_from_diagnostic_result(
            result,
            formal_statement="test",
            verifier="TestGuard",
            attestation_token="fake-jwt",
        )
        ref_in_doc = vc.context.evidence.proof_ref
        assert ref_in_doc is not None
        assert ref_in_doc.startswith("sha256:")
        assert len(ref_in_doc) == 71  # sha256: + 64 hex chars
        # proof_ref in evidence payload should be None (excluded before hashing)
        assert vc.context.evidence.payload.get("proof_ref") is None