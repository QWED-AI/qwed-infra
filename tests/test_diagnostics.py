import pytest
from qwed_infra.diagnostics import (
    InfraAdvisoryCheck,
    InfraDiagnosticResult,
    InfraDiagnosticStatus,
    compute_proof_ref,
)


class TestInfraDiagnosticStatus:
    def test_three_states(self):
        assert InfraDiagnosticStatus.VERIFIED.value == "VERIFIED"
        assert InfraDiagnosticStatus.UNVERIFIABLE.value == "UNVERIFIABLE"
        assert InfraDiagnosticStatus.BLOCKED.value == "BLOCKED"


class TestInfraDiagnosticResultConstruction:
    def test_minimal_verified(self):
        result = InfraDiagnosticResult.verified(
            agent_message="All checks passed",
            developer_fields={"constraint_id": "test"},
            evidence={"rule": "test_rule"},
        )
        assert result.status is InfraDiagnosticStatus.VERIFIED
        assert result.is_verified is True
        assert result.is_authoritative is True
        assert result.proof_ref is not None
        assert result.proof_ref.startswith("sha256:")

    def test_unverifiable(self):
        result = InfraDiagnosticResult.unverifiable(
            agent_message="Could not verify",
            developer_fields={"constraint_id": "test"},
        )
        assert result.status is InfraDiagnosticStatus.UNVERIFIABLE
        assert result.is_verified is False
        assert result.is_authoritative is False
        assert result.is_fail_closed is True
        assert result.proof_ref is None

    def test_blocked(self):
        result = InfraDiagnosticResult.blocked(
            agent_message="Verification blocked",
            developer_fields={"constraint_id": "test"},
        )
        assert result.status is InfraDiagnosticStatus.BLOCKED
        assert result.is_verified is False
        assert result.is_authoritative is False
        assert result.is_fail_closed is True
        assert result.proof_ref is None

    def test_verified_without_evidence_raises(self):
        with pytest.raises(ValueError, match="proof_ref"):
            InfraDiagnosticResult(
                status=InfraDiagnosticStatus.VERIFIED,
                agent_message="test",
                developer_fields={},
                proof_ref=None,
            )

    def test_non_verified_with_proof_ref_raises(self):
        with pytest.raises(ValueError, match="proof_ref"):
            InfraDiagnosticResult(
                status=InfraDiagnosticStatus.UNVERIFIABLE,
                agent_message="test",
                developer_fields={},
                proof_ref="sha256:abc",
            )

    def test_empty_agent_message_raises(self):
        with pytest.raises(ValueError, match="agent_message"):
            InfraDiagnosticResult(
                status=InfraDiagnosticStatus.UNVERIFIABLE,
                agent_message="",
                developer_fields={},
            )

    def test_non_dict_developer_fields_raises(self):
        with pytest.raises(ValueError, match="developer_fields"):
            InfraDiagnosticResult(
                status=InfraDiagnosticStatus.UNVERIFIABLE,
                agent_message="test",
                developer_fields="not-a-dict",
            )

    def test_frozen(self):
        result = InfraDiagnosticResult.unverifiable(
            agent_message="test", developer_fields={}
        )
        with pytest.raises(AttributeError):
            result.agent_message = "changed"


class TestInfraDiagnosticResultProperties:
    def test_constraint_id(self):
        r = InfraDiagnosticResult.unverifiable(
            agent_message="test",
            developer_fields={"constraint_id": "my.guard.check"},
        )
        assert r.constraint_id == "my.guard.check"

    def test_audit_trace(self):
        r = InfraDiagnosticResult.unverifiable(
            agent_message="test",
            developer_fields={"audit_trace": {"rule_id": "R1"}},
        )
        assert r.audit_trace == {"rule_id": "R1"}

    def test_advisory_checks(self):
        r = InfraDiagnosticResult.unverifiable(
            agent_message="test",
            developer_fields={
                "advisory_checks": [
                    {"name": "check1", "constraint_id": "c1"},
                ]
            },
        )
        checks = r.advisory_checks
        assert len(checks) == 1
        assert checks[0].name == "check1"
        assert checks[0].advisory_only is True


class TestInfraDiagnosticResultSerialization:
    def test_to_dict_verified(self):
        r = InfraDiagnosticResult.verified(
            agent_message="OK",
            developer_fields={"constraint_id": "t1"},
            evidence={"key": "val"},
        )
        d = r.to_dict()
        assert d["status"] == "VERIFIED"
        assert d["agent_message"] == "OK"
        assert d["is_authoritative"] is True
        assert d["proof_ref"].startswith("sha256:")

    def test_to_dict_unverifiable(self):
        r = InfraDiagnosticResult.unverifiable(
            agent_message="Not sure",
            developer_fields={"constraint_id": "t1"},
        )
        d = r.to_dict()
        assert d["status"] == "UNVERIFIABLE"
        assert d["proof_ref"] is None
        assert d["is_authoritative"] is False

    def test_from_dict_roundtrip(self):
        original = InfraDiagnosticResult.verified(
            agent_message="Roundtrip test",
            developer_fields={"constraint_id": "t1"},
            evidence={"key": "val"},
        )
        d = original.to_dict()
        restored = InfraDiagnosticResult.from_dict(d)
        assert restored.status == original.status
        assert restored.agent_message == original.agent_message
        assert restored.proof_ref == original.proof_ref
        assert restored.developer_fields["constraint_id"] == "t1"

    def test_from_dict_missing_agent_message_raises(self):
        with pytest.raises(ValueError, match="agent_message"):
            InfraDiagnosticResult.from_dict({"status": "BLOCKED"})

    def test_from_dict_invalid_status_raises(self):
        with pytest.raises(ValueError, match="invalid status"):
            InfraDiagnosticResult.from_dict(
                {"status": "NONSENSE", "agent_message": "test"}
            )


class TestInfraAdvisoryCheck:
    def test_frozen(self):
        c = InfraAdvisoryCheck(name="test")
        with pytest.raises(AttributeError):
            c.name = "changed"

    def test_advisory_only_must_be_true(self):
        with pytest.raises(ValueError, match="advisory_only"):
            InfraAdvisoryCheck(name="bad", advisory_only=False)

    def test_to_dict_roundtrip(self):
        c = InfraAdvisoryCheck(
            name="check1",
            constraint_id="c1",
            details={"key": "val"},
        )
        d = c.to_dict()
        restored = InfraAdvisoryCheck.from_dict(d)
        assert restored.name == "check1"
        assert restored.constraint_id == "c1"
        assert restored.details == {"key": "val"}

    def test_from_dict_int_advisory_only(self):
        c = InfraAdvisoryCheck.from_dict({"name": "test", "advisory_only": 1})
        assert c.advisory_only is True

    def test_from_dict_invalid_advisory_only_raises(self):
        with pytest.raises(ValueError, match="advisory_only"):
            InfraAdvisoryCheck.from_dict({"name": "test", "advisory_only": "maybe"})


class TestComputeProofRef:
    def test_deterministic(self):
        e1 = compute_proof_ref({"a": 1, "b": 2})
        e2 = compute_proof_ref({"b": 2, "a": 1})
        assert e1 == e2

    def test_prefix(self):
        h = compute_proof_ref({"key": "val"})
        assert h.startswith("sha256:")

    def test_non_json_serializable_raises(self):
        with pytest.raises(ValueError, match="JSON-serializable"):
            compute_proof_ref({"bad": object()})
