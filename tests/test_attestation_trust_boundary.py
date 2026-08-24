"""Attestation trust boundary tests (issue #47).

Mirrors qwed-verification's fail-closed attestation contract:
- forged / arbitrary tokens never grant ADMIT
- revoked tokens are rejected
- claim bindings (status / query_hash / proof_hash) are enforced
- distinct accepted attestations yield distinct document proof_refs
- statement overclaims break query_hash binding -> DENY
"""

import pytest

from qwed_infra.attestation import (
    AttestationService,
    mint_diagnostic_attestation,
)
from qwed_infra.diagnostics import InfraDiagnosticResult, enforce_trust_decision
from qwed_infra.guards.cost_guard import CostGuard
from qwed_infra.guards.iam_guard import IamGuard
from qwed_infra.guards.network_guard import NetworkGuard
from qwed_infra.verification_context import Admission, Verdict

STATEMENT = "The verified claim"


class TestProofDataCommitmentEnforced:
    """#47: proof_data must commit to proof_ref on EVERY construction path."""

    def test_direct_construction_mismatched_proof_data_rejected(self):
        from qwed_infra.diagnostics import InfraDiagnosticResult, InfraDiagnosticStatus

        status = InfraDiagnosticStatus.VERIFIED
        fields = {"audit_trace": {"rule_id": "R"}}
        with pytest.raises(ValueError):
            InfraDiagnosticResult(
                status=status,
                agent_message="v",
                developer_fields=fields,
                proof_ref="sha256:" + "0" * 64,
                proof_data='{"altered": true}',
            )

    def test_direct_construction_empty_proof_data_rejected(self):
        from qwed_infra.diagnostics import InfraDiagnosticResult, InfraDiagnosticStatus

        # proof_ref = sha256("") so the pair-integrity check PASSES and the
        # test reaches the dedicated non-empty proof_data rejection instead.
        status = InfraDiagnosticStatus.VERIFIED
        empty_digest = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        with pytest.raises(ValueError):
            InfraDiagnosticResult(
                status=status,
                agent_message="v",
                developer_fields={"audit_trace": {"rule_id": "R"}},
                proof_ref=empty_digest,
                proof_data="",
            )

    def test_direct_construction_missing_proof_data_rejected(self):
        from qwed_infra.diagnostics import InfraDiagnosticResult, InfraDiagnosticStatus

        status = InfraDiagnosticStatus.VERIFIED
        fields = {"audit_trace": {"rule_id": "R"}}
        with pytest.raises(ValueError):
            InfraDiagnosticResult(
                status=status,
                agent_message="v",
                developer_fields=fields,
                proof_ref="sha256:" + "0" * 64,
            )

    def test_matching_commitment_accepted(self):
        result = _verified_diagnostic()
        assert result.proof_data is not None
        # round-trip through serialization keeps the pair valid
        restored = InfraDiagnosticResult.from_dict(result.to_dict())
        assert restored.proof_data == result.proof_data


def _verified_diagnostic():
    return InfraDiagnosticResult.verified(
        agent_message="verified",
        developer_fields={"constraint_id": "test", "audit_trace": {"rule_id": "R", "outcome": "ALLOWED"}},
        evidence={"constraint_id": "test", "outcome": "ALLOWED"},
    )


class TestEnforceTrustDecisionFailClosed:
    def test_verified_without_token_blocked_when_required(self):
        result = _verified_diagnostic()
        enforced = enforce_trust_decision(result, require_attestation=True)
        assert enforced.status.value == "BLOCKED"
        assert enforced.proof_ref is None
        assert enforced.developer_fields["constraint_id"] == "trust_gate.mandatory_attestation_missing"

    def test_verified_without_token_passes_when_optional(self):
        result = _verified_diagnostic()
        enforced = enforce_trust_decision(result, require_attestation=False)
        assert enforced.status.value == "VERIFIED"

    def test_fail_closed_statuses_pass_through(self):
        blocked = InfraDiagnosticResult.blocked(agent_message="b")
        assert enforce_trust_decision(blocked).status.value == "BLOCKED"
        unverifiable = InfraDiagnosticResult.unverifiable(agent_message="u")
        assert enforce_trust_decision(unverifiable).status.value == "UNVERIFIABLE"

    def test_forged_token_blocked(self):
        result = _verified_diagnostic()
        enforced = enforce_trust_decision(
            result,
            attestation_token="not-a-jwt",
            require_attestation=True,
            query=STATEMENT,
        )
        assert enforced.status.value == "BLOCKED"
        assert enforced.developer_fields["constraint_id"] == "trust_gate.invalid_attestation_token"

    def test_token_without_query_is_api_misuse(self):
        """#47: a token with no statement to bind against raises - the
        query_hash binding check can never be skipped by omitting the arg."""
        result = _verified_diagnostic()
        with pytest.raises(ValueError):
            enforce_trust_decision(
                result, attestation_token="not-a-jwt", require_attestation=True
            )

    def test_valid_token_with_matching_claims_passes(self):
        result = _verified_diagnostic()
        att = mint_diagnostic_attestation(result, engine="TestEngine", query=STATEMENT)
        assert att.is_issued
        enforced = enforce_trust_decision(
            result, attestation_token=att.token, query=STATEMENT
        )
        assert enforced.status.value == "VERIFIED"

    def test_statement_overclaim_breaks_query_binding(self):
        """A token minted for one statement must not admit a broader one (#47 P1)."""
        result = _verified_diagnostic()
        att = mint_diagnostic_attestation(result, engine="TestEngine", query="narrow: subnet-a:80")
        enforced = enforce_trust_decision(
            result,
            attestation_token=att.token,
            query="ALL traffic to every subnet and port is safe",
        )
        assert enforced.status.value == "BLOCKED"
        assert enforced.developer_fields["constraint_id"] == "trust_gate.claims_query_mismatch"

    def test_proof_hash_binding_enforced(self):
        result = _verified_diagnostic()
        # Mint against a different diagnostic's evidence commitment.
        tampered = InfraDiagnosticResult.verified(
            agent_message="tampered",
            developer_fields={"constraint_id": "test", "audit_trace": {"rule_id": "R", "outcome": "ALLOWED"}},
            evidence={"constraint_id": "test", "outcome": "TAMPERED"},
        )
        att = mint_diagnostic_attestation(tampered, engine="TestEngine", query=STATEMENT)
        enforced = enforce_trust_decision(
            result, attestation_token=att.token, query=STATEMENT
        )
        assert enforced.status.value == "BLOCKED"
        assert enforced.developer_fields["constraint_id"] == "trust_gate.claims_proof_mismatch"

    def test_status_mismatch_blocked(self):
        from qwed_infra.attestation import (
            VerificationResult as AVR,
            get_attestation_service,
        )

        result = _verified_diagnostic()
        # Mint via the module-default service: enforcement verifies against the
        # singleton's ephemeral key (ADR-005 self-attestation stage).
        service = get_attestation_service()
        att = service.create_attestation(
            AVR(status="FAILED", verified=False, engine="x"),
            original_query=STATEMENT,
            proof_data=result.proof_data,
        )
        enforced = enforce_trust_decision(
            result, attestation_token=att.jwt_token, query=STATEMENT
        )
        assert enforced.status.value == "BLOCKED"
        assert enforced.developer_fields["constraint_id"] == "trust_gate.claims_status_mismatch"

    def test_missing_proof_hash_blocked_distinctly(self):
        """A VERIFIED token without a qwed.proof_hash claim gets its own
        fail-closed reason (claims_proof_missing), not a generic mismatch.

        Issuance now rejects VERIFIED-without-proof_data, so the token is
        crafted and signed directly with the service key (legacy-token shape).
        """
        import time

        import jwt as pyjwt

        from qwed_infra.attestation import get_attestation_service
        from qwed_infra.diagnostics import _compute_query_hash

        result = _verified_diagnostic()
        service = get_attestation_service()
        key_pair = service._ensure_key_pair()
        now = int(time.time())
        payload = {
            "iss": service.issuer_did,
            "sub": _compute_query_hash(STATEMENT),
            "iat": now,
            "exp": now + 3600,
            "jti": "crafted-no-proof-hash",
            "qwed": {
                "version": "1.0",
                "result": {"status": "VERIFIED", "verified": True, "engine": "x", "confidence": 1.0},
                "query_hash": _compute_query_hash(STATEMENT),
                # deliberately NO proof_hash claim
            },
        }
        token = pyjwt.encode(
            payload,
            key_pair.private_key_pem,
            algorithm="ES256",
            headers={"alg": "ES256", "typ": "qwed-attestation+jwt", "kid": key_pair.key_id},
        )
        enforced = enforce_trust_decision(
            result, attestation_token=token, query=STATEMENT
        )
        assert enforced.status.value == "BLOCKED"
        assert enforced.developer_fields["constraint_id"] == "trust_gate.claims_proof_missing"

    def test_create_attestation_rejects_verified_without_proof_data(self):
        """Issuance-side guard: VERIFIED tokens without proof_data cannot exist."""
        from qwed_infra.attestation import (
            VerificationResult as AVR,
            get_attestation_service,
        )

        service = get_attestation_service()
        conflicting = AVR(status="VERIFIED", verified=True, engine="x")
        with pytest.raises(ValueError):
            service.create_attestation(
                conflicting,
                original_query=STATEMENT,
            )

    def test_create_attestation_rejects_verified_status_with_false_flag(self):
        """Issuance-side guard: status='VERIFIED' requires verified=True —
        the service must not sign internally inconsistent claims."""
        import time

        import jwt as pyjwt

        from qwed_infra.attestation import (
            VerificationResult as AVR,
            get_attestation_service,
        )
        from qwed_infra.diagnostics import _compute_query_hash

        service = get_attestation_service()
        key_pair = service._ensure_key_pair()

        # 1. Issuance rejects the conflicting request outright.
        conflicting = AVR(status="VERIFIED", verified=False, engine="x")
        with pytest.raises(ValueError):
            service.create_attestation(
                conflicting,
                original_query=STATEMENT,
                proof_data="proof",
            )

        # 2. Gate-level defense: a hand-signed legacy token carrying the same
        # conflicting claims (with a MATCHING proof_hash) is still rejected.
        now = int(time.time())
        payload = {
            "iss": service.issuer_did,
            "sub": _compute_query_hash(STATEMENT),
            "iat": now,
            "exp": now + 3600,
            "jti": "crafted-verified-false",
            "qwed": {
                "version": "1.0",
                "result": {"status": "VERIFIED", "verified": False, "engine": "x", "confidence": 1.0},
                "query_hash": _compute_query_hash(STATEMENT),
                "proof_hash": "sha256:" + "a" * 64,
            },
        }
        token = pyjwt.encode(
            payload,
            key_pair.private_key_pem,
            algorithm="ES256",
            headers={"alg": "ES256", "typ": "qwed-attestation+jwt", "kid": key_pair.key_id},
        )
        enforced = enforce_trust_decision(
            _verified_diagnostic(), attestation_token=token, query=STATEMENT
        )
        assert enforced.status.value == "BLOCKED"
        assert enforced.developer_fields["constraint_id"] == "trust_gate.claims_verified_mismatch"


class TestAttestationServiceContract:
    def test_revoked_token_rejected(self):
        service = AttestationService()
        from qwed_infra.attestation import VerificationResult as AVR

        att = service.create_attestation(
            AVR(status="VERIFIED", verified=True, engine="e"),
            original_query="q",
            proof_data="proof",
        )
        is_valid, _, _ = service.verify_attestation(att.jwt_token)
        assert is_valid is True
        service.revoke_attestation(att.claims.jti)
        is_valid, _claims, error = service.verify_attestation(att.jwt_token)
        assert is_valid is False
        assert error == "Invalid token"  # generic rejection - no enumeration

    def test_expired_token_rejected(self):
        from qwed_infra.attestation import VerificationResult as AVR

        service = AttestationService(validity_days=1)
        att = service.create_attestation(
            AVR(status="VERIFIED", verified=True, engine="e"),
            original_query="q",
            proof_data="proof",
            issued_at=0,  # epoch -> long expired
        )
        is_valid, _claims, error = service.verify_attestation(att.jwt_token)
        assert is_valid is False
        assert error == "Invalid token"

    def test_tampered_payload_rejected(self):
        from qwed_infra.attestation import VerificationResult as AVR

        service = AttestationService()
        att = service.create_attestation(
            AVR(status="VERIFIED", verified=True, engine="e"),
            original_query="q",
            proof_data="proof",
        )
        header, payload, sig = att.jwt_token.split(".")
        tampered = f"{header}.{payload[:-4]}AAAA.{sig}"
        is_valid, _, error = service.verify_attestation(tampered)
        assert is_valid is False

    def test_oversized_token_rejected(self):
        service = AttestationService()
        is_valid, _, error = service.verify_attestation("x" * 9000)
        assert is_valid is False


class TestGuardEndToEndAttestation:
    """End-to-end: guard computes -> token minted over its diagnostic ->
    bridge enforces -> ADMIT with distinct proof_refs per attestation."""

    FORMAL = "Traffic from internet to subnet-a on port 80 is safe"

    def _reachable_diag(self, guard, resources):
        return NetworkGuard.to_diagnostic(
            guard.verify_reachability(resources, "internet", "subnet-a", 80)
        )

    def _resources(self):
        return {
            "subnets": [{"id": "subnet-a", "security_groups": ["sg-allow-http"]}],
            "route_tables": [
                {"subnet_id": "subnet-a", "routes": {"0.0.0.0/0": "igw-123"}}
            ],
            "security_groups": {
                "sg-allow-http": {"ingress": [{"port": 80, "cidr": "0.0.0.0/0"}]}
            },
        }

    def test_guard_admits_only_with_bound_attestation(self):
        guard = NetworkGuard()
        resources = self._resources()
        diag = self._reachable_diag(guard, resources)
        att = mint_diagnostic_attestation(diag, engine="NetworkGuard", query=self.FORMAL)

        vc_ok = guard.to_verification_context(
            resources, "internet", "subnet-a", 80,
            formal_statement=self.FORMAL, attestation_token=att.token,
        )
        assert vc_ok.verdict == Verdict.VERIFIED
        assert vc_ok.context.decision.admission == Admission.ADMIT

        vc_forged = guard.to_verification_context(
            resources, "internet", "subnet-a", 80,
            formal_statement=self.FORMAL, attestation_token="garbage",
        )
        assert vc_forged.verdict == Verdict.BLOCKED
        assert vc_forged.context.decision.admission == Admission.DENY

    def test_guard_statement_overclaim_blocked_end_to_end(self):
        """Mint for a narrow statement, submit a broader one -> BLOCKED/DENY.

        Proves query_hash binding is enforced through the guard->bridge path
        (not just direct enforce_trust_decision calls).
        """
        guard = NetworkGuard()
        resources = self._resources()
        narrow = "Reachability verified: internet -> subnet-a port 80 only"
        broad = "ALL traffic to every subnet and every port is safe"
        diag = self._reachable_diag(guard, resources)
        att = mint_diagnostic_attestation(diag, engine="NetworkGuard", query=narrow)
        vc = guard.to_verification_context(
            resources, "internet", "subnet-a", 80,
            formal_statement=broad, attestation_token=att.token,
        )
        assert vc.verdict == Verdict.BLOCKED
        assert vc.context.decision.admission == Admission.DENY
        assert vc.context.evidence.proof_ref is None
        # BLOCKED (not VERIFIED) is itself the proof that query binding fired:
        # status and proof_hash both match this diagnostic, so only the
        # statement mismatch can have failed enforcement.
        #
        # Note: the document evidence payload intentionally preserves the
        # original guard diagnostic (its constraint_id), not the trust-gate
        # block reason - evidence records what was computed; the decision
        # layer records the enforcement outcome.

    def test_distinct_attestations_distinct_document_proof_refs(self):
        from qwed_infra.attestation import (
            VerificationResult as AVR,
            get_attestation_service,
        )

        guard = NetworkGuard()
        resources = self._resources()
        tokens = set()
        proof_refs = set()
        service = get_attestation_service()
        for jti in ("att-jti-1", "att-jti-2"):
            diag = self._reachable_diag(guard, resources)
            a = service.create_attestation(
                AVR(status="VERIFIED", verified=True, engine="NetworkGuard"),
                original_query=self.FORMAL,
                proof_data=diag.proof_data,
                jti=jti,
            )
            vc = guard.to_verification_context(
                resources, "internet", "subnet-a", 80,
                formal_statement=self.FORMAL, attestation_token=a.jwt_token,
            )
            assert vc.verdict == Verdict.VERIFIED
            tokens.add(jti)
            proof_refs.add(vc.context.evidence.proof_ref)
        assert len(tokens) == 2
        assert len(proof_refs) == 2  # distinct attestations -> distinct documents

    def test_iam_and_cost_guards_end_to_end(self):
        iam = IamGuard()
        policy = {"Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]}
        stmt_i = "IAM policy is safe to apply"
        diag = IamGuard.to_diagnostic(iam.verify_access(policy, "s3:GetObject", "*"))
        att = mint_diagnostic_attestation(diag, engine="IamGuard", query=stmt_i)
        vc = iam.to_verification_context(
            policy, "s3:GetObject", "*",
            formal_statement=stmt_i, attestation_token=att.token,
        )
        assert vc.verdict == Verdict.VERIFIED

        cost = CostGuard()
        res = {"instances": [{"id": "web", "instance_type": "t3.medium", "count": 1}]}
        stmt_c = "Estimated monthly cost is within the approved budget"
        cdiag = CostGuard.to_diagnostic(cost.verify_budget(res, "100.00"))
        catt = mint_diagnostic_attestation(cdiag, engine="CostGuard", query=stmt_c)
        cvc = cost.to_verification_context(
            res, "100.00", formal_statement=stmt_c, attestation_token=catt.token,
        )
        assert cvc.verdict == Verdict.VERIFIED
