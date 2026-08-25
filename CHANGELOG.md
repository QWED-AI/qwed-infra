# Changelog

## [0.3.0] - 2026-08-24

### Added
- Verification Context v1.0 across all four guards (tracker #36) — every guard now exposes `to_verification_context()`, producing a schema-valid, tamper-evident VC document (claim, verifier identity, `sha256`-bound evidence `proof_ref`, ADMIT/DENY admission):
  - IamGuard (#38, PR #45), NetworkGuard (#39, PR #46), CostGuard (#40, PR #48), ArtifactBoundaryGuard (#41, PR #50)
  - Shared bridge module `verification_context_bridge` (#37, PR #44): diagnostic → VC document conversion with fail-closed attestation policy and decision-status demotion
  - Conformance suite `tests/test_vc_conformance.py` (#42, PR #52) — bridge + all guards + document validation + malformed-input fail-closed acceptance tests
  - README: "Verification Context v1.0" section — why VC, usage examples, downstream integration guide; VC badge in the header
- **Attestation trust boundary (#47, PR #54)** — new `qwed_infra/attestation.py`: ES256 (ECDSA P-256) JWT attestation service with ephemeral key lifecycle auditing, revocation registry, and the never-None fail-closed `AttestationResult` contract; `enforce_trust_decision()` in diagnostics.py as the single consumption-side gate validating signature/issuer/expiry/revocation plus claim bindings (status match, `query_hash == sha256(formal_statement)`, `proof_hash == diagnostic proof_ref`)
- `mint_diagnostic_attestation()` — issues a token bound to a diagnostic's own evidence commitment

### Changed
- **BREAKING (pre-1.0, unreleased API):** guard adapters no longer accept pre-computed result objects. `to_verification_context()` takes **raw verification inputs** and runs the guard's own deterministic solver internally (`NetworkGuard.to_verification_context(resources, source, destination, port, ...)` / `IamGuard.to_verification_context(policy, action, resource, context=None, ...)` / `CostGuard.to_verification_context(resources, budget_monthly, ...)` / `ArtifactBoundaryGuard.to_verification_context(package_dir, ...)`) — a result-accepting signature is forgeable (a caller could fabricate a positive result and mint ADMIT), so it was removed before any release (PRs #45/#46/#48/#50)
- **ADMISSION SEMANTICS:** `VERIFIED` results now admit **only** with a cryptographically valid attestation bound to the exact claim and evidence. Arbitrary non-empty attestation strings no longer grant ADMIT (they are rejected as forged tokens); a missing token demotes VERIFIED to UNVERIFIABLE/DENY. Callers previously passing placeholder tokens must mint via `create_verification_attestation()` / `mint_diagnostic_attestation()`
- New runtime dependencies: `pyjwt>=2.8.0,!=2.12.1`, `cryptography>=41.0.0`

### Fixed
- Fail-closed on malformed inputs at every VC boundary: undecimal budgets, extreme Decimal values, non-string build backends, malformed topology/policy/package inputs, symlink escapes/loops, wheel entries outside the scanned boundary — all map to BLOCKED/DENY documents instead of exceptions or guessed approval (#48, #49/PR #51, #50)
- ArtifactBoundaryGuard proof binding: content manifests (per-file sha256), package identity derived from the inspected directory, exact-match backend allowlist (#47 follow-ups in PR #50)
- IAM verified-denial results demote to BLOCKED (never ADMIT); the diagnostic's own proof hash is preserved inside the evidence payload (`diagnostic_proof_ref`), while the document-level `evidence.proof_ref` stays null for every DENY decision (fail-closed contract)

## [0.2.0] - 2026-07-02

### Added
- ArtifactBoundaryGuard — deterministic release boundary verification (secret scanning, debug artifact detection, hatch build config validation)
- audit.py + InfraDiagnosticResult — 3-layer diagnostic model ported from qwed-tax v0.2.0 (audit_trace, evidence, structured fields)
- CONTRIBUTING.md, PR template, QWED_RULES.md, copilot-instructions — IaC-specific governance files
- CI/CD — CodeQL, Snyk (IaC + SAST), SonarCloud security workflows
- CHANGELOG.md — version tracking

### Fixed
- Terraform parser fail-closed — parse/normalization errors now produce BLOCKED, not silent continue (#8, #9)
- IAM policy extraction — stripped policies now blocked instead of producing empty statements (#9)
- CI fail-open — removed `|| true` and `continue-on-error` from verification steps (#10)
- NetworkGuard internal traffic CIDR — false negative security gap (#14)
- NetworkGuard unsupported topology — fail-closed on missing topology keys (#12)
- CostGuard implicit defaults — unknown instance types now fail-closed instead of defaulting (#11)
- CostGuard float→Decimal — exact financial arithmetic with ROUND_HALF_UP quantization (#15)
- CostGuard unknown volume types — fail-closed on unhandled volume/storage types (#16)
- IamGuard Z3 scope labeling — honest evaluation_in marking (Python vs Z3) (#17)
- README examples — missing port arg, reason string mismatch, instance vs subnet id (#18)
- Config sync — sonar version 1.0→0.1.0, python range fix, removed dead requests dependency (#20)

## [0.1.0] - 2026-07-01

### Added
- IamGuard — Z3-based IAM policy verification (least privilege, condition evaluation)
- NetworkGuard — NetworkX-based VPC reachability analysis with fail-closed on unsupported topologies (NAT, NACL, VPC peering, transit gateway)
- CostGuard — Deterministic cost estimation with Decimal arithmetic, ROUND_HALF_UP quantization, fail-closed on unknown instance/volume types
- Terraform parser — HCL2-based resource normalization with fail-closed on missing required fields
- 3-layer diagnostic model — InfraDiagnosticResult with VERIFIED/BLOCKED/UNVERIFIABLE status, audit trace, and evidence
- Numeric utilities — parse_decimal_input and decimal_text for exact financial computation (ported from qwed-tax v0.2.0)
- CI/CD — Snyk, SonarCloud, GitHub Actions with fail-closed enforcement
