# Changelog

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
