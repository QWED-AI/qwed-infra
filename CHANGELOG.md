# Changelog

## [0.1.0] - 2026-07-01

### Added
- IamGuard — Z3-based IAM policy verification (least privilege, condition evaluation)
- NetworkGuard — NetworkX-based VPC reachability analysis with fail-closed on unsupported topologies (NAT, NACL, VPC peering, transit gateway)
- CostGuard — Deterministic cost estimation with Decimal arithmetic, ROUND_HALF_UP quantization, fail-closed on unknown instance/volume types
- Terraform parser — HCL2-based resource normalization with fail-closed on missing required fields
- 3-layer diagnostic model — InfraDiagnosticResult with VERIFIED/BLOCKED/UNVERIFIABLE status, audit trace, and evidence
- Numeric utilities — parse_decimal_input and decimal_text for exact financial computation (ported from qwed-tax v0.2.0)
- CI/CD — Snyk, SonarCloud, GitHub Actions with fail-closed enforcement
