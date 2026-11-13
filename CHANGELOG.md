# Changelog

## [Unreleased]

## [0.4.0] - 2026-11-13

### Security
- ArtifactBoundaryGuard checked only the wheel target table, but hatchling builds from more configuration. It now refuses, as unmodelled:
  - a `hatch.toml` file (hatchling merges it over `[tool.hatch]`), a root `PKG-INFO` file, and `[project] dynamic` fields other than `version` (hatchling fills them from PKG-INFO or hooks)
  - `[build-system]` keys other than `requires` and `build-backend` (`backend-path` lets the project supply its own backend), and any build requirement other than `hatchling` with public PEP 440 version specifiers and an optional marker, in printable ASCII (any other requirement is installed into the build environment and can run code there; pip installs a requirement ending in an archive extension from a local file, and a line break lets one entry add more requirement lines)
  - root-level modules, namespace directories and programs named like standard library, build tool or interpreter names (`pip.py`, `argparse.py`, `org/`, `python.bat`), which a build run from the project root would use. This is a list of known names: the verdict assumes the build does not import from the project root (`PYTHONSAFEPATH=1`, or a build run from outside it, with an absolute interpreter path)
  - context formatting (`{env:...}`, `{root}`) in dependency strings, which would write build-environment values into METADATA
  - `[tool.hatch.build]` options that apply to every target and add files (such as `force-include`, `include`, `sources`, `packages`, `hooks`), sdist options that add or remap files (`force-include`, `sources`, `hooks`), because `python -m build` builds the wheel from the sdist, and wheel options it does not model (such as `shared-data`, `extra-metadata`, `sources`, `hooks`)
  - version sources other than `regex`, a version `path` through a symlink or a hidden file or directory or resolving outside the project root, and `[tool.hatch.metadata]` hooks, which run code at build time
  - `[project]` readme files other than plain `README*` files in the project root, and license and license-files entries other than plain `LICENSE*` / `LICENCE*` / `COPYING*` / `NOTICE*` / `AUTHORS*` files there; symlinks and names matching a sensitive file pattern by name or suffix are refused (default license-files globs included). File checks are by name; the content of README, LICENSE and version files is not inspected
  - The verdict covers the wheel built by hatchling 1.27 or 1.28; the sdist is not checked
- ArtifactBoundaryGuard blocks wheel `force-include` even with `only-packages`, because hatchling still ships force-included files
- IamGuard no longer reads a condition it cannot evaluate as "does not match", which dropped a Deny and could report a forbidden request as allowed and VERIFIED. Every condition now has three outcomes; an unsupported operator (including `ForAnyValue:` and `ForAllValues:`), a malformed value, a multi-valued request key or an unresolved policy variable makes the result UNVERIFIABLE whenever the decision depends on that statement, for Allow and Deny alike. A Deny that applies still decides the request when another statement cannot be evaluated
- IamGuard follows AWS for absent condition keys: a negated operator (`StringNotEquals`, `NotIpAddress` and the other `...Not...` forms) or an `...IfExists` operator is true when the key is absent, and `Null` tests presence. Values are parsed strictly: numbers as decimal digits with an optional minus sign and fraction, dates as W3C dates (midnight UTC), W3C date-times with a zone or epoch seconds, booleans as `true` or `false`; anything else, and a malformed policy value even when its key is absent, is UNVERIFIABLE. A request context value of `null` or an empty list, and condition operators or keys that differ only in case, are UNVERIFIABLE
- IamGuard implements the `String*`, `Arn*`, `Numeric*`, `Date*` and `IpAddress` operator families, `Bool`, `Null` and the `...IfExists` forms, with AWS multi-value semantics (OR across values, NOR for negated operators)
- IamGuard matching is closer to AWS and refuses what it does not model: actions match case-insensitively, `?` matches exactly one character, `*` matches any run of characters over the whole Unicode range, and for a request resource with colons both stay within one colon-separated segment, except a `*` that ends the last segment (a match that would need a wildcard to cross a colon otherwise is UNVERIFIABLE; so are a policy variable before the fifth colon of a resource ARN and a wildcard in its service segment); condition key names match case-insensitively; case folding is ASCII only, and non-ASCII text compared case-insensitively is UNVERIFIABLE; policy variables (`${aws:username}`, and the `${*}`, `${?}`, `${$}` escapes) are substituted in resources and condition values under `"Version": "2012-10-17"`. A statement with an element outside the policy language (a misspelt `Conditon`, say), an empty `Action` or `Resource`, or an `Effect` other than `Allow` or `Deny` is UNVERIFIABLE, and so is a policy with a top-level element other than `Version`, `Id` and `Statement` or a `Version` other than `2012-10-17` or `2008-10-17`. IP values must be addresses or CIDRs (netmask forms, IPv4-mapped IPv6 request addresses and scoped IPv6 request addresses are UNVERIFIABLE), and `ArnLike` accepts `*`
- IamGuard decides every match and condition in Python on the concrete request; Z3 combines the outcomes under Deny precedence. Z3 string values decoded escape sequences such as `\u{61}`, so a `StringEquals` condition could match a different string, and Z3 regular expressions could stall on long values with mixed `?` and `*`
- `verify_least_privilege` judges full access from the patterns instead of matching a literal `*` request: a Deny counts only when it is unconditional and names every action and every resource with a pattern of `*` alone (a "deny without MFA" guard-rail, or a Deny of `?`, used to hide `*` on `*`); an Allow counts, whatever its condition, when its Action and Resource patterns are made only of `*`, `?` and `:` (`*:*`, `?*`, `arn:*`); an Allow whose coverage the guard cannot tell (a wildcarded service prefix such as `a*`, or a wildcarded partition or service in a resource ARN) makes the result UNVERIFIABLE
- IamGuard bounds the work a policy can cause: `?` counts toward the 64-wildcard bound, a policy may hold at most 2,500 condition values and 131,072 characters of Action, Resource and condition text, and a pattern longer than 8,192 characters after policy variable substitution, or more than 131,072 characters of substituted text in one request, is UNVERIFIABLE

### Fixed
- CostGuard keeps instance prices and EBS storage prices in separate tables, so a storage price key used as an instance type is an unknown instance type and blocks (#104)
- CostGuard prices gp2 at $0.10 and gp3 at $0.08 per GB-month (us-east-1 list price); st1 and sc1 now use their list prices too. `standard` (magnetic) volumes are no longer priced and fail closed, because their per-I/O-request charge cannot be known before deployment (#102)
- CostGuard compares the exact total with the exact budget, so a sub-cent overrun is no longer certified. The published total is rounded up to the cent and the budget down; the exact figures are kept in the new `exact_total_monthly_cost` and `exact_budget` fields, which `to_diagnostic` re-checks and records, with `pricing_region` and `pricing_catalogue_sha256` (a content hash of the price tables), in the developer fields and proof evidence of a VERIFIED diagnostic (#75, #102)
- CostGuard multiplies volume cost by `count` and fails closed on provisioned IOPS or throughput it cannot price (gp3 above its 3000 IOPS / 125 MiB/s baseline, or on any other volume type) (#92)
- TerraformParser records every declaration it does not model in a new `unmodelled` list on the model instead of dropping it; CostGuard blocks while that list is non-empty. Unmodelled resources that may grant access (`aws_iam_*` types, and any type, attribute or block whose name contains `polic`, `principal`, `permission`, `grant` or `authoriz`, or has `acl` or `roles` as a word; `tags` maps are not searched) raise `ParseError` (#74)
- TerraformParser fails closed on a missing directory, a directory with no `.tf` files, `.tf.json` files and module calls; `for_each` and `dynamic` on instances and volumes are recorded as unmodelled; `aws_ebs_volume` without `size` is no longer defaulted to 10 GB (#75)
- TerraformParser carries `count`, `iops` and `throughput` on `aws_ebs_volume`, and models `root_block_device` and `ebs_block_device` on `aws_instance` as volumes; an instance without `root_block_device` records its implicit root volume as unmodelled, because its size comes from the AMI (#92)
- TerraformParser fails closed on Terraform override files (`override.tf`, `*_override.tf`) instead of reading them as independent files (#93)
- TerraformParser reads `.tf` files as UTF-8 on every platform (#96)
- TerraformParser rejects HCL template directives (`%{...}`) in policy documents, and checks keys as well as values for directives and unresolved interpolation (#73)
- IamGuard returns UNVERIFIABLE for statements that use `NotAction`, `NotResource` or `NotPrincipal`, or a `Principal` other than `*`, or that have no `Action` or `Resource`, instead of modelling them as matching nothing; a policy without `Statement` is UNVERIFIABLE, and a single-object `Statement` is accepted. TerraformParser also refuses `NotAction`, `NotResource` and `NotPrincipal` (#67)
- IamGuard refuses policies over fixed size bounds (statements, entries, entry length, wildcards, condition entries and values, request length, request context size) as UNVERIFIABLE, builds the policy logic over the concrete request values and as flat expressions, and treats a Z3 `unknown` as UNVERIFIABLE instead of a proven denial (#76)
- IamGuard records only the exception type for unexpected errors, so no traceback or host path reaches diagnostics or VC evidence (#87)
- NetworkGuard models an explicit set of keys and route targets and returns UNVERIFIABLE for anything else, instead of refusing only a list of known spellings (#81)
- NetworkGuard returns UNVERIFIABLE for ingress rules with unmodelled fields (`protocol`, `ip_protocol`, `prefix_list_id`, `source_security_group_id`, `description` and others), a one-sided `-1` port sentinel, ports that are not ASCII integers in range, a queried port that is not an int in range, duplicate subnet ids, more than one route table for a subnet, a route table without a subnet, a rule mixing `port` with a range, a reversed range, a rule without a valid `cidr`, and a subnet naming an undeclared security group; an IPv4 route no longer pairs with an IPv6-only rule (#82)
- NetworkGuard no longer raises `OverflowError` for an infinite port; it fails closed (#88)
- NetworkGuard treats split ranges whose union covers `0.0.0.0/0` or `::/0` (for example `0.0.0.0/1` plus `128.0.0.0/1`) as the internet, for both security group rules and routes (#94)
- `publish.yml` publishes only for a `v...` release tag that matches the `pyproject.toml` version, runs the boundary check and the test suite before building, installs the build toolchain and the build backend from a hash-pinned requirements file and builds with `--no-isolation`, and no longer passes `skip-existing` (#84)
- `scripts/check_boundary.py` scans `.pyw` files as well as `.py` (case-insensitive), and applies its excluded directories relative to the scan root (#97)
- The committed `qwed_infra/__pycache__/__init__.cpython-311.pyc` is no longer tracked (#98)
- `snyk.yml` pins the snyk CLI version, fails instead of falling back when the dev extras do not install, and grants `security-events: write` per job instead of workflow-wide (#99)

### Changed
- IamGuard audit traces label every condition evaluation `"evaluated_in": "python"`; `StringEquals` and `StringLike` were labelled `"z3"`
- The parsed model has a new `unmodelled` key (a list of `{"address", "reason"}` entries); `TerraformParser._normalize_resource` returns an `unmodelled` entry instead of `None` for types it does not model
- `CostGuard.PRICING_CATALOG` is replaced by `INSTANCE_PRICING` (USD per instance-hour) and `VOLUME_PRICING` (USD per GB-month, keyed by volume type)

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
