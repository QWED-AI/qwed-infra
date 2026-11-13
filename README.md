<div align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/qwed-lockup-white.svg">
    <img src="assets/qwed-lockup.svg" alt="QWED" height="56">
  </picture>

# ☁️ QWED-Infra
**Deterministic Verification for Infrastructure as Code (IaC)**

> "Don't let AI hallucinate your cloud bill to $20,000."

[![Verified by QWED](https://img.shields.io/badge/Verified_by-QWED-00C853?style=flat&logo=checkmarx)](https://github.com/QWED-AI/qwed-infra)
[![Verification Context](https://img.shields.io/badge/VC-v1.0-6C3FC5?style=flat&logo=docusign)](https://github.com/QWED-AI/qwed-infra#verification-context-v10)
[![PyPI](https://img.shields.io/pypi/v/qwed-infra?color=blue&logo=pypi&logoColor=white)](https://pypi.org/project/qwed-infra/)
[![License](https://img.shields.io/badge/License-Apache%202.0-green.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![GitHub stars](https://img.shields.io/github/stars/QWED-AI/qwed-infra?style=social)](https://github.com/QWED-AI/qwed-infra)
[![GitHub Developer Program](https://img.shields.io/badge/GitHub_Developer_Program-Member-4183C4?style=flat&logo=github&logoColor=white)](https://github.com/developer-program)

<a href="https://github.com/sponsors/QWED-AI"><img src="https://img.shields.io/github/sponsors/QWED-AI?style=for-the-badge&logo=githubsponsors&label=Sponsor&color=EA4AAA" alt="Sponsor QWED on GitHub"></a>

[![Twitter](https://img.shields.io/badge/Twitter-@rahuldass29-1DA1F2?style=flat&logo=twitter&logoColor=white)](https://x.com/rahuldass29)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-Rahul%20Dass-0077B5?style=flat&logo=linkedin&logoColor=white)](https://www.linkedin.com/in/rahul-dass-23b370b0/)

</div>

---

## 🚨 The Problem
AI agents like **Devin**, **GitHub Copilot Workspace**, and **Cursor** are writing Terraform and Kubernetes configs. 
**But AI doesn't understand consequences.**

| Case | What AI Wrote | Real World Impact |
| :--- | :--- | :--- |
| **IAM Permission** | `Action: "s3:*", Resource: "*"` | **Data Breach:** Entire bucket exposed to public. |
| **Network Rule** | `Ingress: 0.0.0.0/0, Port: 22` | **Ransomware:** SSH open to the whole internet. |
| **Instance Type** | `instance_type = "p4d.24xlarge"` | **Bankrupt:** **$23,000/month** bill for a dev env. |

---

## 💡 What QWED-Infra Is (and Isn't)

### ✅ QWED-Infra IS:
*   **A Deterministic Verification Engine:** Uses the **Z3 Theorem Prover** to combine IAM statements under Deny precedence. Wildcard matching and conditions on the concrete request are decided deterministically in Python and enter the proof as constants.
*   **A Graph Analyzer:** Uses **NetworkX** to map and verify network reachability (Reachability Analysis).
*   **An Artifact Boundary Gate:** Scans release packages for secrets, debug artifacts, and misconfigured build paths — blocks unsafe releases before they ship.
*   **Deterministic:** Inputs are code; the same input always gives the same verdict: `VERIFIED`, `BLOCKED` or `UNVERIFIABLE`, never a guess.
*   **A "Guard" Layer:** Plugs into CI/CD to block AI-generated PRs that violate rules.

### ❌ QWED-Infra is NOT:
*   **A Linter:** We don't just check syntax (like TFLint). We check *logic*.
*   **A Cost Explorer:** We predict costs *before* deployment, not after you get the bill.
*   **Black Box AI:** We don't use LLMs to verify LLMs. We use Math.

---

## 🆚 How We're Different

| Feature | TFLint / Checkov / TFSec | QWED-Infra |
| :--- | :--- | :--- |
| **Approach** | Regex / Static Pattern Matching | **Symbolic Execution (Z3) & Graph Theory** |
| **IAM Logic** | Can catch `s3:*` text match | Decides each statement on the request and proves `Deny` overrides `Allow` |
| **Network** | Checks generic "port 22 open" | Traces `Internet -> IGW -> Route -> SG -> Subnet` (fail-closed on NAT/NACL/peering) |
| **Cost** | N/A (usually distinct tools) | **Deterministic Pre-Deployment Estimation** |
| **Accuracy** | High False Positives | **Deterministic Correctness** |

---

## 🛡️ The Four Guards

### 1. IamGuard (The Security Math)
Decides whether an AWS IAM policy allows a concrete request.
*   **Wildcards:** Handles `s3:Get*` vs `s3:GetObject`: actions match case-insensitively (ASCII case folding; non-ASCII is UNVERIFIABLE), `*` matches any run of characters and `?` exactly one (in a resource ARN, within one colon-separated segment unless the `*` ends the last segment), and policy variables such as `${aws:username}` are substituted under `"Version": "2012-10-17"`. Decided deterministically in Python.
*   **Logic:** `Deny` statements always win: each statement is decided on the concrete request, and Z3 combines the outcomes under Deny precedence.
*   **Context:** Verifies against specific conditions (e.g., `aws:SourceIp`, `aws:CurrentTime`), with full trace in diagnostic output. Supported operators: the `String*`, `Arn*`, `Numeric*`, `Date*` and `IpAddress` families, `Bool`, `Null`, and the `...IfExists` forms; condition key names match case-insensitively, and an absent key follows AWS (true for negated and `...IfExists` operators). Numbers, dates and booleans are parsed strictly. A condition the guard cannot evaluate (an unsupported operator such as `ForAnyValue:`, a malformed value, a multi-valued request key, an unresolved policy variable) makes the result `UNVERIFIABLE` whenever the decision depends on it, for Allow and Deny alike.
*   **Least privilege:** `verify_least_privilege` judges full access (`*` on `*`) from the patterns: an Allow made only of `*`, `?` and `:` counts whatever its condition, a Deny counts only when it is unconditional and names every action and resource with `*`, and an Allow whose coverage cannot be told (such as `a*`) makes the result UNVERIFIABLE.
*   **Limitations (fail-closed):** `NotAction`, `NotResource`, `NotPrincipal`, a `Principal` other than `*`, set operators (`ForAnyValue:`, `ForAllValues:`), policy variable defaults, a policy variable before the fifth colon of a resource ARN and a wildcard in its service segment return `UNVERIFIABLE`. `verify_least_privilege` detects only a grant of every action on every resource: `iam:*`, enumerated services and privilege-escalation paths are not flagged. A guard may be shared between threads; solver calls are serialised.

### 2. NetworkGuard (The Topology Graph)
Builds a directed graph of your VPC.
*   **Reachability:** "Can an attacker on the Internet reach my Database?"
*   **Path Analysis:** Traces routes through Subnets and Security Groups.
*   **Limitations (fail-closed):** the guard models subnets (`id`, `security_groups`), route tables (`subnet_id`, `routes` to `igw...` or `local`) and security groups (`ingress` rules with `port` or `from_port`/`to_port` and `cidr`). Anything else, such as NAT gateways, VPC peering, NACLs, transit gateways, endpoints, protocol-scoped rules, prefix lists or security-group references, under any key name, returns `UNVERIFIABLE`: the result carries no proof and must not be used for authorization decisions. The check is inbound only: security groups are stateful, so `egress` entries are accepted but not read or validated, and a verdict says nothing about egress. "Reachable from the internet" means the whole internet: the routes and the matching rules must each cover `0.0.0.0/0` or `::/0` in the same address family, alone or as a union of split ranges.

### 3. CostGuard (The Budget Enforcer)
Prevents financial ruin.
*   **Static Catalog:** Embedded prices for standard AWS resources.
*   **Budget Checks:** `if estimated_cost > $500: Block Deployment`.

### 4. ArtifactBoundaryGuard (The Release Gate)
Verifies release artifacts before they ship.
*   **Secret Scanning:** Detects leaked secrets (`.env`, `*.token`, API keys) in package files.
*   **Debug Artifact Detection:** Blocks `.coverage`, `.pytest_cache`, `__pycache__` from entering packages.
*   **Build Config Verification:** Ensures `pyproject.toml` hatch build config only includes intended paths. It also checks the other hatchling inputs we know can change what the wheel ships or run project code at build time, and refuses what it does not model: a `hatch.toml` or root `PKG-INFO` file, `[build-system]` `backend-path` and any build requirement other than `hatchling` with public version specifiers and an optional marker, `[tool.hatch.build]` and sdist options that add files, build and metadata hooks, version sources other than `regex`, `[project] dynamic` fields other than `version`, context formatting (`{env:...}`) in dependency strings, `[project]` readme files that are not plain `README*` files in the project root and license files that are not plain `LICENSE*` / `LICENCE*` / `COPYING*` / `NOTICE*` / `AUTHORS*` files there (symlinks and sensitive names are refused), and root-level modules, namespace directories or programs named like standard library, build tool or interpreter names (`pip.py`, `argparse.py`, `org/`, `python.bat`). That list is of known names only, so the verdict assumes the build does not import from the project root: run `python -m build` with `PYTHONSAFEPATH=1` (or from outside the root) and an absolute interpreter path. File checks are by name; the content of README, LICENSE and version files is not inspected. The modelled behaviour is hatchling 1.27 and 1.28.
*   **Scope:** the verdict covers the wheel. The sdist that `python -m build` also writes contains every root file not ignored by version control and is not checked, so publish only the wheel or check the sdist separately.
*   **Fail-Closed:** Unknown backends, missing configs, or unparseable files produce `BLOCKED`, never a silent pass.

---

## 📦 Installation

```bash
pip install qwed-infra
```
*(Node.js/npm SDK coming soon)*

---

## ⚡ Usage Examples

### Verify IAM Policies
```python
from qwed_infra import IamGuard

guard = IamGuard()
policy = {
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Action": "s3:GetObject",
        "Resource": "*",
        "Condition": {"IpAddress": {"aws:SourceIp": "192.168.1.0/24"}},
    }],
}

# Verify: Is it accessible from the public internet?
result = guard.verify_access(
    policy, 
    action="s3:GetObject", 
    resource="my-bucket", 
    context={"aws:SourceIp": "8.8.8.8"} # Public IP
)

print(result.allowed) # -> False (Blocked by IP)
```

### Verify Network Reachability
```python
from qwed_infra import NetworkGuard

net = NetworkGuard()
infra = {
    "subnets": [
        {"id": "subnet-web", "security_groups": ["sg-web"]},
    ],
    "route_tables": [
        {
            "subnet_id": "subnet-web",
            "routes": {"0.0.0.0/0": "igw-main"},
        }
    ],
    "security_groups": {
        "sg-web": {"ingress": [{"port": 80, "cidr": "0.0.0.0/0"}]},
    },
}

# Is the web subnet reachable from Internet on port 80?
result = net.verify_reachability(infra, "internet", "subnet-web", port=80)
print(result.reachable)  # -> True (Risk Alert!)

# Convert to structured diagnostic for CI/CD enforcement
diagnostic = NetworkGuard.to_diagnostic(result)
print(diagnostic.status.value)  # -> VERIFIED / BLOCKED / UNVERIFIABLE
```

### Enforce Budget
```python
from qwed_infra import CostGuard

cost = CostGuard()
resources = {
    "instances": [
        {"id": "gpu", "instance_type": "p4d.24xlarge", "count": 2}
    ]
}

result = cost.verify_budget(resources, budget_monthly=1000)
print(result.within_budget) # -> False
print(result.reason) # -> "Estimated cost $47844.20 EXCEEDS budget $1000.00"
```

### Verify Package Boundary
```python
from qwed_infra import ArtifactBoundaryGuard

guard = ArtifactBoundaryGuard()
result = guard.verify_package_boundary(package_dir="qwed_infra")

# Convert to structured diagnostic for CI/CD enforcement
diagnostic = ArtifactBoundaryGuard.to_diagnostic(result)

if diagnostic.status.value == "BLOCKED":
    for finding in diagnostic.developer_fields["findings"]:
        print(f"❌ {finding['finding_type']}: {finding['reason']}")
else:
    print("✅ Package boundary verified — safe to ship.")
```

---

## 🔏 Verification Context v1.0

Every guard can emit a **Verification Context (VC) document** — a portable, machine-checkable trust artifact that records *what was verified, by whom, with what proof*, and *whether a downstream system should admit or deny*.

### Why VC?

A `True/False` return value is enough for one process — but CI/CD pipelines, release gates, and audit trails need **evidence that travels**:

| Plain result | Verification Context |
| :--- | :--- |
| `result.allowed == False` | Document: claim, verifier identity+version, hash-linked evidence (`proof_ref`), admission decision |
| Lives only in your process log | JSON-serializable, schema-validated, evidence-bound (`sha256` proof_ref computed over the exact evidence) |
| No story when someone asks "who verified this?" | `proof.verifier`, `audit_trace`, and rule IDs answer it |

The document is **fail-closed by construction**: anything that is not proven is `DENY` — `UNVERIFIABLE` and `BLOCKED` outcomes can never produce `ADMIT`. Attestations are **cryptographically validated** (ES256 signature, issuer, expiry, revocation) and bound to the exact claim and evidence (`query_hash`, `proof_hash`) — a token minted for one statement can never admit another.

### Usage

Each guard runs its own verification internally and returns a VC document. You pass raw inputs — never a pre-computed result object:

```python
from qwed_infra import NetworkGuard
from qwed_infra.attestation import mint_diagnostic_attestation

net = NetworkGuard()
infra = {
    "subnets": [{"id": "subnet-web", "security_groups": ["sg-web"]}],
    "route_tables": [
        {"subnet_id": "subnet-web", "routes": {"0.0.0.0/0": "igw-main"}},
    ],
    "security_groups": {
        "sg-web": {"ingress": [{"port": 80, "cidr": "0.0.0.0/0"}]},
    },
}

statement = "Traffic from internet to subnet-web on port 80 is safe"

# Mint an attestation bound to THIS claim + evidence (the guard computes the
# same check internally; the token's proof_hash must match its commitment).
diagnostic = NetworkGuard.to_diagnostic(
    net.verify_reachability(infra, "internet", "subnet-web", 80)
)
attestation = mint_diagnostic_attestation(
    diagnostic, engine="NetworkGuard", query=statement
)
if not attestation.is_issued:
    # fail-closed contract: never proceed on an unissued attestation
    raise RuntimeError(f"Attestation unavailable [{attestation.error_code}]")

doc = net.to_verification_context(
    infra,                       # raw topology — the guard verifies this itself
    "internet",
    "subnet-web",
    80,
    formal_statement=statement,
    # optional; without it VERIFIED degrades to UNVERIFIABLE/DENY.
    # A forged, expired, revoked, or non-matching token BLOCKS.
    attestation_token=attestation.token,
)

print(doc.verdict.value)          # -> VERIFIED / BLOCKED / UNVERIFIABLE
print(doc.context.decision.admission.value)  # -> ADMIT / DENY
```

The same pattern holds for every guard (`formal_statement` is keyword-only and required).
Schematic — define `policy`/`resources` etc. as in the guard examples above:

```python
IamGuard().to_verification_context(policy, action, resource, context,
                                   formal_statement="IAM policy is safe to apply")
CostGuard().to_verification_context(resources, budget_monthly,
                                    formal_statement="Estimated cost is within budget")
ArtifactBoundaryGuard().to_verification_context(package_dir="mypkg", pyproject_path="pyproject.toml",
                                                formal_statement="Package boundary is safe to publish")
```

### Using VC documents downstream

```python
from qwed_infra.verification_context import is_valid_document, resolve_document_proof_ref

document = doc.to_dict()   # JSON-serializable dict

if not is_valid_document(document):
    raise ValueError("Invalid VC document — reject")   # schema/verdict inconsistency

admission = document["context"]["decision"]["admission"]   # ADMIT or DENY

if admission == "ADMIT":
    # VERIFIED documents carry a proof_ref bound to the exact evidence;
    # require that it resolves before trusting the decision.
    if not resolve_document_proof_ref(document):
        raise ValueError("VC document proof_ref does not resolve — reject")
    # ... proceed with the gated operation ...
else:
    # DENY: fail closed. BLOCKED/UNVERIFIABLE documents do not require
    # context.evidence.proof_ref (diagnostic proof hashes are separate).
    raise PermissionError(f"Verification denied ({document['verdict']}) — reject")
```

Store or forward `document` anywhere JSON goes — release gates, pipeline artifacts, audit logs. The `proof_ref` binds a VERIFIED decision to the exact evidence that produced it. VC evidence can contain sensitive infrastructure, policy, or cost data — apply your own access control, redaction, and retention rules when storing or forwarding documents downstream.

> **Attestation trust model:** attestations are self-signed by the guard process (ES256, ephemeral key) and cryptographically validated at the admission boundary — signature, issuer, expiry, revocation, plus binding to the exact claim and evidence. This is the interim stage on the path to an external witness/transparency log (ADR-005 in qwed-verification); multi-replica deployments require shared signing keys until replica-key resolution exists.

---

## ❓ FAQ

**Q: Do I need Terraform installed?**
A: No. `qwed-infra` parses `.tf` files as text using a custom HCL parser (or operates on JSON plans).

**Q: Can it verify Kubernetes?**
A: Currently focuses on AWS Terraform. K8s Manifest verification is on the roadmap (Phase 19).

**Q: Why standard pricing?**
A: We use public On-Demand pricing for "Worst Case" estimation. If you have Enterprise Discounts, `qwed-infra` ensures you remain safe even at list price.

---

## 🗺️ Roadmap

*   ✅ **v0.1.0:** IAM Z3 Logic, Basic Network Graph, Static Cost Catalog. (Released Jan 2025)
*   ✅ **v0.2.0:** Fail-closed parser + IAM, NetworkGuard CIDR fix, CI fail-open removal, diagnostic port (audit.py/InfraDiagnosticResult), CostGuard Decimal/unknown types, ArtifactBoundaryGuard.
*   ✅ **v0.3.0:** Verification Context v1.0 across all four guards (bridge, `to_verification_context()` adapters, conformance suite) + attestation trust boundary — ES256-signed receipts bound to the exact claim and evidence gate every ADMIT.
*   ✅ **v0.4.0:** Fail-closed hardening across the guards: IamGuard follows AWS matching and condition semantics (three-outcome conditions, least privilege judged from patterns), NetworkGuard models an explicit topology, CostGuard prices exactly and records every unmodelled declaration, ArtifactBoundaryGuard checks every hatchling input it knows can change the wheel, and the publish workflow builds from hash-pinned tools. (Current)
*   🔮 Next: Docker/deployment artifact verification, K8s manifest support, Azure provider.

---

## 🌐 QWED Ecosystem

| Package | Description | Repo |
|---------|-------------|------|
| **qwed** ☑️ | Core deterministic AI verification (Math, Logic, Code) | [GitHub](https://github.com/QWED-AI/qwed-verification) |
| **qwed-infra** ☁️ | IaC verification (Terraform, IAM, Network, Cost, Artifact) ← **you are here** | [GitHub](https://github.com/QWED-AI/qwed-infra) |
| **qwed-finance** 🏦 | Financial computation verification | [GitHub](https://github.com/QWED-AI/qwed-finance) |
| **qwed-legal** 🏛️ | Legal document verification | [GitHub](https://github.com/QWED-AI/qwed-legal) |
| **qwed-tax** 💸 | Tax calculation verification | [GitHub](https://github.com/QWED-AI/qwed-tax) |
| **qwed-mcp** 🔌 | Model Context Protocol verification | [GitHub](https://github.com/QWED-AI/qwed-mcp) |
| **qwed-a2a** 🔄 | Agent-to-Agent verification protocol | [GitHub](https://github.com/QWED-AI/qwed-a2a) |
| **qwed-ucp** 🛒 | Unified Context Protocol | [GitHub](https://github.com/QWED-AI/qwed-ucp) |
| **open-responses** 🤖 | Guards for OpenAI/LangChain agent outputs | [GitHub](https://github.com/QWED-AI/qwed-open-responses) |
| **qwed-learning** 📚 | Educational content verification | [GitHub](https://github.com/QWED-AI/qwed-learning) |

---

## 🛡️ What Does "Verified by QWED" Mean?

When you see the **Verified by QWED** badge on a repository, it is a technical guarantee that:

1. **Deterministic Verification:** The software uses symbolic solvers (Z3, graph theory) — not AI confidence scores — to prove correctness.
2. **Fail-Closed Architecture:** If the infrastructure cannot be fully parsed or verified, it is **blocked**, not silently passed.
3. **No Silent Degradation:** Every guard produces a structured diagnostic with clear status (`VERIFIED`, `BLOCKED`, `UNVERIFIABLE`). Partial verification is never presented as proof.

> **The badge means: "We don't trust the AI. We trust the Math."**

---

## ⭐ Star History

[![Star History Chart](https://api.star-history.com/svg?repos=QWED-AI/qwed-infra&type=Date)](https://star-history.com/#QWED-AI/qwed-infra&Date)

---

## 📄 Citation

If you use qwed-infra in your research or project:

```bibtex
@software{dass2026qwedinfra,
  author = {Dass, Rahul},
  title = {QWED-Infra: Deterministic Verification for Infrastructure as Code},
  year = {2026},
  publisher = {GitHub},
  url = {https://github.com/QWED-AI/qwed-infra}
}
```

---

## 👥 Contributors

<a href="https://github.com/rahuldass19">
  <img src="https://github.com/rahuldass19.png?size=96" width="48px;" alt="Rahul Dass" />
</a>

Thanks to everyone building QWED. [See all contributors →](https://github.com/QWED-AI/qwed-infra/graphs/contributors)

---

## 🙏 Contributors Wanted

[![Good First Issues](https://img.shields.io/github/issues/QWED-AI/qwed-infra/good%20first%20issue?label=good%20first%20issues&color=7057ff)](https://github.com/QWED-AI/qwed-infra/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22)

| Area | What We Need |
|------|-------------|
| 🧪 **Testing** | Edge cases for guards (NetworkGuard, ArtifactBoundaryGuard) |
| 🐛 **Bugs** | Fix issues or report new ones |
| 📝 **Docs** | Improve examples and tutorials |
| 🔧 **SDKs** | Terraform plan JSON integration |

**[→ Read CONTRIBUTING.md](CONTRIBUTING.md)**

---

## 📄 License

Apache 2.0 - Open Source.

<div align="center">
  <b>Safe Infrastructure is Scalable Infrastructure.</b><br>
  Built by <a href="https://github.com/QWED-AI">QWED-AI</a>
</div>
