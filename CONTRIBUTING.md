# Contributing to QWED-Infra

> **QWED-Infra** = Deterministic Verification for Infrastructure as Code (IaC)

Thank you for your interest in contributing! Before you start, please read this guide to understand QWED's philosophy and avoid common misunderstandings.

---

## Required Reading (Before Contributing)

| File | Why It Matters |
|------|----------------|
| [README.md](./README.md) | Understand what QWED-Infra is |
| [QWED_RULES.md](./QWED_RULES.md) | Canonical enforcement rules for contributors and tools |

---

## Understanding QWED's Philosophy

### The Core Principle: Deterministic First

QWED-Infra is NOT a linter, a static analysis tool, or a best-practice checker.

1. **IAM policies are logical formulas** - Z3 SMT solver proves whether access is allowed or denied
2. **Network topologies are graphs** - NetworkX traverses routes, Security Groups are firewall rules
3. **Costs are arithmetic** - Pricing catalog + instance count = deterministic estimate
4. **LLM output is never proof** - No model fallback for verification decisions

### Approved Paths

Sensitive operations must go through approved wrappers:

| Dangerous Operation | Approved Path |
|---------------------|---------------|
| `eval()` / `exec()` | Not needed — use Z3/NetworkX/arithmetic directly |
| `os.system()` / `subprocess.Popen()` | Blocked — use native Python SDK |
| `hcl2.load()` | Approved parser path for Terraform files |

### Common Misunderstandings

| Wrong Approach | Correct Approach |
|----------------|------------------|
| "Let the LLM review the IAM policy" | Use Z3 to prove allow/deny |
| "Check port 22 in the SG string" | Use graph reachability analysis |
| "Regex for wildcard IAM actions" | Use Z3 pattern matching with `InRe` |
| "Skip cost check for unknown instance types" | Fail closed — unknown = blocked |

---

## Development Setup

```bash
# Clone the repo
git clone https://github.com/QWED-AI/qwed-infra.git
cd qwed-infra

# Create virtual environment
python -m venv venv
source venv/bin/activate  # or .\venv\Scripts\activate on Windows

# Install in development mode
pip install -e ".[dev]"

# Run tests
pytest tests/ -v
```

---

## How to Contribute

### 1. Reporting Bugs

Open an issue with:
- Python version
- Input that caused the bug
- Expected vs actual result
- Which guard is affected (IAM, Network, Cost, Parser)

### 2. Proposing Features

Before coding, open an issue to discuss:
- What problem does it solve?
- Does it require LLM or is it deterministic?
- Which guard does it affect?

### 3. Submitting Pull Requests

```bash
# 1. Fork and clone
git clone https://github.com/YOUR_USERNAME/qwed-infra.git

# 2. Create a branch
git checkout -b feat/your-feature

# 3. Make changes

# 4. Run tests
pytest tests/ -v

# 5. Commit with conventional commits
git commit -m "feat(guard): add S3 bucket policy verification"

# 6. Push and create PR
git push origin feat/your-feature
```

### Commit Message Format

```text
type(scope): description

feat(iam): add condition key wildcard matching
fix(network): handle NAT gateway routes
test(cost): add edge case for zero instances
docs: update architecture diagram
```

---

## Repository Structure

```text
qwed-infra/
├── qwed_infra/
│   ├── guards/
│   │   ├── iam_guard.py       # Z3-based IAM policy verification
│   │   ├── network_guard.py   # NetworkX-based reachability analysis
│   │   └── cost_guard.py      # Deterministic cost estimation
│   └── parsers/
│       └── terraform_parser.py # HCL2 Terraform file parser
├── tests/                     # Unit tests
├── demo/                      # Usage demo
└── docs/                      # Documentation
```

---

## License

By contributing, you agree that your contributions will be licensed under the [Apache 2.0 License](./LICENSE).
