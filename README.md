<div align="center">

# ☁️ QWED-Infra
**Deterministic Verification for Infrastructure as Code (IaC)**

> "Don't let AI hallucinate your cloud bill to $20,000."

[![Verified by QWED](https://img.shields.io/badge/Verified_by-QWED-00C853?style=flat&logo=checkmarx)](https://github.com/QWED-AI/qwed-infra)
[![PyPI](https://img.shields.io/pypi/v/qwed-infra?color=blue&logo=pypi&logoColor=white)](https://pypi.org/project/qwed-infra/)
[![License](https://img.shields.io/badge/License-Apache%202.0-green.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)

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
*   **A Mathematical Proof Engine:** Uses **Z3 Theorem Prover** to *prove* your IAM policies are secure.
*   **A Graph Analyzer:** Uses **NetworkX** to map and verify network reachability (Reachability Analysis).
*   **Deterministic:** Inputs are code, output is `True/False` with 100% certainty.
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
| **IAM Logic** | Can catch `s3:*` text match | Proves `Allow` overrides `Deny` logically |
| **Network** | Checks generic "port 22 open" | Traces `Internet -> IGW -> Route -> SG -> VM` |
| **Cost** | N/A (usually distinct tools) | **Deterministic Pre-Deployment Estimation** |
| **Accuracy** | High False Positives | **Mathematically Proven Correctness** |

---

## 🛡️ The Three Guards

### 1. IamGuard (The Security Math)
Converts AWS IAM Policies into logical formulas.
*   **Wildcards:** Handles `s3:Get*` vs `s3:GetObject`.
*   **Logic:** Proves `Deny` statements always win.
*   **Context:** Verifies against specific conditions (e.g., `aws:SourceIp`).

### 2. NetworkGuard (The Topology Graph)
Builds a directed graph of your VPC.
*   **Reachability:** "Can an attacker on the Internet reach my Database?"
*   **Path Analysis:** Traces routes through Subnets, NACLs, and Security Groups.

### 3. CostGuard (The Budget Enforcer)
Prevents financial ruin.
*   **Static Catalog:** Embedded prices for standard AWS resources.
*   **Budget Checks:** `if estimated_cost > $500: Block Deployment`.

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
    "Effect": "Allow",
    "Action": "s3:GetObject",
    "Resource": "*",
    "Condition": {"IpAddress": {"aws:SourceIp": "192.168.1.0/24"}}
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
    "subnets": [{"id": "public", "routes": "igw"}],
    "instances": [{"id": "web", "subnet": "public", "sg": "open-sg"}]
}

# Is the instance reachable from Internet?
print(net.verify_reachability(infra, "internet", "web")) 
# -> True (Risk Alert!)
```

### Enforce Budget
```python
from qwed_infra import CostGuard

cost = CostGuard()
resources = [{"type": "p4d.24xlarge", "count": 2}] # Expensive!

result = cost.verify_budget(resources, budget_monthly=1000)
print(result.within_budget) # -> False
print(result.reason) # -> "Est. $46,000 > Budget $1,000"
```

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

*   ✅ **v0.1.0:** IAM Z3 Logic, Basic Network Graph, Static Cost Catalog. (Released)
*   🚧 **v0.2.0:** K8s Manifest Verification, Azure Support.
*   🔮 **v1.0.0:** VS Code Extension & GitHub App Auto-Commenter.

---

## 🌐 QWED Ecosystem

| Package | What it does |
|---------|-------------|
| **[qwed-verification](https://github.com/QWED-AI/qwed-verification)** | Core deterministic AI verification (Math, Logic, Code) |
| **[qwed-open-responses](https://github.com/QWED-AI/qwed-open-responses)** | Guards for OpenAI/LangChain agent outputs |
| **[qwed-infra](https://github.com/QWED-AI/qwed-infra)** ← you are here | IaC verification (Terraform/IAM/Network/Cost) |
| **[qwed-a2a](https://github.com/QWED-AI/qwed-a2a)** | Agent-to-Agent verification protocol |
| **[qwed-mcp](https://github.com/QWED-AI/qwed-mcp)** | Model Context Protocol verification |
| **[qwed-ucp](https://github.com/QWED-AI/qwed-ucp)** | Unified Context Protocol |
| **[qwed-finance](https://github.com/QWED-AI/qwed-finance)** | Financial computation verification |
| **[qwed-tax](https://github.com/QWED-AI/qwed-tax)** | Tax calculation verification |
| **[qwed-legal](https://github.com/QWED-AI/qwed-legal)** | Legal document verification |
| **[qwed-learning](https://github.com/QWED-AI/qwed-learning)** | Educational content verification |

---

## 📄 License
Apache 2.0 - Open Source.

<div align="center">
  <b>Safe Infrastructure is Scalable Infrastructure.</b><br>
  Built by <a href="https://github.com/QWED-AI">QWED-AI</a>
</div>
