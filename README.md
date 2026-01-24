# qwed-infra

**Deterministic Verification for Infrastructure as Code (IaC)**

`qwed-infra` is a Python library that uses **Formal Methods (Z3 Solver)** and **Graph Theory** to mathematically prove the security and compliance of detailed infrastructure definitions (Terraform, AWS IAM, Kubernetes).

It is part of the [QWED Ecosystem](https://github.com/QWED-AI).

## 🚀 Features

### 1. 🛡️ IamGuard (Implemented)
Verifies AWS IAM Policies using the **Z3 Theorem Prover**.
Instead of regex matching, it converts policies into logical formulas to prove reachability.

- **Wildcard Support:** Handles `s3:*`, `arn:aws:s3:::bucket/*` correctly.
- **Deny Overrides:** Proves that explicit Deny statements always override Allows.
- **Least Privilege:** Mathematically proves if a policy allows stronger permissions than intended.

### 2. 🌐 NetworkGuard (Planned)
Verifies Network Reachability using Graph Theory.
- "Can the Public Internet reach the Database Subnet on Port 5432?" -> **False** (Proven by Graph Traversal).

### 3. 💰 CostGuard (Planned)
Deterministic Cloud Cost estimation before deployment.
- Prevents AI Agents from provisioning expensive instances (e.g., `p4d.24xlarge`) without approval.

## 📦 Installation

```bash
pip install qwed-infra
```

## ⚡ Usage

### Verifying IAM Policies

```python
from qwed_infra import IamGuard

guard = IamGuard()

# A risky policy?
policy = {
    "Version": "2012-10-17",
    "Statement": [
        {"Effect": "Allow", "Action": "s3:*", "Resource": "arn:aws:s3:::prod-data/*"},
        {"Effect": "Deny",  "Action": "s3:DeleteBucket", "Resource": "*"}
    ]
}

# 1. Check specific access
result = guard.verify_access(
    policy, 
    action="s3:GetObject", 
    resource="arn:aws:s3:::prod-data/financials.csv"
)
print(f"Can access? {result.allowed}") # -> True

# 2. Check forbidden action (overridden by Deny)
result = guard.verify_access(
    policy, 
    action="s3:DeleteBucket", 
    resource="arn:aws:s3:::prod-data"
)
print(f"Can delete bucket? {result.allowed}") # -> False (Correctly Denied)

# 3. Verify Least Privilege (Admin check)
result = guard.verify_least_privilege(policy)
print(f"Is Admin? {result.allowed}") # -> False (Safe)
```

## 🏗️ Architecture

```mermaid
graph TD
    A[Terraform/JSON] -->|Parse| B(QWED-Infra)
    B -->|Logic| C[Z3 Solver]
    C -->|SAT/UNSAT| D[Verification Result]
```

## 🤝 Contributing

We welcome contributions! Please see `CONTRIBUTING.md`.

## 📄 License

Apache 2.0
