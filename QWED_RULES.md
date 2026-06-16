# QWED Ecosystem Enforcement Rules

QWED is not an AI model. QWED is not an agent framework.
QWED is not a trust scoring system. QWED is not an orchestration platform.

QWED is a **deterministic verification and enforcement ecosystem**.

Its purpose is to create verifiable boundaries around AI systems, tools, agents,
workflows, and machine-generated outputs. The goal is not to make AI smarter.
The goal is to make AI behavior more governable, auditable, predictable, and
enforceable.

These rules are non-negotiable for contributors, reviewers, and automation
tools operating on this repository.

---

## Priority Order

1. Determinism
2. Safety
3. Control
4. Accountability
5. Convenience

Convenience must never override verification.

---

## Principle 1 — Verification Before Execution

Verification is the primary operation. Execution happens only after verification
succeeds.

**Allowed:**
```
Input → Verify → Execute
```

**Forbidden:**
```
Input → Execute → Verify later
```

## Principle 2 — Fail Closed

When verification cannot prove correctness: **BLOCK**.

Not: retry, guess, trust, approximate, or continue anyway.

Unverifiable is safer than incorrectly verified.

## Principle 3 — Deterministic Decisions

The system avoids confidence scores, trust scores, reputation systems,
probabilistic approvals, and heuristic risk weighting.

**Allowed:** PASS, FAIL, UNVERIFIABLE
**Forbidden:** "85% trusted", "Probably safe", "Likely correct"

## Principle 4 — Explicit Boundaries

Every security boundary must be explicit: parser boundary, verification
boundary, execution boundary, network boundary, cloud boundary.

Crossing a boundary requires verification. Implicit trust is prohibited.

## Principle 5 — Approved Paths Only

Security-sensitive operations must use approved pathways.

**Allowed:** `hcl2.load()` (structured parser)
**Forbidden:** `eval()`, `exec()`, `os.system()`, `subprocess.Popen()`

The existence of a safe boundary automatically makes direct bypasses
architecture violations.

## Principle 6 — No Silent Degradation

A system must not quietly downgrade security.

**Forbidden:**
- Try strict → fail → fallback mode
- Try verifier A → fail → verifier B
- Try parser A → fail → parser B
- Try validation → ignore error

Failures must remain visible.

## Principle 7 — Security Boundaries Are First-Class Features

Security is not documentation. Security is not optional configuration. Security
boundaries must be enforceable in code, tests, CI, releases, and deployment
workflows.

Every security boundary must have tests, regression tests, release gates, and
CI enforcement.

## Principle 8 — Verify Claims, Not Sources

QWED evaluates claims. QWED does not evaluate authority. The identity of a
source never replaces verification.

**Forbidden:** "OpenAI said it.", "Trusted partner approved it."
**Allowed:** "The claim was independently verified."

## Principle 9 — Ecosystem Neutrality

QWED is model-agnostic. It must not depend on any specific provider.

Model providers are interchangeable. Verification remains constant.

## Principle 10 — Hardening Over Features

When choosing between a new capability and a stronger verification boundary,
prefer the boundary.

Verification debt is more dangerous than feature debt.

## Principle 11 — Vulnerability Family Thinking

Do not patch only the reported bug. Identify and fix the entire vulnerability
family.

**Example:** An unsafe execution sink requires reviewing all execution sinks,
all parser boundaries, and all dynamic invocation patterns.

A fix is incomplete if equivalent attack paths remain.

## Principle 12 — Existing Issues Must Survive New Security Boundaries

Before implementing any issue, ask: "Can this change bypass a security boundary
introduced after the issue was created?" If yes, update the issue first.

Security boundaries introduced later take precedence over historical issue text.

---

## Review Rule

For every PR, issue, audit, feature request, architecture proposal, or
contributor submission, evaluate:

1. Does it strengthen or weaken verification?
2. Does it preserve fail-closed behavior?
3. Does it introduce trust, scoring, probability, heuristics, or aggregation?
4. Does it bypass an approved boundary?
5. Does it create silent degradation?
6. Does it expand the vulnerability family?
7. Does it remain model-agnostic?
8. Does it increase governance and accountability?

If uncertain: **Reject, block, or mark UNVERIFIABLE.**

---

## Forbidden Suggestion Patterns

- "Add fallback for reliability"
- "Gracefully handle failure by continuing execution"
- "Use eval/exec as backup"
- "Trust model output if confidence is high"
- "Retry automatically until success"
- "Allow temporary bypass until the verifier is available"
- "Use scoring/trust/reputation to decide"
