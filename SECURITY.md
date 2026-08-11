# Security Policy

Astroid is financial infrastructure for autonomous AI agents. We take security
seriously and appreciate responsible disclosure.

## Supported Versions

The smart contracts follow Semantic Versioning. Security fixes are released for
the latest minor of the current major. During the `0.x` phase, please track the
latest release.

## Reporting a Vulnerability

**Do not open a public GitHub issue for security reports.**

Email `security@astroid.dev` with:

- A description of the vulnerability and its impact
- Steps to reproduce (proof of concept if possible)
- Affected contract(s) and version(s)

We aim to acknowledge reports within 48 hours and to provide a remediation
timeline within five business days.

## Scope & handling guidance

- **Validate everything.** Every contract function must validate caller,
  ownership, inputs, and permissions before executing any state change.
- **Fail safely.** If any validation fails, the contract must revert with a
  deterministic error code. Never leave state partially modified.
- **Emit events.** Every significant state change must emit a standard event.
  The backend subscribes to these to maintain consistency.
- **No external dependencies.** Contracts must not rely on untrusted external
  calls. All data flows through the Registry contract.
- **Storage minimization.** Only store what must be trusted by everyone. Never
  store AI reasoning, analytics, or any off-chain data.

Thank you for helping keep the Astroid ecosystem safe.
