# Contributing to msgp2p

Thank you for your interest in contributing to `msgp2p`! We welcome bug reports, feature proposals, documentation improvements, and code contributions.

Please take a moment to read this document to understand our development workflows, code standards, and non-negotiable architectural invariants.

---

## 1. Architectural Invariants (Must Read)

Before submitting changes, ensure your contributions adhere to these fundamental principles:

1. **Pure Dart Invariant for Core & Sim**:
   * `packages/msgp2p_core` and `packages/msgp2p_sim` **MUST remain 100% pure Dart**.
   * They must never import Flutter libraries (`flutter_test`, `dart:ui`, `package:flutter/...`). All unit and contract tests in these packages must run with standard `dart test`.
2. **Deterministic Canonical CBOR (RFC 8949 §4.2)**:
   * Any map or object that is cryptographically signed (such as `EnvelopeCore`, `MembershipCert`, `ServerReceipt`) must be serialized using strict RFC 8949 canonical CBOR: keys sorted by the lexicographical byte representation of their encoded form, definite lengths, and shortest integer representations.
3. **Protocol & Test Vector Alignment**:
   * Any modification to wire formats, session frame types, or cryptographic Associated Data (AAD) requires updating [protocol/wire-format.md](../protocol/wire-format.md) and regenerating the cross-platform test vectors in [protocol/test-vectors/](../protocol/test-vectors/).
4. **Thin Native Radio Adapters**:
   * Native platform plugins (Android Kotlin / iOS Swift) are strictly I/O pipes. They must not parse CBOR envelopes or make cryptographic decisions.

---

## 2. Policy on Automated, Bot, and AI-Generated Submissions

To preserve code quality, cryptographic security, and maintainer time, `msgp2p` enforces clear rules regarding automated and AI-generated contributions:

1. **No Unsolicited Autonomous Bot PRs**:
   * We do not accept pull requests opened autonomously by bot accounts, scrapers, or automated AI agents without prior human discussion and approval.
   * Automated pull requests (including unsolicited dependency bumps, generic typo sweeps, automated reformatting, or promotional links) will be immediately closed, marked as spam, and the submitting account will be blocked and reported to GitHub.
2. **No Low-Effort / Micro-PRs**:
   * Pull requests that make trivial single-character typo edits, add cosmetic README badges, adjust whitespace, or generate synthetic translations without addressing an open, accepted issue will be rejected.
3. **Responsible Use of AI by Human Contributors**:
   * Human contributors may use AI coding assistants as tools. However, **you must fully understand, test, and be able to defend every line of code you submit**.
   * You are personally responsible for verifying that pure Dart invariants, CBOR canonical ordering rules, and cryptographic boundaries are strictly preserved.
4. **Issue-First / Discussion-First Workflow**:
   * Before opening a pull request for non-trivial features, refactors, or bug fixes, open a [GitHub Issue](https://github.com/ESSENTIELLEMENT/msgp2p/issues) or [Discussion](https://github.com/ESSENTIELLEMENT/msgp2p/discussions) to align on the approach. Unsolicited PRs without context may be closed without review.

---

## 3. Development Setup & Tooling

### Prerequisites
* **Dart SDK**: $\ge 3.0.0$
* **Flutter SDK**: $\ge 3.16.0$
* **PHP**: $\ge 8.2$ with `ext-sodium` and `ext-pdo_mysql` (only required if working on `server/php`)

### Initial Workspace Bootstrap
```bash
git clone https://github.com/ESSENTIELLEMENT/msgp2p.git
cd msgp2p

# Install Dart package dependencies
cd packages/msgp2p_core && dart pub get
cd ../msgp2p_sim && dart pub get
cd ../msgp2p_flutter && flutter pub get
cd ../../examples/bbs_chat_app && flutter pub get
```

---

## 4. Quality & Verification Gates

All contributions must pass automated CI checks before being merged. Run these locally before submitting a pull request:

### 4.1 Code Formatting
We adhere to standard Dart formatting across all packages and examples:
```bash
dart format --output=none --set-exit-if-changed packages examples
```

### 4.2 Static Analysis
No analyzer warnings or errors are allowed:
```bash
dart analyze --fatal-infos packages/msgp2p_core packages/msgp2p_sim packages/msgp2p_flutter examples/bbs_chat_app
```

### 4.3 Running Test Suites
```bash
# msgp2p_core unit and integration tests (100+ tests)
cd packages/msgp2p_core && dart test

# msgp2p_sim discrete-event simulator & churn tests
cd ../msgp2p_sim && dart test

# msgp2p_flutter plugin contract tests
cd ../msgp2p_flutter && flutter test

# examples/bbs_chat_app widget tests
cd ../../examples/bbs_chat_app && flutter test
```

---

## 5. Git & Commit Guidelines

### 5.1 Branch Naming
Use descriptive branch names with conventional prefixes:
* `feat/feature-name` (e.g., `feat/wifi-aware-session-upgrade`)
* `fix/issue-description` (e.g., `fix/chunk-reassembler-crc-timeout`)
* `docs/documentation-update` (e.g., `docs/update-wire-format-specs`)
* `test/test-addition` (e.g., `test/soak-partition-merge`)

### 5.2 Commit Messages
We follow the [Conventional Commits](https://www.conventionalcommits.org/) specification:
* `feat: add per-peer reconnect rate limiting (C_max = 6)`
* `fix: prevent frame timeout during abrupt link disconnection`
* `docs: update OpenAPI schema for batch receipts`
* `test: add 50-seed churn simulation soak suite`

---

## 6. Pull Request Workflow

1. **Open an Issue First**: Ensure your proposed change is discussed and accepted in an Issue or Discussion.
2. **Fork & Branch**: Create your feature branch from `main`.
3. **Implement & Test**: Write your implementation alongside relevant unit/integration tests.
4. **Verify Locally**: Ensure `dart format`, `dart analyze`, and `dart test` succeed across packages.
5. **Open a PR**: Open a pull request against `main` on [GitHub](https://github.com/ESSENTIELLEMENT/msgp2p/pulls).
6. **Complete the PR Template**: Check all applicable boxes, including the mandatory **Human Verification** acknowledgment and link to the relevant issue.
7. **Automated CI & Code Review**: The automated PR guard will verify template compliance, and project maintainers (`@ESSENTIELLEMENT`) will review your submission.

---

## 7. Licensing & Attribution

By contributing to `msgp2p`, you agree that your contributions will be licensed under the **Apache License, Version 2.0**.
