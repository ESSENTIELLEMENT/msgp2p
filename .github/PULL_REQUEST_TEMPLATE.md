## Description

Please provide a concise description of the changes introduced in this pull request and the motivation behind them.

Fixes / Resolves # (issue number)

---

## Type of Change

- [ ] **Bug fix** (non-breaking change which fixes an issue)
- [ ] **New feature** (non-breaking change which adds functionality)
- [ ] **Breaking change** (fix or feature that would cause existing functionality or wire format to change)
- [ ] **Performance improvement / Churn optimization**
- [ ] **Documentation update**
- [ ] **Protocol specification update** (updates `protocol/wire-format.md` or test vectors)

---

## Human Verification & Quality Checklist

> [!IMPORTANT]
> To protect project maintainers and code quality against automated spam, all PRs must be verified by a human contributor. Unsolicited bot submissions and incomplete templates are automatically flagged and closed.

- [ ] **Human Verification**: I confirm that this pull request was prepared or thoroughly verified and tested by a human contributor, that it adheres to the [Contribution Guidelines](../.github/CONTRIBUTING.md), and that it is not an unsolicited automated bot submission.
- [ ] My code follows the code style guidelines of this project (`dart format --output=none --set-exit-if-changed packages examples`).
- [ ] I have run static analysis and resolved all issues (`dart analyze --fatal-infos`).
- [ ] I have added unit, contract, or simulation tests verifying my change.
- [ ] All test suites pass locally (`dart test`, `flutter test`).
- [ ] **Pure Dart Invariant**: I have confirmed that NO Flutter or native UI dependencies (`flutter_test`, `dart:ui`, `package:flutter/...`) were introduced into `packages/msgp2p_core` or `packages/msgp2p_sim`.
- [ ] For protocol or schema modifications: I have updated `protocol/wire-format.md` and cross-platform test vectors where applicable.
