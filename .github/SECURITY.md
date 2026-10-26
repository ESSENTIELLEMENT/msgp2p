# Security Policy

The `msgp2p` team takes the security of peer-to-peer delay-tolerant mesh communication, cryptographic integrity, and user privacy seriously. We appreciate responsible disclosure of security vulnerabilities.

---

## 1. Supported Versions

We actively provide security patches and updates for the following release branches:

| Version | Supported | Status |
| :--- | :---: | :--- |
| **`1.0.x`** | :white_check_mark: | Active production release |
| `< 1.0` | :x: | Unsupported development milestones |

---

## 2. Reporting a Vulnerability

**Please do not report security vulnerabilities via public GitHub issues, discussions, or social channels.**

### Method 1: GitHub Private Vulnerability Reporting (Recommended)
You can report vulnerabilities privately and directly through GitHub's advisory system:
1. Navigate to the repository's [Security Advisories](https://github.com/ESSENTIELLEMENT/msgp2p/security/advisories) page.
2. Click **Report a vulnerability** to open a private advisory draft.
3. This creates a secure, encrypted discussion thread directly between you and the repository maintainers.

### Method 2: Email
If you cannot use GitHub, email the project security contact (note: plain email is not end-to-end encrypted; keep exploit details minimal in the first message and we will move to a private GitHub advisory):
* **Email:** **`msgp2p_admin@msgp2p.squares.net`**

### What to Include in Your Report
To help us triage and reproduce the issue rapidly, please include:
* **Component / Package:** (e.g., `msgp2p_core`, `msgp2p_flutter`, `server/php`).
* **Vulnerability Class:** (e.g., Noise handshake flaw, replay vulnerability, CBOR parser denial-of-service, unhandled native BLE buffer overflow).
* **Step-by-Step Reproduction:** Minimal reproduction script, scenario YAML, or test case demonstrating the vulnerability.
* **Impact Assessment:** Expected attack scenario, prerequisites, and blast radius.

---

## 3. Vulnerability Handling SLA

* **Acknowledgment:** Within **48 business hours** of receipt.
* **Assessment & Triage:** Within **7 calendar days**, we will confirm or refute the finding and provide a projected mitigation timeline.
* **Fix & Release:** Critical security patches will be published within **30 days** (or a mutually agreed embargo period, not exceeding 90 days per standard Coordinated Vulnerability Disclosure guidelines).
* **Credit:** Researchers who report valid vulnerabilities in good faith will be credited in our public security advisory notes and changelogs.

---

## 4. Scope & Boundaries

### In Scope
* Cryptographic bypasses or key leakage in Ed25519, XChaCha20-Poly1305, or Noise-XX implementations.
* Envelope or certificate spoofing, forgeable server receipts, or revocation list evasion.
* Protocol denial-of-service (e.g., algorithmic complexity attacks, memory exhaustion via malformed CBOR chunks).
* Buffer overflows or memory safety defects in native Android (Kotlin) or iOS (Swift) radio drivers.

### Out of Scope
* Physical attacks requiring direct hardware disassembly or JTAG debugging on rooted devices.
* Social engineering or phishing targeting repository contributors.
* Operating system zero-days in vendor Bluetooth/Wi-Fi chip firmware outside SDK control.

---

## 5. Export Control & Cryptography Notice

This distribution includes cryptographic software (Ed25519 signatures, XChaCha20-Poly1305 encryption, and the Noise Protocol Framework with X25519). The country in which you reside may restrict the import, possession, use, or re-export of encryption software; check your local laws before use.

For the U.S. Export Administration Regulations (EAR): this software would otherwise be classified under ECCN 5D002, but its source code is publicly available and therefore not subject to the EAR (15 CFR § 734.3(b)(3), § 734.7). It uses only standard, published cryptographic algorithms, so no BIS/NSA notification is required under 15 CFR § 742.15(b). *This notice is informational and is not legal advice.*
