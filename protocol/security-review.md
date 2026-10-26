# msgp2p v1.0 Security Review & Threat Model Audit

> **Status:** Complete (`v1.0.0`)  
> **Scope:** `protocol/wire-format.md`, `protocol/openapi.yaml`, `packages/msgp2p_core`, `packages/msgp2p_flutter`, `server/php`  
> **Requirements Covered:** `FR-ID-01..05`, `FR-SEC-01..09`

---

## 1. Threat Model & Trust Boundaries (`FR-SEC-09`)

| Actor / Component | Trust Level | Capabilities & Mitigations |
| :--- | :--- | :--- |
| **Passive Radio Observer** | Untrusted | Observes BLE advertisements, Wi-Fi Aware frames, and L2CAP/GATT packets. Mitigated via rotating HMAC advertising tokens (`FR-SEC-07`), Noise-XX session encryption (`FR-SEC-06`), and XChaCha20-Poly1305 group payload encryption (`FR-SEC-01`). |
| **Active Non-Member / Rogue Device** | Untrusted | Attempts to connect, inject fake messages, or harvest version vectors. Blocked at the Noise-XX handshake before `SUMMARY` exchange because it lacks a valid server-signed `MembershipCert` for `group_id` (`FR-ID-04`, `FR-SEC-06`). |
| **Revoked Former Member** | Untrusted | Holds an unexpired certificate whose key was compromised or revoked. Mitigated via server-signed `RevocationNotice` gossip (`FR-ID-05`), `SessionStateMachine` dropping `DATA` envelopes from revoked authors, optional handshake rejection (`rejectRevokedPeerHandshake`), and key epoch rotation (`FR-SEC-02`). |
| **Honest-but-Curious / Tampering Relay** | Semi-trusted (Group Member) | Holds valid group membership and relays envelopes across the mesh. Cannot forge envelopes from other members (`Ed25519` signature over immutable `canonical_cbor(core)`) or mutate header metadata without invalidating both the `Ed25519` signature and the `XChaCha20-Poly1305` AAD tag (`FR-SEC-03..05`). |
| **Group Operator Server (`server/php`)** | Trusted (`FR-SEC-09`) | Issues `MembershipCert`s, rotates group key epochs, signs `ServerReceipt`s and `RevocationNotice`s. Server public key is pinned in client configuration (`FR-ID-03`). |

---

## 2. Cryptographic Primitives & Key Separation Audit

| Function | Algorithm | Key / Nonce Size | Verification Finding |
| :--- | :--- | :--- | :--- |
| **Identity & Envelope Signing** | `Ed25519` (RFC 8032) | 32 B public, 64 B sig | **PASS** — Separate from X25519 key agreement key (`FR-ID-01`). Deterministic signature over `canonical_cbor(core)`. |
| **Session Key Agreement** | `Noise_XX_25519_ChaChaPoly_SHA256` | 32 B static & ephemeral `X25519` | **PASS** — Static `noise_pubkey` is cryptographically bound inside the server-signed `MembershipCert` (`wire-format.md §3.1`). |
| **Group Payload Encryption** | `XChaCha20-Poly1305` | 32 B key, 24 B CSPRNG nonce, 16 B MAC | **PASS** — 192-bit random nonces generated via `SystemRandomSource` (`Random.secure()`) eliminate birthday-bound collision risk across distributed offline writers. |
| **AEAD Associated Data (AAD)** | `group_id \|\| key_epoch \|\| author \|\| seq` | 60 bytes | **PASS** — Prevents cross-group, cross-epoch, or sequence-splice ciphertext transplant attacks even before signature verification. |
| **Content-Addressed IDs** | `SHA-256` | 32 bytes | **PASS** — `message_id = SHA-256(canonical_cbor(core))` (`FR-SEC-04`); attachment blobs verified against `SHA-256(bytes)` prior to storage. |
| **Rotating BLE Beacon** | `HMAC-SHA256` truncated to 16 B | 32 B `group_beacon_key`, 15-min window | **PASS** — Accepts `[w-1, w, w+1]` windows (`±15 min` skew tolerance) and uses constant-time comparison (`FR-SEC-07`). |

---

## 3. Protocol & Implementation Hardening Controls

1. **No Mutable Signed Fields (`FR-SEC-05`)**:
   - Audited `EnvelopeCore` in `packages/msgp2p_core/lib/src/model/envelope.dart` and `server/php/src/GatewayController.php`. All transient state (`origin`, `first_handed_at`, `server_confirmed`) is stored strictly in local SQLite columns outside the CBOR wire envelope.
2. **Bounded Memory Allocations**:
   - `Envelope.maxCoreSizeBytes = 4096`: Enforced in `Envelope.create()`, `Envelope.fromCbor()`, and `GatewayController::push()` (`EnvelopeSizeLimitException`).
   - `Frame.maxPayloadLength = 65536`: Enforced in `Frame.encode()` / `Frame.decode()` and `ChunkReassembler` (`framing/frame.dart`, `framing/chunking.dart`) prior to allocating buffer space.
3. **Clock Skew & Expiration Rules (`FR-SEC-08`)**:
   - `ClockRules.isValidMessageTime()` rejects envelopes with `created_at > now + 10 min` (`maxFutureDriftMs = 600,000`) and envelopes where `expires_at <= now`. Old messages within their TTL are never rejected.
4. **Group Isolation & Revocation Enforcement (`FR-ID-04`, `FR-ID-05`)**:
   - `NoiseHandshake` verifies `peerCert.groupId == expectedGroupId` and `peerCert.verify(pinnedServerKey, currentTimeMillis)` using constant-time byte comparisons before completing the handshake.
   - `SessionStateMachine` verifies `groupId` on all incoming `DATA`, `RECEIPTS`, and `REVOCATIONS` frames and drops any `DATA` envelope authored by a revoked member (`store.isRevoked(env.core.author)`).
5. **SQL Injection & Server Input Validation (`FR-SRV-01..05`)**:
   - Audited `server/php/src/*.php`: 100% of MySQL queries use prepared PDO statements with bound parameters, `declare(strict_types=1);`, and `ext-sodium` signature verification.

---

## 4. Automated Security Verification Suite

All security invariants are continuously verified in CI by:
- `packages/msgp2p_core/test/security_and_nfr_test.dart`
- `packages/msgp2p_core/test/noise_handshake_test.dart`
- `packages/msgp2p_core/test/cbor_and_crypto_test.dart`
- `server/php/tests/run_tests.php` & `tools/verify_test_vectors.php`
