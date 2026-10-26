# Changelog

## 1.0.0

- **Phase 5 Hardening & Production Release**:
  - Added `Envelope.maxCoreSizeBytes` (4 KB hard limit) and `EnvelopeSizeLimitException` enforcement (`requirements.md §3`).
  - Added `Envelope.decryptPayload()` convenience method returning decoded `Map<String, dynamic>`.
  - Added `AdaptiveScanScheduler` (`NFR-PWR-01`) with exponential back-off and immediate reset on peer discovery.
  - Hardened `SessionStateMachine` with constant-time `groupId` isolation checks on `DATA`, `RECEIPTS`, and `REVOCATIONS`, automatic dropping of `DATA` envelopes authored by revoked members, and `rejectRevokedPeerHandshake`.
  - Added security audit (`protocol/security-review.md`) and NFR performance benchmarks (`NFR-PERF-02`, `NFR-PERF-03`, `NFR-PWR-01`).

## 0.2.0

- Added hash-addressed attachment blobs (`BLOB_WANT`, `BLOB_DATA`, `UPGRADE_OFFER`, `UPGRADE_ACCEPT`) to `SessionStateMachine`, `MessageStore`, `MemoryMessageStore`, `SqliteMessageStore`, and `GatewayClient`.
- Added BLE → Wi-Fi Aware upgrade detection (`upgradeRecommended`, `pendingUpgradeBytes`).

## 0.1.0

- Initial release of pure-Dart DTN engine: Canonical CBOR, `Envelope`, `MembershipCert`, `ServerReceipt`, `RevocationNotice`, `VersionVector`, `NoiseHandshake`, `SessionStateMachine`, `SqliteMessageStore`, `GatewayClient`, `FakeTransport`, and `MeshHarness`.
