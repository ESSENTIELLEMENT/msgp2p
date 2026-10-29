# Changelog

## Unreleased

- **KeyVault port** (proposal 0001, step 2; Discussion #10): `KeyVault`, `IdentitySeeds`, `KeyVaultLoad`,
  `MemoryKeyVault` (also `fromSeeds`), `KeyVaultCorruptedError`, `KeyVaultUnavailableError`.
- **Store guard:** `guardStoreIdentity` refuses to let a node author when the store does not belong to the
  vault's identity (`UnsynchronizedIdentityException`: `storeEmpty`, `ownerMismatch`).
- **Persistent author sequence:** the author's `seq` counter was kept in memory only and started again at 0 on
  every start. `MessageStore` gains `getOwnerPubkey`, `setOwner`, `getAuthorSeq` and `saveOwnEnvelope`, which
  stores an own envelope (origin `LOCAL`) and raises the counter in one transaction; pruning never lowers it.
  `SqliteMessageStore` keeps them in a new one-row table `local_identity`, created on open.
- **Breaking for custom `MessageStore` implementations:** the four methods above must be implemented.

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
