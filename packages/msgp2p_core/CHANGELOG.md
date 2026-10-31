# Changelog

## Unreleased

- **`MembershipSource` port & types** (proposal 0001, step 4):
  - Added `MembershipSource` abstract port, `MemberPublicKeys` (32-byte Ed25519 + X25519 public key value type with `fromSeeds` derivation and constant-time equality), `KeyRole` (`member`, `tracker`), `GrantedKey` (unique positive epoch, role, 32-byte key), `MembershipGrant` (`cert`, `keys`, `beaconKey`, server-signed `revocations` per §9.1, `refreshAfter`, `activeAuthoringKey`, and `verify()` against `pinnedServerKey`), and `MembershipException` (`MembershipErrorKind`).
  - Added `MemoryMembershipSource` in-memory authority with enrollment, key-epoch rotation (globally unique epochs, §9.4), and server-signed member revocations.
  - Added `runMembershipSourceContractTests` shared contract test suite (`test/membership_source_contract.dart`).
  - Deprecated `GatewayClient.register` and `GatewayClient.login` (moved to `package:msgp2p_reference_auth`; kept for one minor version).
- **`GatewayApi` & `HttpExecutor` ports** (proposal 0001, step 3):
  - Added `GroupId` 16-byte immutable value type with defensive byte copying, hex string conversions, and strict length validation across all constructors.
  - Added `HttpReply` and `HttpExecutor` abstract port interface, decoupling gateway HTTP operations from `dart:io` `HttpClient` via conditional export (`io_http_executor_stub.dart` on Web/Wasm, `IoHttpExecutor` on `dart:io`).
  - Added `MockHttpExecutor` for socket-less unit testing.
  - Added `GatewayApi` interface port (`push`, `pull`, `receipts`, `revocations`, `uploadAttachment`, `downloadAttachment`) and `GatewayApiSync.syncStore` extension for bidirectional `MessageStore` synchronization over any `GatewayApi` with cryptographic verification of `ServerReceipt`s and `RevocationNotice`s against `pinnedServerKey` and signature, group, revocation, and clock checks on pulled `Envelope`s.
  - Added `MemoryGatewayApi` in-memory implementation with priority-sorted delta pull, computed `serverVector`, strict `since` filtering, group isolation, and SHA-256 attachment integrity checks.
  - **Breaking on `GatewayClient`**: `GatewayClient` now implements `GatewayApi` directly (positional `GroupId` / `AttachmentRef` parameters on `push`, `pull`, `uploadAttachment`, `downloadAttachment`; `GatewayClient.sync` requires `pinnedServerKey`; convenience named helpers `pushEnvelopes`, `pullDelta`, `getReceipts`, `getRevocations`, `uploadAttachmentBlob`, `downloadAttachmentBlob` are also provided), verifies downloaded attachment SHA-256 hashes, handles non-JSON error responses cleanly, and accepts an optional host-supplied `HttpExecutor`.
  - Added `runGatewayApiContractTests` shared contract test suite (`test/gateway_api_contract.dart`), executed against `MemoryGatewayApi`, `GatewayClient` (`MockHttpExecutor`), and `GatewayClient` (`IoHttpExecutor` + `HttpServer`).
  - Added `messageIdHex` getter to `Envelope` and `EnvelopeCore`, and `id` getter to `GroupMembership`.

## 1.1.0

- **KeyVault port** (proposal 0001, step 2; Discussion #10): `KeyVault`, `IdentitySeeds`, `KeyVaultLoad`,
  `MemoryKeyVault` (also `fromSeeds`), `KeyVaultCorruptedError`, `KeyVaultUnavailableError`.
- **Store guard:** `guardStoreIdentity` refuses to let a node author when the store does not belong to the
  vault's identity (`UnsynchronizedIdentityException`: `storeEmpty`, `ownerMismatch`).
- **Persistent author sequence:** the author's `seq` counter was kept in memory only and started again at 0 on
  every start. `MessageStore` gains `getOwnerPubkey`, `setOwner`, `getAuthorSeq` and `saveOwnEnvelope`, which
  stores an own envelope (origin `LOCAL`) and raises the counter in one transaction; pruning never lowers it.
  `SqliteMessageStore` keeps them in a new one-row table `local_identity`, created on open.
- **LoRa Transport & 0-RTT Broadcast Mode**:
  - Added `recommendedFrameTimeout` (up to 45 s for LoRa) and `isBroadcastMedium` to `TransportCapabilities`.
  - Added `BroadcastFrame`, `BroadcastChunkPacket` (magic `0xBD`, CRC-16), `BroadcastChunkSlicer`, and `BroadcastChunkReassembler` (`broadcast_framing.dart`).
  - Added `BroadcastTransport` interface and `BroadcastEngine` (`broadcast_engine.dart`) for 0-RTT flood publishing, reassembly, cryptographic verification, and direct SQLite ingestion over unidirectional or low-bandwidth radio links without interactive handshake overhead.
- **Multiple Groups per Device (Multi-Tenancy)**:
  - Added `GroupMembership` domain model and `GroupStorePool` with `inMemory()` and `sqlite()` factory constructors to cleanly isolate SQLite databases (`messages_group_<hex>.db`), quotas, and message sequence spaces per group.
  - Added `MultiGroupBeaconManager` with round-robin advertising rotation across active groups and constant-time token scanning matcher.
  - Added `closeLinkOnTermination` flag to `SessionStateMachine` allowing persistent connection reuse.
  - Added `MultiGroupSyncCoordinator` to sequentially execute sync sessions across all shared groups over a single physical link without radio reconnect overhead.

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
