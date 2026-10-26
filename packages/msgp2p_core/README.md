# msgp2p_core

Pure-Dart delay-tolerant networking (DTN) engine, cryptographic envelope layer, version-vector reconciliation protocol, Noise-XX session state machine, SQLite WAL storage, and HTTPS gateway client for **msgp2p**.

## Features

- **100% Pure Dart (`FR-SDK-01`)**: Zero Flutter framework dependencies. Runs on mobile, desktop, headless Linux CLI, and discrete-event simulators.
- **Content-Addressed Envelopes (`FR-SEC-01..05`)**: Deterministic RFC 8949 §4.2 Canonical CBOR serialization, `SHA-256` message IDs, `Ed25519` author signatures, and `XChaCha20-Poly1305` group payload encryption with `key_epoch` rotation.
- **Authenticated Peer Sessions (`FR-SEC-06`)**: `Noise_XX_25519_ChaChaPoly_SHA256` session handshake cryptographically bound to server-issued `MembershipCert`s.
- **Exact Delta Reconciliation (`FR-SYNC-02..04`)**: Per-author monotonic sequence numbers and sparse gap sets (`VersionVector`) with priority scheduling (`SOS` → `Receipts/Revocations` → `Newest` → `Backfill`) and resumable chunked framing.
- **Hash-Addressed Bulk Attachments (`v0.2+`)**: Separate `BLOB_WANT` / `BLOB_DATA` transfer over bulk links (`WifiAwareTransport`) and server gateway (`/sync/attachments`).
- **Adaptive Power & Storage Management (`FR-SYNC-05`, `NFR-PWR-01`)**: `SqliteMessageStore` with WAL batch transactions, deterministic quota eviction, and `AdaptiveScanScheduler` with exponential back-off.

## Quick Start

```dart
import 'dart:typed_data';
import 'package:msgp2p_core/msgp2p_core.dart';

Future<void> main() async {
  final store = SqliteMessageStore.inMemory();
  final authorKp = await MsgP2PCrypto.newKeyPair();

  final envelope = await Envelope.create(
    groupId: Uint8List(16),
    keyEpoch: 1,
    groupKey: Uint8List(32),
    authorKeyPair: authorKp,
    certRef: Uint8List(32),
    seq: 1,
    priority: 0, // SOS
    payload: {
      'type': 'sos_alert',
      'body': {'title': 'Ridge shelter needed', 'lat': 35.36, 'lng': 138.72},
    },
  );

  await store.saveEnvelope(envelope);
  final vector = await store.getVersionVector();
  print('Stored message ${envelope.messageId}, vector authors: ${vector.authors.length}');
}
```
