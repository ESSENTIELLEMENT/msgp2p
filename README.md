# msgp2p

[![CI](https://github.com/ESSENTIELLEMENT/msgp2p/actions/workflows/ci.yml/badge.svg)](https://github.com/ESSENTIELLEMENT/msgp2p/actions/workflows/ci.yml)
[![Nightly Soak](https://github.com/ESSENTIELLEMENT/msgp2p/actions/workflows/nightly.yml/badge.svg)](https://github.com/ESSENTIELLEMENT/msgp2p/actions/workflows/nightly.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Dart](https://img.shields.io/badge/Dart-%3E%3D3.0.0-0175C2.svg?logo=dart)](https://dart.dev)
[![Flutter](https://img.shields.io/badge/Flutter-%3E%3D3.16.0-02569B.svg?logo=flutter)](https://flutter.dev)

> **An open-source Flutter SDK for server-anchored, delay-tolerant group synchronization over phone-to-phone radios (Bluetooth LE & Wi-Fi Aware).**

* **Homepage:** [https://msgp2p.squares.net](https://msgp2p.squares.net)
* **Repository:** [https://github.com/ESSENTIELLEMENT/msgp2p](https://github.com/ESSENTIELLEMENT/msgp2p)
* **Issue Tracker:** [https://github.com/ESSENTIELLEMENT/msgp2p/issues](https://github.com/ESSENTIELLEMENT/msgp2p/issues)
* **Discussions:** [https://github.com/ESSENTIELLEMENT/msgp2p/discussions](https://github.com/ESSENTIELLEMENT/msgp2p/discussions)

---

## 1. What It Does

In remote mountains, disaster zones, and environments with intermittent or nonexistent cellular coverage, only some devices in a group have Internet connectivity at any given moment. `msgp2p` allows mobile applications to communicate seamlessly regardless of network availability:

1. **Local Mesh Sync**: Devices exchange small, **digitally signed and group-encrypted** messages over **Bluetooth LE** (Coded PHY / 1M) and **Wi-Fi Aware** using delay-tolerant store-carry-forward replication.
2. **Deterministic Version Vectors**: Peers exchange compact version vectors and request exactly what sequence ranges they are missing—minimizing radio airtime and battery consumption.
3. **Server Reconciliation**: When **any** device reaches cellular/Wi-Fi coverage, it opportunistically uploads held messages to the group's central gateway server and brings server updates back into the mesh.
4. **Cryptographic Proofs**: Server-signed **receipts** propagate through the mesh, giving every participant cryptographic proof of what reached the headquarters.

```
[Phone A, valley, offline] ──BLE──► [Phone B, trail, offline] ──BLE──► [Phone C, ridge, 4G] ──HTTPS──► [Group server / HQ]
         ◄────────────── receipts + server updates carried back into the mesh ◄──────────────
```

---

## 2. Competitive Comparison

| Feature | `msgp2p` | Bitchat | Briar | Meshtastic | Ditto |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Form Factor** | **Flutter SDK** | Standalone App | Standalone App | App + Firmware | Proprietary SDK |
| **Hardware Required** | **None (Smartphones)** | None | None | External LoRa radio | None |
| **Server is Source of Truth** | **Yes (Server-Anchored)** | No (Nostr relays) | No | No (optional MQTT) | Yes |
| **Platform Support** | **Android + iOS (iOS foreground first)** | Android + iOS | Android only | Android + iOS | Android + iOS |
| **License** | **Open Source (Apache-2.0)** | Open Source | Open Source | Open Source | Proprietary |

---

## 3. Architecture & Core Invariants

* **Thin Native, Fat Dart**: All protocol logic, version vector arithmetic, Noise-XX handshakes, cryptographic parsing, and storage management reside in pure Dart (`msgp2p_core`). Native Android (Kotlin) and iOS (Swift) plugins simply transport raw byte buffers.
* **Deterministic Wire Format**: All signed envelope cores and receipts strictly follow **RFC 8949 §4.2 Canonical CBOR** rules to ensure identical byte representations across all platforms.
* **Cryptographic Foundation**:
  * **Ed25519 (RFC 8032)** for author message signatures and server receipt verification.
  * **XChaCha20-Poly1305** with rotating key epochs for symmetric group payload encryption.
  * **Noise_XX_25519_ChaChaPoly_SHA256** for mutual peer channel authentication bound to membership certificates.
  * **Anonymous Rotating BLE Beacons**: 16-byte HMAC-SHA256 rotating tokens prevent location tracking by eavesdroppers.
* **Churn Robustness**: Integrated per-peer reconnect rate limiting ($C_{\text{max}} = 6\text{ attempts/min}$), eviction re-fetch suppression ($E_{\text{max}} = 2$), and 3-tier peer sighting history.

---

## 4. Monorepo Structure

```text
msgp2p/
├── packages/
│   ├── msgp2p_core/       # Pure Dart protocol engine, crypto, storage & sync state machine
│   ├── msgp2p_sim/        # Deterministic discrete-event simulator & CLI scenario runner
│   └── msgp2p_flutter/    # Flutter plugin bridging Android BLE/Wi-Fi Aware & iOS CoreBluetooth
├── server/
│   └── php/               # Reference gateway server (ext-sodium, PDO MySQL, OpenAPI 3.0)
├── protocol/
│   ├── wire-format.md     # Formal CDDL and cryptographic wire specification
│   ├── openapi.yaml       # OpenAPI 3.0 REST gateway interface
│   └── test-vectors/      # Deterministic cross-platform JSON test vectors
├── examples/
│   └── bbs_chat_app/      # Offline BBS bulletin board reference app with radar & SOS
└── tools/
    ├── emulator/          # Android emulator mesh orchestration scripts
    └── calibration/       # Field measurement kit for radio range and battery consumption
```

---

## 5. Quick Start

### 5.1 Prerequisites
* [Dart SDK](https://dart.dev) $\ge 3.0.0$
* [Flutter SDK](https://flutter.dev) $\ge 3.16.0$
* [PHP](https://www.php.net) $\ge 8.2$ with `ext-sodium` and `ext-pdo_mysql` (for server development)

### 5.2 Running Tests Locally

```bash
# Run msgp2p_core test suite (pure Dart, zero Flutter dependencies)
cd packages/msgp2p_core
dart test

# Run deterministic 100-node simulator scenarios
cd ../msgp2p_sim
dart test

# Run Flutter plugin tests
cd ../msgp2p_flutter
flutter test
```

### 5.3 SDK Usage Example

```dart
import 'dart:typed_data';
import 'package:msgp2p_flutter/msgp2p_flutter.dart';

Future<void> startNode(Uint8List pinnedServerPublicKey, Uint8List groupId) async {
  // Initialize the node with server endpoint, pinned server public key and group ID
  final node = await MsgP2PNode.initialize(
    config: MsgP2PConfig(
      serverEndpoint: Uri.parse('https://hq.example.org/api/v1'),
      serverPublicKey: pinnedServerPublicKey,
      groupId: groupId, // 16-byte group UUID
    ),
  );

  // While online: fetch membership certificate + group keys
  await node.login(username: 'alice', password: 'secure_password');

  // Start BLE advertising (rotating beacon token) and scanning
  await node.startMeshRadio();

  // Publish a signed, group-encrypted envelope into the local mesh
  final envelope = await node.publish(
    type: 'bbs_post',
    body: {
      'title': 'Trail Obstruction at Mile 4',
      'detail': 'Fallen tree blocking path. Detour east.',
      'lat': 45.331,
      'lng': -121.711,
    },
    priority: Priority.normal,
  );
  print('Published ${envelope.messageId}');

  // Snapshot stream of decrypted messages (SOS first, then newest)
  node.messagesStream.listen((messages) {
    for (final m in messages) {
      print('[${m.authorShortId}] ${m.type}: ${m.body}  (${m.status.label})');
    }
  });
}
```

---

## 6. Roadmap

| Release | Scope |
| :--- | :--- |
| **v0.1** | Pure-Dart core + simulator, PHP reference server, Android BLE (incl. Coded PHY), reference BBS app on Android |
| **v0.2** | iOS (foreground), **Wi-Fi Aware** bulk transfer on Android & iOS 26+, attachments |
| **v1.0** | Field calibration, hardening, churn robustness |
| **Future** | LoRa/Meshtastic transport, NestJS/Firebase server adapters, multiple groups per device |

---

## 7. Documents

- [requirements.md](requirements.md): requirements with stable IDs
- [architecture.md](architecture.md): data model, protocol, transports, testing architecture
- [protocol/wire-format.md](protocol/wire-format.md): wire format & cryptographic specification
- [protocol/openapi.yaml](protocol/openapi.yaml): gateway server REST API
- [protocol/security-review.md](protocol/security-review.md): security review

---

## 8. Security & Vulnerability Reporting

Security and privacy are core to `msgp2p`. If you discover a cryptographic vulnerability, timing attack, or denial-of-service vector, please review our [Security Policy](.github/SECURITY.md) and report it privately via [GitHub Private Vulnerability Reporting](https://github.com/ESSENTIELLEMENT/msgp2p/security/advisories/new) or by emailing **`msgp2p_admin@msgp2p.squares.net`**.

---

## 9. Export Control & Cryptography Notice

This distribution includes cryptographic software (Ed25519 signatures, XChaCha20-Poly1305 encryption, and the Noise Protocol Framework with X25519). The country in which you currently reside may have restrictions on the import, possession, use, and/or re-export of encryption software. Before using this software, please check your country's laws and regulations.

For the U.S. Export Administration Regulations (EAR): this software would otherwise be classified under ECCN 5D002, but its source code is publicly available and therefore not subject to the EAR (15 CFR § 734.3(b)(3), § 734.7). It uses only standard, published cryptographic algorithms, so no BIS/NSA notification is required under 15 CFR § 742.15(b). *This notice is informational and is not legal advice.*

---

## 10. Community & Contributing

* Review [CONTRIBUTING.md](.github/CONTRIBUTING.md) for branch policies, coding conventions, and PR requirements.
* All participants must abide by our [Code of Conduct](.github/CODE_OF_CONDUCT.md).
* Join discussions and ask questions on [GitHub Discussions](https://github.com/ESSENTIELLEMENT/msgp2p/discussions).

---

## 11. License

`msgp2p` is distributed under the **Apache License, Version 2.0**. See the [LICENSE](LICENSE) file for details.
