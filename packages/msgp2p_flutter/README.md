# msgp2p_flutter

Flutter plugin and high-level `MsgP2PNode` SDK facade for **msgp2p** server-anchored, delay-tolerant group synchronization over Bluetooth LE (1M/2M + Coded PHY) and Wi-Fi Aware.

## Features

- **`MsgP2PNode` High-Level Facade (`FR-SDK-04`)**: Payload-agnostic API for initializing a node, logging in to obtain a server-signed `MembershipCert` and group keys, publishing messages with optional attachments, subscribing to message status updates (`localOnly` → `handedToPeer` → `serverConfirmed`), and syncing over mesh radios or HTTPS gateway.
- **Android BLE Adapter (`AndroidBleTransport`)**: Supports Bluetooth 5 Extended Advertising, LE Coded PHY (`S=8`) for long-range discovery, L2CAP Connection-Oriented Channels (`CoC`) with GATT fallback, and Android 14+ `connectedDevice` foreground service.
- **iOS CoreBluetooth Adapter (`IosBleTransport`)**: Foreground central/peripheral participation with L2CAP/GATT channels and best-effort background state restoration (`CBCentralManagerOptionRestoreIdentifierKey`).
- **Device identity in the platform keystore (`PlatformKeyVault`, `FR-ID-01`)**: the node's signing and Noise seeds kept in the Android Keystore / iOS Keychain, device-only (see below).
- **Wi-Fi Aware Bulk Upgrade (`WifiAwareTransport` & `SessionUpgradeCoordinator`)**: Negotiates high-throughput Wi-Fi Aware data paths on Android 8+ (`WifiAwareManager`) and iOS 26+ (`WiFiAware` framework on iPhone 12+) for large backlogs and hash-addressed attachments, tearing down the Wi-Fi Aware link immediately after transfer.

## Usage

```dart
import 'package:msgp2p_flutter/msgp2p_flutter.dart';

Future<void> runNode() async {
  final node = await MsgP2PNode.initialize(
    config: MsgP2PConfig(
      groupId: groupIdBytes,
      pinnedServerPublicKey: pinnedServerKeyBytes,
      serverBaseUrl: Uri.parse('https://hq.example.org'),
    ),
    transport: AndroidBleTransport(),
    keyVault: PlatformKeyVault(),
  );

  await node.startMeshRadio();
  await node.publish(
    type: 'bbs_post',
    body: {'title': 'Trail clear', 'text': 'Reached North Ridge'},
    priority: 2,
  );
}
```

## Device identity (`PlatformKeyVault`)

The node's long-lived identity (Ed25519 signing seed and X25519 Noise seed) comes from a `KeyVault` (proposal 0001,
step 2; [Discussion #10](https://github.com/ESSENTIELLEMENT/msgp2p/discussions/10)). `PlatformKeyVault` keeps it in
the platform keystore, on this device only:

- **Android:** the seeds are sealed with AES-256-GCM under a non-exportable Android Keystore key and stored in
  `noBackupFilesDir/msgp2p/keyvault-<name>.bin` (written to a temporary file, then renamed).
- **iOS:** a Keychain item (service `org.msgp2p.keyvault`, account `<name>`) with
  `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`, plus a marker file
  `Application Support/msgp2p/keyvault-<name>.marker`.

**Keep the identity on the device.** A copy on a second device would be the same author there, and two devices
with one identity author conflicting `(author, seq)` pairs. Host apps must:

- **Android:** keep `noBackupFilesDir` out of backups and device transfers (Android does this by default; do not
  copy that folder with a custom `BackupAgent` or migration tool). A vault file that reaches another device
  anyway cannot be decrypted there: `loadOrCreate` throws `KeyVaultUnavailableError`. The host then calls
  `erase()` and starts a new identity (and signs in again for a new membership certificate).
- **Both:** keep the identity and the message store together. Back up neither or both to the same device; if the
  store is lost while the identity stays, the node refuses to author (`UnsynchronizedIdentityException`).

**iOS reinstall:** Keychain items survive uninstalling the app, but the app's files do not. An item found without
its marker file is left over from an earlier install, whose message store is gone, so the vault replaces it with a
new identity (`created: true`). Without this, the node would refuse to author after every reinstall.

**Errors:**

| Error | Meaning | What the host does |
|---|---|---|
| `KeyVaultUnavailableError` | Stored seeds this device cannot decrypt (Android: restored from another device or install) | `erase()`, then a new identity |
| `KeyVaultCorruptedError` | Stored bytes are malformed | Decide: report, then `erase()` if it persists |
| `PlatformException` `LOCKED` | iOS, before the first unlock after a restart | Retry later; **do not erase** |
| `PlatformException` `KEYCHAIN` / `KEYSTORE` | Other platform failures | Retry or report |

Each `name` (default `default`, 1 to 64 of `A-Z a-z 0-9 _ -`) is a separate identity. Concurrent first calls,
also from several isolates, create one identity: the native side runs the vault on one serial queue (iOS) or under a
process and file lock (Android). Headless Linux nodes use `FileKeyVault` from `msgp2p_keyvault_file` instead.
