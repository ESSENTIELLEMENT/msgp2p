# msgp2p_flutter

Flutter plugin and high-level `MsgP2PNode` SDK facade for **msgp2p** server-anchored, delay-tolerant group synchronization over Bluetooth LE (1M/2M + Coded PHY) and Wi-Fi Aware.

## Features

- **`MsgP2PNode` High-Level Facade (`FR-SDK-04`)**: Payload-agnostic API for initializing a node, logging in to obtain a server-signed `MembershipCert` and group keys, publishing messages with optional attachments, subscribing to message status updates (`localOnly` → `handedToPeer` → `serverConfirmed`), and syncing over mesh radios or HTTPS gateway.
- **Android BLE Adapter (`AndroidBleTransport`)**: Supports Bluetooth 5 Extended Advertising, LE Coded PHY (`S=8`) for long-range discovery, L2CAP Connection-Oriented Channels (`CoC`) with GATT fallback, and Android 14+ `connectedDevice` foreground service.
- **iOS CoreBluetooth Adapter (`IosBleTransport`)**: Foreground central/peripheral participation with L2CAP/GATT channels and best-effort background state restoration (`CBCentralManagerOptionRestoreIdentifierKey`).
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
  );

  await node.startMeshRadio();
  await node.publish(
    type: 'bbs_post',
    body: {'title': 'Trail clear', 'text': 'Reached North Ridge'},
    priority: 2,
  );
}
```
