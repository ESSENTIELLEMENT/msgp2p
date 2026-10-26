# msgp2p Reference App: Off-Grid Group Bulletin Board (`bbs_chat_app`)

Reference Flutter consumer application (`FR-APP-01..04`) demonstrating how to build an off-grid group bulletin board, emergency SOS alert system, and peer diagnostic radar using `msgp2p_flutter`.

## Screens & Capabilities

1. **Bulletin Board (`FR-APP-01`, `FR-APP-02`)**:
   - Displays group posts ordered by priority (`SOS` emergency banner at priority `0`, normal posts at priority `2`).
   - Shows per-message delivery lifecycle badges:
     - `Local only` (stored on device, awaiting first peer or gateway encounter)
     - `Handed to peer` (replicated to at least one nearby phone over BLE / Wi-Fi Aware)
     - `Server confirmed` (cryptographically verified via a server-signed `ServerReceipt`)
   - Supports composing new posts, attaching photos (`AttachmentRef`, synced over Wi-Fi Aware or HTTPS gateway), and triggering one-tap **SOS** alerts.
2. **Peer Radar (`FR-APP-03`)**:
   - Displays nearby group peers discovered via rotating unlinkable HMAC tokens (`M2P_<hex>`), RSSI signal bars, active radio transport (`BLE 1M/Coded` or `Wi-Fi Aware`), and manual/automatic sync triggers.
3. **Onboarding & OEM Power Checklist (`FR-APP-04`)**:
   - Guides users through Android 12+ Nearby Devices permissions (`BLUETOOTH_SCAN`, `BLUETOOTH_ADVERTISE`, `BLUETOOTH_CONNECT`), Android 14+ `connectedDevice` foreground service activation, and OEM battery optimization exemptions.

## Running & Testing

```bash
# Run widget & E2E integration tests
flutter test

# Launch on a connected Android or iOS device
flutter run --release
```
