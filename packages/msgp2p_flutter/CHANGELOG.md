# Changelog

## Unreleased

- `MsgP2PNode.initialize(membershipSource: ...)` & `refreshMembership()` (proposal 0001, step 4): `MsgP2PNode`
  now provisions and refreshes its `MembershipCert`, group encryption keys, beacon key, and active server-signed
  `RevocationNotice`s (§9.1) from a host-supplied `MembershipSource`, verifying signatures and group/public-key
  bindings against `config.serverPublicKey`. `MsgP2PNode.register` and `MsgP2PNode.login` are deprecated and will
  be removed in the next minor version.
- `MsgP2PNode.initialize(gateway: ..., httpExecutor: ...)` (proposal 0001, step 3): `MsgP2PNode` now accepts a
  host-supplied `GatewayApi` or `HttpExecutor` and routes `syncWithGateway()` through `GatewayApiSync.syncStore`.
- `MsgP2PNode.initialize(keyVault: ...)` (proposal 0001, step 2): the identity comes from a `KeyVault`; the
  store is checked against it before the node authors, and the node continues its sequence numbers from the
  store after a restart (before, they started again at 1). `signingSeed` / `noiseSeed` are deprecated and will
  be removed in the next minor version. Publishes are serialized, so sequence numbers are stored in order.
- `PlatformKeyVault` (proposal 0001, step 2b; Discussion #10): the identity in the Android Keystore (AES-256-GCM,
  sealed file in `noBackupFilesDir`) or the iOS Keychain (`AfterFirstUnlockThisDeviceOnly`, with a marker file
  so an item left over from an earlier install is replaced). A vault file restored to another device throws
  `KeyVaultUnavailableError`; concurrent first calls create one identity across isolates. Backup rules in the
  README. Channel `org.msgp2p/key_vault`; the iOS pod now links `Security`.

## 1.0.0

- Production `v1.0.0` release with complete API documentation, security hardening, and field-calibrated radio profiles.

## 0.2.0

- Added `IosBleTransport` and Swift CoreBluetooth native adapter (`BleHardwareAdapter.swift`) with XCTest protocol fakes.
- Added `WifiAwareTransport`, `WifiAwareRadioBridge`, and `SessionUpgradeCoordinator` for automatic BLE → Wi-Fi Aware bulk session upgrades and immediate teardown.
- Added hash-addressed attachment publishing and retrieval on `MsgP2PNode`.

## 0.1.0

- Initial release with `MsgP2PNode`, `AndroidBleTransport`, `BleRadioBridge`, Kotlin BLE/Coded PHY/L2CAP adapter, and `Msgp2pForegroundService`.
