# Changelog

## Unreleased

- `MsgP2PNode.initialize(keyVault: ...)` (proposal 0001, step 2): the identity comes from a `KeyVault`; the
  store is checked against it before the node authors, and the node continues its sequence numbers from the
  store after a restart (before, they started again at 1). `signingSeed` / `noiseSeed` are deprecated and will
  be removed in the next minor version. Publishes are serialized, so sequence numbers are stored in order.
- The keystore-backed vault for Android and iOS follows in step 2b.

## 1.0.0

- Production `v1.0.0` release with complete API documentation, security hardening, and field-calibrated radio profiles.

## 0.2.0

- Added `IosBleTransport` and Swift CoreBluetooth native adapter (`BleHardwareAdapter.swift`) with XCTest protocol fakes.
- Added `WifiAwareTransport`, `WifiAwareRadioBridge`, and `SessionUpgradeCoordinator` for automatic BLE → Wi-Fi Aware bulk session upgrades and immediate teardown.
- Added hash-addressed attachment publishing and retrieval on `MsgP2PNode`.

## 0.1.0

- Initial release with `MsgP2PNode`, `AndroidBleTransport`, `BleRadioBridge`, Kotlin BLE/Coded PHY/L2CAP adapter, and `Msgp2pForegroundService`.
