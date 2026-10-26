# Changelog

## 1.0.0

- Production `v1.0.0` release with complete API documentation, security hardening, and field-calibrated radio profiles.

## 0.2.0

- Added `IosBleTransport` and Swift CoreBluetooth native adapter (`BleHardwareAdapter.swift`) with XCTest protocol fakes.
- Added `WifiAwareTransport`, `WifiAwareRadioBridge`, and `SessionUpgradeCoordinator` for automatic BLE → Wi-Fi Aware bulk session upgrades and immediate teardown.
- Added hash-addressed attachment publishing and retrieval on `MsgP2PNode`.

## 0.1.0

- Initial release with `MsgP2PNode`, `AndroidBleTransport`, `BleRadioBridge`, Kotlin BLE/Coded PHY/L2CAP adapter, and `Msgp2pForegroundService`.
