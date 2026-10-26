# Changelog

## 1.0.0

- Updated `link_profiles.yaml` and `LinkProfile` with v1.0 field-calibrated measurements (`ble_1m`, `ble_1m_forest`, `ble_coded_s8`, `ble_coded_s8_forest`, `ios_ble`, `wifi_aware`).
- Added 8-node mixed Android/iOS mountain SAR scenario (`scenarios/field_trial_8_nodes.yaml`) and `test/field_trial_sim_test.dart`.

## 0.2.0

- Added `ios_ble` link profile, platform capability filtering (`supportsCodedPhy`, `supportsWifiAware`), and automatic BLE → Wi-Fi Aware attachment upgrade simulation (`scenarios/mixed_android_ios_upgrade.yaml`).

## 0.1.0

- Initial release with `Simulator`, `SimClock`, `EventQueue`, `SimTransport`, `SimServer`, and `trail_sync.yaml` / `partition_merge.yaml` / `ridge_gateway.yaml` scenarios.
