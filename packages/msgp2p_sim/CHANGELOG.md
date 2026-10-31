# Changelog

## Unreleased

- Migrated `Simulator` real-gateway E2E provisioning from deprecated `GatewayClient.register`/`login` to `ReferenceMembershipSource` (`package:msgp2p_reference_auth`, proposal 0001, step 4).

## 1.1.0

- Added `lora_sf7_125k` and `lora_sf11_125k` link profiles to `link_profiles.yaml` and `LinkProfile.named()`.
- Added `SimLoRaTransport` (`sim_lora_transport.dart`) for simulating half-duplex, low-bitrate, long-range LoRa broadcast communications.
- Added 5-node Mountain SAR 0-RTT broadcast simulation (`test/sim_lora_broadcast_test.dart`) verifying SOS flood propagation from deep ravine via mountain ridge relay to base camp without interactive round-trips.

## 1.0.0

- Updated `link_profiles.yaml` and `LinkProfile` with v1.0 field-calibrated measurements (`ble_1m`, `ble_1m_forest`, `ble_coded_s8`, `ble_coded_s8_forest`, `ios_ble`, `wifi_aware`).
- Added 8-node mixed Android/iOS mountain SAR scenario (`scenarios/field_trial_8_nodes.yaml`) and `test/field_trial_sim_test.dart`.

## 0.2.0

- Added `ios_ble` link profile, platform capability filtering (`supportsCodedPhy`, `supportsWifiAware`), and automatic BLE → Wi-Fi Aware attachment upgrade simulation (`scenarios/mixed_android_ios_upgrade.yaml`).

## 0.1.0

- Initial release with `Simulator`, `SimClock`, `EventQueue`, `SimTransport`, `SimServer`, and `trail_sync.yaml` / `partition_merge.yaml` / `ridge_gateway.yaml` scenarios.
