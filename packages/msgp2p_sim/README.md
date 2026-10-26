# msgp2p_sim

Deterministic discrete-event simulator (`FR-TEST-02`) and CLI scenario runner for **msgp2p** delay-tolerant mesh networks.

## Features

- **Virtual Clock & Seeded RNG**: Reproducible multi-hour, multi-node simulations executing in milliseconds in CI.
- **Field-Calibrated Link Profiles (`link_profiles.yaml`)**: Empirical models for `ble_1m`, `ble_1m_forest`, `ble_coded_s8`, `ble_coded_s8_forest`, `ios_ble`, and `wifi_aware`.
- **Mixed Platform & Session Upgrade Modeling**: Simulates Android Coded PHY long-range relays, iOS 1M BLE constraints, and automatic BLE → Wi-Fi Aware bulk attachment upgrades.
- **Live Server E2E Support**: Can run simulated gateway nodes against either the in-memory `SimServer` or a live PHP/MySQL reference server (`GatewayClient`).

## CLI Usage

```bash
dart run bin/sim.dart --scenario scenarios/field_trial_8_nodes.yaml
```
