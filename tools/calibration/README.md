# msgp2p Manual Field Calibration Kit (`FR-TEST-06`)

This directory contains the manual field-calibration protocol and checklist for measuring real-world Bluetooth LE 1M/2M and Coded PHY (`S=8`) radio characteristics on physical smartphones and feeding those empirical measurements back into [`packages/msgp2p_sim/link_profiles.yaml`](../../packages/msgp2p_sim/link_profiles.yaml).

> [!NOTE]
> Per `FR-TEST-06`, automated CI never requires physical hardware. Field calibration is performed periodically on 2–3 physical Android devices to keep simulator link profiles grounded in real radio physics.

---

## 1. Equipment & Prerequisites
- **Devices:** 2–3 Android 12+ smartphones with Bluetooth 5.0+ LE Coded PHY support (`BluetoothAdapter.isLeCodedPhySupported() == true`).
- **App:** Install `examples/bbs_chat_app` in release/profile mode on each device:
  ```bash
  cd examples/bbs_chat_app
  flutter run --release
  ```
- **Onboarding Checklist:** Verify all three toggles on the **Onboarding** tab (`Android 12+ Nearby Devices Permissions`, `Foreground Service (connectedDevice)`, and `OEM Battery Optimization Exemption`) are enabled.

---

## 2. Measurement Matrix

Record the following metrics across two environments (**Open Line-of-Sight** and **Dense Forest / Trail Switchback**):

| Metric | Target Profile Key in `link_profiles.yaml` | How to Measure |
| :--- | :--- | :--- |
| **Max Usable Range (m)** | `max_range_meters` | Walk apart at 10 m increments until **Peer Radar** stops receiving rotating beacon advertisements within 30 s. |
| **Connection + Handshake Setup (ms)** | `setup_latency_ms` | Tap **Sync Now** on Peer Radar and record elapsed time from `session_start` to `SUMMARY` exchange. |
| **Sustained Goodput (bytes/s)** | `throughput_bps` | Sync a backlog of 50 × 1.5 KB messages (75 KB total) and divide total bytes transferred by DATA phase duration. |
| **Chunk Loss Rate (0.0–1.0)** | `packet_loss_rate` | Ratio of CRC-failed / retransmitted chunks over total chunks sent at 75% of max range. |
| **8-Hour Battery Drain (%)** | `NFR-PWR-02` (Target ≤ 10% / 8 h) | Leave devices with screen off and `Msgp2pForegroundService` running for 8 hours; record battery percentage delta. |

---

## 3. Android ↔ iOS Cross-Platform Calibration (`v0.2`)

Measure cross-platform discovery and L2CAP/GATT throughput between an Android 12+ phone and an iPhone 12+ (iOS 16+ / iOS 26+):

| Scenario | Target Profile (`ios_ble` / `wifi_aware`) | Procedure & Target |
| :--- | :--- | :--- |
| **Foreground ↔ Foreground BLE Discovery** | `ios_ble.setup_latency_ms` | Both apps open in foreground. Measure time until rotating `M2P_<hex>` beacon appears on Peer Radar (target ≤ 2.0 s). |
| **Android Foreground ↔ iOS Background Discovery** | Best-effort background mode | Lock iOS screen (`CBCentralManagerOptionRestoreIdentifierKey` + service UUID `0000FD6F-...` filter). Verify Android scanner discovers iOS peripheral service UUID and completes L2CAP/GATT sync. |
| **BLE → Wi-Fi Aware Session Upgrade Handshake** | `wifi_aware.setup_latency_ms` | Publish a post with an attachment (`≥ 16 KB`) on Android, initiate sync with peer, and record elapsed time from BLE `WANT` completion to Wi-Fi Aware data-path connection (target ≤ 1.0 s). |
| **Wi-Fi Aware Bulk Goodput & Teardown** | `wifi_aware.throughput_bps` | Transfer a 1 MB attachment over Wi-Fi Aware and verify `teardownAfterTransfer()` closes the NAN data-path within 500 ms of `BYE`. |

---

## 4. Updating Simulator Link Profiles

After completing a field trial, update [`packages/msgp2p_sim/link_profiles.yaml`](../../packages/msgp2p_sim/link_profiles.yaml) with the measured medians and re-run the simulator regression suite:

```bash
cd packages/msgp2p_sim && dart test
```
