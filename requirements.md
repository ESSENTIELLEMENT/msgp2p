# msgp2p: Requirements Specification

> Status: **v1.0.0 Specification** (2026-10-26).
> Requirement IDs are stable; reference them in issues, PRs, and tests.

## 1. Purpose

**msgp2p** is an open-source **Flutter SDK** for **server-anchored, delay-tolerant group data sync**. Phones in a group copy small signed and encrypted messages to each other over local radios (BLE, later Wi-Fi Aware). Whenever any phone gets Internet access, it acts as a **gateway**: it uploads everything it carries to the group's server and brings server-side updates back into the mesh.

The server stays the **source of truth**. The mesh is a delay-tolerant transport for reaching it.

A reference app (`examples/bbs_chat_app`, a group bulletin board) shows how to use the SDK.

## 2. Scope by Release

| Release | In scope | Out of scope (deferred) |
| :--- | :--- | :--- |
| **v0.1** | Pure-Dart core, simulator, PHP reference server, **Android** BLE (1M/2M + Coded PHY), reference app on Android | iOS, Wi-Fi Aware, attachments over P2P |
| **v0.2** | **iOS foreground** BLE participation, **Wi-Fi Aware** bulk link (Android 8+ / iOS 26+), attachments over Wi-Fi Aware | iOS background discovery guarantees |
| **v1.0** | Hardening, field calibration, pub.dev release | — |
| **Future** | LoRa/Meshtastic transport, additional server adapters (NestJS, Firebase) | — |

## 3. Operating Assumptions

| Parameter | Value | Notes |
| :--- | :--- | :--- |
| Group size | ≤ 100 members | One group per mesh in v0.1 |
| Offline duration | ≤ 8 h | Message TTL default 24 h |
| Messages per member per offline window | ~200 | |
| **Core message size** | **target ≤ 2 KB, hard limit 4 KB** (encoded, compressed) | Text, BBS posts, location, small sensor data |
| Attachments | Separate objects referenced by hash | Never sent over BLE. Moved via Wi-Fi Aware (v0.2) or server |
| Full group history per device | ≈ 100 × 200 × 1.5 KB ≈ **30 MB** | Every member replicates all core messages |
| BLE throughput (app-level, estimates) | 1M/2M PHY: ~50–150 KB/s · Coded S=8: ~5–7 KB/s | **To be calibrated** (FR-TEST-06) |

> [!NOTE]
> Limiting the core message to ≤ 2 KB is what makes BLE sync feasible. One member's 8-hour backlog is ~300 KB: seconds on 1M PHY, under a minute on Coded PHY.

## 4. Functional Requirements

### 4.1 SDK Structure (FR-SDK)
- **FR-SDK-01** `msgp2p_core` is **pure Dart** (no Flutter imports). It contains the envelope format, cryptography, sync protocol, wire framing, storage interfaces and gateway client.
- **FR-SDK-02** `msgp2p_flutter` contains **thin native adapters** that only move raw bytes and report radio events. All protocol logic (framing, chunking, retries, state machines) lives in Dart.
- **FR-SDK-03** All radios implement the `P2PTransport` interface. Engine code never references platform radio APIs.
- **FR-SDK-04** The public API (`MsgP2PNode`) is payload-agnostic. Apps define their own payload types.
- **FR-SDK-05** The sync protocol is specified independently of any implementation (`protocol/`), with **shared test vectors** used by both Dart and PHP tests.

### 4.2 Group Membership & Identity (FR-ID)
- **FR-ID-01** Each device generates an **Ed25519 signing key** (for envelope signatures) and an **X25519 key agreement key** (for Noise-XX session encryption) on first launch. Both private keys are stored wrapped by platform keystores (Android Keystore / iOS Keychain).
- **FR-ID-02** While online, a member registers both public keys with the server and receives a **membership certificate** signed by the server: `{group_id, user_id, member_pubkey, noise_pubkey, role, issued_at, expires_at}`.
- **FR-ID-03** The server's signing public key is **pinned** in app configuration.
- **FR-ID-04** Peers accept sessions and messages only from holders of a valid, unexpired certificate for the same group.
- **FR-ID-05** Certificates are short-lived (default 7 days). The server can publish signed **revocation notices**, which spread through the mesh like normal messages.

### 4.3 Message Security (FR-SEC)
- **FR-SEC-01** **Group encryption:** payloads are encrypted with the current **group key** (XChaCha20-Poly1305). The envelope carries `key_epoch`.
- **FR-SEC-02** Group keys are delivered over the authenticated HTTPS session at login and stored wrapped by the platform keystore. The server **rotates the key epoch** when membership changes. Devices accept the previous epoch for a grace period (default 24 h).
- **FR-SEC-03** **Signatures:** the author signs the immutable envelope core (including ciphertext) with Ed25519. Any member can verify integrity without decrypting.
- **FR-SEC-04** **Content-addressed IDs:** `message_id = SHA-256(canonical_cbor(core))`.
- **FR-SEC-05** **No mutable signed fields.** Anything a relay may change lives outside the signed core and is advisory only.
- **FR-SEC-06** **Session encryption:** peer sessions use a Noise-XX-style handshake authenticated by membership certificates. All sync traffic, including metadata such as version vectors, is encrypted per session.
- **FR-SEC-07** **Unlinkable advertising:** BLE advertisements carry a rotating token `HMAC(group_beacon_key, time_window)` (rotated ≤ 15 min). It lets members recognise each other without revealing who they are.
- **FR-SEC-08** **Clock handling:** reject messages with `created_at` more than 10 min in the future. Never reject messages for being old; age is governed only by `expires_at`. Use GNSS time when available.
- **FR-SEC-09** **Threat model (explicit):** protects against non-members, eavesdroppers and tampering relays. The **group operator's server is trusted** and can read content, because it issues group keys and serves the HQ dashboard. End-to-end encryption against the server is out of scope.

### 4.4 Sync & Delay-Tolerant Replication (FR-SYNC)
- **FR-SYNC-01** **Store-carry-forward:** every member stores all valid group messages until they expire, and passes them to every peer it meets (full replication of core messages).
- **FR-SYNC-02** **Exact reconciliation via version vectors:** each author numbers messages with monotonic sequence numbers. Peers exchange `{author → highest contiguous seq + sparse gap set}` and request exactly the missing ranges. (Bloom filters are not used for correctness because false positives can lose messages.)
- **FR-SYNC-03** **Priority order** within a session: SOS/emergency → server receipts and revocations → newest messages → backfill.
- **FR-SYNC-04** **Resumable sessions:** a dropped connection loses at most the in-flight chunk. The next encounter resumes from the updated vectors.
- **FR-SYNC-05** **Storage quota & eviction:** per device (default 100 MB). Eviction order: expired → server-confirmed and older than retention window → lowest priority oldest. Eviction reports resulting sequence gaps in the version vector; re-fetching of evicted messages is permitted but bounded (`E_max` bounds re-sync loops).
- **FR-SYNC-06** **Adaptive PHY (Android):** use 1M/2M PHY when the link is strong and Coded PHY when weak or when scanning for distant peers.
- **FR-SYNC-07** **Per-peer reconnect cooldown & back-off:** when connection attempts to a peer fail, time out, or drop prematurely, the engine applies per-peer back-off/cooldown (in-memory state, starting clean on restart) to bound connect attempts (≤ 6 attempts/min per flapping peer) and prevent slot starvation (`maxConnections`). Cooldown resets upon a successfully completed sync session.
- **FR-SYNC-08** **Tiered peer history & retention:**
  - *Tier 1 (Raw token sightings):* anonymous rotating beacon tokens, seen timestamp, RSSI, transport; retained ≤ 24 hours with a hard row cap, pruned at startup and periodically.
  - *Tier 2 (Per-member daily statistics):* keyed by authenticated member public key; records daily session count, failure count, flap count, and bytes exchanged; retained for 90 days (configurable) with a hard row cap.
  - *Tier 3 (Ephemeral session/cooldown):* transient link quality, back-off timers; in-memory only.

### 4.5 Server & Gateway (FR-SRV)
- **FR-SRV-01** **One reference server** (PHP 8.2+ / MySQL, `ext-sodium`) implementing the protocol spec. Other backends are adapters that must pass the conformance suite.
- **FR-SRV-02** Any node with Internet automatically **pushes** all messages the server hasn't confirmed and **pulls** messages newer than its server vector.
- **FR-SRV-03** The server verifies certificate + signature, deduplicates by `message_id`, and returns **signed receipts** `{group_id, author, confirmed seq ranges}`.
- **FR-SRV-04** Receipts spread through the mesh so every device can show "server confirmed" and skip redundant uploads.
- **FR-SRV-05** Endpoints: `register`, `login` (returns certificate + group keys), `sync/push`, `sync/pull`, `receipts`, `revocations`. Defined in `protocol/openapi.yaml`.

### 4.6 Reference App (FR-APP)
- **FR-APP-01** BBS-style board: topics, threads, post form, location attach, SOS button.
- **FR-APP-02** Per-message status: `Local only` → `Handed to peer` → `Server confirmed`.
- **FR-APP-03** Peer radar: nearby peers (anonymised), link quality, last sync, current transport.
- **FR-APP-04** Onboarding: permission and battery-optimisation exemption guidance (Android OEMs).

## 5. Testing Requirements (FR-TEST)

Automated tests must not require physical hardware. Real devices are used only for occasional manual calibration.

- **FR-TEST-01** **Pure-Dart unit tests** for envelope, crypto, version vectors, framing, storage and engine state machines. Target ≥ 90% line coverage in `msgp2p_core`.
- **FR-TEST-02** **Deterministic discrete-event simulator** (`msgp2p_sim`) with a virtual clock, contact plans / mobility scenarios, and per-link bandwidth, MTU, loss and connection-time models. Runs 100 nodes × 8 simulated hours in CI in seconds.
- **FR-TEST-03** **Transport contract test suite:** one shared set of tests that every `P2PTransport` (fake, simulated, Android BLE, Wi-Fi Aware) must pass.
- **FR-TEST-04** **Native adapter unit tests** with platform APIs wrapped behind interfaces: Kotlin (JVM JUnit / Robolectric) and Swift (XCTest with protocol fakes; the iOS Simulator has no Bluetooth).
- **FR-TEST-05** **Android emulator integration tests:** two or more emulator instances connected through the emulator's virtual Bluetooth (netsim / Root-Canal), running in public GitHub Actions CI with hardware acceleration (KVM).
- **FR-TEST-06** **Manual calibration (not in CI):** a short checklist on real devices measures range, throughput, connection time and battery. Results update `msgp2p_sim` link profiles. (Optionally supported on a self-hosted physical device rack via adb).
- **FR-TEST-07** **Server conformance suite** driven by `protocol/test-vectors/`, run against the PHP server in CI (Docker MySQL).
- **FR-TEST-08** **In-Process Multi-Node Integration Harness:** Fast in-process test runner executing N real engine nodes on `FakeMedium` with virtual clock and seeded faults to verify convergence, partitions, mid-transfer drops/resumes, and simultaneous connect races before simulator and emulator runs.

## 6. Non-Functional Requirements

| ID | Requirement | Verification |
| :--- | :--- | :--- |
| NFR-PERF-01 | Session setup (connect → handshake → vectors exchanged) ≤ 3 s on 1M PHY | Emulator test + calibration |
| NFR-PERF-02 | Missing-range computation ≤ 50 ms for 20,000 messages | Dart benchmark |
| NFR-PERF-03 | Storage for 20,000 core messages ≤ 60 MB | Dart benchmark |
| NFR-REL-01 | Atomic ingestion (SQLite WAL, one transaction per batch) | Unit tests with crash injection |
| NFR-REL-02 | Zero message loss in simulator scenarios once a connected path existed before TTL | Simulator assertions |
| NFR-PWR-01 | Adaptive scan duty cycle with exponential back-off when no peers are seen | Unit tests on scheduler |
| NFR-PWR-02 | Battery budget is a **measured target** (goal: ≤ 10% per 8 h on reference Android device) | Manual calibration |
| NFR-PORT-01 | `msgp2p_core` and `msgp2p_sim` run on Linux, macOS, Windows Dart VM | CI matrix |