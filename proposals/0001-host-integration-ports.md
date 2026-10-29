# Proposal 0001: Host Integration Ports (modular SDK and server library)

> Status: **Draft for review** (2026-10-28). Requirement IDs refer to [requirements.md](../requirements.md).
> Scope: `packages/msgp2p_core`, `packages/msgp2p_flutter`, `server/php`, `protocol/`.
> Nothing here changes the wire format of existing envelopes, certificates, receipts or revocations.

## 1. Motivation

msgp2p is meant to be embedded in apps that **already have** a server, a sign-in system and local storage. The
first such host is a hunting-group app (Flutter + PHP 8.3 / MySQL on shared hosting) that wants to relay the
traffic of a running hunt (positions, short posts, SOS, map markers, reactions) between phones that are out of
coverage. Another likely host is a headless Linux node, such as an on-board computer of a drone.

Today several host-side decisions are built into the SDK, and each of them blocks such an app:

| Built in today | Where | Problem for a host app |
| :--- | :--- | :--- |
| Sign-in through msgp2p's own `/auth/register` and `/auth/login` | `GatewayClient.register/login` | The host already signs users in and decides who is a member. Two sign-in systems double the attack surface. |
| HTTP through `dart:io` `HttpClient`, with its own bearer token | `GatewayClient` | Bypasses the host's token refresh, version headers and error handling. Not usable on the web. |
| Identity keys made from fresh random seeds unless the app passes seeds | `MsgP2PNode.initialize` | Every host must invent safe key storage; a host that forgets gets a new identity at every start. FR-ID-01 asks for keys wrapped by the platform keystore, but no code provides it. |
| One store interface for envelopes, trust objects, attachments and peer history | `MessageStore` | A host cannot reuse its own SQLite stack (e.g. `sqflite`) without implementing ~25 methods at once. |
| SQLite only through `package:sqlite3` (FFI) | `SqliteMessageStore` | On Android the system SQLite cannot be loaded by apps, so a Flutter app must bundle a second SQLite library (`sqlite3_flutter_libs`) next to the one it may already ship, or write its own store. |
| The node (orchestration) in the Flutter package, with `AndroidBleTransport` as the default transport | `msgp2p_flutter/lib/src/node/msgp2p_node.dart` | A pure-Dart host (CLI, Linux on-board computer, server-side relay) cannot run a node. |
| The PHP server as one application (router, auth, SQL, crypto) and `ext-sodium` required | `server/php` | A host server cannot embed the protocol logic behind its own routes and SQL rules; shared hosting often has no `ext-sodium`. |

## 2. Goals and non-goals

**Goals**
1. A host can plug in its own **sign-in and membership**, **HTTP stack**, **key storage** and **storage engine**
   without forking.
2. `msgp2p_core` contains the whole node, so a node runs on any Dart VM (FR-SDK-01, NFR-PORT-01).
3. The PHP protocol logic is a **library** with no SQL, routing or global state; the reference server is a thin
   app on top of it.
4. Every port gets a **contract test suite**, like the existing `P2PTransport` suite (FR-TEST-03).
5. Existing apps keep working: today's classes stay as default adapters behind the new interfaces.

**Non-goals**
- No new cryptographic primitives and no change to the verification pipeline (wire-format §4.4).
- No change to the trust model (FR-SEC-09): the server stays trusted.

## 3. Ports (Dart, in `msgp2p_core`)

Sketches; names are open to review.

```dart
/// Long-lived identity keys of this device (FR-ID-01). The SDK never stores seeds itself.
abstract interface class KeyVault {
  /// The seeds, created and stored on first use. Implementations: Android Keystore / iOS Keychain
  /// (msgp2p_flutter), a file with 0600 permissions (Linux), memory (tests).
  Future<IdentitySeeds> loadOrCreate();
  Future<void> erase(); // sign-out, device reset
}

/// Where certificates, group keys and the beacon key come from (FR-ID-02, FR-SEC-02).
/// The reference implementation calls /auth/register + /auth/login; a host calls its own API.
abstract interface class MembershipSource {
  Future<MembershipGrant> fetch(GroupId group, MemberPublicKeys keys);
}

class MembershipGrant {
  final MembershipCert cert;
  final Map<int, Uint8List> groupKeys; // epoch -> key
  final Uint8List beaconKey;
  final DateTime refreshAfter;
}

/// The gateway operations (FR-SRV-02..05), independent of how HTTP is done.
abstract interface class GatewayApi {
  Future<PushResult> push(GroupId group, List<Envelope> envelopes);
  Future<PullResult> pull(GroupId group, VersionVector serverVector, {int? limit});
  Future<List<ServerReceipt>> receipts(GroupId group, {int? since});
  Future<List<RevocationNotice>> revocations(GroupId group, {int? since});
  Future<void> uploadAttachment(GroupId group, AttachmentRef ref, Uint8List bytes);
  Future<StoredAttachmentBlob> downloadAttachment(GroupId group, AttachmentRef ref);
}

/// The only thing the default GatewayApi needs from the host: send a request, get bytes back.
/// Default: dart:io. A host passes its own client (auth headers, refresh, retries, proxies).
abstract interface class HttpExecutor {
  Future<HttpReply> send(String method, Uri url, {Map<String, String> headers, Uint8List? body});
}
```

**Store split.** `MessageStore` becomes the composite of four smaller interfaces, so a host can implement one
at a time and reuse the defaults for the rest:

| Interface | Methods (today's names) |
| :--- | :--- |
| `EnvelopeStore` | `saveEnvelope`, `saveBatch`, `getEnvelope`, `containsEnvelope`, `isSequenceHeld`, `getEnvelopesByAuthorAndRanges`, `getVersionVector`, `getEnvelopeCount`, `prune` |
| `TrustStore` | `saveReceipt`, `getConfirmedRanges`, `isConfirmed`, `getReceipts`, `saveCertificate`, `getCertificate`, `saveRevocation`, `isRevoked`, `getRevocations` |
| `AttachmentStore` | `saveAttachmentBlob`, `getAttachmentBlob`, `containsAttachmentBlob`, `getMissingAttachments` |
| `PeerHistoryStore` | `recordPeerSighting`, `getRecentPeerSightings`, `recordPeerDailyStat`, `getPeerDailyStats`, `prunePeerHistory` |

`abstract interface class MessageStore implements EnvelopeStore, TrustStore, AttachmentStore, PeerHistoryStore {}`
keeps every current implementation and caller compiling.

**The node moves to core.** `MsgP2PNode`'s orchestration (session start, gateway sync, decrypt-on-read, status
tracking) moves to `msgp2p_core` as `MsgP2PEngine`, built only from ports. `msgp2p_flutter` keeps
`MsgP2PNode.initialize(...)` as a thin wrapper that fills in Flutter defaults (BLE transport, keystore vault), so
the public API of the Flutter package does not change.

## 4. Packages

```
msgp2p_core              protocol, crypto, engine, ports; pure Dart (unchanged rule: no Flutter imports)
msgp2p_sim               simulator (unchanged)
msgp2p_flutter           radios (BLE, Wi-Fi Aware) + KeyVault on Keystore/Keychain + MsgP2PNode wrapper
msgp2p_store_sqlite3     today's SqliteMessageStore (FFI; desktop, CLI, tests; Flutter apps add a bundled lib)
msgp2p_store_sqflite     the same schema on sqflite, for Flutter apps that already ship it
msgp2p_gateway_http      today's GatewayClient as GatewayApi + HttpExecutor (dart:io default)
msgp2p_reference_auth    MembershipSource for the reference server's /auth/register + /auth/login
```

Each adapter package depends on `msgp2p_core` only. The core keeps an in-memory store and no HTTP code, so it
stays free of I/O choices. The schema of both SQLite stores is the one in architecture.md §6, with a shared
migration test.

## 5. PHP: protocol library + thin reference server

```
server/php-lib/ (Composer package, PHP 8.2+, declare(strict_types=1), no SQL, no routing)
  Cbor, Envelope verification (wire-format §4.4), cert / receipt / revocation signing, pull paging, receipt
  range compaction
  interfaces:
    EnvelopeRepository   insertIfNew(id, author, seq, raw), heldRanges(author), after(vector, limit)
    MemberDirectory      memberOf(group, pubkey) -> role|null, revoked(group) -> list
    ServerKeys           certSigningKey(), serverAuthorKey(), groupKey(group, epoch)
    Crypto               Ed25519 sign/verify, XChaCha20-Poly1305: SodiumCrypto (ext-sodium, or the
                         paragonie/sodium_compat polyfill on hosts without the extension)
server/php/ (reference server) = Router + Auth + PDO repositories + the library
```

A host server implements the four interfaces with its own repositories and exposes the endpoints behind its
own routes and sign-in. The conformance suite (FR-TEST-07) runs against the library and the reference server.
The library prefers `ext-sodium` and falls back to `sodium_compat`, so it runs on shared hosting; the cost of
the pure-PHP path is measured in CI and documented.

## 6. Protocol additions

### P1. Server-authored envelopes (server → mesh fan-out)
Messages that reach the server over plain HTTP (from members who are online) should also reach offline
members through the mesh. The server gets an **author identity of its own**:

- a separate Ed25519 key (`serverAuthorKey`, never the certificate-signing key), with a membership certificate
  issued by the pinned server key, `role: 2` (server), one per group;
- its own monotonic `seq`, encrypted under the group key like any member's envelope;
- gateways pull these envelopes like any other, and peers relay them unchanged.

The verification pipeline (wire-format §4.4) does not change: the certificate is checked like every other one.
Only the `role` enumeration grows (`2 = server`). Envelopes the server received from members are **not**
re-authored; only content that never was an envelope is.

### P2. Group lifecycle
For groups with a known end (an event, a hunt):

- certificates may expire at the group's end plus a margin instead of the default 7 days (already allowed by
  `expires_at`; documented as a pattern);
- a new server-signed **group notice** `{v, group_id, kind: "closed", at, server_sig}` spreads like a
  revocation (priority 1). A node that verifies it stops advertising for the group and deletes the group's
  stored envelopes, keys and certificates, so relayed messages do not stay on phones after the event.

### P3. Short-lived message classes
Position fixes are only useful for minutes, but full replication keeps every one until it expires. Proposal:
document lifetime classes (e.g. position 15 min, posts 24 h, SOS 72 h) that apps set through `expires_at`;
**no wire change**. A "replaceable" field (a newer envelope of the same author and slot makes older ones
unnecessary) is deferred: it would have to be inside the signed core, and the version vectors would need to
treat superseded sequences as held. Revisit it only if measurements show positions crowding out posts.

### P4. Write-only members (devices that report but must not read)
Some members are devices, not people: a phone on a hunting dog's collar, a drone. They report their own
position and should relay the group's traffic (a dog runs between people), but they never need to read it, and
a lost device should not carry the group's messages in readable form.

- The server issues **two keys per group**: the group key (people) and a **tracker key** (devices), each with
  its own `key_epoch` values (e.g. a reserved range or a key-class field in the grant, not in the envelope).
- People get both keys and read everything. A device gets only the tracker key: it encrypts its own envelopes
  with it and **relays all other envelopes without decrypting them**, which the verification pipeline already
  allows (wire-format §4.4 needs no group key).
- The certificate gets `role: 3` (tracker), so apps can show such authors differently and the server can refuse
  content types a tracker must not author (e.g. posts).
- No wire change: `key_epoch` already selects the key; only key distribution (`MembershipSource` /
  `/auth/login`) and the `role` enumeration grow. Rotating either key on membership change works as today.

## 7. Migration plan (small PRs, each with tests)

| PR | Content | Compatibility |
| :--- | :--- | :--- |
| 1 | This proposal | — |
| 2 | `KeyVault` port; `MsgP2PNode.initialize` uses it (seeds still accepted) | additive |
| 3 | `HttpExecutor` + `GatewayApi`; `GatewayClient` becomes the default adapter | additive |
| 4 | `MembershipSource`; register/login move behind it (`msgp2p_reference_auth`) | `GatewayClient.register/login` deprecated, kept one minor version |
| 5 | Store split + contract suites for each store interface | additive (`MessageStore` = composite) |
| 6 | `msgp2p_store_sqlite3` and `msgp2p_store_sqflite` packages | `SqliteMessageStore` re-exported from core for one minor version |
| 7 | `MsgP2PEngine` in core; `MsgP2PNode` becomes the Flutter wrapper | public API unchanged |
| 8 | `server/php-lib` + reference server on top of it; `sodium_compat` fallback | endpoints unchanged |
| 9 | P1 server-authored envelopes (vectors, Dart, PHP, simulator scenario) | `role` enum grows |
| 10 | P2 group notice (vectors, Dart, PHP, simulator scenario) | new message kind |
| 11 | P4 write-only members: tracker key class, `role: 3`, blind relaying test (a tracker relays what it cannot read) | `role` enum grows |

## 8. Tests

- One contract suite per port (`KeyVault`, `MembershipSource`, `GatewayApi`, each store interface), run against
  every adapter, as the `P2PTransport` contract suite does today.
- The PHP library runs the existing `protocol/test-vectors/` with both `SodiumCrypto` backends.
- Simulator scenarios for P1 (an online member's post reaching an offline member through a gateway) and P2
  (the closed notice removing the group's data from every node within the scenario).

## 9. Open questions

1. Should `MembershipSource` also deliver **revocations** and key-epoch changes (push), or do nodes keep
   pulling `/sync/revocations`?
2. Package count: is one `msgp2p_adapters` package with conditional imports preferable to several small ones?
3. P1: one server author per group, or one per server with the group in the certificate only?
4. P4: how is a key's class (group / tracker) carried in the grant: a reserved `key_epoch` range, or a field
   next to each key?
5. Should the 4 KB envelope limit stay a protocol constant, with long texts truncated by the app, or should a
   multi-part message kind be specified?
