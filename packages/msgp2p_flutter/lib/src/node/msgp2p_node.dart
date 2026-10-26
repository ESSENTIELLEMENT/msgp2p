import 'dart:async';
import 'dart:typed_data';
import 'package:convert/convert.dart';
import 'package:cryptography/cryptography.dart' as cg;
import 'package:meta/meta.dart';
import 'package:msgp2p_core/msgp2p_core.dart';
import '../transport/android_ble_transport.dart';
import '../transport/ios_ble_transport.dart';
import '../transport/wifi_aware_transport.dart';

/// Per-message delivery status badge states (FR-APP-02).
enum MessageDeliveryStatus {
  /// Stored locally on this device; not yet replicated to any peer or server.
  localOnly('Local only'),

  /// Replicated to at least one nearby mesh peer over BLE / Wi-Fi Aware.
  handedToPeer('Handed to peer'),

  /// Confirmed stored on the group server via a signed [ServerReceipt].
  serverConfirmed('Server confirmed');

  final String label;
  const MessageDeliveryStatus(this.label);
}

/// Priority levels for published messages (FR-SYNC-03).
enum Priority {
  sos(0),
  high(1),
  normal(2),
  low(3);

  final int code;
  const Priority(this.code);
}

/// Decrypted application-level message emitted by [MsgP2PNode] (FR-SDK-04).
@immutable
class DecryptedMessage {
  final Uint8List messageId;
  final String messageIdHex;
  final Uint8List authorPubkey;
  final String authorShortId;
  final int seq;
  final int createdAt;
  final int expiresAt;
  final int priority;
  final String type;
  final Map<String, dynamic> body;
  final List<AttachmentRef> attachments;
  final MessageDeliveryStatus status;

  const DecryptedMessage({
    required this.messageId,
    required this.messageIdHex,
    required this.authorPubkey,
    required this.authorShortId,
    required this.seq,
    required this.createdAt,
    required this.expiresAt,
    required this.priority,
    required this.type,
    required this.body,
    this.attachments = const [],
    required this.status,
  });

  bool get isSos => priority == 0 || type == 'sos' || type == 'sos_alert';

  DecryptedMessage copyWith({MessageDeliveryStatus? status}) {
    return DecryptedMessage(
      messageId: messageId,
      messageIdHex: messageIdHex,
      authorPubkey: authorPubkey,
      authorShortId: authorShortId,
      seq: seq,
      createdAt: createdAt,
      expiresAt: expiresAt,
      priority: priority,
      type: type,
      body: body,
      attachments: attachments,
      status: status ?? this.status,
    );
  }
}

/// Diagnostic peer entry displayed on the Peer Radar screen (FR-APP-03).
@immutable
class DiscoveredPeerInfo {
  final String address;
  final String rotatingTokenHex;
  final int rssi;
  final String activePhy;
  final DateTime lastSeen;
  final DateTime? lastSyncedAt;

  const DiscoveredPeerInfo({
    required this.address,
    required this.rotatingTokenHex,
    required this.rssi,
    required this.activePhy,
    required this.lastSeen,
    this.lastSyncedAt,
  });

  DiscoveredPeerInfo copyWith({
    int? rssi,
    String? activePhy,
    DateTime? lastSeen,
    DateTime? lastSyncedAt,
  }) {
    return DiscoveredPeerInfo(
      address: address,
      rotatingTokenHex: rotatingTokenHex,
      rssi: rssi ?? this.rssi,
      activePhy: activePhy ?? this.activePhy,
      lastSeen: lastSeen ?? this.lastSeen,
      lastSyncedAt: lastSyncedAt ?? this.lastSyncedAt,
    );
  }
}

/// Configuration for initializing a [MsgP2PNode] (FR-SDK-04).
@immutable
class MsgP2PConfig {
  final Uri serverEndpoint;
  final Uint8List serverPublicKey;
  final Uint8List groupId;
  final Duration defaultMessageTtl;

  const MsgP2PConfig({
    required this.serverEndpoint,
    required this.serverPublicKey,
    required this.groupId,
    this.defaultMessageTtl = const Duration(hours: 24),
  });
}

/// High-level payload-agnostic Flutter SDK facade for `msgp2p` (FR-SDK-04).
class MsgP2PNode {
  final MsgP2PConfig config;
  final MessageStore store;
  final P2PTransport transport;
  final WifiAwareTransport? wifiAwareTransport;
  final GatewayClient gatewayClient;
  final Clock clock;
  final RandomSource randomSource;

  final cg.SimpleKeyPair signingKeyPair;
  final Uint8List memberPubkey;
  final cg.SimpleKeyPair noiseKeyPair;
  final Uint8List noisePubkey;

  MembershipCert? _membershipCert;
  Uint8List? _groupBeaconKey;
  final Map<int, Uint8List> _groupKeysByEpoch = {};
  int _activeKeyEpoch = 1;
  int _localSeq = 0;

  final Set<String> _handedToPeerMessageIds = {};
  final Map<String, DiscoveredPeerInfo> _peersByAddress = {};
  final List<Envelope> _knownEnvelopes = [];
  final Map<String, (String, Map<String, dynamic>)> _decryptedPayloadCache = {};

  final StreamController<List<DecryptedMessage>> _messagesController =
      StreamController<List<DecryptedMessage>>.broadcast();
  final StreamController<List<DiscoveredPeerInfo>> _peersController =
      StreamController<List<DiscoveredPeerInfo>>.broadcast();

  StreamSubscription<PeerAdvert>? _discoveredSub;
  StreamSubscription<PeerLink>? _incomingSub;

  MsgP2PNode._({
    required this.config,
    required this.store,
    required this.transport,
    this.wifiAwareTransport,
    required this.gatewayClient,
    required this.clock,
    required this.randomSource,
    required this.signingKeyPair,
    required this.memberPubkey,
    required this.noiseKeyPair,
    required this.noisePubkey,
  }) {
    _discoveredSub = transport.discovered.listen(_onPeerDiscovered);
    _incomingSub = transport.incoming.listen(_onIncomingPeerLink);
  }

  /// Initializes a [MsgP2PNode] instance (FR-SDK-04).
  static Future<MsgP2PNode> initialize({
    required MsgP2PConfig config,
    MessageStore? store,
    P2PTransport? transport,
    WifiAwareTransport? wifiAwareTransport,
    GatewayClient? gatewayClient,
    Clock? clock,
    RandomSource? randomSource,
    Uint8List? signingSeed,
    Uint8List? noiseSeed,
    MembershipCert? initialCert,
    Map<int, Uint8List>? initialGroupKeys,
    Uint8List? initialBeaconKey,
  }) async {
    final rng = randomSource ?? SystemRandomSource();
    final signKp =
        await MsgP2PCrypto.newKeyPairFromSeed(signingSeed ?? rng.nextBytes(32));
    final memberPk = await MsgP2PCrypto.getPublicKeyBytes(signKp);

    final noiseKp =
        await cg.X25519().newKeyPairFromSeed(noiseSeed ?? rng.nextBytes(32));
    final noisePk = await NoiseHandshake.getPublicKeyBytes(noiseKp);

    final nodeStore = store ?? MemoryMessageStore();
    final nodeTransport = transport ?? AndroidBleTransport();
    final nodeGateway = gatewayClient ??
        GatewayClient(baseUrl: config.serverEndpoint.toString());

    final node = MsgP2PNode._(
      config: config,
      store: nodeStore,
      transport: nodeTransport,
      wifiAwareTransport: wifiAwareTransport,
      gatewayClient: nodeGateway,
      clock: clock ?? const SystemClock(),
      randomSource: rng,
      signingKeyPair: signKp,
      memberPubkey: memberPk,
      noiseKeyPair: noiseKp,
      noisePubkey: noisePk,
    );

    if (initialCert != null) {
      node._membershipCert = initialCert;
      await nodeStore.saveCertificate(initialCert);
    }
    if (initialGroupKeys != null && initialGroupKeys.isNotEmpty) {
      node._groupKeysByEpoch.addAll(initialGroupKeys);
      node._activeKeyEpoch =
          initialGroupKeys.keys.reduce((a, b) => a > b ? a : b);
    }
    if (initialBeaconKey != null) {
      node._groupBeaconKey = initialBeaconKey;
    }

    return node;
  }

  MembershipCert? get membershipCert => _membershipCert;
  int get activeKeyEpoch => _activeKeyEpoch;
  String get memberShortId => hex.encode(memberPubkey).substring(0, 8);

  /// Stream of all decrypted messages ordered by SOS priority then newest first.
  Stream<List<DecryptedMessage>> get messagesStream =>
      _messagesController.stream;

  /// Stream of nearby discovered peers for the Peer Radar UI (FR-APP-03).
  Stream<List<DiscoveredPeerInfo>> get peersStream => _peersController.stream;

  /// Current snapshot of discovered peers.
  List<DiscoveredPeerInfo> get currentPeers {
    final list = _peersByAddress.values.toList()
      ..sort((a, b) => b.lastSeen.compareTo(a.lastSeen));
    return list;
  }

  /// Registers this device's Ed25519 & X25519 public keys with the group server (FR-ID-02).
  Future<RegisterResult> register({
    required String username,
    required String password,
  }) async {
    return gatewayClient.register(
      username: username,
      password: password,
      groupId: hex.encode(config.groupId),
      memberPubkey: memberPubkey,
      noisePubkey: noisePubkey,
    );
  }

  /// Authenticates with the server and provisions membership certificate + group keys (FR-ID-02, FR-SEC-02).
  Future<LoginResult> login({
    required String username,
    required String password,
  }) async {
    final res =
        await gatewayClient.login(username: username, password: password);
    _membershipCert = res.membershipCert;
    _groupBeaconKey = res.groupBeaconKey;
    await store.saveCertificate(res.membershipCert);

    for (final k in res.groupKeys) {
      _groupKeysByEpoch[k.epoch] = Uint8List.fromList(hex.decode(k.keyHex));
      if (k.epoch > _activeKeyEpoch) {
        _activeKeyEpoch = k.epoch;
      }
    }
    return res;
  }

  /// Starts BLE advertising (with rotating HMAC beacon token) and scanning (`FR-SEC-07`).
  Future<void> startMeshRadio({ScanPolicy policy = const ScanPolicy()}) async {
    final beaconKey = _groupBeaconKey ?? Uint8List(32);
    final nowSec = clock.now().millisecondsSinceEpoch ~/ 1000;
    final token =
        BeaconTokenGenerator(groupBeaconKey: beaconKey).generateToken(nowSec);
    await transport.startAdvertising(token);
    await transport.startScanning(policy);
  }

  /// Stops BLE advertising and scanning.
  Future<void> stopMeshRadio() async {
    await transport.stop();
  }

  /// Publishes a signed, group-encrypted message envelope (`FR-SDK-04`, `FR-SEC-01..04`),
  /// optionally storing and referencing hash-addressed [attachments] (`v0.2`).
  Future<Envelope> publish({
    required String type,
    required Map<String, dynamic> body,
    Priority priority = Priority.normal,
    Duration? ttl,
    List<({Uint8List bytes, String mime})>? attachments,
  }) async {
    final cert = _membershipCert;
    if (cert == null) {
      throw StateError('Cannot publish before provisioning a MembershipCert');
    }
    final groupKey = _groupKeysByEpoch[_activeKeyEpoch];
    if (groupKey == null) {
      throw StateError('No group key available for epoch $_activeKeyEpoch');
    }

    _localSeq++;
    final nowMs = clock.now().millisecondsSinceEpoch;
    List<AttachmentRef>? attachmentRefs;
    if (attachments != null && attachments.isNotEmpty) {
      attachmentRefs = <AttachmentRef>[];
      for (final att in attachments) {
        final ref = AttachmentRef.fromBytes(bytes: att.bytes, mime: att.mime);
        attachmentRefs.add(ref);
        await store.saveAttachmentBlob(
          hash: ref.hash,
          mime: att.mime,
          bytes: att.bytes,
          customStoredAt: nowMs,
        );
      }
    }

    final payloadMap = <String, dynamic>{
      'type': type,
      'body': body,
    };

    final env = await Envelope.create(
      groupId: config.groupId,
      keyEpoch: _activeKeyEpoch,
      groupKey: groupKey,
      authorKeyPair: signingKeyPair,
      certRef: cert.certRef,
      seq: _localSeq,
      payload: payloadMap,
      priority: priority.code,
      ttl: ttl ?? config.defaultMessageTtl,
      attachments: attachmentRefs,
      customCreatedAt: nowMs,
      randomSource: randomSource,
    );

    await store.saveEnvelope(env, customStoredAt: nowMs);
    _decryptedPayloadCache[hex.encode(env.messageId)] =
        (type, Map<String, dynamic>.from(body));
    _trackEnvelope(env);
    await _emitUpdatedMessages();
    return env;
  }

  /// Retrieves a stored hash-addressed attachment blob by its 32-byte SHA-256 [hash].
  Future<StoredAttachmentBlob?> getAttachmentBlob(Uint8List hash) {
    return store.getAttachmentBlob(hash);
  }

  /// Initiates a Noise-XX encrypted P2P sync session with [peer] (`FR-SYNC-02..04`).
  Future<SessionSyncResult> syncWithPeer(PeerAdvert peer) async {
    final cert = _membershipCert;
    if (cert == null) {
      throw StateError('Cannot sync with peer without a local MembershipCert');
    }

    final link = await transport.connect(peer);
    final sm = SessionStateMachine(
      store: store,
      link: link,
      isInitiator: true,
      staticKeyPair: noiseKeyPair,
      localCert: cert,
      pinnedServerKey: config.serverPublicKey,
      expectedGroupId: config.groupId,
      clock: clock,
      transferAttachments: transport.capabilities.supportsBulk,
    );

    final result = await sm.run();
    if (result.completedSuccessfully) {
      for (final env in _knownEnvelopes) {
        _handedToPeerMessageIds.add(hex.encode(env.messageId));
      }
      final existingPeer = _peersByAddress[peer.peerAddress];
      if (existingPeer != null) {
        _peersByAddress[peer.peerAddress] =
            existingPeer.copyWith(lastSyncedAt: clock.now());
        _emitPeers();
      }
      await _refreshKnownEnvelopesFromStore();
      await _emitUpdatedMessages();
    }
    return result;
  }

  /// Synchronizes with another [MsgP2PNode] directly over a shared medium (convenience for multi-node tests/demos).
  Future<SessionSyncResult> syncDirectlyWithNode(
    MsgP2PNode peerNode, {
    String? peerAddress,
    bool runTransportSession = true,
  }) async {
    final targetAddr = peerAddress ?? peerNode.memberShortId;
    final beaconKey = _groupBeaconKey ?? Uint8List(32);
    final nowSec = clock.now().millisecondsSinceEpoch ~/ 1000;
    final token =
        BeaconTokenGenerator(groupBeaconKey: beaconKey).generateToken(nowSec);

    final advert = PeerAdvert(
      peerAddress: targetAddr,
      token: token,
      rssi: -60,
      hints: const {'phy': 'le_2m'},
    );
    _onPeerDiscovered(advert);

    SessionSyncResult? res;
    if (runTransportSession) {
      res = await syncWithPeer(advert);
    }

    var sent = 0;
    var received = 0;
    var attachmentsSent = 0;
    var attachmentsReceived = 0;
    final canTransferAttachments = transport.capabilities.supportsBulk ||
        (wifiAwareTransport != null && peerNode.wifiAwareTransport != null);

    for (final env in List<Envelope>.from(_knownEnvelopes)) {
      final idHex = hex.encode(env.messageId);
      await peerNode.store.saveEnvelope(env);
      if (_decryptedPayloadCache.containsKey(idHex)) {
        peerNode._decryptedPayloadCache[idHex] = _decryptedPayloadCache[idHex]!;
      }
      if (canTransferAttachments && env.core.attachments != null) {
        for (final att in env.core.attachments!) {
          final blob = await store.getAttachmentBlob(att.hash);
          if (blob != null) {
            final saved = await peerNode.store.saveAttachmentBlob(
              hash: blob.hash,
              mime: blob.mime,
              bytes: blob.bytes,
            );
            if (saved) attachmentsSent++;
          }
        }
      }
      peerNode._trackEnvelope(env);
      peerNode._handedToPeerMessageIds.add(idHex);
      _handedToPeerMessageIds.add(idHex);
      sent++;
    }
    for (final env in List<Envelope>.from(peerNode._knownEnvelopes)) {
      final idHex = hex.encode(env.messageId);
      await store.saveEnvelope(env);
      if (peerNode._decryptedPayloadCache.containsKey(idHex)) {
        _decryptedPayloadCache[idHex] = peerNode._decryptedPayloadCache[idHex]!;
      }
      if (canTransferAttachments && env.core.attachments != null) {
        for (final att in env.core.attachments!) {
          final blob = await peerNode.store.getAttachmentBlob(att.hash);
          if (blob != null) {
            final saved = await store.saveAttachmentBlob(
              hash: blob.hash,
              mime: blob.mime,
              bytes: blob.bytes,
            );
            if (saved) attachmentsReceived++;
          }
        }
      }
      _trackEnvelope(env);
      _handedToPeerMessageIds.add(idHex);
      peerNode._handedToPeerMessageIds.add(idHex);
      received++;
    }
    final existingPeer = _peersByAddress[targetAddr];
    if (existingPeer != null) {
      _peersByAddress[targetAddr] = existingPeer.copyWith(
        lastSyncedAt: clock.now(),
        activePhy: (attachmentsSent > 0 || attachmentsReceived > 0)
            ? 'wifi_aware'
            : existingPeer.activePhy,
      );
      _emitPeers();
    }
    if (attachmentsSent > 0 || attachmentsReceived > 0) {
      await wifiAwareTransport?.teardownAfterTransfer();
      await peerNode.wifiAwareTransport?.teardownAfterTransfer();
    }
    await _emitUpdatedMessages();
    await peerNode._emitUpdatedMessages();
    return res ??
        SessionSyncResult(
          envelopesSent: sent,
          envelopesReceived: received,
          attachmentsSent: attachmentsSent,
          attachmentsReceived: attachmentsReceived,
          completedSuccessfully: true,
        );
  }

  /// Synchronizes unconfirmed messages, receipts, and revocations with the HTTPS gateway (`FR-SRV-02`).
  Future<SyncResult> syncWithGateway() async {
    final unconfirmed = <Envelope>[];
    for (final env in _knownEnvelopes) {
      if (!await store.isConfirmed(env.core.author, env.core.seq)) {
        unconfirmed.add(env);
      }
    }

    final syncRes = await gatewayClient.sync(
      store: store,
      groupId: config.groupId,
      pendingEnvelopes: unconfirmed,
    );

    await _refreshKnownEnvelopesFromStore();
    await _emitUpdatedMessages();
    return syncRes;
  }

  /// Marks a message (or author sequence range) as confirmed via a signed [ServerReceipt].
  Future<void> applyServerReceipt(ServerReceipt receipt) async {
    await store.saveReceipt(receipt);
    await _emitUpdatedMessages();
  }

  /// Returns the current list of decrypted messages with up-to-date [MessageDeliveryStatus].
  Future<List<DecryptedMessage>> getDecryptedMessages() async {
    final results = <DecryptedMessage>[];
    for (final env in _knownEnvelopes) {
      final groupKey = _groupKeysByEpoch[env.core.keyEpoch];
      if (groupKey == null) continue;

      try {
        final idHex = hex.encode(env.messageId);
        var type = 'message';
        var body = <String, dynamic>{};

        final cached = _decryptedPayloadCache[idHex];
        if (cached != null) {
          type = cached.$1;
          body = cached.$2;
        } else {
          final plainBytes = await env.decryptPayloadCbor(groupKey);
          final decoded = CanonicalCbor.decode(plainBytes);
          if (decoded is Map) {
            if (decoded.containsKey('type') && decoded['body'] is Map) {
              type = decoded['type'].toString();
              body = (decoded['body'] as Map).cast<String, dynamic>();
            } else {
              body = decoded.cast<String, dynamic>();
            }
          }
          _decryptedPayloadCache[idHex] = (type, body);
        }

        final confirmed =
            await store.isConfirmed(env.core.author, env.core.seq);
        final status = confirmed
            ? MessageDeliveryStatus.serverConfirmed
            : (_handedToPeerMessageIds.contains(idHex)
                ? MessageDeliveryStatus.handedToPeer
                : MessageDeliveryStatus.localOnly);

        results.add(DecryptedMessage(
          messageId: env.messageId,
          messageIdHex: idHex,
          authorPubkey: env.core.author,
          authorShortId: hex.encode(env.core.author).substring(0, 8),
          seq: env.core.seq,
          createdAt: env.core.createdAt,
          expiresAt: env.core.expiresAt,
          priority: env.core.priority,
          type: type,
          body: body,
          attachments: env.core.attachments ?? const [],
          status: status,
        ));
      } catch (_) {
        // Ignore envelopes encrypted with unknown key epochs
      }
    }

    // Sort: SOS (priority 0) first, then newest created_at first
    results.sort((a, b) {
      if (a.isSos != b.isSos) {
        return a.isSos ? -1 : 1;
      }
      final pCmp = a.priority.compareTo(b.priority);
      if (pCmp != 0) return pCmp;
      return b.createdAt.compareTo(a.createdAt);
    });

    return results;
  }

  void _trackEnvelope(Envelope env) {
    final idHex = hex.encode(env.messageId);
    if (!_knownEnvelopes.any((e) => hex.encode(e.messageId) == idHex)) {
      _knownEnvelopes.add(env);
    }
  }

  Future<void> _refreshKnownEnvelopesFromStore() async {
    final vv = await store.getVersionVector();
    for (final entry in vv.authors.entries) {
      final authorBytes = Uint8List.fromList(hex.decode(entry.key));
      final maxSeq = entry.value.gaps.isEmpty
          ? entry.value.contiguous
          : entry.value.gaps.reduce((a, b) => a > b ? a : b);
      if (maxSeq > 0) {
        final envs = await store.getEnvelopesByAuthorAndRanges(
          authorBytes,
          [SeqRange(1, maxSeq)],
        );
        for (final env in envs) {
          _trackEnvelope(env);
        }
      }
    }
  }

  Future<void> _emitUpdatedMessages() async {
    if (_messagesController.isClosed) return;
    final list = await getDecryptedMessages();
    if (!_messagesController.isClosed) {
      _messagesController.add(list);
    }
  }

  void _onPeerDiscovered(PeerAdvert advert) {
    final tokenHex = hex.encode(advert.token);
    final shortToken =
        tokenHex.length > 12 ? tokenHex.substring(0, 12) : tokenHex;
    final existing = _peersByAddress[advert.peerAddress];
    final phyHint = advert.hints['phy']?.toString() ?? 'le_coded_s8';
    _peersByAddress[advert.peerAddress] = DiscoveredPeerInfo(
      address: advert.peerAddress,
      rotatingTokenHex: shortToken,
      rssi: advert.rssi,
      activePhy: phyHint,
      lastSeen: clock.now(),
      lastSyncedAt: existing?.lastSyncedAt,
    );
    _emitPeers();
  }

  void _emitPeers() {
    if (!_peersController.isClosed) {
      _peersController.add(currentPeers);
    }
  }

  void _onIncomingPeerLink(PeerLink link) {
    final cert = _membershipCert;
    if (cert == null) {
      unawaited(link.close());
      return;
    }

    final sm = SessionStateMachine(
      store: store,
      link: link,
      isInitiator: false,
      staticKeyPair: noiseKeyPair,
      localCert: cert,
      pinnedServerKey: config.serverPublicKey,
      expectedGroupId: config.groupId,
      clock: clock,
      transferAttachments: transport.capabilities.supportsBulk,
    );

    unawaited(sm.run().then((res) async {
      if (res.completedSuccessfully) {
        for (final env in _knownEnvelopes) {
          _handedToPeerMessageIds.add(hex.encode(env.messageId));
        }
        await _refreshKnownEnvelopesFromStore();
        await _emitUpdatedMessages();
      }
    }));
  }

  /// Disposes the node, transport, and streams.
  Future<void> dispose() async {
    await _discoveredSub?.cancel();
    await _incomingSub?.cancel();
    await transport.stop();
    if (transport is AndroidBleTransport) {
      await (transport as AndroidBleTransport).dispose();
    } else if (transport is IosBleTransport) {
      await (transport as IosBleTransport).dispose();
    } else if (transport is WifiAwareTransport) {
      await (transport as WifiAwareTransport).dispose();
    }
    await wifiAwareTransport?.dispose();
    gatewayClient.close();
    await _messagesController.close();
    await _peersController.close();
  }
}
