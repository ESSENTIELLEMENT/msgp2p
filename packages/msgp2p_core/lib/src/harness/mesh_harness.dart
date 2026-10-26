import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';
import 'package:convert/convert.dart';
import 'package:cryptography/cryptography.dart' as cg;
import '../crypto/crypto.dart';
import '../crypto/noise_handshake.dart';
import '../crypto/random_source.dart';
import '../encoding/canonical_cbor.dart';
import '../model/certificate.dart';
import '../model/envelope.dart';
import '../model/receipt.dart';
import '../model/revocation.dart';
import '../model/version_vector.dart';
import '../storage/memory_message_store.dart';
import '../storage/message_store.dart';
import '../sync/clock_rules.dart';
import '../sync/peer_cooldown_tracker.dart';
import '../sync/session_state_machine.dart';
import '../transport/fake_transport.dart';
import '../transport/transport.dart';
import 'scenario.dart';

/// Mutable virtual clock supporting deterministic advances and jumps (IT-FI-11).
class MutableClock implements Clock {
  DateTime _now;

  MutableClock([DateTime? initial])
      : _now = (initial ??
                DateTime.fromMillisecondsSinceEpoch(1700000000000, isUtc: true))
            .toUtc();

  @override
  DateTime now() => _now;

  void advance(Duration delta) {
    _now = _now.add(delta);
  }

  void jump(Duration offset) {
    _now = _now.add(offset);
  }

  void setNow(DateTime time) {
    _now = time.toUtc();
  }
}

/// Per-node clock wrapper applying a deterministic clock skew (IT-FI-08).
class NodeClock implements Clock {
  final Clock baseClock;
  int skewMs;

  NodeClock(this.baseClock, [this.skewMs = 0]);

  @override
  DateTime now() {
    final targetMs = baseClock.now().millisecondsSinceEpoch + skewMs;
    return DateTime.fromMillisecondsSinceEpoch(targetMs < 0 ? 0 : targetMs,
        isUtc: true);
  }
}

/// Event categories for structured multi-node trace logging (FR-TEST-08, IT-OBS-01).
enum MeshEventType {
  published('published'),
  received('received'),
  stored('stored'),
  evicted('evicted'),
  sessionStart('session_start'),
  sessionEnd('session_end'),
  revocationApplied('revocation_applied'),
  receiptApplied('receipt_applied'),
  linkCut('link_cut'),
  connectAttempt('connect_attempt'),
  connectRejected('connect_rejected'),
  frameSent('frame_sent'),
  envelopeReceived('envelope_received'),
  serverPush('server_push'),
  serverPull('server_pull'),
  linkClosed('link_closed'),
  slotState('slot_state');

  final String wireName;
  const MeshEventType(this.wireName);

  static MeshEventType fromWireName(String value) {
    for (final t in MeshEventType.values) {
      if (t.wireName == value || t.name == value) {
        return t;
      }
    }
    throw ArgumentError('Unknown MeshEventType: $value');
  }
}

/// A structured event recorded during multi-node mesh execution (JSONL trace schema).
class MeshTraceEvent {
  final int timestamp;
  final String nodeId;
  final MeshEventType type;
  final String? messageId;
  final String? peerId;
  final int? priority;
  final int? bytes;
  final Map<String, dynamic> metadata;

  MeshTraceEvent({
    required this.timestamp,
    required this.nodeId,
    required this.type,
    this.messageId,
    this.peerId,
    this.priority,
    this.bytes,
    this.metadata = const {},
  });

  Map<String, dynamic> toJson() => {
        'time': timestamp,
        'node': nodeId,
        'type': type.wireName,
        if (messageId != null) 'message_id': messageId,
        if (peerId != null) 'peer': peerId,
        if (priority != null) 'priority': priority,
        if (bytes != null) 'bytes': bytes,
        if (metadata.isNotEmpty) 'meta': metadata,
      };

  String toJsonLine() => jsonEncode(toJson());

  factory MeshTraceEvent.fromJson(Map<String, dynamic> json) {
    return MeshTraceEvent(
      timestamp: json['time'] as int,
      nodeId: json['node'] as String,
      type: MeshEventType.fromWireName(json['type'] as String),
      messageId: json['message_id'] as String?,
      peerId: json['peer'] as String?,
      priority: json['priority'] as int?,
      bytes: json['bytes'] as int?,
      metadata: (json['meta'] as Map?)?.cast<String, dynamic>() ?? const {},
    );
  }

  factory MeshTraceEvent.fromJsonLine(String line) {
    return MeshTraceEvent.fromJson(jsonDecode(line) as Map<String, dynamic>);
  }
}

/// Represents an active in-process mesh node running pure Dart protocol components.
class MeshNode {
  final String nodeId;
  final cg.SimpleKeyPair signingKeyPair;
  final Uint8List memberPubkey;
  final cg.SimpleKeyPair noiseKeyPair;
  final Uint8List noisePubkey;
  final MembershipCert cert;
  final Uint8List groupId;
  final int keyEpoch;
  final Uint8List epochKey;
  MessageStore store;
  final FakeTransport transport;
  final MeshHarness harness;
  final PeerCooldownTracker cooldownTracker;
  final NodeClock nodeClock;
  Duration frameTimeout;
  bool dropAfterHandshake;

  int _seq = 0;
  final List<Envelope> publishedEnvelopes = [];

  MeshNode({
    required this.nodeId,
    required this.signingKeyPair,
    required this.memberPubkey,
    required this.noiseKeyPair,
    required this.noisePubkey,
    required this.cert,
    required this.groupId,
    required this.keyEpoch,
    required this.epochKey,
    required this.store,
    required this.transport,
    required this.harness,
    PeerCooldownTracker? cooldownTracker,
    int clockSkewMs = 0,
    this.frameTimeout = const Duration(seconds: 10),
    this.dropAfterHandshake = false,
  })  : cooldownTracker = cooldownTracker ?? PeerCooldownTracker(),
        nodeClock = NodeClock(harness.clock, clockSkewMs);

  int get clockSkewMs => nodeClock.skewMs;
  set clockSkewMs(int value) => nodeClock.skewMs = value;

  /// Simulates node restart: clears in-memory Tier 3 cooldowns (`IT-DS-05c`),
  /// optionally swaps to a reopened store (`IT-FI-07`), and runs startup peer history pruning (`IT-DS-05d`).
  Future<void> restart({MessageStore? reopenedStore}) async {
    cooldownTracker.resetAll();
    if (reopenedStore != null) {
      store = reopenedStore;
    }
    await store.prunePeerHistory(
        currentTimeMillis: nodeClock.now().millisecondsSinceEpoch);
  }

  /// Publishes a new message from this node, signing it with Ed25519 and encrypting
  /// its payload with XChaCha20-Poly1305.
  Future<Envelope> publish({
    required String type,
    required Map<String, dynamic> body,
    int priority = 2,
    int ttlSeconds = 86400,
    List<({Uint8List bytes, String mime})>? attachments,
  }) async {
    _seq++;
    final now = nodeClock.now();
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
          customStoredAt: now.millisecondsSinceEpoch,
        );
      }
    }

    final env = await Envelope.create(
      groupId: groupId,
      keyEpoch: keyEpoch,
      groupKey: epochKey,
      authorKeyPair: signingKeyPair,
      certRef: cert.certRef,
      seq: _seq,
      payload: body,
      priority: priority,
      ttl: Duration(seconds: ttlSeconds),
      attachments: attachmentRefs,
      customCreatedAt: now.millisecondsSinceEpoch,
      randomSource: harness.randomSource,
    );

    await store.saveEnvelope(env, customStoredAt: now.millisecondsSinceEpoch);
    publishedEnvelopes.add(env);

    final idHex = hex.encode(env.messageId);
    final byteLen = env.toCanonicalCbor().length;

    harness.recordEvent(MeshTraceEvent(
      timestamp: now.millisecondsSinceEpoch,
      nodeId: nodeId,
      type: MeshEventType.published,
      messageId: idHex,
      priority: priority,
      bytes: byteLen,
      metadata: {'seq': _seq, 'type': type},
    ));
    harness.recordEvent(MeshTraceEvent(
      timestamp: now.millisecondsSinceEpoch,
      nodeId: nodeId,
      type: MeshEventType.stored,
      messageId: idHex,
      priority: priority,
      bytes: byteLen,
      metadata: {'origin': 'LOCAL'},
    ));

    return env;
  }

  /// Synchronizes state with [peer] over [FakeMedium].
  Future<Map<String, SessionSyncResult>> syncWith(
    MeshNode peer, {
    bool transferAttachments = false,
    int? mtuOverride,
    bool enforceCooldown = false,
    int? cutAfterSendingFrameType,
  }) async {
    final now = harness.clock.now().millisecondsSinceEpoch;

    if (enforceCooldown) {
      final decision = cooldownTracker.checkConnectAllowed(peer.nodeId, now);
      if (!decision.allowed) {
        harness.recordEvent(MeshTraceEvent(
          timestamp: now,
          nodeId: nodeId,
          type: MeshEventType.connectRejected,
          peerId: peer.nodeId,
          metadata: {
            'reason': decision.reason ?? 'cooldown',
            'retry_after_ms': decision.waitMs,
          },
        ));
        final skipped = SessionSyncResult(
          envelopesSent: 0,
          envelopesReceived: 0,
          completedSuccessfully: false,
          failureReason: 'Connect suppressed by cooldown: ${decision.reason}',
        );
        return {nodeId: skipped, peer.nodeId: skipped};
      }
      cooldownTracker.recordConnectAttempt(peer.nodeId, now);
    }

    harness.recordEvent(MeshTraceEvent(
      timestamp: now,
      nodeId: nodeId,
      type: MeshEventType.connectAttempt,
      peerId: peer.nodeId,
    ));

    harness.recordEvent(MeshTraceEvent(
      timestamp: now,
      nodeId: nodeId,
      type: MeshEventType.sessionStart,
      peerId: peer.nodeId,
    ));
    harness.recordEvent(MeshTraceEvent(
      timestamp: now,
      nodeId: peer.nodeId,
      type: MeshEventType.sessionStart,
      peerId: nodeId,
    ));

    FakePeerLink linkA;
    try {
      linkA = await harness.medium.establishConnection(
        initiator: transport,
        targetAddress: peer.nodeId,
        mtu: mtuOverride ?? transport.capabilities.defaultMtu,
      );
    } on StateError catch (e) {
      cooldownTracker.recordSessionFailure(peer.nodeId, now);
      harness.recordEvent(MeshTraceEvent(
        timestamp: now,
        nodeId: nodeId,
        type: MeshEventType.connectRejected,
        peerId: peer.nodeId,
        metadata: {
          'reason': e.message.contains('maxConnections')
              ? 'max_connections_exceeded'
              : 'link_unreachable',
          'error': e.message,
        },
      ));
      rethrow;
    }
    final linkB = linkA.peerLink!;

    harness.recordEvent(MeshTraceEvent(
      timestamp: now,
      nodeId: nodeId,
      type: MeshEventType.slotState,
      peerId: peer.nodeId,
      metadata: {
        'active_slots': transport.activeLinkCount,
        'max_slots': transport.capabilities.maxConnections,
      },
    ));
    harness.recordEvent(MeshTraceEvent(
      timestamp: now,
      nodeId: peer.nodeId,
      type: MeshEventType.slotState,
      peerId: nodeId,
      metadata: {
        'active_slots': peer.transport.activeLinkCount,
        'max_slots': peer.transport.capabilities.maxConnections,
      },
    ));

    var sessionCounterA = 0;
    var sessionCounterB = 0;
    final sessionId = '${nodeId}_${peer.nodeId}_$now';

    final smA = SessionStateMachine(
      link: linkA,
      isInitiator: true,
      staticKeyPair: noiseKeyPair,
      localCert: cert,
      pinnedServerKey: harness.serverPubkey,
      expectedGroupId: groupId,
      store: store,
      clock: nodeClock,
      transferAttachments: transferAttachments,
      frameTimeout: frameTimeout,
      dropAfterHandshake: dropAfterHandshake,
      cutAfterSendingFrameType: cutAfterSendingFrameType,
      onFrameSent: (frameType, wireBytes, chunkCount) {
        sessionCounterA++;
        harness.recordEvent(MeshTraceEvent(
          timestamp: harness.clock.now().millisecondsSinceEpoch,
          nodeId: nodeId,
          type: MeshEventType.frameSent,
          peerId: peer.nodeId,
          bytes: wireBytes,
          metadata: {
            'frame_type': frameType,
            'chunks': chunkCount,
            'session_id': sessionId,
            'frame_seq': sessionCounterA,
          },
        ));
      },
      onEnvelopeReceived: (envelope, isDuplicate, evictionRefetchCount) {
        final envBytes = envelope.toCanonicalCbor().length;
        harness.recordEvent(MeshTraceEvent(
          timestamp: harness.clock.now().millisecondsSinceEpoch,
          nodeId: nodeId,
          type: MeshEventType.envelopeReceived,
          peerId: peer.nodeId,
          messageId: hex.encode(envelope.messageId),
          bytes: envBytes,
          metadata: {
            'session_id': sessionId,
            'duplicate': isDuplicate,
            'eviction_refetch_count': evictionRefetchCount,
          },
        ));
      },
    );

    final smB = SessionStateMachine(
      link: linkB,
      isInitiator: false,
      staticKeyPair: peer.noiseKeyPair,
      localCert: peer.cert,
      pinnedServerKey: harness.serverPubkey,
      expectedGroupId: peer.groupId,
      store: peer.store,
      clock: peer.nodeClock,
      transferAttachments: transferAttachments,
      frameTimeout: peer.frameTimeout,
      dropAfterHandshake: peer.dropAfterHandshake,
      onFrameSent: (frameType, wireBytes, chunkCount) {
        sessionCounterB++;
        harness.recordEvent(MeshTraceEvent(
          timestamp: harness.clock.now().millisecondsSinceEpoch,
          nodeId: peer.nodeId,
          type: MeshEventType.frameSent,
          peerId: nodeId,
          bytes: wireBytes,
          metadata: {
            'frame_type': frameType,
            'chunks': chunkCount,
            'session_id': sessionId,
            'frame_seq': sessionCounterB,
          },
        ));
      },
      onEnvelopeReceived: (envelope, isDuplicate, evictionRefetchCount) {
        final envBytes = envelope.toCanonicalCbor().length;
        harness.recordEvent(MeshTraceEvent(
          timestamp: harness.clock.now().millisecondsSinceEpoch,
          nodeId: peer.nodeId,
          type: MeshEventType.envelopeReceived,
          peerId: nodeId,
          messageId: hex.encode(envelope.messageId),
          bytes: envBytes,
          metadata: {
            'session_id': sessionId,
            'duplicate': isDuplicate,
            'eviction_refetch_count': evictionRefetchCount,
          },
        ));
      },
    );

    final results = await Future.wait([smA.run(), smB.run()]);
    final resA = results[0];
    final resB = results[1];

    // Clear any unconsumed one-shot fault triggers from this session
    harness.medium.clearFaultTriggers(nodeA: nodeId, nodeB: peer.nodeId);

    // Ensure both sides close their link handles if one side aborted early
    if (!linkA.isClosed) {
      await linkA.close();
    }
    if (!linkB.isClosed) {
      await linkB.close();
    }

    final endNow = harness.clock.now().millisecondsSinceEpoch;
    if (resA.completedSuccessfully && resB.completedSuccessfully) {
      cooldownTracker.recordSessionSuccess(peer.nodeId);
      peer.cooldownTracker.recordSessionSuccess(nodeId);
    } else {
      cooldownTracker.recordSessionFailure(peer.nodeId, endNow);
      peer.cooldownTracker.recordSessionFailure(nodeId, endNow);
    }

    if (resA.envelopesReceived > 0) {
      harness.recordEvent(MeshTraceEvent(
        timestamp: endNow,
        nodeId: nodeId,
        type: MeshEventType.received,
        peerId: peer.nodeId,
        metadata: {'count': resA.envelopesReceived},
      ));
      harness.recordEvent(MeshTraceEvent(
        timestamp: endNow,
        nodeId: nodeId,
        type: MeshEventType.stored,
        peerId: peer.nodeId,
        metadata: {'count': resA.envelopesReceived, 'origin': 'PEER'},
      ));
    }
    if (resB.envelopesReceived > 0) {
      harness.recordEvent(MeshTraceEvent(
        timestamp: endNow,
        nodeId: peer.nodeId,
        type: MeshEventType.received,
        peerId: nodeId,
        metadata: {'count': resB.envelopesReceived},
      ));
      harness.recordEvent(MeshTraceEvent(
        timestamp: endNow,
        nodeId: peer.nodeId,
        type: MeshEventType.stored,
        peerId: nodeId,
        metadata: {'count': resB.envelopesReceived, 'origin': 'PEER'},
      ));
    }

    if (resA.receiptsReceived > 0) {
      harness.recordEvent(MeshTraceEvent(
        timestamp: endNow,
        nodeId: nodeId,
        type: MeshEventType.receiptApplied,
        peerId: peer.nodeId,
        metadata: {'count': resA.receiptsReceived},
      ));
    }
    if (resB.receiptsReceived > 0) {
      harness.recordEvent(MeshTraceEvent(
        timestamp: endNow,
        nodeId: peer.nodeId,
        type: MeshEventType.receiptApplied,
        peerId: nodeId,
        metadata: {'count': resB.receiptsReceived},
      ));
    }

    harness.recordEvent(MeshTraceEvent(
      timestamp: endNow,
      nodeId: nodeId,
      type: MeshEventType.linkClosed,
      peerId: peer.nodeId,
      bytes: resA.totalBytesSent + resA.totalBytesReceived,
      metadata: {
        'reason': resA.completedSuccessfully
            ? 'clean'
            : (resA.failureReason ?? 'aborted')
      },
    ));

    harness.recordEvent(MeshTraceEvent(
      timestamp: endNow,
      nodeId: nodeId,
      type: MeshEventType.sessionEnd,
      peerId: peer.nodeId,
      bytes: resA.totalBytesSent,
      metadata: {
        'sent': resA.envelopesSent,
        'received': resA.envelopesReceived,
        'duplicates': resA.duplicateEnvelopesReceived,
        'bytes_sent': resA.totalBytesSent,
        'bytes_received': resA.totalBytesReceived,
        'success': resA.completedSuccessfully,
        if (resA.failureReason != null) 'error': resA.failureReason,
      },
    ));
    harness.recordEvent(MeshTraceEvent(
      timestamp: endNow,
      nodeId: peer.nodeId,
      type: MeshEventType.sessionEnd,
      peerId: nodeId,
      bytes: resB.totalBytesSent,
      metadata: {
        'sent': resB.envelopesSent,
        'received': resB.envelopesReceived,
        'duplicates': resB.duplicateEnvelopesReceived,
        'bytes_sent': resB.totalBytesSent,
        'bytes_received': resB.totalBytesReceived,
        'success': resB.completedSuccessfully,
        if (resB.failureReason != null) 'error': resB.failureReason,
      },
    ));

    return {
      nodeId: resA,
      peer.nodeId: resB,
    };
  }

  /// Applies a server receipt to this node's store and records a trace event.
  Future<void> applyReceipt(ServerReceipt receipt) async {
    await store.saveReceipt(receipt);
    harness.recordEvent(MeshTraceEvent(
      timestamp: harness.clock.now().millisecondsSinceEpoch,
      nodeId: nodeId,
      type: MeshEventType.receiptApplied,
      metadata: {'author': hex.encode(receipt.author)},
    ));
  }

  /// Prunes expired/confirmed/over-quota messages and records an eviction event if any were evicted.
  Future<int> pruneStore(
      {Duration retentionWindow = const Duration(hours: 24)}) async {
    final now = harness.clock.now().millisecondsSinceEpoch;
    final evicted = await store.prune(
      currentTimeMillis: now,
      retentionWindow: retentionWindow,
    );
    if (evicted > 0) {
      harness.recordEvent(MeshTraceEvent(
        timestamp: now,
        nodeId: nodeId,
        type: MeshEventType.evicted,
        metadata: {'count': evicted},
      ));
    }
    return evicted;
  }

  /// Checks if this node currently holds the specified envelope.
  Future<bool> holdsMessage(Uint8List messageId) async {
    return store.containsEnvelope(messageId);
  }

  /// Checks if this node holds the envelope by author and sequence.
  Future<bool> holdsAuthorSeq(Uint8List author, int seq) async {
    return store.isSequenceHeld(author, seq);
  }

  /// Decrypts the payload of [env] using this node's group key.
  Future<dynamic> decryptPayload(Envelope env) async {
    final plaintext = await env.decryptPayloadCbor(epochKey);
    return CanonicalCbor.decode(plaintext);
  }

  /// Disposes this node's resources.
  Future<void> dispose() async {
    await transport.dispose();
  }
}

/// Orchestrates an in-process multi-node mesh test environment (FR-TEST-08).
class MeshHarness {
  final FakeMedium medium;
  final RandomSource randomSource;
  final Clock clock;
  final cg.SimpleKeyPair serverSigningKeyPair;
  final Uint8List serverPubkey;
  final Uint8List groupId;
  final int defaultEpoch;
  final Uint8List defaultEpochKey;

  final Map<String, MeshNode> _nodes = {};
  final List<MeshTraceEvent> _traces = [];
  final MemoryMessageStore serverStore = MemoryMessageStore();
  final List<ServerReceipt> serverReceipts = [];

  MeshHarness._({
    required this.medium,
    required this.randomSource,
    required this.clock,
    required this.serverSigningKeyPair,
    required this.serverPubkey,
    required this.groupId,
    required this.defaultEpoch,
    required this.defaultEpochKey,
  });

  /// Factory constructor to spin up a deterministic mesh test harness.
  static Future<MeshHarness> create({
    int seed = 42,
    Uint8List? groupId,
    Uint8List? defaultEpochKey,
    Clock? clock,
    cg.SimpleKeyPair? serverSigningKeyPair,
  }) async {
    final rng = DeterministicRandomSource(seed);
    final serverKeySeed = rng.nextBytes(32);
    final serverKeyPair = serverSigningKeyPair ??
        await MsgP2PCrypto.newKeyPairFromSeed(serverKeySeed);
    final serverPk = await MsgP2PCrypto.getPublicKeyBytes(serverKeyPair);

    final gid = groupId ?? Uint8List.fromList(List.generate(16, (i) => 0x42));
    final eKey =
        defaultEpochKey ?? Uint8List.fromList(List.generate(32, (i) => 0x99));

    return MeshHarness._(
      medium: FakeMedium(rng: rng),
      randomSource: rng,
      clock: clock ?? const SystemClock(),
      serverSigningKeyPair: serverKeyPair,
      serverPubkey: serverPk,
      groupId: gid,
      defaultEpoch: 1,
      defaultEpochKey: eKey,
    );
  }

  Map<String, MeshNode> get nodes => Map.unmodifiable(_nodes);
  List<MeshTraceEvent> get traces => List.unmodifiable(_traces);

  void recordEvent(MeshTraceEvent event) {
    _traces.add(event);
  }

  /// Creates and registers a new [MeshNode] in the harness.
  Future<MeshNode> addNode(
    String nodeId, {
    int maxConnections = 4,
    int defaultMtu = 512,
    int? validUntilMillis,
    MessageStore? customStore,
    int? storageQuotaBytes,
    int clockSkewMs = 0,
    Duration frameTimeout = const Duration(seconds: 10),
    bool dropAfterHandshake = false,
  }) async {
    if (_nodes.containsKey(nodeId)) {
      throw StateError('Node $nodeId already exists in harness');
    }

    final signingSeed = randomSource.nextBytes(32);
    final signingKeyPair = await MsgP2PCrypto.newKeyPairFromSeed(signingSeed);
    final memberPk = await MsgP2PCrypto.getPublicKeyBytes(signingKeyPair);

    final noiseSeed = randomSource.nextBytes(32);
    final noiseKeyPair = await cg.X25519().newKeyPairFromSeed(noiseSeed);
    final noisePk = await NoiseHandshake.getPublicKeyBytes(noiseKeyPair);

    final issuedAt = clock.now().millisecondsSinceEpoch;
    final validUntil = validUntilMillis ?? (issuedAt + 365 * 86400 * 1000);

    final certCore = MembershipCert(
      groupId: groupId,
      userId: nodeId,
      memberPubkey: memberPk,
      noisePubkey: noisePk,
      role: 0,
      issuedAt: issuedAt,
      expiresAt: validUntil,
      serverSig: Uint8List(0),
    );
    final serverSig =
        await MsgP2PCrypto.sign(certCore.toCoreCbor(), serverSigningKeyPair);
    final cert = MembershipCert(
      groupId: groupId,
      userId: nodeId,
      memberPubkey: memberPk,
      noisePubkey: noisePk,
      role: 0,
      issuedAt: issuedAt,
      expiresAt: validUntil,
      serverSig: serverSig,
    );

    final transport = FakeTransport(
      nodeAddress: nodeId,
      medium: medium,
      capabilities: TransportCapabilities(
        transportName: 'mesh_harness_radio',
        defaultMtu: defaultMtu,
        maxConnections: maxConnections,
      ),
    );

    final store = customStore ??
        (storageQuotaBytes != null
            ? MemoryMessageStore(maxStorageBytes: storageQuotaBytes)
            : MemoryMessageStore());

    final node = MeshNode(
      nodeId: nodeId,
      signingKeyPair: signingKeyPair,
      memberPubkey: memberPk,
      noiseKeyPair: noiseKeyPair,
      noisePubkey: noisePk,
      cert: cert,
      groupId: groupId,
      keyEpoch: defaultEpoch,
      epochKey: defaultEpochKey,
      store: store,
      transport: transport,
      harness: this,
      clockSkewMs: clockSkewMs,
      frameTimeout: frameTimeout,
      dropAfterHandshake: dropAfterHandshake,
    );

    await node.store.saveCertificate(cert);
    for (final existing in _nodes.values) {
      await existing.store.saveCertificate(cert);
      await node.store.saveCertificate(existing.cert);
    }

    _nodes[nodeId] = node;
    return node;
  }

  /// Sets connectivity graph: {nodeId: {reachablePeers}}.
  void setTopology(Map<String, Set<String>> topology) {
    medium.setTopology(topology);
  }

  /// Isolates nodes into disconnected network clusters.
  void partition(List<List<String>> clusters) {
    medium.partition(clusters);
  }

  /// Restores network to full mesh where all nodes can communicate.
  void setFullMesh() {
    medium.setFullMesh();
  }

  /// Cuts links between [nodeA] and [nodeB], optionally after [afterBytes] transmitted.
  void cutLink(
      {required String nodeA, required String nodeB, int? afterBytes}) {
    medium.cutLink(nodeA: nodeA, nodeB: nodeB, afterBytes: afterBytes);
    recordEvent(MeshTraceEvent(
      timestamp: clock.now().millisecondsSinceEpoch,
      nodeId: nodeA,
      type: MeshEventType.linkCut,
      peerId: nodeB,
      bytes: afterBytes,
    ));
  }

  /// Synchronizes a specific pair of nodes.
  Future<Map<String, SessionSyncResult>> syncPair(
    String nodeA,
    String nodeB, {
    bool transferAttachments = false,
    int? mtuOverride,
    bool enforceCooldown = false,
    int? cutAfterSendingFrameType,
  }) async {
    final a = _nodes[nodeA];
    final b = _nodes[nodeB];
    if (a == null || b == null) {
      throw ArgumentError('Both nodes must exist in harness ($nodeA, $nodeB)');
    }
    return a.syncWith(
      b,
      transferAttachments: transferAttachments,
      mtuOverride: mtuOverride,
      enforceCooldown: enforceCooldown,
      cutAfterSendingFrameType: cutAfterSendingFrameType,
    );
  }

  /// Issues a signed [RevocationNotice] from the server and ingests it into [sourceNodeId].
  Future<RevocationNotice> issueAndIngestRevocation({
    required String targetNodeId,
    required String sourceNodeId,
    String reason = 'compromised_credential',
  }) async {
    final target = _nodes[targetNodeId];
    final source = _nodes[sourceNodeId];
    if (target == null || source == null) {
      throw ArgumentError('Target and source nodes must exist');
    }

    final now = clock.now().millisecondsSinceEpoch;
    final revCore = RevocationNotice(
      groupId: groupId,
      memberPubkey: target.memberPubkey,
      revokedAt: now,
      reason: reason,
      serverSig: Uint8List(0),
    );
    final sig =
        await MsgP2PCrypto.sign(revCore.toCoreCbor(), serverSigningKeyPair);
    final notice = RevocationNotice(
      groupId: groupId,
      memberPubkey: target.memberPubkey,
      revokedAt: now,
      reason: reason,
      serverSig: sig,
    );

    await source.store.saveRevocation(notice);
    recordEvent(MeshTraceEvent(
      timestamp: now,
      nodeId: sourceNodeId,
      type: MeshEventType.revocationApplied,
      metadata: {
        'revoked_member': hex.encode(target.memberPubkey),
        'reason': reason
      },
    ));

    return notice;
  }

  /// Synchronizes a gateway node with the harness's in-process central server (`IT-AMP-04`, `IT-FI-06`).
  ///
  /// - Only unconfirmed envelopes held by [gatewayNodeId] are uploaded (`server_push`).
  /// - If [reconcileReceiptsBeforePush] is true (e.g., on retry after a mid-push cut), the gateway
  ///   fetches existing [serverReceipts] before uploading, preventing duplicate re-uploads.
  /// - If [cutBeforeReceiptResponse] is true (`IT-FI-06`), the server ingests the envelopes and
  ///   generates signed receipts, but drops the HTTP response before [gatewayNodeId] receives them.
  Future<({int pushed, int pulled, int receiptsApplied})> gatewaySync(
    String gatewayNodeId, {
    bool cutBeforeReceiptResponse = false,
    bool reconcileReceiptsBeforePush = false,
  }) async {
    final gw = _nodes[gatewayNodeId];
    if (gw == null) {
      throw ArgumentError('Gateway node $gatewayNodeId does not exist');
    }
    final now = clock.now().millisecondsSinceEpoch;
    var receiptsApplied = 0;

    if (reconcileReceiptsBeforePush) {
      for (final receipt in serverReceipts) {
        await gw.store.saveReceipt(receipt);
        receiptsApplied++;
      }
      if (receiptsApplied > 0) {
        recordEvent(MeshTraceEvent(
          timestamp: now,
          nodeId: gatewayNodeId,
          type: MeshEventType.receiptApplied,
          metadata: {'count': receiptsApplied, 'source': 'SERVER_PRE_SYNC'},
        ));
      }
    }

    // Gather all unconfirmed envelopes held by the gateway node
    final localVec = await gw.store.getVersionVector(currentTimeMillis: now);
    final allHeld = <Envelope>[];
    for (final entry in localVec.authors.entries) {
      final authorBytes = Uint8List.fromList(hex.decode(entry.key));
      final maxSeq = entry.value.gaps.isEmpty
          ? entry.value.contiguous
          : [entry.value.contiguous, ...entry.value.gaps]
              .reduce((a, b) => a > b ? a : b);
      if (maxSeq > 0) {
        final envs = await gw.store.getEnvelopesByAuthorAndRanges(
          authorBytes,
          [SeqRange(1, maxSeq)],
          currentTimeMillis: now,
        );
        for (final env in envs) {
          final isConf =
              await gw.store.isConfirmed(env.core.author, env.core.seq);
          if (!isConf) {
            allHeld.add(env);
          }
        }
      }
    }

    final newlyIssuedReceipts = <ServerReceipt>[];
    if (allHeld.isNotEmpty) {
      final byAuthor = <String, List<int>>{};
      for (final env in allHeld) {
        final idHex = hex.encode(env.messageId);
        recordEvent(MeshTraceEvent(
          timestamp: now,
          nodeId: gatewayNodeId,
          type: MeshEventType.serverPush,
          messageId: idHex,
          bytes: env.toCanonicalCbor().length,
          metadata: {'seq': env.core.seq},
        ));
        await serverStore.saveEnvelope(env, customStoredAt: now);
        final authorHex = hex.encode(env.core.author);
        byAuthor.putIfAbsent(authorHex, () => <int>[]).add(env.core.seq);
      }

      for (final entry in byAuthor.entries) {
        final authorBytes = Uint8List.fromList(hex.decode(entry.key));
        final seqs = entry.value..sort();
        final rawRanges = seqs.map((s) => SeqRange(s, s)).toList();
        final mergedRanges = SeqRange.mergeRanges(rawRanges);
        final core = ServerReceipt(
          groupId: groupId,
          author: authorBytes,
          ranges: mergedRanges,
          issuedAt: now,
          serverSig: Uint8List(0),
        );
        final sig =
            await MsgP2PCrypto.sign(core.toCoreCbor(), serverSigningKeyPair);
        final receipt = ServerReceipt(
          groupId: groupId,
          author: authorBytes,
          ranges: mergedRanges,
          issuedAt: now,
          serverSig: sig,
        );
        serverReceipts.add(receipt);
        await serverStore.saveReceipt(receipt);
        newlyIssuedReceipts.add(receipt);
      }
    }

    if (cutBeforeReceiptResponse) {
      recordEvent(MeshTraceEvent(
        timestamp: now,
        nodeId: gatewayNodeId,
        type: MeshEventType.linkCut,
        peerId: 'CENTRAL_SERVER',
        metadata: {'phase': 'mid_push_before_receipt_response'},
      ));
      return (
        pushed: allHeld.length,
        pulled: 0,
        receiptsApplied: receiptsApplied
      );
    }

    for (final receipt in [...serverReceipts, ...newlyIssuedReceipts]) {
      await gw.store.saveReceipt(receipt);
      receiptsApplied++;
    }
    if (receiptsApplied > 0) {
      recordEvent(MeshTraceEvent(
        timestamp: now,
        nodeId: gatewayNodeId,
        type: MeshEventType.receiptApplied,
        metadata: {'count': receiptsApplied, 'source': 'SERVER'},
      ));
    }

    // Pull any envelopes on server missing from gateway
    final serverVec =
        await serverStore.getVersionVector(currentTimeMillis: now);
    final gwWant = localVec.calculateWant(serverVec);
    var pulledCount = 0;
    for (final want in gwWant) {
      final authorBytes = Uint8List.fromList(hex.decode(want.authorHex));
      final envs = await serverStore.getEnvelopesByAuthorAndRanges(
        authorBytes,
        want.ranges,
        currentTimeMillis: now,
      );
      for (final env in envs) {
        final saved = await gw.store.saveEnvelope(env, customStoredAt: now);
        if (saved) {
          pulledCount++;
          recordEvent(MeshTraceEvent(
            timestamp: now,
            nodeId: gatewayNodeId,
            type: MeshEventType.serverPull,
            messageId: hex.encode(env.messageId),
            bytes: env.toCanonicalCbor().length,
          ));
        }
      }
    }

    return (
      pushed: allHeld.length,
      pulled: pulledCount,
      receiptsApplied: receiptsApplied
    );
  }

  /// Executes a unified [Scenario] in-process on this harness and returns assertion failures (empty if all pass).
  Future<List<String>> runScenario(Scenario scenario) async {
    for (final sNode in scenario.nodes) {
      if (!_nodes.containsKey(sNode.id)) {
        await addNode(sNode.id);
      }
    }

    setTopology({});

    // Combine workload and contact start/end into chronological events
    final events = <_ScheduledAction>[];
    final publishedMessages = <Envelope>[];

    for (final work in scenario.workload) {
      events.add(_ScheduledAction(work.timeMs, 0, () async {
        final node = _nodes[work.author];
        if (node != null) {
          final env = await node.publish(
            type: work.type,
            body: work.body,
            priority: work.priority,
          );
          publishedMessages.add(env);
        }
      }));
    }

    for (final contact in scenario.contacts) {
      events.add(_ScheduledAction(contact.startMs, 1, () async {
        medium.setLink(contact.from, contact.to, true);
        await syncPair(contact.from, contact.to);
      }));
      events.add(_ScheduledAction(contact.endMs, 2, () async {
        medium.setLink(contact.from, contact.to, false);
      }));
    }

    events.sort((a, b) {
      final tCmp = a.timeMs.compareTo(b.timeMs);
      if (tCmp != 0) return tCmp;
      return a.order.compareTo(b.order);
    });

    for (final ev in events) {
      if (ev.timeMs > scenario.durationMs) break;
      await ev.action();
    }

    final failures = <String>[];
    for (var i = 0; i < scenario.assertions.length; i++) {
      final assertion = scenario.assertions[i];
      for (final env in publishedMessages) {
        for (final targetId in assertion.deliveredTo) {
          final targetNode = _nodes[targetId];
          final held = targetNode != null &&
              await targetNode.holdsMessage(env.messageId);
          if (!held) {
            failures.add(
              'Assertion #${i + 1} failed: Message ${hex.encode(env.messageId)} not delivered to $targetId',
            );
          }
        }
      }
    }
    return failures;
  }

  /// Calculates delivery ratio for [messageId] across all nodes (or [targetNodeIds]).
  Future<double> getDeliveryRatio(Uint8List messageId,
      [List<String>? targetNodeIds]) async {
    final checkList = targetNodeIds ?? _nodes.keys.toList();
    if (checkList.isEmpty) return 0.0;

    var heldCount = 0;
    for (final id in checkList) {
      final node = _nodes[id];
      if (node != null && await node.holdsMessage(messageId)) {
        heldCount++;
      }
    }
    return heldCount / checkList.length;
  }

  /// Exports all collected trace events as JSON Lines.
  String exportTraceJsonl() {
    return _traces.map((e) => e.toJsonLine()).join('\n');
  }

  /// Parses JSONL trace string back into structured [MeshTraceEvent] list.
  static List<MeshTraceEvent> parseTraceJsonl(String jsonl) {
    if (jsonl.trim().isEmpty) return const [];
    return jsonl
        .split('\n')
        .where((line) => line.trim().isNotEmpty)
        .map(MeshTraceEvent.fromJsonLine)
        .toList();
  }

  /// Disposes all harness nodes and transports.
  Future<void> dispose() async {
    for (final node in _nodes.values) {
      await node.dispose();
    }
    _nodes.clear();
  }
}

class _ScheduledAction {
  final int timeMs;
  final int order;
  final Future<void> Function() action;

  _ScheduledAction(this.timeMs, this.order, this.action);
}

/// Trace analyzer computing amplification, flap-resilience, and data-structure metrics (IT-OBS-02).
class ChurnTraceAnalyzer {
  final List<MeshTraceEvent> events;

  ChurnTraceAnalyzer(this.events);

  /// Maximum times any `(node, envelope_id)` was received over the air across all sessions (`IT-AMP-01`).
  /// If an envelope was received once (initial reception), duplicate count is 0.
  /// Returns total receptions - 1 (i.e., extra/duplicate receptions), or total receptions via [totalReceptionsPerNodeEnvelope].
  int maxDuplicatesPerNodeEnvelope() {
    final counts = totalReceptionsPerNodeEnvelope();
    var maxDup = 0;
    for (final c in counts.values) {
      final dup = c > 1 ? c - 1 : 0;
      if (dup > maxDup) maxDup = dup;
    }
    return maxDup;
  }

  /// Total reception count for each `(node, envelope_id)`.
  Map<String, int> totalReceptionsPerNodeEnvelope() {
    final counts = <String, int>{};
    for (final ev in events) {
      if (ev.type == MeshEventType.envelopeReceived && ev.messageId != null) {
        final key = '${ev.nodeId}:${ev.messageId}';
        counts[key] = (counts[key] ?? 0) + 1;
      }
    }
    return counts;
  }

  /// Maximum receptions of any `envelope_id` by the same node within a single session (`IT-AMP-01`: must be <= 1).
  int maxIntraSessionReceptionsPerEnvelope() {
    final counts = <String, int>{};
    var maxCount = 0;
    for (final ev in events) {
      if (ev.type == MeshEventType.envelopeReceived && ev.messageId != null) {
        final sessionId = ev.metadata['session_id']?.toString() ?? 'unknown';
        final key = '${ev.nodeId}:$sessionId:${ev.messageId}';
        final next = (counts[key] ?? 0) + 1;
        counts[key] = next;
        if (next > maxCount) maxCount = next;
      }
    }
    return maxCount;
  }

  /// Computes total bytes sent on air across all `frame_sent` events (`IT-AMP-02`).
  int totalBytesOnAir() {
    var total = 0;
    for (final ev in events) {
      if (ev.type == MeshEventType.frameSent && ev.bytes != null) {
        total += ev.bytes!;
      }
    }
    return total;
  }

  /// Computes air-byte amplification ratio `bytes_on_air / ideal_bytes` (`IT-AMP-02`).
  double amplificationRatio({required int idealBytes}) {
    if (idealBytes <= 0) return 1.0;
    return totalBytesOnAir() / idealBytes;
  }

  /// Computes the maximum number of `connect_attempt` events from any `(node, peer)` within any 60-second sliding window (`IT-FLAP-03`).
  int maxConnectAttemptsPerMinute() {
    final byPair = <String, List<int>>{};
    for (final ev in events) {
      if (ev.type == MeshEventType.connectAttempt && ev.peerId != null) {
        final key = '${ev.nodeId}->${ev.peerId}';
        byPair.putIfAbsent(key, () => <int>[]).add(ev.timestamp);
      }
    }
    var maxAttempts = 0;
    for (final timestamps in byPair.values) {
      timestamps.sort();
      for (var i = 0; i < timestamps.length; i++) {
        final windowStart = timestamps[i];
        var count = 0;
        for (var j = i; j < timestamps.length; j++) {
          if (timestamps[j] - windowStart < 60000) {
            count++;
          } else {
            break;
          }
        }
        if (count > maxAttempts) maxAttempts = count;
      }
    }
    return maxAttempts;
  }

  /// Computes the maximum number of `server_push` events for any `envelope_id` (`IT-AMP-04`).
  int maxServerPushesPerEnvelope() {
    final counts = <String, int>{};
    var maxPushes = 0;
    for (final ev in events) {
      if (ev.type == MeshEventType.serverPush && ev.messageId != null) {
        final next = (counts[ev.messageId!] ?? 0) + 1;
        counts[ev.messageId!] = next;
        if (next > maxPushes) maxPushes = next;
      }
    }
    return maxPushes;
  }

  /// Returns frames sent filtered by `frame_type`.
  List<MeshTraceEvent> framesSentOfType(int frameType) {
    return events
        .where((e) =>
            e.type == MeshEventType.frameSent &&
            e.metadata['frame_type'] == frameType)
        .toList();
  }
}
