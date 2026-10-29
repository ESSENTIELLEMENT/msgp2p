import 'dart:async';
import 'dart:math';
import 'dart:typed_data';
import 'package:convert/convert.dart';
import '../crypto/random_source.dart';
import '../framing/broadcast_framing.dart';
import '../model/certificate.dart';
import '../model/envelope.dart';
import '../storage/message_store.dart';
import '../transport/broadcast_transport.dart';
import 'clock_rules.dart';

/// Coordinator for unacknowledged 0-RTT broadcast push mode across packet radios (e.g. LoRa / Meshtastic).
class BroadcastEngine {
  final BroadcastTransport transport;
  final MessageStore store;
  final Uint8List pinnedServerKey;
  final Uint8List expectedGroupId;
  final Map<int, Uint8List> groupKeysByEpoch;
  final Clock clock;
  final RandomSource randomSource;
  final bool relayEnabled;

  final BroadcastChunkReassembler _reassembler = BroadcastChunkReassembler();
  final Set<String> _seenMessageIds = {};
  final Set<int> _seenBroadcastIds = {};

  final StreamController<Envelope> _envelopeReceivedController =
      StreamController<Envelope>.broadcast();
  final StreamController<(Envelope, Map<String, dynamic>)>
      _decryptedMessageController =
      StreamController<(Envelope, Map<String, dynamic>)>.broadcast();

  StreamSubscription<BroadcastPacket>? _rxSub;
  bool _running = false;

  BroadcastEngine({
    required this.transport,
    required this.store,
    required this.pinnedServerKey,
    required this.expectedGroupId,
    Map<int, Uint8List>? groupKeysByEpoch,
    this.clock = const SystemClock(),
    RandomSource? randomSource,
    this.relayEnabled = true,
  })  : groupKeysByEpoch = groupKeysByEpoch ?? {},
        randomSource = randomSource ?? SystemRandomSource();

  /// Stream of all valid received envelopes ingested into the local store.
  Stream<Envelope> get onEnvelopeReceived => _envelopeReceivedController.stream;

  /// Stream of successfully decrypted envelope payloads.
  Stream<(Envelope, Map<String, dynamic>)> get onDecryptedMessage =>
      _decryptedMessageController.stream;

  /// Starts listening for incoming broadcast packets.
  void start() {
    if (_running) return;
    _running = true;
    _rxSub = transport.broadcastRx.listen(_onIncomingPacket);
  }

  /// Stops listening and cleans up subscriptions.
  Future<void> stop() async {
    _running = false;
    await _rxSub?.cancel();
    _rxSub = null;
    _reassembler.reset();
  }

  /// Closes stream controllers and resources.
  Future<void> dispose() async {
    await stop();
    await _envelopeReceivedController.close();
    await _decryptedMessageController.close();
  }

  /// Broadcasts an envelope directly over the radio with zero handshake round-trips.
  Future<void> broadcastEnvelope(
    Envelope envelope, {
    MembershipCert? cert,
    int hopLimit = 3,
  }) async {
    final idBytes = randomSource.nextBytes(4);
    final broadcastId = ByteData.sublistView(idBytes).getUint32(0);
    final frame = BroadcastFrame(
      version: 1,
      envelope: envelope,
      cert: cert,
      broadcastId: broadcastId,
      hopLimit: hopLimit,
      hopCount: 0,
    );

    final msgIdHex = hex.encode(envelope.messageId);
    _seenMessageIds.add(msgIdHex);
    _seenBroadcastIds.add(broadcastId);

    final mtu = transport.capabilities.defaultMtu;
    final chunks = BroadcastChunkSlicer.slice(frame, mtu: mtu);

    for (final chunk in chunks) {
      await transport.sendBroadcast(chunk.encode());
    }
  }

  Future<void> _onIncomingPacket(BroadcastPacket packet) async {
    final now = clock.now().millisecondsSinceEpoch;
    final frame = _reassembler.processRawChunk(packet.payload, nowMs: now);
    if (frame == null) return;

    await _processReassembledFrame(frame, now);
  }

  Future<void> _processReassembledFrame(BroadcastFrame frame, int now) async {
    final envelope = frame.envelope;
    final msgIdHex = hex.encode(envelope.messageId);

    // 1. Deduplication check
    if (_seenMessageIds.contains(msgIdHex)) return;
    if (_seenBroadcastIds.contains(frame.broadcastId)) return;
    final alreadyStored = await store.containsEnvelope(envelope.messageId);
    if (alreadyStored) {
      _seenMessageIds.add(msgIdHex);
      _seenBroadcastIds.add(frame.broadcastId);
      return;
    }

    // 2. Group ID verification
    if (!_constantTimeEquals(envelope.core.groupId, expectedGroupId)) {
      return;
    }

    // 3. Expiration / Clock verification
    if (envelope.core.expiresAt <= now) {
      return;
    }

    // 4. Certificate verification
    MembershipCert? cert = frame.cert;
    if (cert != null) {
      // Verify attached certificate against pinned server key
      final certValid = await cert.verify(pinnedServerKey);
      if (!certValid) return;

      if (!_constantTimeEquals(cert.groupId, expectedGroupId)) return;
      if (cert.expiresAt <= now) return;

      // Check if revoked
      final isRevoked = await store.isRevoked(cert.memberPubkey);
      if (isRevoked) return;

      await store.saveCertificate(cert);
    } else {
      // Lookup stored certificate by reference hash
      cert = await store.getCertificate(envelope.certRef);
      if (cert == null) return;
    }

    // 5. Verify certificate matches author
    if (!_constantTimeEquals(cert.memberPubkey, envelope.core.author)) {
      return;
    }

    // 6. Verify author's signature on envelope core
    final sigValid = await envelope.verifySignature();
    if (!sigValid) return;

    // 7. Accept and ingest into local store
    _seenMessageIds.add(msgIdHex);
    _seenBroadcastIds.add(frame.broadcastId);
    await store.saveEnvelope(envelope, customStoredAt: now);
    _envelopeReceivedController.add(envelope);

    // 8. Attempt payload decryption if group key is available
    final groupKey = groupKeysByEpoch[envelope.core.keyEpoch];
    if (groupKey != null) {
      try {
        final decrypted = await envelope.decryptPayload(groupKey);
        _decryptedMessageController.add((envelope, decrypted));
      } catch (_) {
        // Payload decryption failed (e.g. wrong key)
      }
    }

    // 9. Mesh relaying / forwarding
    if (relayEnabled && frame.canForward) {
      _scheduleRelay(frame.nextHop());
    }
  }

  void _scheduleRelay(BroadcastFrame forwardedFrame) {
    // Apply randomized CSMA jitter backoff (50ms to 200ms) before retransmitting
    final jitterMs = 50 + Random().nextInt(150);
    Timer(Duration(milliseconds: jitterMs), () async {
      if (!_running) return;
      try {
        final mtu = transport.capabilities.defaultMtu;
        final chunks = BroadcastChunkSlicer.slice(forwardedFrame, mtu: mtu);
        for (final chunk in chunks) {
          await transport.sendBroadcast(chunk.encode());
        }
      } catch (_) {
        // Broadcast send error
      }
    });
  }

  static bool _constantTimeEquals(Uint8List a, Uint8List b) {
    if (a.length != b.length) return false;
    var diff = 0;
    for (var i = 0; i < a.length; i++) {
      diff |= a[i] ^ b[i];
    }
    return diff == 0;
  }
}
