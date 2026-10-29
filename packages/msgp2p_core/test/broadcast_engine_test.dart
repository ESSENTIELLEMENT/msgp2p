import 'dart:async';
import 'dart:typed_data';
import 'package:convert/convert.dart';
import 'package:cryptography/cryptography.dart' as cg;
import 'package:msgp2p_core/msgp2p_core.dart';
import 'package:test/test.dart';

/// In-memory fake implementation of [BroadcastTransport] for unit testing.
class FakeBroadcastTransport implements BroadcastTransport {
  @override
  final TransportCapabilities capabilities;

  final StreamController<BroadcastPacket> _rxController =
      StreamController<BroadcastPacket>.broadcast();
  final List<Uint8List> transmittedPackets = [];

  FakeBroadcastTransport({
    int mtu = 230,
    String name = 'FakeLoRa',
  }) : capabilities = TransportCapabilities(
          transportName: name,
          defaultMtu: mtu,
          isBroadcastMedium: true,
          recommendedFrameTimeout: const Duration(seconds: 45),
        );

  @override
  Stream<BroadcastPacket> get broadcastRx => _rxController.stream;

  @override
  Future<void> sendBroadcast(Uint8List packet) async {
    if (packet.length > capabilities.defaultMtu) {
      throw ArgumentError(
          'Packet size ${packet.length} exceeds MTU ${capabilities.defaultMtu}');
    }
    transmittedPackets.add(packet);
  }

  /// Injects a packet as if received over the air.
  void deliverIncoming(Uint8List packet, {int rssi = -85, double snr = 7.5}) {
    _rxController.add(BroadcastPacket(
      payload: packet,
      rssi: rssi,
      snr: snr,
      sourceAddress: 'NODE_TEST',
    ));
  }

  void close() {
    _rxController.close();
  }

  // Stubs for unused P2PTransport methods in broadcast-only mode
  @override
  Stream<PeerAdvert> get discovered => const Stream.empty();
  @override
  Stream<PeerLink> get incoming => const Stream.empty();
  @override
  Future<void> startAdvertising(Uint8List token) async {}
  @override
  Future<void> stopAdvertising() async {}
  @override
  Future<void> startScanning([ScanPolicy policy = const ScanPolicy()]) async {}
  @override
  Future<void> stopScanning() async {}
  @override
  Future<void> stop() async {}
  @override
  Future<PeerLink> connect(PeerAdvert peer) => throw UnimplementedError();
}

void main() {
  group('0-RTT Broadcast & LoRaTransport Suite', () {
    late Uint8List serverSeed;
    late cg.SimpleKeyPair serverKeyPair;
    late Uint8List serverPublicKey;
    late Uint8List groupId;
    late Uint8List groupKey;

    late cg.SimpleKeyPair aliceKeyPair;
    late Uint8List alicePk;
    late MembershipCert aliceCert;

    setUpAll(() async {
      serverSeed = Uint8List.fromList(List.filled(32, 7));
      serverKeyPair = await MsgP2PCrypto.newKeyPairFromSeed(serverSeed);
      serverPublicKey = await MsgP2PCrypto.getPublicKeyBytes(serverKeyPair);

      groupId =
          Uint8List.fromList(hex.decode('a0b1c2d3e4f50123456789abcdef0123'));
      groupKey = Uint8List.fromList(List.filled(32, 0x42));

      aliceKeyPair = await MsgP2PCrypto.newKeyPairFromSeed(
          Uint8List.fromList(List.filled(32, 1)));
      alicePk = await MsgP2PCrypto.getPublicKeyBytes(aliceKeyPair);

      final now = DateTime.now().millisecondsSinceEpoch;
      final certCoreMap = {
        'v': 1,
        'group_id': groupId,
        'user_id': 'alice_sar',
        'member_pubkey': alicePk,
        'noise_pubkey': Uint8List(32),
        'role': 0,
        'issued_at': now,
        'expires_at': now + 86400000,
      };
      final coreCbor = CanonicalCbor.encode(certCoreMap);
      final sig = await MsgP2PCrypto.sign(coreCbor, serverKeyPair);
      aliceCert = MembershipCert(
        version: 1,
        groupId: groupId,
        userId: 'alice_sar',
        memberPubkey: alicePk,
        noisePubkey: Uint8List(32),
        role: 0,
        issuedAt: now,
        expiresAt: now + 86400000,
        serverSig: sig,
      );
    });

    test(
        '1. BroadcastChunkSlicer and BroadcastChunkReassembler with scrambled arrival',
        () async {
      final now = DateTime.now().millisecondsSinceEpoch;
      final envelope = await Envelope.create(
        groupId: groupId,
        keyEpoch: 1,
        groupKey: groupKey,
        authorKeyPair: aliceKeyPair,
        certRef: aliceCert.certRef,
        seq: 1,
        payload: {
          'type': 'sos',
          'victim': 'Lost Hiker',
          'lat': 45.1234,
          'lng': -122.5678,
          'notes': 'Severe hypothermia, requesting medical evacuation.',
        },
        priority: 0,
        customCreatedAt: now,
      );

      final frame = BroadcastFrame(
        version: 1,
        envelope: envelope,
        cert: aliceCert,
        broadcastId: 0xA1B2C3D4,
        hopLimit: 3,
        hopCount: 0,
      );

      // Slice with MTU 120 bytes (simulating conservative LoRa framing)
      final chunks = BroadcastChunkSlicer.slice(frame, mtu: 120);
      expect(chunks.length, greaterThanOrEqualTo(3));

      for (var i = 0; i < chunks.length; i++) {
        expect(chunks[i].chunkIndex, equals(i));
        expect(chunks[i].totalChunks, equals(chunks.length));
        expect(chunks[i].broadcastId, equals(0xA1B2C3D4));
      }

      // Reassemble in scrambled / out-of-order sequence (e.g. last, second, first, ...)
      final reassembler = BroadcastChunkReassembler();
      final scrambledIndices = List.generate(chunks.length, (i) => i)
        ..shuffle();

      BroadcastFrame? result;
      for (final idx in scrambledIndices) {
        final encodedChunk = chunks[idx].encode();
        final res = reassembler.processRawChunk(encodedChunk, nowMs: now);
        if (res != null) {
          result = res;
        }
      }

      expect(result, isNotNull);
      expect(result!.broadcastId, equals(0xA1B2C3D4));
      expect(result.hopLimit, equals(3));
      expect(result.hopCount, equals(0));
      expect(hex.encode(result.envelope.messageId),
          equals(hex.encode(envelope.messageId)));
      expect(result.cert, isNotNull);
      expect(result.cert!.userId, equals('alice_sar'));
    });

    test(
        '2. Corrupted CRC chunk is rejected cleanly without crashing reassembler',
        () async {
      final now = DateTime.now().millisecondsSinceEpoch;
      final envelope = await Envelope.create(
        groupId: groupId,
        keyEpoch: 1,
        groupKey: groupKey,
        authorKeyPair: aliceKeyPair,
        certRef: aliceCert.certRef,
        seq: 1,
        payload: {'text': 'Test CRC corruption'},
        customCreatedAt: now,
      );

      final frame = BroadcastFrame(
        envelope: envelope,
        broadcastId: 12345,
      );

      final chunks = BroadcastChunkSlicer.slice(frame, mtu: 100);
      expect(chunks.length, greaterThanOrEqualTo(2));

      final rawChunk0 = chunks[0].encode();
      // Corrupt payload byte
      rawChunk0[rawChunk0.length - 1] ^= 0xFF;

      final reassembler = BroadcastChunkReassembler();
      final res = reassembler.processRawChunk(rawChunk0, nowMs: now);
      expect(res, isNull);
    });

    test(
        '3. Full BroadcastEngine 0-RTT SOS transmission, verification and direct ingestion',
        () async {
      final aliceTransport = FakeBroadcastTransport(mtu: 230);
      final bobTransport = FakeBroadcastTransport(mtu: 230);

      final aliceStore = MemoryMessageStore();
      final bobStore = MemoryMessageStore();

      final now = DateTime.now().millisecondsSinceEpoch;

      final aliceEngine = BroadcastEngine(
        transport: aliceTransport,
        store: aliceStore,
        pinnedServerKey: serverPublicKey,
        expectedGroupId: groupId,
        groupKeysByEpoch: {1: groupKey},
      );

      final bobEngine = BroadcastEngine(
        transport: bobTransport,
        store: bobStore,
        pinnedServerKey: serverPublicKey,
        expectedGroupId: groupId,
        groupKeysByEpoch: {1: groupKey},
      );

      bobEngine.start();
      aliceEngine.start();

      // Setup simulated RF channel: deliver packets Alice transmits to Bob's radio
      Timer.run(() async {
        for (;;) {
          await Future.delayed(const Duration(milliseconds: 10));
          if (aliceTransport.transmittedPackets.isNotEmpty) {
            final pkt = aliceTransport.transmittedPackets.removeAt(0);
            bobTransport.deliverIncoming(pkt);
          }
        }
      });

      final envelope = await Envelope.create(
        groupId: groupId,
        keyEpoch: 1,
        groupKey: groupKey,
        authorKeyPair: aliceKeyPair,
        certRef: aliceCert.certRef,
        seq: 1,
        payload: {
          'type': 'sos',
          'alert': 'Avalanche at North Basin',
          'beacons': 3,
        },
        priority: 0,
        customCreatedAt: now,
      );

      // Listen for Bob's ingestion & decryption events
      final bobIngestedFuture = bobEngine.onEnvelopeReceived.first;
      final bobDecryptedFuture = bobEngine.onDecryptedMessage.first;

      // Alice sends 0-RTT broadcast
      await aliceEngine.broadcastEnvelope(envelope, cert: aliceCert);

      // Verify Bob ingests the envelope in his store without any session handshake
      final receivedEnv =
          await bobIngestedFuture.timeout(const Duration(seconds: 3));
      expect(hex.encode(receivedEnv.messageId),
          equals(hex.encode(envelope.messageId)));

      final storedInBob = await bobStore.getEnvelope(envelope.messageId);
      expect(storedInBob, isNotNull);

      // Verify Bob decrypts payload
      final decryptedTuple =
          await bobDecryptedFuture.timeout(const Duration(seconds: 3));
      expect(decryptedTuple.$2['type'], equals('sos'));
      expect(decryptedTuple.$2['alert'], equals('Avalanche at North Basin'));

      // Check deduplication: delivering the same packets again does not re-emit
      var duplicateEmitted = false;
      final sub =
          bobEngine.onEnvelopeReceived.listen((_) => duplicateEmitted = true);
      for (final chunk in BroadcastChunkSlicer.slice(
        BroadcastFrame(envelope: envelope, broadcastId: 9999),
        mtu: 230,
      )) {
        bobTransport.deliverIncoming(chunk.encode());
      }
      await Future.delayed(const Duration(milliseconds: 50));
      expect(duplicateEmitted, isFalse);
      await sub.cancel();

      await aliceEngine.dispose();
      await bobEngine.dispose();
      aliceTransport.close();
      bobTransport.close();
    });
  });
}
