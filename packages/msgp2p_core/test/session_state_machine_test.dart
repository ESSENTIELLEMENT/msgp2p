import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';
import 'package:convert/convert.dart';
import 'package:cryptography/cryptography.dart' as cg;
import 'package:msgp2p_core/msgp2p_core.dart';
import 'package:test/test.dart';

void main() {
  final cg.X25519 x25519 = cg.X25519();
  late Map<String, dynamic> cryptoKeys;
  late Uint8List serverPk;
  late cg.SimpleKeyPair serverKp;
  late Uint8List groupId;
  late Uint8List groupKey;

  setUpAll(() async {
    var dir = Directory.current;
    while (!File('${dir.path}/protocol/test-vectors/crypto_keys.json')
        .existsSync()) {
      final parent = dir.parent;
      if (parent.path == dir.path) {
        throw StateError('Cannot find protocol/test-vectors/');
      }
      dir = parent;
    }
    final vDir = '${dir.path}/protocol/test-vectors';
    cryptoKeys = jsonDecode(File('$vDir/crypto_keys.json').readAsStringSync());

    final serverSeed =
        Uint8List.fromList(hex.decode(cryptoKeys['server']['seed_hex']));
    serverKp = await MsgP2PCrypto.newKeyPairFromSeed(serverSeed);
    serverPk =
        Uint8List.fromList(hex.decode(cryptoKeys['server']['public_key_hex']));
    groupId = Uint8List.fromList(hex.decode(cryptoKeys['group_id_hex']));
    groupKey =
        Uint8List.fromList(hex.decode(cryptoKeys['group_key_epoch_1_hex']));
  });

  Future<MembershipCert> createCert({
    required String userId,
    required Uint8List memberPubkey,
    required Uint8List noisePubkey,
    Uint8List? targetGroupId,
  }) async {
    final now = DateTime.now().millisecondsSinceEpoch;
    final gid = targetGroupId ?? groupId;
    final certCore = MembershipCert(
      groupId: gid,
      userId: userId,
      memberPubkey: memberPubkey,
      noisePubkey: noisePubkey,
      role: 0,
      issuedAt: now - 1000,
      expiresAt: now + (7 * 86400 * 1000),
      serverSig: Uint8List(64),
    );
    final sig = await MsgP2PCrypto.sign(certCore.toCoreCbor(), serverKp);
    return MembershipCert(
      groupId: gid,
      userId: userId,
      memberPubkey: memberPubkey,
      noisePubkey: noisePubkey,
      role: 0,
      issuedAt: certCore.issuedAt,
      expiresAt: certCore.expiresAt,
      serverSig: sig,
    );
  }

  Future<Envelope> createEnvelope({
    required cg.SimpleKeyPair authorKp,
    required Uint8List certRef,
    required int seq,
    int priority = 2,
    String text = 'Test message',
  }) async {
    return Envelope.create(
      groupId: groupId,
      keyEpoch: 1,
      groupKey: groupKey,
      authorKeyPair: authorKp,
      certRef: certRef,
      seq: seq,
      priority: priority,
      payload: {
        'type': 'test',
        'body': {'text': text, 'seq': seq},
      },
    );
  }

  group('SessionStateMachine (FR-SYNC-04 & FR-SEC-06)', () {
    test(
        'Full bidirectional synchronization: SOS priority, messages, receipts & revocations',
        () async {
      final medium = FakeMedium();
      final transportA = FakeTransport(nodeAddress: 'peer_a', medium: medium);
      final transportB = FakeTransport(nodeAddress: 'peer_b', medium: medium);

      final storeA = MemoryMessageStore();
      final storeB = MemoryMessageStore();

      // Setup Alice
      final aliceSigningKp = await MsgP2PCrypto.newKeyPairFromSeed(
          Uint8List(32)..fillRange(0, 32, 1));
      final aliceSigningPk =
          await MsgP2PCrypto.getPublicKeyBytes(aliceSigningKp);
      final aliceNoiseKp = await x25519.newKeyPair();
      final aliceNoisePk = await NoiseHandshake.getPublicKeyBytes(aliceNoiseKp);
      final aliceCert = await createCert(
        userId: 'alice',
        memberPubkey: aliceSigningPk,
        noisePubkey: aliceNoisePk,
      );

      // Setup Bob
      final bobSigningKp = await MsgP2PCrypto.newKeyPairFromSeed(
          Uint8List(32)..fillRange(0, 32, 2));
      final bobSigningPk = await MsgP2PCrypto.getPublicKeyBytes(bobSigningKp);
      final bobNoiseKp = await x25519.newKeyPair();
      final bobNoisePk = await NoiseHandshake.getPublicKeyBytes(bobNoiseKp);
      final bobCert = await createCert(
        userId: 'bob',
        memberPubkey: bobSigningPk,
        noisePubkey: bobNoisePk,
      );

      // Populate Alice with messages: 1 Normal, 1 SOS (priority 0)
      final envA1 = await createEnvelope(
        authorKp: aliceSigningKp,
        certRef: aliceCert.certRef,
        seq: 1,
        priority: 2,
        text: 'Alice normal report',
      );
      final envA2 = await createEnvelope(
        authorKp: aliceSigningKp,
        certRef: aliceCert.certRef,
        seq: 2,
        priority: 0, // Emergency SOS
        text: 'Alice EMERGENCY SOS',
      );
      await storeA.saveBatch([envA1, envA2]);

      // Populate Bob with messages: 1 Normal, and 1 server receipt + 1 revocation notice
      final envB1 = await createEnvelope(
        authorKp: bobSigningKp,
        certRef: bobCert.certRef,
        seq: 1,
        priority: 2,
        text: 'Bob normal report',
      );
      await storeB.saveEnvelope(envB1);

      // Server receipt confirming Alice's message 1
      final receiptCore = ServerReceipt(
        groupId: groupId,
        author: aliceSigningPk,
        ranges: const [SeqRange(1, 1)],
        issuedAt: DateTime.now().millisecondsSinceEpoch,
        serverSig: Uint8List(64),
      );
      final receiptSig =
          await MsgP2PCrypto.sign(receiptCore.toCoreCbor(), serverKp);
      final receipt = ServerReceipt(
        groupId: groupId,
        author: aliceSigningPk,
        ranges: receiptCore.ranges,
        issuedAt: receiptCore.issuedAt,
        serverSig: receiptSig,
      );
      await storeB.saveReceipt(receipt);

      // Revocation notice for a rogue member
      final roguePk = Uint8List.fromList(List.generate(32, (i) => 0x99));
      final revCore = RevocationNotice(
        groupId: groupId,
        memberPubkey: roguePk,
        revokedAt: DateTime.now().millisecondsSinceEpoch,
        reason: 'Compromised key',
        serverSig: Uint8List(64),
      );
      final revSig = await MsgP2PCrypto.sign(revCore.toCoreCbor(), serverKp);
      final rev = RevocationNotice(
        groupId: groupId,
        memberPubkey: roguePk,
        revokedAt: revCore.revokedAt,
        reason: revCore.reason,
        serverSig: revSig,
      );
      await storeB.saveRevocation(rev);

      // Connect Alice -> Bob via FakeTransport
      final incomingFuture = transportB.incoming.first;
      final linkA = await transportA.connect(PeerAdvert(
        token: Uint8List(16),
        rssi: -50,
        peerAddress: 'peer_b',
      ));
      final linkB = await incomingFuture;

      final sessionA = SessionStateMachine(
        store: storeA,
        link: linkA,
        isInitiator: true,
        staticKeyPair: aliceNoiseKp,
        localCert: aliceCert,
        pinnedServerKey: serverPk,
        expectedGroupId: groupId,
      );

      final sessionB = SessionStateMachine(
        store: storeB,
        link: linkB,
        isInitiator: false,
        staticKeyPair: bobNoiseKp,
        localCert: bobCert,
        pinnedServerKey: serverPk,
        expectedGroupId: groupId,
      );

      // Run synchronization concurrently
      final results = await Future.wait([sessionA.run(), sessionB.run()]);
      final resA = results[0];
      final resB = results[1];

      // Assert session outcomes
      if (!resA.completedSuccessfully)
        print('resA failed: ${resA.failureReason}');
      if (!resB.completedSuccessfully)
        print('resB failed: ${resB.failureReason}');
      expect(resA.completedSuccessfully, isTrue);
      expect(resB.completedSuccessfully, isTrue);
      expect(resA.peerCert?.userId, equals('bob'));
      expect(resB.peerCert?.userId, equals('alice'));

      // Assert data replication completeness
      // Alice sent 2 envelopes (A1, A2) and received 1 (B1)
      expect(resA.envelopesSent, equals(2));
      expect(resA.envelopesReceived, equals(1));
      // Bob sent 1 envelope (B1) and received 2 (A1, A2)
      expect(resB.envelopesSent, equals(1));
      expect(resB.envelopesReceived, equals(2));

      // Alice now holds B1
      expect(await storeA.containsEnvelope(envB1.messageId), isTrue);
      // Bob now holds A1 and A2
      expect(await storeB.containsEnvelope(envA1.messageId), isTrue);
      expect(await storeB.containsEnvelope(envA2.messageId), isTrue);

      // Metadata replicated: Alice received receipt and revocation from Bob
      expect(await storeA.isConfirmed(aliceSigningPk, 1), isTrue);
      expect(await storeA.isRevoked(roguePk), isTrue);
    });

    test('Simultaneous connect tie-break (§7.4)', () {
      final pkLower = Uint8List.fromList([0x01, 0x02, 0x03]);
      final pkHigher = Uint8List.fromList([0x01, 0x02, 0x04]);

      expect(
          SessionStateMachine.comparePubkeys(pkLower, pkHigher), lessThan(0));
      expect(SessionStateMachine.comparePubkeys(pkHigher, pkLower),
          greaterThan(0));
      expect(SessionStateMachine.comparePubkeys(pkLower, pkLower), equals(0));
    });

    test('Rejects session when peer certificate belongs to different group',
        () async {
      final medium = FakeMedium();
      final transportA = FakeTransport(nodeAddress: 'peer_a', medium: medium);
      final transportB = FakeTransport(nodeAddress: 'peer_b', medium: medium);

      final otherGroupId = Uint8List.fromList(List.generate(16, (i) => 0x88));

      final aliceNoiseKp = await x25519.newKeyPair();
      final aliceNoisePk = await NoiseHandshake.getPublicKeyBytes(aliceNoiseKp);
      final aliceCert = await createCert(
        userId: 'alice',
        memberPubkey: Uint8List(32),
        noisePubkey: aliceNoisePk,
        targetGroupId: otherGroupId, // Different group!
      );

      final bobNoiseKp = await x25519.newKeyPair();
      final bobNoisePk = await NoiseHandshake.getPublicKeyBytes(bobNoiseKp);
      final bobCert = await createCert(
        userId: 'bob',
        memberPubkey: Uint8List(32),
        noisePubkey: bobNoisePk,
        targetGroupId: groupId,
      );

      final incomingFuture = transportB.incoming.first;
      final linkA = await transportA.connect(PeerAdvert(
        token: Uint8List(16),
        rssi: -50,
        peerAddress: 'peer_b',
      ));
      final linkB = await incomingFuture;

      final sessionA = SessionStateMachine(
        store: MemoryMessageStore(),
        link: linkA,
        isInitiator: true,
        staticKeyPair: aliceNoiseKp,
        localCert: aliceCert,
        pinnedServerKey: serverPk,
        expectedGroupId: otherGroupId,
      );

      final sessionB = SessionStateMachine(
        store: MemoryMessageStore(),
        link: linkB,
        isInitiator: false,
        staticKeyPair: bobNoiseKp,
        localCert: bobCert,
        pinnedServerKey: serverPk,
        expectedGroupId: groupId,
      );

      final results = await Future.wait([sessionA.run(), sessionB.run()]);
      expect(results[0].completedSuccessfully, isFalse);
      expect(results[1].completedSuccessfully, isFalse);
    });

    test(
        'Resumable synchronization: connection drop mid-DATA preserves progress and avoids retransmission (FR-SYNC-04)',
        () async {
      final medium = FakeMedium();
      final transportA = FakeTransport(nodeAddress: 'node_a', medium: medium);
      final transportB = FakeTransport(nodeAddress: 'node_b', medium: medium);

      final storeA = MemoryMessageStore();
      final storeB = MemoryMessageStore();

      final aliceKp = await MsgP2PCrypto.newKeyPairFromSeed(
          Uint8List(32)..fillRange(0, 32, 11));
      final alicePk = await MsgP2PCrypto.getPublicKeyBytes(aliceKp);
      final aliceNoiseKp = await x25519.newKeyPair();
      final aliceNoisePk = await NoiseHandshake.getPublicKeyBytes(aliceNoiseKp);
      final aliceCert = await createCert(
          userId: 'alice', memberPubkey: alicePk, noisePubkey: aliceNoisePk);

      final bobKp = await MsgP2PCrypto.newKeyPairFromSeed(
          Uint8List(32)..fillRange(0, 32, 12));
      final bobPk = await MsgP2PCrypto.getPublicKeyBytes(bobKp);
      final bobNoiseKp = await x25519.newKeyPair();
      final bobNoisePk = await NoiseHandshake.getPublicKeyBytes(bobNoiseKp);
      final bobCert = await createCert(
          userId: 'bob', memberPubkey: bobPk, noisePubkey: bobNoisePk);

      // Alice generates 5 envelopes
      for (var s = 1; s <= 5; s++) {
        await storeA.saveEnvelope(await createEnvelope(
          authorKp: aliceKp,
          certRef: aliceCert.certRef,
          seq: s,
          text: 'Message sequence $s',
        ));
      }
      expect(await storeA.getEnvelopeCount(), equals(5));
      expect(await storeB.getEnvelopeCount(), equals(0));

      // Simulate partial sync by manually storing 1 and 2 on Bob (representing a dropped connection after 2)
      final env1 = (await storeA
              .getEnvelopesByAuthorAndRanges(alicePk, const [SeqRange(1, 1)]))
          .first;
      final env2 = (await storeA
              .getEnvelopesByAuthorAndRanges(alicePk, const [SeqRange(2, 2)]))
          .first;
      await storeB.saveBatch([env1, env2]);
      expect(await storeB.getEnvelopeCount(), equals(2));

      // Reconnect peers after drop
      final incomingFuture = transportB.incoming.first;
      final linkA = await transportA.connect(PeerAdvert(
        token: Uint8List(16),
        rssi: -45,
        peerAddress: 'node_b',
      ));
      final linkB = await incomingFuture;

      final sessionA = SessionStateMachine(
        store: storeA,
        link: linkA,
        isInitiator: true,
        staticKeyPair: aliceNoiseKp,
        localCert: aliceCert,
        pinnedServerKey: serverPk,
        expectedGroupId: groupId,
      );

      final sessionB = SessionStateMachine(
        store: storeB,
        link: linkB,
        isInitiator: false,
        staticKeyPair: bobNoiseKp,
        localCert: bobCert,
        pinnedServerKey: serverPk,
        expectedGroupId: groupId,
      );

      final results = await Future.wait([sessionA.run(), sessionB.run()]);
      final resA = results[0];
      final resB = results[1];

      expect(resA.completedSuccessfully, isTrue);
      expect(resB.completedSuccessfully, isTrue);

      // Crucial verification: Alice sent ONLY the 3 remaining missing envelopes (3, 4, 5)!
      // Envelopes 1 and 2 were NOT retransmitted!
      expect(resA.envelopesSent, equals(3));
      expect(resB.envelopesReceived, equals(3));

      // Bob now holds all 5 envelopes
      expect(await storeB.getEnvelopeCount(), equals(5));
      for (var s = 1; s <= 5; s++) {
        expect(await storeB.isSequenceHeld(alicePk, s), isTrue);
      }
    });
  });
}
