import 'dart:convert';
import 'dart:typed_data';
import 'package:cryptography/cryptography.dart' as cg;
import 'package:msgp2p_core/msgp2p_core.dart';
import 'package:test/test.dart';

void main() {
  final x25519 = cg.X25519();
  late cg.SimpleKeyPair serverKp;
  late Uint8List serverPk;
  late Uint8List groupId;

  setUpAll(() async {
    // Generate server key for signing membership certificates
    serverKp = await MsgP2PCrypto.newKeyPairFromSeed(
      Uint8List.fromList(List.generate(32, (i) => 0x99 ^ i)),
    );
    serverPk = await MsgP2PCrypto.getPublicKeyBytes(serverKp);
    groupId = Uint8List.fromList(List.generate(16, (i) => 0x42));
  });

  Future<MembershipCert> createTestCert({
    required String userId,
    required Uint8List memberPubkey,
    Uint8List? noisePubkey,
    required Uint8List targetGroupId,
    int? issuedAt,
    int? expiresAt,
  }) async {
    final now = DateTime.now().millisecondsSinceEpoch;
    final iAt = issuedAt ?? (now - 10000);
    final eAt = expiresAt ?? (now + 86400000);
    final nPk = noisePubkey ?? memberPubkey;

    final certCore = MembershipCert(
      groupId: targetGroupId,
      userId: userId,
      memberPubkey: memberPubkey,
      noisePubkey: nPk,
      role: 0,
      issuedAt: iAt,
      expiresAt: eAt,
      serverSig: Uint8List(64),
    );
    final sig = await MsgP2PCrypto.sign(certCore.toCoreCbor(), serverKp);
    return MembershipCert(
      groupId: targetGroupId,
      userId: userId,
      memberPubkey: memberPubkey,
      noisePubkey: nPk,
      role: 0,
      issuedAt: iAt,
      expiresAt: eAt,
      serverSig: sig,
    );
  }

  group('Noise-XX Mutually Authenticated Handshake (FR-SEC-06)', () {
    test('Successful mutual handshake and bidirectional encrypted pipe',
        () async {
      // 1. Setup Alice (Initiator)
      final aliceStaticKp = await x25519.newKeyPair();
      final aliceStaticPk =
          await NoiseHandshake.getPublicKeyBytes(aliceStaticKp);
      final aliceCert = await createTestCert(
        userId: 'alice',
        memberPubkey: aliceStaticPk,
        targetGroupId: groupId,
      );

      // 2. Setup Bob (Responder)
      final bobStaticKp = await x25519.newKeyPair();
      final bobStaticPk = await NoiseHandshake.getPublicKeyBytes(bobStaticKp);
      final bobCert = await createTestCert(
        userId: 'bob',
        memberPubkey: bobStaticPk,
        targetGroupId: groupId,
      );

      // 3. Initiate Handshake
      final aliceState = await NoiseHandshake.startInitiator(
        staticKeyPair: aliceStaticKp,
        localCert: aliceCert,
        pinnedServerKey: serverPk,
        expectedGroupId: groupId,
      );

      final bobState = await NoiseHandshake.startResponder(
        staticKeyPair: bobStaticKp,
        localCert: bobCert,
        pinnedServerKey: serverPk,
        expectedGroupId: groupId,
      );

      // --- Message 1: Alice -> Bob ---
      final msg1 = await aliceState.createMessage1();
      expect(msg1.length, equals(32));

      // --- Message 2: Bob -> Alice ---
      final msg2 = await bobState.processMessage1AndCreateMessage2(msg1);
      expect(msg2.length, greaterThan(32 + 48));

      // --- Message 3: Alice -> Bob ---
      final aliceResult =
          await aliceState.processMessage2AndCreateMessage3(msg2);
      final msg3 = aliceResult.message3Bytes;
      final aliceSession = aliceResult.session;

      final bobSession = await bobState.processMessage3(msg3);

      // Verify mutual authentication
      expect(aliceSession.peerCert.userId, equals('bob'));
      expect(aliceSession.peerStaticPubkey, equals(bobStaticPk));
      expect(bobSession.peerCert.userId, equals('alice'));
      expect(bobSession.peerStaticPubkey, equals(aliceStaticPk));

      // 4. Test encrypted pipe communication
      final plaintextFromAlice =
          Uint8List.fromList(utf8.encode('Hello Bob from Alice!'));
      final encryptedFromAlice = await aliceSession.encrypt(plaintextFromAlice);
      final decryptedByBob = await bobSession.decrypt(encryptedFromAlice);
      expect(decryptedByBob, equals(plaintextFromAlice));

      final plaintextFromBob =
          Uint8List.fromList(utf8.encode('Hello Alice from Bob!'));
      final encryptedFromBob = await bobSession.encrypt(plaintextFromBob);
      final decryptedByAlice = await aliceSession.decrypt(encryptedFromBob);
      expect(decryptedByAlice, equals(plaintextFromBob));

      // Subsequent messages increment nonces correctly
      for (var i = 0; i < 5; i++) {
        final data = Uint8List.fromList([i, i + 1, i + 2]);
        final enc = await aliceSession.encrypt(data);
        final dec = await bobSession.decrypt(enc);
        expect(dec, equals(data));
      }
    });

    test(
        'Rejects handshake when static key does not match certificate noise_pubkey',
        () async {
      final aliceStaticKp = await x25519.newKeyPair();
      final fakeNoisePk = Uint8List.fromList(List.generate(32, (i) => 0xFE));

      // Cert contains fakeNoisePk, but Alice holds aliceStaticKp
      final certWithMismatchedPk = await createTestCert(
        userId: 'alice',
        memberPubkey: Uint8List(32),
        noisePubkey: fakeNoisePk,
        targetGroupId: groupId,
      );

      final bobStaticKp = await x25519.newKeyPair();
      final bobStaticPk = await NoiseHandshake.getPublicKeyBytes(bobStaticKp);
      final bobCert = await createTestCert(
        userId: 'bob',
        memberPubkey: bobStaticPk,
        targetGroupId: groupId,
      );

      final aliceState = await NoiseHandshake.startInitiator(
        staticKeyPair: aliceStaticKp,
        localCert: certWithMismatchedPk,
        pinnedServerKey: serverPk,
        expectedGroupId: groupId,
      );
      final bobState = await NoiseHandshake.startResponder(
        staticKeyPair: bobStaticKp,
        localCert: bobCert,
        pinnedServerKey: serverPk,
        expectedGroupId: groupId,
      );

      final msg1 = await aliceState.createMessage1();
      final msg2 = await bobState.processMessage1AndCreateMessage2(msg1);
      final aliceResult =
          await aliceState.processMessage2AndCreateMessage3(msg2);

      // Bob processing msg3 should fail because Alice's static key != cert member_pubkey
      expect(
        () => bobState.processMessage3(aliceResult.message3Bytes),
        throwsA(isA<SecurityException>()),
      );
    });

    test('Rejects handshake when certificate server signature is forged',
        () async {
      final aliceStaticKp = await x25519.newKeyPair();
      final aliceStaticPk =
          await NoiseHandshake.getPublicKeyBytes(aliceStaticKp);
      final now = DateTime.now().millisecondsSinceEpoch;
      final forgedCert = MembershipCert(
        groupId: groupId,
        userId: 'alice',
        memberPubkey: Uint8List(32),
        noisePubkey: aliceStaticPk,
        role: 0,
        issuedAt: now - 1000,
        expiresAt: now + 86400000,
        serverSig: Uint8List(64), // Bogus zero signature
      );

      final bobStaticKp = await x25519.newKeyPair();
      final bobStaticPk = await NoiseHandshake.getPublicKeyBytes(bobStaticKp);
      final bobCert = await createTestCert(
        userId: 'bob',
        memberPubkey: bobStaticPk,
        targetGroupId: groupId,
      );

      final aliceState = await NoiseHandshake.startInitiator(
        staticKeyPair: aliceStaticKp,
        localCert: forgedCert,
        pinnedServerKey: serverPk,
        expectedGroupId: groupId,
      );
      final bobState = await NoiseHandshake.startResponder(
        staticKeyPair: bobStaticKp,
        localCert: bobCert,
        pinnedServerKey: serverPk,
        expectedGroupId: groupId,
      );

      final msg1 = await aliceState.createMessage1();
      final msg2 = await bobState.processMessage1AndCreateMessage2(msg1);
      final aliceResult =
          await aliceState.processMessage2AndCreateMessage3(msg2);

      expect(
        () => bobState.processMessage3(aliceResult.message3Bytes),
        throwsA(isA<SecurityException>()),
      );
    });

    test('Rejects handshake when peer belongs to different group ID', () async {
      final otherGroupId = Uint8List.fromList(List.generate(16, (i) => 0x99));

      final aliceStaticKp = await x25519.newKeyPair();
      final aliceStaticPk =
          await NoiseHandshake.getPublicKeyBytes(aliceStaticKp);
      final aliceCert = await createTestCert(
        userId: 'alice',
        memberPubkey: aliceStaticPk,
        targetGroupId: otherGroupId, // Different group!
      );

      final bobStaticKp = await x25519.newKeyPair();
      final bobStaticPk = await NoiseHandshake.getPublicKeyBytes(bobStaticKp);
      final bobCert = await createTestCert(
        userId: 'bob',
        memberPubkey: bobStaticPk,
        targetGroupId: groupId,
      );

      final aliceState = await NoiseHandshake.startInitiator(
        staticKeyPair: aliceStaticKp,
        localCert: aliceCert,
        pinnedServerKey: serverPk,
        expectedGroupId: otherGroupId,
      );
      final bobState = await NoiseHandshake.startResponder(
        staticKeyPair: bobStaticKp,
        localCert: bobCert,
        pinnedServerKey: serverPk,
        expectedGroupId: groupId, // Expects original groupId
      );

      final msg1 = await aliceState.createMessage1();
      final msg2 = await bobState.processMessage1AndCreateMessage2(msg1);
      // Alice expects otherGroupId, so Alice rejects Bob's cert which has groupId
      expect(
        () => aliceState.processMessage2AndCreateMessage3(msg2),
        throwsA(isA<SecurityException>()),
      );
    });

    test('Rejects handshake when peer certificate is expired', () async {
      final now = DateTime.now().millisecondsSinceEpoch;
      final aliceStaticKp = await x25519.newKeyPair();
      final aliceStaticPk =
          await NoiseHandshake.getPublicKeyBytes(aliceStaticKp);
      final expiredCert = await createTestCert(
        userId: 'alice',
        memberPubkey: aliceStaticPk,
        targetGroupId: groupId,
        issuedAt: now - 20000,
        expiresAt: now - 5000, // Expired 5 seconds ago
      );

      final bobStaticKp = await x25519.newKeyPair();
      final bobStaticPk = await NoiseHandshake.getPublicKeyBytes(bobStaticKp);
      final bobCert = await createTestCert(
        userId: 'bob',
        memberPubkey: bobStaticPk,
        targetGroupId: groupId,
      );

      final aliceState = await NoiseHandshake.startInitiator(
        staticKeyPair: aliceStaticKp,
        localCert: expiredCert,
        pinnedServerKey: serverPk,
        expectedGroupId: groupId,
      );
      final bobState = await NoiseHandshake.startResponder(
        staticKeyPair: bobStaticKp,
        localCert: bobCert,
        pinnedServerKey: serverPk,
        expectedGroupId: groupId,
      );

      final msg1 = await aliceState.createMessage1();
      final msg2 = await bobState.processMessage1AndCreateMessage2(msg1);
      final aliceResult =
          await aliceState.processMessage2AndCreateMessage3(msg2);

      expect(
        () => bobState.processMessage3(aliceResult.message3Bytes),
        throwsA(isA<SecurityException>()),
      );
    });
  });
}
