import 'dart:typed_data';
import 'package:convert/convert.dart';
import 'package:cryptography/cryptography.dart' as cg;
import 'package:msgp2p_core/msgp2p_core.dart';
import 'package:test/test.dart';

void main() {
  final cg.X25519 x25519 = cg.X25519();

  group(
      'Phase 5 Security Review & Hardening Suite (FR-SEC-01..09, FR-ID-04..05)',
      () {
    late cg.SimpleKeyPair serverKp;
    late Uint8List serverPk;
    late Uint8List groupId;
    late Uint8List groupKey;

    setUp(() async {
      serverKp = await MsgP2PCrypto.newKeyPairFromSeed(
        Uint8List.fromList(List.generate(32, (i) => i + 1)),
      );
      serverPk = await MsgP2PCrypto.getPublicKeyBytes(serverKp);
      groupId = Uint8List.fromList(List.generate(16, (i) => 0x10 + i));
      groupKey = Uint8List.fromList(List.generate(32, (i) => 0xA0 + i));
    });

    Future<MembershipCert> signCert({
      required String userId,
      required Uint8List memberPubkey,
      required Uint8List noisePubkey,
      Uint8List? customGroupId,
    }) async {
      final now = DateTime.now().millisecondsSinceEpoch;
      final gid = customGroupId ?? groupId;
      final unsigned = MembershipCert(
        groupId: gid,
        userId: userId,
        memberPubkey: memberPubkey,
        noisePubkey: noisePubkey,
        role: 0,
        issuedAt: now - 5000,
        expiresAt: now + 86400000,
        serverSig: Uint8List(64),
      );
      final sig = await MsgP2PCrypto.sign(unsigned.toCoreCbor(), serverKp);
      return MembershipCert(
        groupId: gid,
        userId: userId,
        memberPubkey: memberPubkey,
        noisePubkey: noisePubkey,
        role: 0,
        issuedAt: unsigned.issuedAt,
        expiresAt: unsigned.expiresAt,
        serverSig: sig,
      );
    }

    test(
        'AEAD header binding: modifying core metadata invalidates both Ed25519 sig and XChaCha20-Poly1305 tag',
        () async {
      final authorKp = await MsgP2PCrypto.newKeyPairFromSeed(
          Uint8List(32)..fillRange(0, 32, 7));
      final env = await Envelope.create(
        groupId: groupId,
        keyEpoch: 1,
        groupKey: groupKey,
        authorKeyPair: authorKp,
        certRef: Uint8List(32),
        seq: 1,
        priority: 2,
        payload: {
          'type': 'bbs_post',
          'body': {'text': 'Confidential coordinates'},
        },
      );

      expect(await env.verifySignature(), isTrue);
      final decrypted = await env.decryptPayload(groupKey);
      expect(decrypted['type'], equals('bbs_post'));

      // Construct an envelope with seq/priority modified without re-encrypting
      final tamperedCore = EnvelopeCore(
        version: env.core.version,
        groupId: env.core.groupId,
        keyEpoch: env.core.keyEpoch,
        author: env.core.author,
        seq: 2, // Tampered sequence number (in AAD and signed core)!
        createdAt: env.core.createdAt,
        expiresAt: env.core.expiresAt,
        priority: 0, // Tampered priority (in signed core)!
        nonce: env.core.nonce,
        ciphertext: env.core.ciphertext,
        attachments: env.core.attachments,
      );
      final tamperedEnv = Envelope(
        core: tamperedCore,
        sig: env.sig,
        certRef: env.certRef,
      );

      // 1. Signature verification fails because priority is part of canonical_cbor(core)
      expect(await tamperedEnv.verifySignature(), isFalse);

      // 2. Even if attacker re-signed with their own key, AEAD decryption fails because AAD binds priority
      await expectLater(
        () => tamperedEnv.decryptPayload(groupKey),
        throwsA(anything),
      );
    });

    test(
        'SessionStateMachine drops DATA envelopes authored by revoked members and rejects handshake when rejectRevokedPeerHandshake is true',
        () async {
      final medium = FakeMedium();
      final transportA = FakeTransport(nodeAddress: 'node_a', medium: medium);
      final transportB = FakeTransport(nodeAddress: 'node_b', medium: medium);

      final storeA = MemoryMessageStore();
      final storeB = MemoryMessageStore();

      final aliceKp = await MsgP2PCrypto.newKeyPairFromSeed(
          Uint8List(32)..fillRange(0, 32, 0x21));
      final alicePk = await MsgP2PCrypto.getPublicKeyBytes(aliceKp);
      final aliceNoiseKp = await x25519.newKeyPair();
      final aliceNoisePk = await NoiseHandshake.getPublicKeyBytes(aliceNoiseKp);
      final aliceCert = await signCert(
        userId: 'alice',
        memberPubkey: alicePk,
        noisePubkey: aliceNoisePk,
      );

      final bobKp = await MsgP2PCrypto.newKeyPairFromSeed(
          Uint8List(32)..fillRange(0, 32, 0x22));
      final bobPk = await MsgP2PCrypto.getPublicKeyBytes(bobKp);
      final bobNoiseKp = await x25519.newKeyPair();
      final bobNoisePk = await NoiseHandshake.getPublicKeyBytes(bobNoiseKp);
      final bobCert = await signCert(
        userId: 'bob',
        memberPubkey: bobPk,
        noisePubkey: bobNoisePk,
      );

      // Compromise Charlie and record revocation in Bob's store
      final charlieKp = await MsgP2PCrypto.newKeyPairFromSeed(
          Uint8List(32)..fillRange(0, 32, 0x23));
      final charliePk = await MsgP2PCrypto.getPublicKeyBytes(charlieKp);
      final revUnsigned = RevocationNotice(
        groupId: groupId,
        memberPubkey: charliePk,
        revokedAt: DateTime.now().millisecondsSinceEpoch,
        reason: 'compromised',
        serverSig: Uint8List(64),
      );
      final revSig =
          await MsgP2PCrypto.sign(revUnsigned.toCoreCbor(), serverKp);
      final rev = RevocationNotice(
        groupId: groupId,
        memberPubkey: charliePk,
        revokedAt: revUnsigned.revokedAt,
        reason: revUnsigned.reason,
        serverSig: revSig,
      );
      await storeB.saveRevocation(rev);

      // Alice carries a message authored by revoked Charlie and a valid message authored by Alice
      final charlieEnv = await Envelope.create(
        groupId: groupId,
        keyEpoch: 1,
        groupKey: groupKey,
        authorKeyPair: charlieKp,
        certRef: Uint8List(32),
        seq: 1,
        priority: 2,
        payload: {
          'type': 'post',
          'body': {'text': 'From revoked Charlie'}
        },
      );
      final aliceEnv = await Envelope.create(
        groupId: groupId,
        keyEpoch: 1,
        groupKey: groupKey,
        authorKeyPair: aliceKp,
        certRef: aliceCert.certRef,
        seq: 1,
        priority: 2,
        payload: {
          'type': 'post',
          'body': {'text': 'From valid Alice'}
        },
      );
      await storeA.saveBatch([charlieEnv, aliceEnv]);

      // Sync A <-> B: Bob must ingest Alice's message but drop revoked Charlie's message
      final incoming1 = transportB.incoming.first;
      final linkA1 = await transportA.connect(
        PeerAdvert(token: Uint8List(16), rssi: -50, peerAddress: 'node_b'),
      );
      final linkB1 = await incoming1;

      final sA1 = SessionStateMachine(
        store: storeA,
        link: linkA1,
        isInitiator: true,
        staticKeyPair: aliceNoiseKp,
        localCert: aliceCert,
        pinnedServerKey: serverPk,
        expectedGroupId: groupId,
      );
      final sB1 = SessionStateMachine(
        store: storeB,
        link: linkB1,
        isInitiator: false,
        staticKeyPair: bobNoiseKp,
        localCert: bobCert,
        pinnedServerKey: serverPk,
        expectedGroupId: groupId,
      );

      final res1 = await Future.wait([sA1.run(), sB1.run()]);
      expect(res1[0].completedSuccessfully, isTrue);
      expect(res1[1].completedSuccessfully, isTrue);
      expect(await storeB.containsEnvelope(aliceEnv.messageId), isTrue);
      expect(await storeB.containsEnvelope(charlieEnv.messageId), isFalse);

      // Now revoke Alice on Bob's store and verify strict handshake rejection
      final revAliceUnsigned = RevocationNotice(
        groupId: groupId,
        memberPubkey: alicePk,
        revokedAt: DateTime.now().millisecondsSinceEpoch,
        reason: 'device_lost',
        serverSig: Uint8List(64),
      );
      final revAliceSig =
          await MsgP2PCrypto.sign(revAliceUnsigned.toCoreCbor(), serverKp);
      await storeB.saveRevocation(RevocationNotice(
        groupId: groupId,
        memberPubkey: alicePk,
        revokedAt: revAliceUnsigned.revokedAt,
        reason: revAliceUnsigned.reason,
        serverSig: revAliceSig,
      ));

      final incoming2 = transportB.incoming.first;
      final linkA2 = await transportA.connect(
        PeerAdvert(token: Uint8List(16), rssi: -50, peerAddress: 'node_b'),
      );
      final linkB2 = await incoming2;

      final sA2 = SessionStateMachine(
        store: storeA,
        link: linkA2,
        isInitiator: true,
        staticKeyPair: aliceNoiseKp,
        localCert: aliceCert,
        pinnedServerKey: serverPk,
        expectedGroupId: groupId,
        rejectRevokedPeerHandshake: true,
      );
      final sB2 = SessionStateMachine(
        store: storeB,
        link: linkB2,
        isInitiator: false,
        staticKeyPair: bobNoiseKp,
        localCert: bobCert,
        pinnedServerKey: serverPk,
        expectedGroupId: groupId,
        rejectRevokedPeerHandshake: true,
      );

      final res2 = await Future.wait([sA2.run(), sB2.run()]);
      expect(res2[1].completedSuccessfully, isFalse);
      expect(res2[1].failureReason, contains('revoked'));
    });

    test(
        'Resource exhaustion bounds: rejects > 4 KB core envelope and > 64 KB wire frame (requirements.md §3)',
        () async {
      final authorKp = await MsgP2PCrypto.newKeyPairFromSeed(
          Uint8List(32)..fillRange(0, 32, 9));
      await expectLater(
        () => Envelope.create(
          groupId: groupId,
          keyEpoch: 1,
          groupKey: groupKey,
          authorKeyPair: authorKp,
          certRef: Uint8List(32),
          seq: 1,
          priority: 2,
          payload: {
            'type': 'oversized',
            'body': {'blob': 'A' * 5000},
          },
        ),
        throwsA(isA<EnvelopeSizeLimitException>()),
      );

      expect(
        () => Frame(type: SessionFrameType.data, payload: Uint8List(70000))
            .encode(),
        throwsA(anyOf(isA<AssertionError>(), isA<FormatException>())),
      );
    });
  });

  group(
      'Non-Functional Requirements Benchmarks (NFR-PERF-02, NFR-PERF-03, NFR-PWR-01)',
      () {
    test(
        'NFR-PERF-02: Missing-range computation completes in <= 50 ms for 20,000 messages',
        () {
      final localVector = VersionVector();
      final remoteVector = VersionVector();

      // 100 authors x 200 messages = 20,000 messages with realistic sparse gaps
      for (var a = 0; a < 100; a++) {
        final authorHex = hex.encode(
            Uint8List.fromList(List.generate(32, (i) => (a + i) & 0xFF)));
        final localState = localVector.getOrCreate(authorHex);
        final remoteState = remoteVector.getOrCreate(authorHex);

        for (var seq = 1; seq <= 200; seq++) {
          remoteState.add(seq);
          // Local node holds first 150 contiguous + every even sequence from 152..200
          if (seq <= 150 || seq.isEven) {
            localState.add(seq);
          }
        }
      }

      final sw = Stopwatch()..start();
      final wantList = localVector.calculateWant(remoteVector);
      sw.stop();

      expect(wantList.length, equals(100));
      // Each author is missing 25 odd sequences (151, 153, ..., 199) => 2,500 missing messages total
      final totalRanges =
          wantList.fold<int>(0, (sum, w) => sum + w.ranges.length);
      expect(totalRanges, equals(2500));
      expect(
        sw.elapsedMilliseconds,
        lessThanOrEqualTo(50),
        reason:
            'NFR-PERF-02 requires 20,000-message diff in <= 50 ms (took ${sw.elapsedMilliseconds} ms)',
      );
    });

    test('NFR-PERF-03: Storage for 20,000 core messages stays <= 60 MB',
        () async {
      final store = MemoryMessageStore(maxStorageBytes: 100 * 1024 * 1024);
      final groupId = Uint8List(16);
      final nonce = Uint8List(24);
      // Typical 1.2 KB encrypted core payload
      final ciphertext = Uint8List(1200);
      final sig = Uint8List(64);
      final certRef = Uint8List(32);

      for (var a = 0; a < 100; a++) {
        final author = Uint8List(32)..[0] = a;
        for (var seq = 1; seq <= 200; seq++) {
          final env = Envelope(
            core: EnvelopeCore(
              version: 1,
              groupId: groupId,
              keyEpoch: 1,
              author: author,
              seq: seq,
              createdAt: 1700000000000 + seq,
              expiresAt: 1700086400000 + seq,
              priority: 2,
              nonce: nonce,
              ciphertext: ciphertext,
            ),
            sig: sig,
            certRef: certRef,
          );
          await store.saveEnvelope(env, customStoredAt: 1700000000000);
        }
      }

      expect(await store.getEnvelopeCount(), equals(20000));
      const sixtyMegabytes = 60 * 1024 * 1024;
      expect(
        store.currentStorageBytes,
        lessThanOrEqualTo(sixtyMegabytes),
        reason: 'NFR-PERF-03 requires 20,000 core messages to occupy <= 60 MB',
      );
    });

    test(
        'NFR-PWR-01: AdaptiveScanScheduler applies exponential back-off and resets on peer discovery',
        () {
      final scheduler = AdaptiveScanScheduler(
        baseInterval: const Duration(seconds: 5),
        maxInterval: const Duration(seconds: 160),
        scanWindow: const Duration(seconds: 1),
        backoffFactor: 2.0,
      );

      // Initial baseline policy: 1s window every 5s (20% duty cycle, aggressive: true)
      expect(
          scheduler.currentPolicy.interval, equals(const Duration(seconds: 5)));
      expect(
          scheduler.currentPolicy.window, equals(const Duration(seconds: 1)));
      expect(scheduler.currentPolicy.aggressive, isTrue);
      expect(scheduler.currentDutyCycleRatio, closeTo(0.20, 0.001));

      // Consecutive empty scan cycles back off exponentially: 10s, 20s, 40s, 80s, 160s (cap)
      expect(scheduler.recordEmptyScanCycle().interval,
          equals(const Duration(seconds: 10)));
      expect(scheduler.currentPolicy.aggressive, isFalse);
      expect(scheduler.recordEmptyScanCycle().interval,
          equals(const Duration(seconds: 20)));
      expect(scheduler.recordEmptyScanCycle().interval,
          equals(const Duration(seconds: 40)));
      expect(scheduler.recordEmptyScanCycle().interval,
          equals(const Duration(seconds: 80)));
      expect(scheduler.recordEmptyScanCycle().interval,
          equals(const Duration(seconds: 160)));
      // Further empty cycles remain capped at maxInterval (160s -> 0.625% duty cycle)
      expect(scheduler.recordEmptyScanCycle().interval,
          equals(const Duration(seconds: 160)));
      expect(scheduler.currentDutyCycleRatio, closeTo(0.00625, 0.0001));

      // Discovering a peer immediately resets back-off to baseline (5s, aggressive: true)
      final resetPolicy = scheduler.recordPeerDiscovered();
      expect(scheduler.emptyScanCycles, equals(0));
      expect(resetPolicy.interval, equals(const Duration(seconds: 5)));
      expect(resetPolicy.aggressive, isTrue);
    });
  });
}
