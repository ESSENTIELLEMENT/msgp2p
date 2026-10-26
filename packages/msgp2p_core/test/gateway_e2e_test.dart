import 'dart:io';
import 'dart:typed_data';
import 'package:cbor/cbor.dart' as cbor;
import 'package:convert/convert.dart';
import 'package:msgp2p_core/msgp2p_core.dart';
import 'package:test/test.dart';

void main() {
  group('Gateway End-to-End Integration Suite (FR-SRV-02..05 & FR-TEST-07)',
      () {
    late Process phpServer;
    late GatewayClient client;
    const port = 8999;
    const baseUrl = 'http://127.0.0.1:$port/api/v1';

    // Group ID and seed keys matching protocol/test-vectors/crypto_keys.json
    final groupId =
        Uint8List.fromList(hex.decode('a0b1c2d3e4f50123456789abcdef0123'));
    final groupKeyEpoch1 = Uint8List.fromList(hex.decode(
        '6a6857b42afacd39bae57823e733fc9165583be6c3d46dfa4af174bdca658656'));

    setUpAll(() async {
      // 1. Reset msgp2p_test database
      final migrateRes = await Process.run(
          'php',
          [
            '-r',
            'require_once "server/php/vendor/autoload.php"; MsgP2P\\Server\\Database::resetDatabase("msgp2p_test");'
          ],
          workingDirectory: '../../');
      expect(migrateRes.exitCode, equals(0),
          reason: 'Failed to reset test database: ${migrateRes.stderr}');

      // 2. Start PHP server against msgp2p_test
      phpServer = await Process.start(
        'php',
        ['-S', '127.0.0.1:$port', '-t', 'server/php/public'],
        environment: {'DB_NAME': 'msgp2p_test'},
        workingDirectory: '../../',
      );

      // Brief delay to allow web server to bind
      await Future.delayed(const Duration(milliseconds: 300));
      client = GatewayClient(baseUrl: baseUrl);
    });

    tearDownAll(() async {
      client.close();
      phpServer.kill();
    });

    test(
        'Full lifecycle: register, login, push envelopes, verify receipts, and pull',
        () async {
      // 1. Generate keys for Alice & Bob
      final aliceKeyPair = await MsgP2PCrypto.newKeyPairFromSeed(
        Uint8List.fromList(hex.decode(
            '6c6645b012fb247612a9b8d48841d700be0dcda62a2c5780ea72fa7a03aa0b1c')),
      );
      final alicePk = await MsgP2PCrypto.getPublicKeyBytes(aliceKeyPair);
      final aliceNoisePk = Uint8List.fromList(hex.decode(
          '33da15b221906070a5a3e60b225d3e79c979aac6127ca9692829952758d53472'));

      final bobKeyPair = await MsgP2PCrypto.newKeyPairFromSeed(
        Uint8List.fromList(hex.decode(
            '1f0c33be0b3a1771922c0ccc8b4cad2c3a2e3ae96742193f96131167dd752aec')),
      );
      final bobPk = await MsgP2PCrypto.getPublicKeyBytes(bobKeyPair);
      final bobNoisePk = Uint8List.fromList(hex.decode(
          '5b688c9741b9d511d5b03b8fa7db05d1db2d45a18088c9e8c51b437973c2937f'));

      // 2. Register Alice and Bob
      final aliceReg = await client.register(
        username: 'alice_e2e',
        password: 'passwordAlice123!',
        groupId: hex.encode(groupId),
        memberPubkey: alicePk,
        noisePubkey: aliceNoisePk,
      );
      expect(aliceReg.status, equals('ACTIVE'));
      expect(aliceReg.userId, startsWith('usr_'));

      final bobReg = await client.register(
        username: 'bob_e2e',
        password: 'passwordBob123!',
        groupId: hex.encode(groupId),
        memberPubkey: bobPk,
        noisePubkey: bobNoisePk,
      );
      expect(bobReg.status, equals('ACTIVE'));

      // 3. Login as Alice
      final aliceLogin = await client.login(
        username: 'alice_e2e',
        password: 'passwordAlice123!',
      );
      expect(aliceLogin.accessToken, isNotEmpty);
      expect(
          aliceLogin.serverPubkey,
          equals(Uint8List.fromList(hex.decode(
              'cfbb7b389c637893cb03da870625f9763a7143ec93513e3661ee3a5e47335f97'))));
      expect(aliceLogin.groupKeys, isNotEmpty);

      // Verify Alice's certificate
      final aliceCert = aliceLogin.membershipCert;
      expect(aliceCert.userId, equals(aliceReg.userId));
      expect(aliceCert.memberPubkey, equals(alicePk));
      final certValid = await aliceCert.verify(aliceLogin.serverPubkey);
      expect(certValid, isTrue);

      // Initialize Alice's local store
      final aliceStore = MemoryMessageStore();
      await aliceStore.saveCertificate(aliceCert);
      final aliceCertRef = aliceCert.certRef;

      // 4. Create and store messages on Alice
      final sosEnv = await Envelope.create(
        groupId: groupId,
        keyEpoch: 1,
        groupKey: groupKeyEpoch1,
        authorKeyPair: aliceKeyPair,
        certRef: aliceCertRef,
        seq: 1,
        ttl: const Duration(hours: 24),
        priority: 0, // SOS
        payload: {
          'type': 'sos',
          'body': {'alert': 'Hiker needs assistance at ridge'},
        },
      );
      final bbsEnv = await Envelope.create(
        groupId: groupId,
        keyEpoch: 1,
        groupKey: groupKeyEpoch1,
        authorKeyPair: aliceKeyPair,
        certRef: aliceCertRef,
        seq: 2,
        ttl: const Duration(hours: 24),
        priority: 2, // Normal BBS
        payload: {
          'type': 'bbs_post',
          'body': {'title': 'Weather update', 'text': 'Clear skies on summit'},
        },
      );
      await aliceStore.saveEnvelope(sosEnv);
      await aliceStore.saveEnvelope(bbsEnv);

      // 5. Alice synchronizes with the gateway server
      final syncResult = await client.sync(
        store: aliceStore,
        groupId: groupId,
        pendingEnvelopes: [sosEnv, bbsEnv],
      );
      expect(syncResult.pushedCount, equals(2));
      expect(syncResult.acceptedCount, equals(2));
      expect(syncResult.receiptsCount, greaterThanOrEqualTo(1));

      // Verify that Alice's store records both messages as server-confirmed
      expect(await aliceStore.isConfirmed(alicePk, 1), isTrue);
      expect(await aliceStore.isConfirmed(alicePk, 2), isTrue);

      // 6. Bob logs in and synchronizes with empty local store
      final bobLogin = await client.login(
        username: 'bob_e2e',
        password: 'passwordBob123!',
      );
      final bobClient =
          GatewayClient(baseUrl: baseUrl, authToken: bobLogin.accessToken);
      final bobStore = MemoryMessageStore();
      await bobStore.saveCertificate(bobLogin.membershipCert);

      final bobSyncResult = await bobClient.sync(
        store: bobStore,
        groupId: groupId,
      );
      expect(bobSyncResult.pulledCount, equals(2));

      // Verify Bob received both messages in correct sequence and decryptable
      final pulled1 = await bobStore.getEnvelope(sosEnv.messageId);
      final pulled2 = await bobStore.getEnvelope(bbsEnv.messageId);
      expect(pulled1, isNotNull);
      expect(pulled2, isNotNull);
      expect(pulled1!.core.priority, equals(0));
      expect(pulled2!.core.priority, equals(2));

      final decryptedSosBytes =
          await pulled1.decryptPayloadCbor(groupKeyEpoch1);
      final decryptedSos =
          cbor.cbor.decode(decryptedSosBytes).toObject() as Map;
      expect((decryptedSos['body'] as Map)['alert'],
          equals('Hiker needs assistance at ridge'));

      // 7. Verify Server Receipts stored on Bob
      final receipts = await bobStore.getReceipts();
      expect(receipts, isNotEmpty);
      for (final r in receipts) {
        final verified = await r.verify(bobLogin.serverPubkey);
        expect(verified, isTrue);
        expect(r.confirms(1), isTrue);
        expect(r.confirms(2), isTrue);
      }

      // 8. Revoke a compromised member & verify group key epoch rotation (FR-SEC-02, FR-ID-05)
      final compromisedPk = Uint8List.fromList(List.filled(32, 0xaa));
      final revokeRes = await bobClient.revokeMember(
        groupId: hex.encode(groupId),
        memberPubkey: compromisedPk,
        reason: 'compromised_key',
      );
      expect(revokeRes.newGroupKey.epoch, equals(2));
      expect(revokeRes.newGroupKey.keyHex.length, equals(64));
      expect(await revokeRes.revocation.verify(bobLogin.serverPubkey), isTrue);

      // Alice syncs and receives the revocation notice
      final aliceSync2 = await client.sync(store: aliceStore, groupId: groupId);
      expect(aliceSync2.revocationsCount, greaterThanOrEqualTo(1));
      expect(await aliceStore.isRevoked(compromisedPk), isTrue);

      // 9. Attachment blob upload & download over Gateway API (v0.2)
      final attachmentBytes =
          Uint8List.fromList(List.generate(1024, (i) => (i * 19) & 0xFF));
      final attRef =
          AttachmentRef.fromBytes(bytes: attachmentBytes, mime: 'image/png');
      await aliceStore.saveAttachmentBlob(
        hash: attRef.hash,
        mime: attRef.mime,
        bytes: attachmentBytes,
      );
      final envWithAtt = await Envelope.create(
        groupId: groupId,
        keyEpoch: 1,
        groupKey: groupKeyEpoch1,
        authorKeyPair: aliceKeyPair,
        certRef: aliceCertRef,
        seq: 3,
        payload: {
          'type': 'bbs_post',
          'body': {'text': 'Map snapshot attached'}
        },
        attachments: [attRef],
      );
      await aliceStore.saveEnvelope(envWithAtt);

      final aliceAttSync = await client.sync(
        store: aliceStore,
        groupId: groupId,
        pendingEnvelopes: [envWithAtt],
      );
      expect(aliceAttSync.acceptedCount, equals(1));
      expect(aliceAttSync.attachmentsUploaded, equals(1));

      final bobAttSync = await bobClient.sync(
        store: bobStore,
        groupId: groupId,
      );
      expect(bobAttSync.pulledCount, equals(1));
      expect(bobAttSync.attachmentsDownloaded, equals(1));
      expect(await bobStore.containsAttachmentBlob(attRef.hash), isTrue);
      final bobBlob = await bobStore.getAttachmentBlob(attRef.hash);
      expect(bobBlob!.bytes, equals(attachmentBytes));

      bobClient.close();
    });
  });
}
