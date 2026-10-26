import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';
import 'package:convert/convert.dart';
import 'package:msgp2p_core/msgp2p_core.dart';
import 'package:test/test.dart';

void main() {
  late Map<String, dynamic> cryptoKeys;
  late Map<String, dynamic> versionVectorsData;
  late Uint8List serverPk;
  late Uint8List alicePk;
  late Uint8List aliceSeed;
  late Uint8List groupId;
  late Uint8List groupKey;

  setUpAll(() {
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
    versionVectorsData =
        jsonDecode(File('$vDir/version_vectors.json').readAsStringSync());

    serverPk =
        Uint8List.fromList(hex.decode(cryptoKeys['server']['public_key_hex']));
    alicePk =
        Uint8List.fromList(hex.decode(cryptoKeys['alice']['public_key_hex']));
    aliceSeed = Uint8List.fromList(hex.decode(cryptoKeys['alice']['seed_hex']));
    groupId = Uint8List.fromList(hex.decode(cryptoKeys['group_id_hex']));
    groupKey =
        Uint8List.fromList(hex.decode(cryptoKeys['group_key_epoch_1_hex']));
  });

  group('Envelope creation & verification', () {
    test('Envelope.create produces verifiable and decryptable message',
        () async {
      final aliceKp = await MsgP2PCrypto.newKeyPairFromSeed(aliceSeed);
      final dummyCertRef = Uint8List(32);

      final envelope = await Envelope.create(
        groupId: groupId,
        keyEpoch: 1,
        groupKey: groupKey,
        authorKeyPair: aliceKp,
        certRef: dummyCertRef,
        seq: 42,
        priority: 0,
        payload: {
          'type': 'sos',
          'body': {'alert': 'Test emergency', 'code': 99},
        },
      );

      // 1. Verify author signature
      final validSig = await envelope.verifySignature();
      expect(validSig, isTrue);

      // 2. Message ID is 32 bytes SHA-256
      expect(envelope.messageId.length, equals(32));

      // 3. Decrypt payload
      final decryptedCbor = await envelope.decryptPayloadCbor(groupKey);
      expect(decryptedCbor, isNotEmpty);
    });
  });

  group('ServerReceipt model', () {
    test('ServerReceipt verifies and accurately checks sequence confirmation',
        () async {
      final serverKp = await MsgP2PCrypto.newKeyPairFromSeed(
        Uint8List.fromList(hex.decode(cryptoKeys['server']['seed_hex'])),
      );

      final receiptCore = ServerReceipt(
        groupId: groupId,
        author: alicePk,
        ranges: const [SeqRange(1, 10), SeqRange(15, 20)],
        issuedAt: 1773822000000,
        serverSig: Uint8List(64), // placeholder
      );

      final sig = await MsgP2PCrypto.sign(receiptCore.toCoreCbor(), serverKp);
      final signedReceipt = ServerReceipt(
        groupId: groupId,
        author: alicePk,
        ranges: receiptCore.ranges,
        issuedAt: receiptCore.issuedAt,
        serverSig: sig,
      );

      final valid = await signedReceipt.verify(serverPk);
      expect(valid, isTrue);

      expect(signedReceipt.confirms(5), isTrue);
      expect(signedReceipt.confirms(10), isTrue);
      expect(signedReceipt.confirms(12), isFalse);
      expect(signedReceipt.confirms(17), isTrue);
      expect(signedReceipt.confirms(25), isFalse);
    });
  });

  group('VersionVector reconciliation & WANT calculation', () {
    test('Accurately matches protocol/test-vectors/version_vectors.json', () {
      final aliceHex = versionVectorsData['author_alice_hex'] as String;
      final bobHex = versionVectorsData['author_bob_hex'] as String;

      // 1. Reconstruct Peer A vector
      final peerA = VersionVector();
      peerA.getOrCreate(aliceHex).contiguous = 5;
      peerA.getOrCreate(aliceHex).gaps.addAll([8, 9]);
      peerA.getOrCreate(bobHex).contiguous = 10;

      // 2. Reconstruct Peer B vector
      final peerB = VersionVector();
      peerB.getOrCreate(aliceHex).contiguous = 10;
      peerB.getOrCreate(bobHex).contiguous = 6;
      peerB.getOrCreate(bobHex).gaps.add(8);

      // 3. Peer A wants missing items from Peer B
      final wantA = peerA.calculateWant(peerB);
      expect(wantA.length, equals(1));
      expect(wantA.first.authorHex, equals(aliceHex));
      expect(
        wantA.first.ranges,
        equals(const [SeqRange(6, 7), SeqRange(10, 10)]),
      );

      // 4. Peer B wants missing items from Peer A
      final wantB = peerB.calculateWant(peerA);
      expect(wantB.length, equals(1));
      expect(wantB.first.authorHex, equals(bobHex));
      expect(
        wantB.first.ranges,
        equals(const [SeqRange(7, 7), SeqRange(9, 10)]),
      );
    });

    test('Consolidates contiguous sequences as gaps fill in', () {
      final state = AuthorState(contiguous: 5, gaps: {7, 8, 10});
      expect(state.contiguous, equals(5));

      // Adding 6 should connect 5, 6, 7, 8 and advance contiguous to 8!
      state.add(6);
      expect(state.contiguous, equals(8));
      expect(state.gaps, equals({10}));

      // Adding 9 should connect 8, 9, 10 and advance contiguous to 10!
      state.add(9);
      expect(state.contiguous, equals(10));
      expect(state.gaps, isEmpty);
    });
  });
}
