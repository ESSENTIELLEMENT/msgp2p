import 'dart:typed_data';
import 'package:cryptography/cryptography.dart' as cg;
import 'package:flutter_test/flutter_test.dart';
import 'package:msgp2p_flutter/msgp2p_flutter.dart';

void main() {
  group('MsgP2PNode SDK Facade (FR-SDK-04 & FR-APP-02)', () {
    late Uint8List groupId;
    late Uint8List groupKey;
    late cg.SimpleKeyPair serverKeyPair;
    late Uint8List serverPubkey;
    late LoopbackBleMedium bleMedium;

    setUp(() async {
      groupId = Uint8List.fromList(List.generate(16, (i) => i + 1));
      groupKey = Uint8List.fromList(List.generate(32, (i) => i + 10));
      serverKeyPair = await MsgP2PCrypto.newKeyPairFromSeed(
          Uint8List.fromList(List.filled(32, 7)));
      serverPubkey = await MsgP2PCrypto.getPublicKeyBytes(serverKeyPair);
      bleMedium = LoopbackBleMedium();
    });

    Future<MsgP2PNode> createProvisionedNode(
        String address, int seedByte) async {
      final signSeed = Uint8List.fromList(List.filled(32, seedByte));
      final noiseSeed = Uint8List.fromList(List.filled(32, seedByte + 50));

      final signKp = await MsgP2PCrypto.newKeyPairFromSeed(signSeed);
      final memberPk = await MsgP2PCrypto.getPublicKeyBytes(signKp);
      final noiseKp = await cg.X25519().newKeyPairFromSeed(noiseSeed);
      final noisePk = await NoiseHandshake.getPublicKeyBytes(noiseKp);

      final now = DateTime.now().millisecondsSinceEpoch;
      final certCore = MembershipCert(
        groupId: groupId,
        userId: address,
        memberPubkey: memberPk,
        noisePubkey: noisePk,
        role: 0,
        issuedAt: now - 10000,
        expiresAt: now + 86400000,
        serverSig: Uint8List(0),
      );
      final sig = await MsgP2PCrypto.sign(certCore.toCoreCbor(), serverKeyPair);
      final cert = MembershipCert(
        groupId: groupId,
        userId: address,
        memberPubkey: memberPk,
        noisePubkey: noisePk,
        role: 0,
        issuedAt: certCore.issuedAt,
        expiresAt: certCore.expiresAt,
        serverSig: sig,
      );

      final bridge = bleMedium.createBridge(address);
      final transport = AndroidBleTransport(bridge: bridge);

      return MsgP2PNode.initialize(
        config: MsgP2PConfig(
          serverEndpoint: Uri.parse('http://localhost:8000/api/v1'),
          serverPublicKey: serverPubkey,
          groupId: groupId,
        ),
        transport: transport,
        signingSeed: signSeed,
        noiseSeed: noiseSeed,
        initialCert: cert,
        initialGroupKeys: {1: groupKey},
        initialBeaconKey: Uint8List.fromList(List.filled(32, 0x55)),
      );
    }

    test(
        'Message lifecycle: Local only -> Handed to peer -> Server confirmed, with SOS priority sorting',
        () async {
      final nodeAlice = await createProvisionedNode('AA:BB:CC:00:01', 11);
      final nodeBob = await createProvisionedNode('AA:BB:CC:00:02', 22);
      addTearDown(() async {
        await nodeAlice.dispose();
        await nodeBob.dispose();
      });

      // 1. Alice publishes a normal BBS post and an emergency SOS alert
      await nodeAlice.publish(
        type: 'bbs_post',
        body: {'title': 'Trail condition', 'text': 'Muddy near creek'},
        priority: Priority.normal,
      );
      await nodeAlice.publish(
        type: 'sos',
        body: {
          'title': 'SOS Alert',
          'text': 'Injured climber at North Ridge',
          'lat': 35.36,
          'lng': 138.72
        },
        priority: Priority.sos,
      );

      final initialMsgs = await nodeAlice.getDecryptedMessages();
      expect(initialMsgs.length, equals(2));
      // SOS (priority 0) must be ordered first
      expect(initialMsgs.first.isSos, isTrue);
      expect(initialMsgs.first.status, equals(MessageDeliveryStatus.localOnly));
      expect(initialMsgs.last.status, equals(MessageDeliveryStatus.localOnly));

      // 2. Alice and Bob start radios and sync over AndroidBleTransport
      await nodeBob.startMeshRadio();
      await nodeAlice.startMeshRadio();

      final syncRes = await nodeAlice.syncDirectlyWithNode(
        nodeBob,
        peerAddress: 'AA:BB:CC:00:02',
      );
      expect(syncRes.completedSuccessfully, isTrue);
      expect(syncRes.envelopesSent, equals(2));

      // Verify Alice's messages transitioned to `Handed to peer`
      final afterPeerSyncMsgs = await nodeAlice.getDecryptedMessages();
      expect(afterPeerSyncMsgs.first.status,
          equals(MessageDeliveryStatus.handedToPeer));
      expect(afterPeerSyncMsgs.last.status,
          equals(MessageDeliveryStatus.handedToPeer));

      // Verify Bob received and decrypted both messages
      final bobMsgs = await nodeBob.getDecryptedMessages();
      expect(bobMsgs.length, equals(2));
      expect(bobMsgs.first.body['title'], equals('SOS Alert'));

      // 3. Apply a server-signed receipt confirming seq 1..2 for Alice
      final receiptCore = ServerReceipt(
        groupId: groupId,
        author: nodeAlice.memberPubkey,
        ranges: const [SeqRange(1, 2)],
        issuedAt: DateTime.now().millisecondsSinceEpoch,
        serverSig: Uint8List(0),
      );
      final receiptSig =
          await MsgP2PCrypto.sign(receiptCore.toCoreCbor(), serverKeyPair);
      final signedReceipt = ServerReceipt(
        groupId: groupId,
        author: nodeAlice.memberPubkey,
        ranges: const [SeqRange(1, 2)],
        issuedAt: receiptCore.issuedAt,
        serverSig: receiptSig,
      );

      await nodeAlice.applyServerReceipt(signedReceipt);

      final confirmedMsgs = await nodeAlice.getDecryptedMessages();
      expect(confirmedMsgs.first.status,
          equals(MessageDeliveryStatus.serverConfirmed));
      expect(confirmedMsgs.last.status,
          equals(MessageDeliveryStatus.serverConfirmed));
    });
  });
}
