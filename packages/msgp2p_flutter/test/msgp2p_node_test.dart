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
      String address,
      int seedByte, {
      GatewayApi? gateway,
    }) async {
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
        gateway: gateway,
        keyVault: MemoryKeyVault.fromSeeds(
            IdentitySeeds(signing: signSeed, noise: noiseSeed)),
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

    test('syncWithGateway syncs over an injected GatewayApi port', () async {
      final sharedGateway = MemoryGatewayApi(
        serverPublicKey: serverPubkey,
        serverSigningKeyPair: serverKeyPair,
      );
      final nodeAlice = await createProvisionedNode(
        'AA:BB:CC:00:11',
        31,
        gateway: sharedGateway,
      );
      final nodeBob = await createProvisionedNode(
        'AA:BB:CC:00:12',
        42,
        gateway: sharedGateway,
      );
      addTearDown(() async {
        await nodeAlice.dispose();
        await nodeBob.dispose();
      });

      await nodeAlice.publish(
        type: 'sos',
        body: {'title': 'SOS via GatewayApi'},
        priority: Priority.sos,
      );

      final aliceSync = await nodeAlice.syncWithGateway();
      expect(aliceSync.pushedCount, equals(1));
      expect(aliceSync.acceptedCount, equals(1));
      expect(aliceSync.receiptsCount, greaterThanOrEqualTo(1));

      final aliceMsgs = await nodeAlice.getDecryptedMessages();
      expect(aliceMsgs.single.status,
          equals(MessageDeliveryStatus.serverConfirmed));

      final bobSync = await nodeBob.syncWithGateway();
      expect(bobSync.pulledCount, equals(1));
      final bobMsgs = await nodeBob.getDecryptedMessages();
      expect(bobMsgs.single.body['title'], equals('SOS via GatewayApi'));
      expect(
          bobMsgs.single.status, equals(MessageDeliveryStatus.serverConfirmed));
    });

    test(
        'provisions via MembershipSource on initialize, refreshes rotated keys & revocations (§9.1), and syncs P2P',
        () async {
      final authority = MemoryMembershipSource(
        serverSigningKeyPair: serverKeyPair,
      );
      authority.configureGroup(
        GroupId(groupId),
        initialGroupKey: groupKey,
        initialBeaconKey: Uint8List.fromList(List.filled(32, 0x55)),
      );

      final nodeAlice = await MsgP2PNode.initialize(
        config: MsgP2PConfig(
          serverEndpoint: Uri.parse('http://localhost:8000/api/v1'),
          serverPublicKey: serverPubkey,
          groupId: groupId,
        ),
        transport: AndroidBleTransport(
            bridge: bleMedium.createBridge('AA:BB:CC:00:21')),
        keyVault: MemoryKeyVault(),
        membershipSource: authority,
      );

      // Deferred provisioning (offline cold start -> refreshMembership)
      final nodeBob = await MsgP2PNode.initialize(
        config: MsgP2PConfig(
          serverEndpoint: Uri.parse('http://localhost:8000/api/v1'),
          serverPublicKey: serverPubkey,
          groupId: groupId,
        ),
        transport: AndroidBleTransport(
            bridge: bleMedium.createBridge('AA:BB:CC:00:22')),
        keyVault: MemoryKeyVault(),
        membershipSource: authority,
        provisionOnInitialize: false,
      );
      addTearDown(() async {
        await nodeAlice.dispose();
        await nodeBob.dispose();
      });

      expect(nodeAlice.membershipCert, isNotNull);
      expect(nodeAlice.currentMembershipGrant, isNotNull);
      expect(nodeAlice.membershipRefreshAfter, isNotNull);
      expect(nodeBob.membershipCert, isNull);

      await nodeBob.refreshMembership();
      expect(nodeBob.membershipCert, isNotNull);

      final initialEpoch = nodeAlice.activeKeyEpoch;
      await nodeAlice.publish(
        type: 'bbs_post',
        body: const {'title': 'Epoch 1 post'},
      );

      // Revoke a third peer -> authority signs RevocationNotice and rotates group key epoch
      final revokedPk = Uint8List.fromList(List.filled(32, 0xDE));
      await authority.revokeMember(
        GroupId(groupId),
        revokedPk,
        reason: 'lost_device',
      );

      final refreshedGrant = await nodeAlice.refreshMembership();
      expect(nodeAlice.activeKeyEpoch, greaterThan(initialEpoch));
      expect(refreshedGrant.revocations, hasLength(1));
      expect(await nodeAlice.store.isRevoked(revokedPk), isTrue);

      // Alice authors under the rotated epoch; Bob refreshes and syncs P2P
      await nodeAlice.publish(
        type: 'sos',
        body: const {'title': 'Post-rotation SOS'},
        priority: Priority.sos,
      );
      await nodeBob.refreshMembership();
      expect(await nodeBob.store.isRevoked(revokedPk), isTrue);

      await nodeBob.startMeshRadio();
      await nodeAlice.startMeshRadio();
      final p2pRes = await nodeAlice.syncDirectlyWithNode(
        nodeBob,
        peerAddress: 'AA:BB:CC:00:22',
      );
      expect(p2pRes.completedSuccessfully, isTrue);

      final bobMsgs = await nodeBob.getDecryptedMessages();
      expect(bobMsgs, hasLength(2));
      expect(bobMsgs.first.body['title'], equals('Post-rotation SOS'));
    });

    test(
        'rejects forged MembershipGrant from untrusted MembershipSource before writing to store',
        () async {
      final rogueKp = await MsgP2PCrypto.newKeyPairFromSeed(
        Uint8List.fromList(List.filled(32, 0xEE)),
      );
      final rogueAuthority = MemoryMembershipSource(
        serverSigningKeyPair: rogueKp,
      );

      await expectLater(
        MsgP2PNode.initialize(
          config: MsgP2PConfig(
            serverEndpoint: Uri.parse('http://localhost:8000/api/v1'),
            serverPublicKey: serverPubkey,
            groupId: groupId,
          ),
          transport: AndroidBleTransport(
            bridge: bleMedium.createBridge('AA:BB:CC:00:31'),
          ),
          keyVault: MemoryKeyVault(),
          membershipSource: rogueAuthority,
        ),
        throwsA(
          isA<MembershipException>().having(
            (e) => e.kind,
            'kind',
            MembershipErrorKind.invalidGrant,
          ),
        ),
      );
    });
  });
}
