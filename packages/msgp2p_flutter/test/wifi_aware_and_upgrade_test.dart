import 'dart:typed_data';
import 'package:cryptography/cryptography.dart' as cg;
import 'package:flutter_test/flutter_test.dart';
import 'package:msgp2p_flutter/msgp2p_flutter.dart';

void main() {
  group('WifiAwareTransport & BLE -> Wi-Fi Aware Session Upgrade (v0.2)', () {
    late LoopbackWifiAwareMedium awareMedium;
    late LoopbackWifiAwareRadioBridge awareBridgeA;
    late LoopbackWifiAwareRadioBridge awareBridgeB;
    late WifiAwareTransport awareTransportA;
    late WifiAwareTransport awareTransportB;

    setUp(() {
      awareMedium =
          LoopbackWifiAwareMedium(defaultMtu: 1400, maxConnectionsPerNode: 2);
      awareBridgeA = awareMedium.createBridge('NAN-HANDLE-A');
      awareBridgeB = awareMedium.createBridge('NAN-HANDLE-B');
      awareTransportA = WifiAwareTransport(bridge: awareBridgeA);
      awareTransportB = WifiAwareTransport(bridge: awareBridgeB);
    });

    tearDown(() async {
      await awareTransportA.dispose();
      await awareTransportB.dispose();
    });

    test(
        'WifiAwareTransport passes P2PTransport discovery, full-duplex 1400B MTU, and teardown contract',
        () async {
      expect(awareTransportA.capabilities.supportsBulk, isTrue);
      expect(awareTransportA.capabilities.defaultMtu, equals(1400));

      final token = Uint8List.fromList(List.generate(16, (i) => i + 50));
      final discoveredFuture = awareTransportA.discovered.first;

      await awareTransportA.startScanning();
      await awareTransportB.startAdvertising(token);

      final advert = await discoveredFuture;
      expect(advert.peerAddress, equals('NAN-HANDLE-B'));
      expect(advert.token, equals(token));
      expect(advert.hints['transport'], equals('wifi_aware'));

      final incomingOnB = awareTransportB.incoming.first;
      final linkA = await awareTransportA.connect(advert);
      final linkB = await incomingOnB;

      final bulkPayload =
          Uint8List.fromList(List.generate(1350, (i) => i & 0xFF));
      final rxFuture = linkB.rx.first;
      await linkA.send(bulkPayload);
      expect(await rxFuture, equals(bulkPayload));

      await awareTransportA.teardownAfterTransfer();
      expect(linkA.isClosed, isTrue);
      expect(awareTransportA.isPublishing, isFalse);
      expect(awareTransportA.isSubscribing, isFalse);
      expect(awareBridgeA.teardownCount, greaterThanOrEqualTo(1));
    });

    test(
        'SessionUpgradeCoordinator upgrades BLE -> Wi-Fi Aware for hash-addressed attachments and tears down after transfer',
        () async {
      final bleMedium = LoopbackBleMedium(defaultMtu: 244);
      final bleBridgeA = bleMedium.createBridge('BLE-ADDR-A');
      final bleBridgeB = bleMedium.createBridge('BLE-ADDR-B');
      final bleTransportA = AndroidBleTransport(bridge: bleBridgeA);
      final bleTransportB = IosBleTransport(bridge: bleBridgeB);
      addTearDown(() async {
        await bleTransportA.dispose();
        await bleTransportB.dispose();
      });

      final rng = DeterministicRandomSource(777);
      final serverKp = await MsgP2PCrypto.newKeyPairFromSeed(rng.nextBytes(32));
      final serverPk = await MsgP2PCrypto.getPublicKeyBytes(serverKp);
      final groupId = Uint8List.fromList(List.filled(16, 0x11));
      final groupKey = Uint8List.fromList(List.filled(32, 0x22));

      Future<
          (
            cg.SimpleKeyPair,
            Uint8List,
            cg.SimpleKeyPair,
            Uint8List,
            MembershipCert
          )> makeMember(String userId) async {
        final signKp = await MsgP2PCrypto.newKeyPairFromSeed(rng.nextBytes(32));
        final signPk = await MsgP2PCrypto.getPublicKeyBytes(signKp);
        final noiseKp = await cg.X25519().newKeyPairFromSeed(rng.nextBytes(32));
        final noisePk = await NoiseHandshake.getPublicKeyBytes(noiseKp);
        final now = DateTime.now().millisecondsSinceEpoch;
        final certCore = MembershipCert(
          groupId: groupId,
          userId: userId,
          memberPubkey: signPk,
          noisePubkey: noisePk,
          role: 0,
          issuedAt: now - 1000,
          expiresAt: now + 86400000,
          serverSig: Uint8List(0),
        );
        final sig = await MsgP2PCrypto.sign(certCore.toCoreCbor(), serverKp);
        final cert = MembershipCert(
          groupId: groupId,
          userId: userId,
          memberPubkey: signPk,
          noisePubkey: noisePk,
          role: 0,
          issuedAt: certCore.issuedAt,
          expiresAt: certCore.expiresAt,
          serverSig: sig,
        );
        return (signKp, signPk, noiseKp, noisePk, cert);
      }

      final (signKpA, _, noiseKpA, _, certA) = await makeMember('android_user');
      final (_, _, noiseKpB, _, certB) = await makeMember('ios_user');

      final storeA = MemoryMessageStore();
      final storeB = MemoryMessageStore();
      await storeA.saveCertificate(certA);
      await storeA.saveCertificate(certB);
      await storeB.saveCertificate(certA);
      await storeB.saveCertificate(certB);

      // Publish a message with a 12 KB hash-addressed photo attachment on Node A
      final photoBytes =
          Uint8List.fromList(List.generate(12288, (i) => (i * 31) & 0xFF));
      final attRef =
          AttachmentRef.fromBytes(bytes: photoBytes, mime: 'image/jpeg');
      await storeA.saveAttachmentBlob(
        hash: attRef.hash,
        mime: attRef.mime,
        bytes: photoBytes,
      );
      final env = await Envelope.create(
        groupId: groupId,
        keyEpoch: 1,
        groupKey: groupKey,
        authorKeyPair: signKpA,
        certRef: certA.certRef,
        seq: 1,
        payload: {
          'type': 'bbs_post',
          'body': {'text': 'Hazard photo attached'}
        },
        attachments: [attRef],
      );
      await storeA.saveEnvelope(env);

      // Establish initial BLE connection (Android <-> iOS)
      final bleIncomingB = bleTransportB.incoming.first;
      final bleLinkA = await bleTransportA.connect(PeerAdvert(
        peerAddress: 'BLE-ADDR-B',
        token: Uint8List(16),
        rssi: -62,
      ));
      final bleLinkB = await bleIncomingB;

      const coordinator =
          SessionUpgradeCoordinator(upgradeThresholdBytes: 4096);
      final outcome = await coordinator.runUpgradablePairSession(
        bleLinkInitiator: bleLinkA,
        bleLinkResponder: bleLinkB,
        storeInitiator: storeA,
        storeResponder: storeB,
        noiseKeyPairInitiator: noiseKpA,
        noiseKeyPairResponder: noiseKpB,
        certInitiator: certA,
        certResponder: certB,
        pinnedServerKey: serverPk,
        expectedGroupId: groupId,
        sessionToken: Uint8List.fromList(List.filled(16, 0x77)),
        wifiAwareInitiator: awareTransportA,
        wifiAwareResponder: awareTransportB,
        responderWifiAwareHandle: 'NAN-HANDLE-B',
      );

      // Verify Stage 1 (BLE): envelope transferred, attachment NOT sent over BLE, upgrade triggered
      expect(outcome.initiator.bleResult.envelopesSent, equals(1));
      expect(outcome.initiator.bleResult.attachmentsSent, equals(0));
      expect(outcome.initiator.upgradedToWifiAware, isTrue);

      // Verify Stage 2 (Wi-Fi Aware): attachment blob transferred and verified via SHA-256
      expect(outcome.initiator.totalAttachmentsSent, equals(1));
      expect(outcome.responder.totalAttachmentsReceived, equals(1));
      expect(await storeB.containsAttachmentBlob(attRef.hash), isTrue);
      final receivedBlob = await storeB.getAttachmentBlob(attRef.hash);
      expect(receivedBlob!.bytes, equals(photoBytes));

      // Verify Stage 3: Wi-Fi Aware links and discovery sessions torn down immediately after transfer
      expect(outcome.initiator.wifiAwareTornDown, isTrue);
      expect(outcome.responder.wifiAwareTornDown, isTrue);
      expect(awareTransportA.activeLinks, isEmpty);
      expect(awareTransportB.activeLinks, isEmpty);
    });
  });
}
