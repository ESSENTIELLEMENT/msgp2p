import 'dart:typed_data';
import 'package:flutter_test/flutter_test.dart';
import 'package:msgp2p_flutter/msgp2p_flutter.dart';

void main() {
  group(
      'AndroidBleTransport — P2PTransport Contract Suite & Adaptive PHY (FR-TEST-03, FR-SYNC-06)',
      () {
    late LoopbackBleMedium medium;
    late LoopbackBleRadioBridge bridgeA;
    late LoopbackBleRadioBridge bridgeB;
    late AndroidBleTransport transportA;
    late AndroidBleTransport transportB;

    setUp(() {
      medium = LoopbackBleMedium(defaultMtu: 244, maxConnectionsPerNode: 2);
      bridgeA = medium.createBridge('AA:BB:CC:00:00:01');
      bridgeB = medium.createBridge('AA:BB:CC:00:00:02');
      transportA = AndroidBleTransport(
        bridge: bridgeA,
        capabilities: const TransportCapabilities(
          transportName: 'android_ble',
          defaultMtu: 244,
          maxConnections: 2,
        ),
      );
      transportB = AndroidBleTransport(
        bridge: bridgeB,
        capabilities: const TransportCapabilities(
          transportName: 'android_ble',
          defaultMtu: 244,
          maxConnections: 2,
        ),
      );
    });

    tearDown(() async {
      await transportA.dispose();
      await transportB.dispose();
    });

    test(
        'Discovery: scanning node discovers advertising node with rotating token',
        () async {
      final tokenB = Uint8List.fromList(List.generate(16, (i) => i + 10));
      final discoveredFuture = transportA.discovered.first;

      await transportA.startScanning();
      await transportB.startAdvertising(tokenB);

      final advert = await discoveredFuture;
      expect(advert.peerAddress, equals('AA:BB:CC:00:00:02'));
      expect(advert.token, equals(tokenB));
      expect(advert.hints['phy'], equals('le_coded_s8'));
    });

    test('Full-duplex byte transmission and MTU boundary enforcement',
        () async {
      final incomingOnB = transportB.incoming.first;
      final linkA = await transportA.connect(PeerAdvert(
        peerAddress: 'AA:BB:CC:00:00:02',
        token: Uint8List(16),
        rssi: -65,
      ));
      final linkB = await incomingOnB;

      final payloadAtoB = Uint8List.fromList([10, 20, 30, 40, 50]);
      final rxFutureB = linkB.rx.first;
      await linkA.send(payloadAtoB);
      expect(await rxFutureB, equals(payloadAtoB));

      final payloadBtoA = Uint8List.fromList([99, 88, 77]);
      final rxFutureA = linkA.rx.first;
      await linkB.send(payloadBtoA);
      expect(await rxFutureA, equals(payloadBtoA));

      // Exceeding MTU throws ArgumentError
      final oversized = Uint8List(300);
      await expectLater(() => linkA.send(oversized), throwsArgumentError);
    });

    test(
        'Adaptive PHY switching: Coded S=8 at weak RSSI (< -80 dBm) and 2M PHY at strong RSSI (>= -75 dBm)',
        () async {
      final linkA = await transportA.connect(PeerAdvert(
        peerAddress: 'AA:BB:CC:00:00:02',
        token: Uint8List(16),
        rssi: -65, // Strong RSSI -> initial upgrade to le_2m
      )) as AndroidBlePeerLink;

      expect(linkA.currentPhy, equals(BlePhyMode.le2M));

      // Simulate hiker walking into deep forest / ridge shadow (RSSI drops to -88 dBm)
      final phyEvents = <String>[];
      final sub = linkA.events.listen((e) {
        if (e is PhyChanged) {
          phyEvents.add(e.phy);
        }
      });

      bridgeA.simulateRssiChange('AA:BB:CC:00:00:02', -88);
      await Future<void>.delayed(const Duration(milliseconds: 10));
      expect(linkA.currentPhy, equals(BlePhyMode.codedS8));
      expect(phyEvents, contains('le_coded_s8'));

      // Simulate peers walking close together again (RSSI improves to -60 dBm)
      bridgeA.simulateRssiChange('AA:BB:CC:00:00:02', -60);
      await Future<void>.delayed(const Duration(milliseconds: 10));
      expect(linkA.currentPhy, equals(BlePhyMode.le2M));
      expect(phyEvents, contains('le_2m'));

      await sub.cancel();
    });

    test('Enforces maxConnections limit and closes open links on stop()',
        () async {
      final bridgeC = medium.createBridge('AA:BB:CC:00:00:03');
      final bridgeD = medium.createBridge('AA:BB:CC:00:00:04');
      final transportC = AndroidBleTransport(bridge: bridgeC);
      final transportD = AndroidBleTransport(bridge: bridgeD);
      addTearDown(() async {
        await transportC.dispose();
        await transportD.dispose();
      });

      final link1 = await transportA.connect(PeerAdvert(
        peerAddress: 'AA:BB:CC:00:00:02',
        token: Uint8List(16),
        rssi: -65,
      ));
      final link2 = await transportA.connect(PeerAdvert(
        peerAddress: 'AA:BB:CC:00:00:03',
        token: Uint8List(16),
        rssi: -65,
      ));

      // Third connection exceeds maxConnections (2)
      await expectLater(
        () => transportA.connect(PeerAdvert(
          peerAddress: 'AA:BB:CC:00:00:04',
          token: Uint8List(16),
          rssi: -65,
        )),
        throwsStateError,
      );

      await transportA.stop();
      expect(link1.isClosed, isTrue);
      expect(link2.isClosed, isTrue);
    });
  });
}
