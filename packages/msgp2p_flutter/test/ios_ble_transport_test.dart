import 'dart:typed_data';
import 'package:flutter_test/flutter_test.dart';
import 'package:msgp2p_flutter/msgp2p_flutter.dart';

void main() {
  group(
      'IosBleTransport — CoreBluetooth Contract Suite & Foreground/Background Modes (FR-TEST-03, v0.2)',
      () {
    late LoopbackBleMedium medium;
    late LoopbackBleRadioBridge bridgeA;
    late LoopbackBleRadioBridge bridgeB;
    late IosBleTransport transportA;
    late IosBleTransport transportB;

    setUp(() {
      medium = LoopbackBleMedium(defaultMtu: 185, maxConnectionsPerNode: 2);
      bridgeA = medium.createBridge('CB-IOS-UUID-0001');
      bridgeB = medium.createBridge('CB-IOS-UUID-0002');
      transportA = IosBleTransport(
        bridge: bridgeA,
        capabilities: const TransportCapabilities(
          transportName: 'ios_ble',
          defaultMtu: 185,
          maxConnections: 2,
          supportsBulk: false,
        ),
      );
      transportB = IosBleTransport(
        bridge: bridgeB,
        capabilities: const TransportCapabilities(
          transportName: 'ios_ble',
          defaultMtu: 185,
          maxConnections: 2,
          supportsBulk: false,
        ),
      );
    });

    tearDown(() async {
      await transportA.dispose();
      await transportB.dispose();
    });

    test(
        'Foreground discovery: scanning iOS central discovers iOS peripheral advertising rotating token',
        () async {
      final tokenB = Uint8List.fromList(List.generate(16, (i) => i + 30));
      final discoveredFuture = transportA.discovered.first;

      await transportA.startScanning();
      await transportB.startAdvertising(tokenB);

      final advert = await discoveredFuture;
      expect(advert.peerAddress, equals('CB-IOS-UUID-0002'));
      expect(advert.token, equals(tokenB));
      expect(advert.hints['phy'], equals('le_1m'));
      expect(advert.hints['platform'], equals('ios'));
    });

    test(
        'Background mode transition updates scan policy and preserves link communication',
        () async {
      await transportA.startScanning();
      expect(transportA.isInBackground, isFalse);

      await transportA.setBackgroundMode(true);
      expect(transportA.isInBackground, isTrue);

      final incomingOnB = transportB.incoming.first;
      final linkA = await transportA.connect(PeerAdvert(
        peerAddress: 'CB-IOS-UUID-0002',
        token: Uint8List(16),
        rssi: -68,
      ));
      final linkB = await incomingOnB;

      final chunk = Uint8List.fromList([1, 2, 3, 4, 5, 6]);
      final rxFuture = linkB.rx.first;
      await linkA.send(chunk);
      expect(await rxFuture, equals(chunk));

      // Exceeding iOS 185-byte GATT MTU throws ArgumentError
      await expectLater(() => linkA.send(Uint8List(200)), throwsArgumentError);
    });

    test(
        'Enforces maxConnections and cleanly closes open CoreBluetooth links on stop()',
        () async {
      final bridgeC = medium.createBridge('CB-IOS-UUID-0003');
      final bridgeD = medium.createBridge('CB-IOS-UUID-0004');
      final transportC = IosBleTransport(bridge: bridgeC);
      final transportD = IosBleTransport(bridge: bridgeD);
      addTearDown(() async {
        await transportC.dispose();
        await transportD.dispose();
      });

      final link1 = await transportA.connect(PeerAdvert(
        peerAddress: 'CB-IOS-UUID-0002',
        token: Uint8List(16),
        rssi: -65,
      ));
      final link2 = await transportA.connect(PeerAdvert(
        peerAddress: 'CB-IOS-UUID-0003',
        token: Uint8List(16),
        rssi: -65,
      ));

      await expectLater(
        () => transportA.connect(PeerAdvert(
          peerAddress: 'CB-IOS-UUID-0004',
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
