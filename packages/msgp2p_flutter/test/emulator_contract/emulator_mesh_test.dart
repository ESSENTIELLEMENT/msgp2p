import 'dart:async';
import 'dart:typed_data';
import 'package:flutter_test/flutter_test.dart';
import 'package:msgp2p_core/msgp2p_core.dart';
import 'package:msgp2p_flutter/src/platform/ble_radio_bridge.dart';
import 'package:msgp2p_flutter/src/transport/android_ble_transport.dart';

/// Test suite verifying the exact contract specifications of IT-EMU-01 and IT-EMU-02
/// for Android BLE radio events, slot reclamation, and flapping isolation.
void main() {
  group(
      'L5 Android Emulator Layer Specification & Radio Contract (IT-EMU-01 & IT-EMU-02)',
      () {
    late LoopbackBleMedium medium;

    setUp(() {
      medium = LoopbackBleMedium(defaultMtu: 244, maxConnectionsPerNode: 4);
    });

    test(
        'IT-EMU-01: Bluetooth toggle or app kill triggers LinkClosed and slot reclamation on peer',
        () async {
      final bridgeA = medium.createBridge('AA:00:00:00:00:01');
      final bridgeB = medium.createBridge('BB:00:00:00:00:02');

      final transportA = AndroidBleTransport(bridge: bridgeA);
      final transportB = AndroidBleTransport(bridge: bridgeB);
      addTearDown(() async {
        await transportA.dispose();
        await transportB.dispose();
      });

      final tokenA = Uint8List.fromList(List.generate(16, (i) => i + 1));
      final discoveredOnB = transportB.discovered.first;

      await transportB.startScanning();
      await transportA.startAdvertising(tokenA);

      // Discovery
      final advertA = await discoveredOnB;
      expect(advertA.peerAddress, equals('AA:00:00:00:00:01'));

      // Establish connection (consumes 1 slot on both sides)
      final linkBtoA = await transportB.connect(advertA);
      expect(transportB.activeLinks.length, equals(1));

      final closeCompleter = Completer<LinkClosed>();
      linkBtoA.events.listen((event) {
        if (event is LinkClosed && !closeCompleter.isCompleted) {
          closeCompleter.complete(event);
        }
      });

      // Emulate IT-EMU-01: Node A abruptly toggles Bluetooth OFF (or process dies)
      // Native Android BLE stack drops all connected GATT/L2CAP channels and delivers disconnect
      await transportA.stop();

      // Verify Node B observes LinkClosed within T_detect (< 1 second)
      final closedEvent = await closeCompleter.future.timeout(
        const Duration(seconds: 1),
        onTimeout: () => throw TimeoutException(
            'Peer did not observe link closure within T_detect'),
      );

      expect(closedEvent, isNotNull);
      // Verify connection slot is freed on Node B
      expect(transportB.activeLinks.length, equals(0));
      expect(linkBtoA.isClosed, isTrue);
    });

    test(
        'IT-EMU-02: Three-node mesh maintains stable gossip between A and B while node C flaps',
        () async {
      final bridgeA = medium.createBridge('AA:00:00:00:00:0A');
      final bridgeB = medium.createBridge('BB:00:00:00:00:0B');
      final bridgeC = medium.createBridge('CC:00:00:00:00:0C');

      final transportA = AndroidBleTransport(bridge: bridgeA);
      final transportB = AndroidBleTransport(bridge: bridgeB);
      final transportC = AndroidBleTransport(bridge: bridgeC);
      addTearDown(() async {
        await transportA.dispose();
        await transportB.dispose();
        await transportC.dispose();
      });

      // Start scanning on A
      await transportA.startScanning();

      // Connect stable link A <-> B (linkAtoB on A, linkBtoA on B)
      final incomingOnB = transportB.incoming.first;
      final tokenB = Uint8List.fromList(List.generate(16, (i) => 0xB0 + i));
      final discB = transportA.discovered
          .firstWhere((a) => a.peerAddress == bridgeB.address);
      await transportB.startAdvertising(tokenB);
      final advB = await discB;
      final linkAtoB = await transportA.connect(advB);
      final linkBtoA = await incomingOnB;

      expect(linkAtoB.isClosed, isFalse);
      expect(linkBtoA.isClosed, isFalse);
      expect(transportA.activeLinks.length, equals(1));
      expect(transportB.activeLinks.length, equals(1));

      var messagesFromAToB = 0;
      linkBtoA.rx.listen((_) => messagesFromAToB++);

      // Flap node C 3 times (advertising on/off, connect, abrupt drop)
      final tokenC = Uint8List.fromList(List.generate(16, (i) => 0xC0 + i));
      for (var flap = 0; flap < 3; flap++) {
        final discC = transportA.discovered
            .firstWhere((a) => a.peerAddress == bridgeC.address);
        await transportC.startAdvertising(tokenC);
        final advC = await discC;
        final linkAtoC = await transportA.connect(advC);

        // C drops abruptly
        await transportC.stop();
        expect(linkAtoC.isClosed, isTrue);

        // Stable link A <-> B sends data during flapping and stays healthy
        await linkAtoB.send(Uint8List.fromList([0x01, 0x02, flap]));
      }

      await Future<void>.delayed(const Duration(milliseconds: 50));

      // Assertions per IT-EMU-02 & IT-FLAP-01:
      // 1. Stable link A <-> B never dropped despite rapid neighbor flapping
      expect(linkAtoB.isClosed, isFalse);
      expect(linkBtoA.isClosed, isFalse);
      expect(messagesFromAToB, equals(3));

      // 2. Flapping node C never permanently leaked slots on Node A
      expect(transportA.activeLinks.length, equals(1));
      expect(transportA.activeLinks.containsKey(bridgeB.address), isTrue);
    });
  });
}
