import 'dart:typed_data';
import 'package:msgp2p_sim/msgp2p_sim.dart';
import 'package:test/test.dart';

void main() {
  group('SimTransport Contract Suite', () {
    late SimMedium medium;
    late SimTransport nodeA;
    late SimTransport nodeB;

    setUp(() async {
      medium = SimMedium();
      nodeA = SimTransport(nodeAddress: 'node_alpha', medium: medium);
      nodeB = SimTransport(nodeAddress: 'node_beta', medium: medium);
    });

    tearDown(() async {
      await nodeA.dispose();
      await nodeB.dispose();
    });

    test('Capabilities expose valid MTU and profile name', () {
      expect(nodeA.capabilities.defaultMtu, greaterThanOrEqualTo(20));
      expect(nodeA.capabilities.transportName, equals('ble_1m'));
      expect(nodeB.capabilities.defaultMtu, greaterThanOrEqualTo(20));
    });

    test('Discovery and connection between simulated nodes', () async {
      final token = Uint8List(16)..[0] = 0xAA;

      final discoveredFuture = nodeB.discovered.first;
      final incomingFuture = nodeA.incoming.first;

      await nodeB.startScanning();
      await nodeA.startAdvertising(token);

      final advert = await discoveredFuture.timeout(const Duration(seconds: 3));
      expect(advert.peerAddress, equals('node_alpha'));

      final linkB = await nodeB.connect(advert);
      final linkA = await incomingFuture.timeout(const Duration(seconds: 3));

      expect(linkB.isClosed, isFalse);
      expect(linkA.isClosed, isFalse);

      await linkB.close();
      await linkA.close();
    });

    test('Full-duplex data transmission and MTU boundary enforcement',
        () async {
      final token = Uint8List(16)..[0] = 0xBB;
      final discFuture = nodeB.discovered.first;
      final incFuture = nodeA.incoming.first;

      await nodeB.startScanning();
      await nodeA.startAdvertising(token);

      final adv = await discFuture;
      final linkB = await nodeB.connect(adv);
      final linkA = await incFuture;

      final msg = Uint8List.fromList([1, 2, 3, 4, 5]);
      final rxFuture = linkA.rx.first;

      await linkB.send(msg);
      final received = await rxFuture;
      expect(received, equals(msg));

      // MTU violation
      final oversized = Uint8List(linkB.mtu + 1);
      expect(() => linkB.send(oversized), throwsArgumentError);

      await linkB.close();
      await linkA.close();
    });
  });
}
