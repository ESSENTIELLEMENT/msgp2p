import 'dart:async';
import 'dart:typed_data';
import 'package:msgp2p_core/msgp2p_core.dart';
import 'package:test/test.dart';

/// Test fixture pair representing communicating transport endpoints.
class TransportPair {
  final P2PTransport transportA;
  final P2PTransport transportB;
  final Future<void> Function() cleanup;

  TransportPair({
    required this.transportA,
    required this.transportB,
    required this.cleanup,
  });
}

/// Shared reusable contract test suite that ANY [P2PTransport] implementation must pass.
void runTransportContractTests(
  String transportName,
  Future<TransportPair> Function() createPair,
) {
  group('P2PTransport Contract Suite ($transportName)', () {
    late TransportPair pair;
    late P2PTransport nodeA;
    late P2PTransport nodeB;

    setUp(() async {
      pair = await createPair();
      nodeA = pair.transportA;
      nodeB = pair.transportB;
    });

    tearDown(() async {
      await pair.cleanup();
    });

    test('Capabilities expose valid MTU and transport name', () {
      expect(nodeA.capabilities.defaultMtu, greaterThanOrEqualTo(20));
      expect(nodeA.capabilities.transportName, isNotEmpty);
      expect(nodeB.capabilities.defaultMtu, greaterThanOrEqualTo(20));
      expect(nodeB.capabilities.transportName, isNotEmpty);
    });

    test(
        'Discovery: scanning node discovers advertising node with matching token',
        () async {
      final token = Uint8List.fromList(List.generate(16, (i) => i + 1));

      final discoveredFuture = nodeB.discovered.firstWhere((adv) {
        if (adv.token.length != token.length) return false;
        for (var i = 0; i < token.length; i++) {
          if (adv.token[i] != token[i]) return false;
        }
        return true;
      });

      await nodeB.startScanning();
      await nodeA.startAdvertising(token);

      final advert = await discoveredFuture.timeout(const Duration(seconds: 3));
      expect(advert.token, equals(token));
      expect(advert.peerAddress, isNotEmpty);
      expect(advert.rssi, isNotNull);

      await nodeA.stopAdvertising();
      await nodeB.stopScanning();
    });

    test('Connection: establish link, verify MTU and incoming connection',
        () async {
      final token = Uint8List.fromList(List.generate(16, (i) => 0xAA));

      final discoveredFuture = nodeB.discovered.first;
      final incomingFuture = nodeA.incoming.first;

      await nodeB.startScanning();
      await nodeA.startAdvertising(token);

      final advert = await discoveredFuture.timeout(const Duration(seconds: 3));
      final linkBtoA = await nodeB.connect(advert);
      final linkAtoB = await incomingFuture.timeout(const Duration(seconds: 3));

      expect(linkBtoA.isClosed, isFalse);
      expect(linkAtoB.isClosed, isFalse);
      expect(linkBtoA.mtu, greaterThanOrEqualTo(20));
      expect(linkAtoB.mtu, equals(linkBtoA.mtu));

      await linkBtoA.close();
      await linkAtoB.close();
    });

    test('Communication: full-duplex transmission and FIFO ordering', () async {
      final token = Uint8List.fromList(List.generate(16, (i) => 0xBB));

      final discoveredFuture = nodeB.discovered.first;
      final incomingFuture = nodeA.incoming.first;

      await nodeB.startScanning();
      await nodeA.startAdvertising(token);

      final advert = await discoveredFuture.timeout(const Duration(seconds: 3));
      final linkB = await nodeB.connect(advert);
      final linkA = await incomingFuture.timeout(const Duration(seconds: 3));

      final msgFromB1 = Uint8List.fromList([1, 2, 3]);
      final msgFromB2 = Uint8List.fromList([4, 5, 6, 7]);

      final aReceived = <Uint8List>[];
      final completerA = Completer<void>();

      final subA = linkA.rx.listen((data) {
        aReceived.add(data);
        if (aReceived.length == 2) completerA.complete();
      });

      await linkB.send(msgFromB1);
      await linkB.send(msgFromB2);
      await completerA.future.timeout(const Duration(seconds: 3));

      expect(aReceived[0], equals(msgFromB1));
      expect(aReceived[1], equals(msgFromB2));

      final msgFromA = Uint8List.fromList([99, 100, 101]);
      final completerB = Completer<Uint8List>();
      final subB = linkB.rx.listen((data) {
        if (!completerB.isCompleted) completerB.complete(data);
      });

      await linkA.send(msgFromA);
      final bReceived =
          await completerB.future.timeout(const Duration(seconds: 3));
      expect(bReceived, equals(msgFromA));

      await subA.cancel();
      await subB.cancel();
      await linkB.close();
      await linkA.close();
    });

    test('Enforces MTU limit on send()', () async {
      final token = Uint8List.fromList(List.generate(16, (i) => 0xCC));

      final discoveredFuture = nodeB.discovered.first;
      final incomingFuture = nodeA.incoming.first;

      await nodeB.startScanning();
      await nodeA.startAdvertising(token);

      final advert = await discoveredFuture.timeout(const Duration(seconds: 3));
      final linkB = await nodeB.connect(advert);
      final linkA = await incomingFuture.timeout(const Duration(seconds: 3));

      final oversizedChunk = Uint8List(linkB.mtu + 1);
      expect(() => linkB.send(oversizedChunk), throwsArgumentError);

      await linkB.close();
      await linkA.close();
    });

    test('Close propagation: closing one end closes peer with LinkClosed event',
        () async {
      final token = Uint8List.fromList(List.generate(16, (i) => 0xDD));

      final discoveredFuture = nodeB.discovered.first;
      final incomingFuture = nodeA.incoming.first;

      await nodeB.startScanning();
      await nodeA.startAdvertising(token);

      final advert = await discoveredFuture.timeout(const Duration(seconds: 3));
      final linkB = await nodeB.connect(advert);
      final linkA = await incomingFuture.timeout(const Duration(seconds: 3));

      final aCloseEventFuture =
          linkA.events.where((e) => e is LinkClosed).first;

      await linkB.close('test_shutdown');
      expect(linkB.isClosed, isTrue);

      final event = await aCloseEventFuture.timeout(const Duration(seconds: 3));
      expect(event, isA<LinkClosed>());
      expect(linkA.isClosed, isTrue);

      expect(() => linkB.send(Uint8List.fromList([1])), throwsStateError);
      expect(() => linkA.send(Uint8List.fromList([1])), throwsStateError);
    });

    test('stop() closes all open links cleanly', () async {
      final token = Uint8List.fromList(List.generate(16, (i) => 0xEE));

      final discoveredFuture = nodeB.discovered.first;
      final incomingFuture = nodeA.incoming.first;

      await nodeB.startScanning();
      await nodeA.startAdvertising(token);

      final advert = await discoveredFuture.timeout(const Duration(seconds: 3));
      final linkB = await nodeB.connect(advert);
      final linkA = await incomingFuture.timeout(const Duration(seconds: 3));

      expect(linkA.isClosed, isFalse);
      expect(linkB.isClosed, isFalse);

      await nodeA.stop();
      expect(linkA.isClosed, isTrue);
      expect(linkB.isClosed, isTrue);
    });
  });

  group('P2PTransport Multi-Peer & Capacity Extensions ($transportName)', () {
    test('Multi-peer discovery and concurrent connections', () async {
      final medium = FakeMedium();
      final node1 = FakeTransport(
          nodeAddress: 'node_1',
          medium: medium,
          capabilities: const TransportCapabilities(
              transportName: 'test', defaultMtu: 256, maxConnections: 2));
      final node2 = FakeTransport(nodeAddress: 'node_2', medium: medium);
      final node3 = FakeTransport(nodeAddress: 'node_3', medium: medium);

      final token2 = Uint8List(16)..[0] = 2;
      final token3 = Uint8List(16)..[0] = 3;

      await node2.startAdvertising(token2);
      await node3.startAdvertising(token3);

      final adverts = <PeerAdvert>[];
      final completer = Completer<void>();
      final sub = node1.discovered.listen((adv) {
        adverts.add(adv);
        if (adverts.length == 2) completer.complete();
      });

      await node1.startScanning();
      await completer.future.timeout(const Duration(seconds: 3));

      expect(adverts.map((a) => a.peerAddress).toSet(),
          equals({'node_2', 'node_3'}));

      // Connect to node2
      final link12 = await node1
          .connect(adverts.firstWhere((a) => a.peerAddress == 'node_2'));
      expect(node1.activeLinkCount, equals(1));

      // Connect to node3 (reaches maxConnections = 2)
      final link13 = await node1
          .connect(adverts.firstWhere((a) => a.peerAddress == 'node_3'));
      expect(node1.activeLinkCount, equals(2));

      // Attempting a 3rd connection on node1 should fail due to maxConnections limit
      final node4 = FakeTransport(nodeAddress: 'node_4', medium: medium);
      expect(
        () => node1.connect(
            PeerAdvert(token: Uint8List(16), peerAddress: 'node_4', rssi: -50)),
        throwsStateError,
      );

      await sub.cancel();
      await link12.close();
      await link13.close();
      await node1.dispose();
      await node2.dispose();
      await node3.dispose();
      await node4.dispose();
    });

    test('FakeMedium topology partitioning and link cutting', () async {
      final medium = FakeMedium();
      final nodeA = FakeTransport(nodeAddress: 'A', medium: medium);
      final nodeB = FakeTransport(nodeAddress: 'B', medium: medium);
      final nodeC = FakeTransport(nodeAddress: 'C', medium: medium);

      // Relay topology: A - B - C (A cannot hear C)
      medium.setTopology({
        'A': {'B'},
        'B': {'A', 'C'},
        'C': {'B'},
      });

      expect(medium.canHear('A', 'B'), isTrue);
      expect(medium.canHear('B', 'C'), isTrue);
      expect(medium.canHear('A', 'C'), isFalse);

      // A cannot connect to C directly
      expect(
        () => nodeA.connect(
            PeerAdvert(token: Uint8List(16), peerAddress: 'C', rssi: -50)),
        throwsStateError,
      );

      // A can connect to B
      final linkAB = await nodeA.connect(
          PeerAdvert(token: Uint8List(16), peerAddress: 'B', rssi: -50));
      expect(linkAB.isClosed, isFalse);

      // Cut link after 10 bytes
      medium.cutLink(nodeA: 'A', nodeB: 'B', afterBytes: 10);

      // Send 5 bytes (not cut yet)
      await linkAB.send(Uint8List.fromList([1, 2, 3, 4, 5]));
      expect(linkAB.isClosed, isFalse);

      // Send 6 bytes (exceeds 10 bytes -> triggers cut)
      await linkAB.send(Uint8List.fromList([6, 7, 8, 9, 10, 11]));
      expect(linkAB.isClosed, isTrue);

      await nodeA.dispose();
      await nodeB.dispose();
      await nodeC.dispose();
    });
  });
}

void main() {
  runTransportContractTests('FakeTransport', () async {
    final medium = FakeMedium();
    final nodeA = FakeTransport(nodeAddress: 'node_alpha', medium: medium);
    final nodeB = FakeTransport(nodeAddress: 'node_beta', medium: medium);

    return TransportPair(
      transportA: nodeA,
      transportB: nodeB,
      cleanup: () async {
        await nodeA.dispose();
        await nodeB.dispose();
      },
    );
  });
}
