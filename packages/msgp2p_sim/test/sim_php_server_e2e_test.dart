import 'dart:io';
import 'dart:typed_data';
import 'package:convert/convert.dart';
import 'package:msgp2p_core/msgp2p_core.dart';
import 'package:msgp2p_sim/msgp2p_sim.dart';
import 'package:test/test.dart';

void main() {
  group('End-to-End Simulator Gateway Node <-> Real PHP Server (Phase 2)', () {
    late Process phpServer;
    late GatewayClient gatewayClient;
    const port = 8998;
    const baseUrl = 'http://127.0.0.1:$port/api/v1';

    // Server seed matching server/php/config/config.php
    final serverKeySeed = Uint8List.fromList(
      hex.decode(
          'b0f7ab3ba4d1f2cdbd54861ab828f8930b3bffb538a51ea068dff247533bdd1a'),
    );
    final groupKeyEpoch1 = Uint8List.fromList(
      hex.decode(
          '6a6857b42afacd39bae57823e733fc9165583be6c3d46dfa4af174bdca658656'),
    );

    setUpAll(() async {
      final migrateRes = await Process.run(
        'php',
        [
          '-r',
          'require_once "server/php/vendor/autoload.php"; MsgP2P\\Server\\Database::resetDatabase("msgp2p_test");'
        ],
        workingDirectory: '../../',
      );
      expect(migrateRes.exitCode, equals(0),
          reason: 'Failed to reset msgp2p_test: ${migrateRes.stderr}');

      phpServer = await Process.start(
        'php',
        ['-S', '127.0.0.1:$port', '-t', 'server/php/public'],
        environment: {
          'DB_NAME': 'msgp2p_test',
          'MOCK_TIME_MS':
              '160000', // Align with ridge_gateway.yaml gateway window (t=160s)
        },
        workingDirectory: '../../',
      );

      await Future.delayed(const Duration(milliseconds: 300));
      gatewayClient = GatewayClient(baseUrl: baseUrl);
    });

    tearDownAll(() async {
      gatewayClient.close();
      phpServer.kill();
    });

    test(
        'Offline hiker relays SOS to ridge gateway node, which pushes to PHP server and propagates receipt back',
        () async {
      const scenarioYaml = '''
name: "Ridge Gateway Round-Trip E2E"
duration_seconds: 500
seed: 999
group_id: "a0b1c2d3e4f50123456789abcdef0123"

nodes:
  - id: "hiker_a"
    profile: "ble_1m"
  - id: "gateway_node"
    profile: "wifi_aware"

contacts:
  - from: "hiker_a"
    to: "gateway_node"
    start_s: 30
    duration_s: 60
    profile: "ble_1m"
  - from: "gateway_node"
    to: "hiker_a"
    start_s: 250
    duration_s: 60
    profile: "ble_1m"

workload:
  - time_s: 10
    author: "hiker_a"
    type: "sos_alert"
    priority: 0
    body:
      title: "Need medical supplies at ridge"

gateways:
  - node: "gateway_node"
    start_s: 160
    duration_s: 60

assertions:
  - message_from: "hiker_a"
    delivered_to: ["hiker_a", "gateway_node"]
    min_delivery_ratio: 1.0
''';

      final scenario = Scenario.fromYaml(scenarioYaml);
      final serverKeyPair =
          await MsgP2PCrypto.newKeyPairFromSeed(serverKeySeed);

      final sim = Simulator(
        scenario: scenario,
        realGatewayClient: gatewayClient,
        serverSigningKeyPair: serverKeyPair,
        defaultEpochKey: groupKeyEpoch1,
      );

      await sim.initialize();
      final metrics = await sim.run();

      expect(metrics.deliveryRatio, equals(1.0));
      expect(metrics.assertionFailures, isEmpty);

      final hikerA = sim.simNodes['hiker_a']!;
      final gatewayNode = sim.simNodes['gateway_node']!;

      // 1. Verify gateway_node received a real server-signed receipt from the PHP server
      final gwReceipts = await gatewayNode.store.getReceipts();
      expect(gwReceipts, isNotEmpty);

      // 2. Verify that during the second contact (t=250s), gateway_node gossiped the server receipt back to hiker_a
      expect(await hikerA.store.isConfirmed(hikerA.memberPubkey, 1), isTrue);

      // 3. Verify that pulling directly from the PHP server returns hiker_a's SOS envelope
      final pullRes = await gatewayClient.pull(
        GroupId.from('a0b1c2d3e4f50123456789abcdef0123'),
        VersionVector(),
      );
      expect(pullRes.envelopes.length, equals(1));
      expect(pullRes.envelopes.first.core.author, equals(hikerA.memberPubkey));
      expect(pullRes.envelopes.first.core.priority, equals(0));

      // 4. Verify structured JSONL trace includes REAL_SERVER receipt_applied event
      final traceEvents = MeshHarness.parseTraceJsonl(sim.exportTraceJsonl());
      final realServerReceipts = traceEvents.where(
        (e) =>
            e.type == MeshEventType.receiptApplied &&
            e.metadata['source'] == 'REAL_SERVER',
      );
      expect(realServerReceipts, isNotEmpty);

      await sim.dispose();
    });
  });
}
