import 'dart:io';
import 'package:msgp2p_sim/msgp2p_sim.dart';
import 'package:test/test.dart';

void main() {
  group('msgp2p_sim Discrete-Event Simulator Engine (FR-TEST-02)', () {
    test('SimClock and EventQueue execute events in strict chronological order',
        () async {
      final clock = SimClock(1000);
      final queue = EventQueue(clock: clock);

      final executionLog = <String>[];

      queue.schedule(1500, () async {
        executionLog.add('event_1500');
      });

      queue.schedule(1200, () async {
        executionLog.add('event_1200');
      });

      queue.schedule(2000, () async {
        executionLog.add('event_2000');
      });

      final count = await queue.runUntil(2500);
      expect(count, equals(3));
      expect(executionLog, equals(['event_1200', 'event_1500', 'event_2000']));
      expect(clock.currentTimeMs, equals(2500));
    });

    test('LinkProfile YAML parser loads pre-calibrated profiles', () {
      final yaml =
          "ble_custom:\n  name: 'ble_custom'\n  default_mtu: 256\n  throughput_bps: 20000\n  transit_latency_ms: 50\n  setup_latency_ms: 1000\n  packet_loss_rate: 0.02\n  max_range_meters: 45.0\n";
      final profiles = LinkProfile.parseYaml(yaml);
      expect(profiles.containsKey('ble_custom'), isTrue);
      final p = profiles['ble_custom']!;
      expect(p.defaultMtu, equals(256));
      expect(p.throughputBps, equals(20000));
      expect(p.transitLatencyMs, equals(50));
      expect(p.packetLossRate, equals(0.02));
    });

    test('Runs trail_sync.yaml scenario to 100% convergence with 0 duplicates',
        () async {
      final file = File('scenarios/trail_sync.yaml');
      expect(file.existsSync(), isTrue);

      final scenario = Scenario.fromYaml(file.readAsStringSync());
      final sim = Simulator(scenario: scenario);

      await sim.initialize();
      final metrics = await sim.run();

      expect(metrics.deliveryRatio, equals(1.0));
      expect(metrics.duplicateEnvelopesReceived, equals(0));
      expect(metrics.assertionFailures, isEmpty);
      expect(metrics.deliveriesByMessage.values.first, equals(3));

      await sim.dispose();
    });

    test('Runs partition_merge.yaml scenario reconciling disconnected clusters',
        () async {
      final file = File('scenarios/partition_merge.yaml');
      expect(file.existsSync(), isTrue);

      final scenario = Scenario.fromYaml(file.readAsStringSync());
      final sim = Simulator(scenario: scenario);

      await sim.initialize();
      final metrics = await sim.run();

      expect(metrics.deliveryRatio, equals(1.0));
      expect(metrics.assertionFailures, isEmpty);
      expect(metrics.deliveriesByMessage.length, equals(2));
      for (final count in metrics.deliveriesByMessage.values) {
        expect(count, equals(4)); // Delivered to all 4 nodes
      }

      await sim.dispose();
    });

    test('Runs ridge_gateway.yaml and verifies server upload', () async {
      final file = File('scenarios/ridge_gateway.yaml');
      expect(file.existsSync(), isTrue);

      final scenario = Scenario.fromYaml(file.readAsStringSync());
      final sim = Simulator(scenario: scenario);

      await sim.initialize();
      final metrics = await sim.run();

      expect(metrics.deliveryRatio, equals(1.0));
      expect(metrics.assertionFailures, isEmpty);
      expect(sim.server.issuedReceipts.length, greaterThanOrEqualTo(1));

      await sim.dispose();
    });
  });
}
