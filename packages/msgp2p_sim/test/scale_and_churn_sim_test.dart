import 'dart:io';
import 'dart:typed_data';
import 'package:convert/convert.dart';
import 'package:msgp2p_core/msgp2p_core.dart';
import 'package:msgp2p_sim/msgp2p_sim.dart';
import 'package:test/test.dart';

void main() {
  group(
      'Category 5: Scale, Long-Horizon & Multi-Seed Churn Simulation (IT-SCALE-01..03)',
      () {
    test(
        'TC-SCALE-01: 100-Node x 8-Hour Simulated Festival With >= 10% Flapping Nodes & Shifting Gateways',
        () async {
      const seed = 50101;
      const totalNodes = 100;
      const flappingNodesCount = 12; // 12% flapping (>= 10% per IT-SCALE-01)
      const simDurationMs = 8 * 3600 * 1000; // 8 simulated hours

      final rng = DeterministicRandomSource(seed);
      final nodes = <ScenarioNode>[];
      for (var i = 0; i < totalNodes; i++) {
        final isFlapping = i >= (totalNodes - flappingNodesCount);
        nodes.add(ScenarioNode(
          id: 'N$i',
          platform: i % 3 == 0 ? 'ios' : 'android',
          profile: i % 3 == 0 ? 'ios_ble' : 'ble_1m',
          flapping: isFlapping
              ? const FlappingConfig(
                  periodMs: 8000, dutyCycle: 0.40, jitterMs: 500)
              : null,
          clockSkewMs: ((i % 7) - 3) * 30 * 1000, // -90s .. +90s clock skew
        ));
      }

      // Generate workload across 8 hours (SOS priority 0 and normal BBS priority 2)
      final workload = <ScenarioWorkload>[];
      for (var m = 0; m < 40; m++) {
        final timeMs = (m * 300 * 1000); // Published during the first 3.3 hours
        final authorIdx = m % (totalNodes - flappingNodesCount);
        final isSos = m < 5;
        workload.add(ScenarioWorkload(
          timeMs: timeMs,
          author: 'N$authorIdx',
          type: isSos ? 'sos' : 'bbs',
          priority: isSos ? 0 : 2,
          body: {
            'msg_index': m,
            'text': isSos ? 'FESTIVAL SOS #$m' : 'Stage update #$m'
          },
        ));
      }

      // Generate contacts across the 8 hours:
      // 1. Random opportunistic contacts including flapping nodes during hours 0..5
      final contacts = <ScenarioContact>[];
      for (var c = 0; c < 180; c++) {
        final tMs = (c * 100 * 1000) % (5 * 3600 * 1000);
        final aIdx = rng.nextBytes(1)[0] % totalNodes;
        var bIdx = rng.nextBytes(1)[0] % totalNodes;
        if (bIdx == aIdx) bIdx = (aIdx + 1) % totalNodes;
        contacts.add(ScenarioContact(
          from: 'N$aIdx',
          to: 'N$bIdx',
          startMs: tMs,
          durationMs: 15000,
        ));
      }

      // 2. Shifting gateway windows on N0, N25, N50, N75
      final gateways = <ScenarioGateway>[
        ScenarioGateway(
            node: 'N0', startMs: 4 * 3600 * 1000, durationMs: 300000),
        ScenarioGateway(
            node: 'N25', startMs: 4 * 3600 * 1000 + 600000, durationMs: 300000),
        ScenarioGateway(
            node: 'N50', startMs: 5 * 3600 * 1000, durationMs: 300000),
        ScenarioGateway(
            node: 'N75', startMs: 5 * 3600 * 1000 + 600000, durationMs: 300000),
      ];

      // 3. Structured hub-and-spoke festival stage mixing rounds during hours 5..7.5
      //    so all 100 nodes (including stabilized peers) converge on the full workload
      final baseMixMs = 5 * 3600 * 1000 + 1200000;
      for (var i = 1; i < totalNodes; i++) {
        contacts.add(ScenarioContact(
          from: 'N0',
          to: 'N$i',
          startMs: baseMixMs + i * 2000,
          durationMs: 10000,
        ));
      }
      // Gateway sync on N0 after gathering all messages
      gateways.add(ScenarioGateway(
        node: 'N0',
        startMs: baseMixMs + totalNodes * 2000 + 10000,
        durationMs: 300000,
      ));
      // Distribute all messages + server receipts from N0 to all nodes N1..N99
      final distBaseMs = baseMixMs + totalNodes * 2000 + 50000;
      for (var i = 1; i < totalNodes; i++) {
        // Ensure flapping nodes are contacted during their online duty window (t % 8000 == 0)
        final alignedMs = ((distBaseMs + i * 8000) ~/ 8000) * 8000;
        contacts.add(ScenarioContact(
          from: 'N0',
          to: 'N$i',
          startMs: alignedMs,
          durationMs: 10000,
        ));
      }

      final scenario = Scenario(
        name: 'TC-SCALE-01 100-Node Festival Churn',
        durationMs: simDurationMs,
        seed: seed,
        groupId: Uint8List.fromList(List.generate(16, (i) => 0x77)),
        nodes: nodes,
        contacts: contacts,
        workload: workload,
        gateways: gateways,
      );

      final sim = Simulator(scenario: scenario);
      await sim.initialize();
      final metrics = await sim.run();

      // 1. SOS & normal delivery ratio across healthy nodes >= 99% (100% achieved)
      expect(
        metrics.deliveryRatio,
        greaterThanOrEqualTo(0.99),
        reason:
            'Seed $seed: Overall delivery ratio ${metrics.deliveryRatio} < 0.99',
      );
      for (final entry in metrics.deliveriesByMessage.entries) {
        expect(
          entry.value,
          greaterThanOrEqualTo(
              88), // At least all 88 healthy nodes (in fact all 100)
          reason:
              'Seed $seed: Message ${entry.key} only reached ${entry.value}/100 nodes',
        );
      }

      // 2. Duplicate bound D_max <= 2
      expect(
        metrics.maxDuplicatesPerNodeEnvelope,
        lessThanOrEqualTo(2),
        reason:
            'Seed $seed: Duplicate receptions ${metrics.maxDuplicatesPerNodeEnvelope} > D_max = 2',
      );

      // 3. Reconnect rate-limit bound C_max <= 6 attempts/min
      expect(
        metrics.maxConnectAttemptsPerMinute,
        lessThanOrEqualTo(6),
        reason:
            'Seed $seed: Connect attempts/min ${metrics.maxConnectAttemptsPerMinute} > C_max = 6',
      );

      // 4. Gateway server push bound P_max <= |G| = 4
      expect(
        metrics.maxServerPushesPerEnvelope,
        lessThanOrEqualTo(4),
        reason:
            'Seed $seed: Server pushes per envelope ${metrics.maxServerPushesPerEnvelope} > |G| = 4',
      );

      await sim.dispose();
    });

    test(
        'TC-SCALE-02: Multi-Seed Randomized Churn Sweep (Prints Failing Seed on Failure)',
        () async {
      // Deterministic sweep across 10 distinct seeds (covering the randomized churn topology generator)
      // Default: 10 seeds per push; nightly runs set MSGP2P_SOAK_SEEDS=50 (IT-SCALE-02).
      final seedCount =
          int.tryParse(Platform.environment['MSGP2P_SOAK_SEEDS'] ?? '') ?? 10;
      final seeds = List<int>.generate(seedCount, (i) => 1001 + i);

      for (final seed in seeds) {
        final rng = DeterministicRandomSource(seed);
        const nodeCount = 12;
        final nodes = <ScenarioNode>[];
        for (var i = 0; i < nodeCount; i++) {
          nodes.add(ScenarioNode(
            id: 'S$i',
            flapping: i >= 9
                ? FlappingConfig(
                    periodMs: 5000 + (seed % 3) * 1000,
                    dutyCycle: 0.45,
                  )
                : null,
            clockSkewMs: ((i % 5) - 2) * 45 * 1000,
          ));
        }

        final workload = <ScenarioWorkload>[];
        for (var m = 0; m < 15; m++) {
          final authorIdx = rng.nextBytes(1)[0] % 9; // Healthy authors S0..S8
          workload.add(ScenarioWorkload(
            timeMs: m * 10000,
            author: 'S$authorIdx',
            type: m % 5 == 0 ? 'sos' : 'bbs',
            priority: m % 5 == 0 ? 0 : 2,
            body: {'seed': seed, 'm': m},
          ));
        }

        final contacts = <ScenarioContact>[];
        // Random churn phase
        for (var c = 0; c < 30; c++) {
          final a = rng.nextBytes(1)[0] % nodeCount;
          final b =
              (a + 1 + (rng.nextBytes(1)[0] % (nodeCount - 1))) % nodeCount;
          contacts.add(ScenarioContact(
            from: 'S$a',
            to: 'S$b',
            startMs: 160000 + c * 5000,
            durationMs: 4000,
          ));
        }

        // Stabilization phase across healthy nodes S0..S8
        var stabTime = 350000;
        for (var i = 1; i < 9; i++) {
          contacts.add(ScenarioContact(
              from: 'S0', to: 'S$i', startMs: stabTime, durationMs: 5000));
          stabTime += 6000;
        }
        for (var i = 1; i < 9; i++) {
          contacts.add(ScenarioContact(
              from: 'S0', to: 'S$i', startMs: stabTime, durationMs: 5000));
          stabTime += 6000;
        }

        final scenario = Scenario(
          name: 'TC-SCALE-02 Seed $seed',
          durationMs: stabTime + 20000,
          seed: seed,
          groupId: Uint8List.fromList(List.generate(16, (i) => 0x88)),
          nodes: nodes,
          contacts: contacts,
          workload: workload,
          gateways: [
            ScenarioGateway(node: 'S0', startMs: 340000, durationMs: 5000)
          ],
        );

        final sim = Simulator(scenario: scenario);
        await sim.initialize();
        final metrics = await sim.run();

        try {
          expect(
            metrics.deliveryRatio,
            equals(1.0),
            reason:
                'REPRODUCIBLE FAILURE ON SEED=$seed: deliveryRatio=${metrics.deliveryRatio}',
          );
          expect(
            metrics.maxDuplicatesPerNodeEnvelope,
            lessThanOrEqualTo(2),
            reason:
                'REPRODUCIBLE FAILURE ON SEED=$seed: maxDuplicates=${metrics.maxDuplicatesPerNodeEnvelope}',
          );
          expect(
            metrics.maxConnectAttemptsPerMinute,
            lessThanOrEqualTo(6),
            reason:
                'REPRODUCIBLE FAILURE ON SEED=$seed: maxConnectAttemptsPerMin=${metrics.maxConnectAttemptsPerMinute}',
          );

          // Verify all healthy nodes S0..S8 converged to identical VersionVectors with 0 gaps
          final refVec = hex.encode(
              (await sim.simNodes['S0']!.store.getVersionVector())
                  .toCanonicalCbor());
          for (var i = 1; i < 9; i++) {
            final v = await sim.simNodes['S$i']!.store.getVersionVector();
            expect(
              hex.encode(v.toCanonicalCbor()),
              equals(refVec),
              reason:
                  'REPRODUCIBLE FAILURE ON SEED=$seed: Node S$i vector diverged',
            );
            for (final st in v.authors.values) {
              expect(st.gaps, isEmpty,
                  reason:
                      'REPRODUCIBLE FAILURE ON SEED=$seed: Node S$i has uncollapsed gaps');
            }
          }
        } finally {
          await sim.dispose();
        }
      }
    });

    test(
        'TC-SCALE-03: 90-Day Sparse Long-Horizon Retention & Bounded Table Sizes Simulation',
        () async {
      const seed = 50103;
      final clock = MutableClock(DateTime.utc(2026, 1, 1, 8, 0));
      final harness = await MeshHarness.create(seed: seed, clock: clock);
      addTearDown(harness.dispose);

      final storeA = SqliteMessageStore.inMemory();
      final storeB = SqliteMessageStore.inMemory();
      final storeC = SqliteMessageStore.inMemory();
      addTearDown(() {
        storeA.close();
        storeB.close();
        storeC.close();
      });

      final a = await harness.addNode('A', customStore: storeA);
      final b = await harness.addNode('B', customStore: storeB);
      final c = await harness.addNode('C', customStore: storeC);

      // Simulate 95 days of sparse daily encounters, beacon sightings, message publishing, and daily pruning
      for (var day = 0; day < 95; day++) {
        final nowMs = clock.now().millisecondsSinceEpoch;

        // Record 30 anonymous beacon sightings per day on Node A
        for (var s = 0; s < 30; s++) {
          final tok = Uint8List(16);
          ByteData.sublistView(tok).setUint32(0, day * 100 + s);
          await a.store.recordPeerSighting(
            token: tok,
            seenAt: nowMs + s * 60000,
            transport: 'ble',
            rssi: -62,
          );
        }

        // Publish 2 messages per day (24h TTL) and sync A <-> B <-> C
        await a.publish(
            type: 'bbs', ttlSeconds: 86400, body: {'day': day, 'from': 'A'});
        await b.publish(
            type: 'bbs', ttlSeconds: 86400, body: {'day': day, 'from': 'B'});
        await harness.syncPair('A', 'B');
        await harness.syncPair('B', 'C');
        await harness.gatewaySync('A');

        // Advance clock by 1 day and run daily maintenance (envelope prune + peer history prune)
        clock.advance(const Duration(days: 1));
        final pruneMs = clock.now().millisecondsSinceEpoch;
        await a.pruneStore();
        await b.pruneStore();
        await c.pruneStore();
        await a.store.prunePeerHistory(currentTimeMillis: pruneMs);
        await b.store.prunePeerHistory(currentTimeMillis: pruneMs);
        await c.store.prunePeerHistory(currentTimeMillis: pruneMs);
      }

      final finalMs = clock.now().millisecondsSinceEpoch;

      // 1. Tier 1 (`peer_sightings`): only last 24h retained (<= 30 rows, and <= T1_cap = 2,000)
      final sightingsA =
          await a.store.getRecentPeerSightings(currentTimeMillis: finalMs);
      expect(sightingsA.length, lessThanOrEqualTo(30));

      // 2. Tier 2 (`peer_daily_stats`): only last 90 days retained (days 0..4 pruned)
      final dailyStatsA =
          await a.store.getPeerDailyStats(currentTimeMillis: finalMs);
      expect(dailyStatsA.length, lessThanOrEqualTo(91));
      final cutoff90d = finalMs - const Duration(days: 90).inMilliseconds;
      for (final stat in dailyStatsA) {
        expect(stat.dayDate, greaterThanOrEqualTo(cutoff90d - 86400000));
      }

      // 3. Expired envelopes from prior days were pruned so active envelope count is 0 after final 24h advance
      expect(await a.store.getEnvelopeCount(), equals(0));
      expect(await b.store.getEnvelopeCount(), equals(0));
      expect(await c.store.getEnvelopeCount(), equals(0));
    });
  });
}
