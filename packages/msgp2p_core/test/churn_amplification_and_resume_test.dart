import 'dart:io';
import 'package:convert/convert.dart';
import 'package:msgp2p_core/msgp2p_core.dart';
import 'package:test/test.dart';

void main() {
  group(
      'Category 1: Duplicate & Traffic Amplification Prevention (IT-AMP-01..04)',
      () {
    test(
        'TC-AMP-01: Intra-Session and Cross-Session Envelope Deduplication Under Rapid Flapping',
        () async {
      const seed = 10101;
      final clock = MutableClock();
      final harness = await MeshHarness.create(seed: seed, clock: clock);
      addTearDown(harness.dispose);

      // 6 nodes: N1..N4 healthy, F1..F2 flapping
      final n1 = await harness.addNode('N1');
      final n2 = await harness.addNode('N2');
      final n3 = await harness.addNode('N3');
      final n4 = await harness.addNode('N4');
      final f1 = await harness.addNode('F1');
      final f2 = await harness.addNode('F2');
      final allNodes = [n1, n2, n3, n4, f1, f2];

      // Each node publishes 5 messages (30 unique envelopes total)
      final allEnvelopes = <Envelope>[];
      for (final node in allNodes) {
        for (var i = 1; i <= 5; i++) {
          final env = await node.publish(
            type: 'bbs',
            body: {
              'from': node.nodeId,
              'seq': i,
              'text': 'Msg $i from ${node.nodeId}'
            },
          );
          allEnvelopes.add(env);
        }
      }
      expect(allEnvelopes.length, equals(30),
          reason: 'Seed $seed: Expected 30 published messages');

      // Execute overlapping gossip rounds with mid-transfer link cuts on F1 and F2
      final pairs = [
        (n1, f1, true),
        (n2, f2, true),
        (n1, n2, false),
        (n3, n4, false),
        (n2, n3, false),
        (f1, n3, true),
        (f2, n4, true),
        (n1, f1, false),
        (n2, f2, false),
        (f1, n3, false),
        (f2, n4, false),
        (n1, n4, false),
        (n2, n3, false),
        (f1, f2, false),
      ];

      for (final (a, b, cutMidway) in pairs) {
        clock.advance(const Duration(seconds: 2));
        if (cutMidway) {
          harness.cutLink(nodeA: a.nodeId, nodeB: b.nodeId, afterBytes: 1200);
        }
        await a.syncWith(b);
      }

      final analyzer = ChurnTraceAnalyzer(harness.traces);

      // 1. Intra-session duplicate count == 0 (max 1 reception per (node, session, envelope))
      expect(
        analyzer.maxIntraSessionReceptionsPerEnvelope(),
        lessThanOrEqualTo(1),
        reason:
            'Seed $seed: Intra-session duplicate envelope reception detected',
      );

      // 2. Cross-session duplicate receptions <= D_max = 2
      expect(
        analyzer.maxDuplicatesPerNodeEnvelope(),
        lessThanOrEqualTo(2),
        reason:
            'Seed $seed: Cross-session duplicate receptions exceeded D_max = 2',
      );

      // 3. All 6 nodes hold all 30 unique envelopes with zero duplicate rows in storage
      for (final node in allNodes) {
        for (final env in allEnvelopes) {
          expect(
            await node.holdsMessage(env.messageId),
            isTrue,
            reason:
                'Seed $seed: Node ${node.nodeId} missing envelope ${hex.encode(env.messageId)}',
          );
        }
      }
    });

    test(
        'TC-AMP-02: Air-Byte Amplification Bound Under Overlapping Gossip & Flapping',
        () async {
      const seed = 10102;
      final clock = MutableClock();
      final harness = await MeshHarness.create(seed: seed, clock: clock);
      addTearDown(harness.dispose);

      // 8 nodes: 6 healthy (N1..N6), 2 flapping (F1..F2)
      final nodes = <MeshNode>[];
      for (var i = 1; i <= 6; i++) {
        nodes.add(await harness.addNode('N$i'));
      }
      final f1 = await harness.addNode('F1');
      final f2 = await harness.addNode('F2');
      nodes.addAll([f1, f2]);

      // 40 messages of ~350B payload so DATA payload dominates handshake/summary framing
      final published = <Envelope>[];
      final filler = 'X' * 220;
      for (var i = 0; i < 40; i++) {
        final author = nodes[i % nodes.length];
        final env = await author.publish(
          type: 'bbs',
          body: {'idx': i, 'text': filler},
        );
        published.add(env);
      }

      // First: introduce 2 mid-session cuts on F1/F2, then converge via structured spanning tree + ring
      harness.cutLink(nodeA: 'N1', nodeB: 'F1', afterBytes: 1800);
      await harness.syncPair('N1', 'F1');

      harness.cutLink(nodeA: 'N2', nodeB: 'F2', afterBytes: 1800);
      await harness.syncPair('N2', 'F2');

      // Tree-gather to N1, then distribute from N1 to all peers
      for (var i = 1; i < nodes.length; i++) {
        clock.advance(const Duration(seconds: 1));
        await harness.syncPair('N1', nodes[i].nodeId);
      }
      for (var i = 1; i < nodes.length; i++) {
        clock.advance(const Duration(seconds: 1));
        await harness.syncPair('N1', nodes[i].nodeId);
      }

      // Compute ideal_bytes: sum of envelope wire size * (nodes.length - 1) non-author recipients
      var idealBytes = 0;
      for (final env in published) {
        final envBytes = env.toCanonicalCbor().length;
        idealBytes += envBytes * (nodes.length - 1);
      }

      final analyzer = ChurnTraceAnalyzer(harness.traces);
      final ratio = analyzer.amplificationRatio(idealBytes: idealBytes);

      for (final node in nodes) {
        for (final env in published) {
          expect(await node.holdsMessage(env.messageId), isTrue);
        }
      }
      expect(
        ratio,
        lessThanOrEqualTo(1.50),
        reason: 'Seed $seed: Amplification ratio $ratio exceeded A_max = 1.50',
      );
    });

    test(
        'TC-AMP-03: Receipt & Revocation Control-Frame Idempotence Across Repeated Syncs',
        () async {
      const seed = 10103;
      final clock = MutableClock();
      final harness = await MeshHarness.create(seed: seed, clock: clock);
      addTearDown(harness.dispose);

      final a = await harness.addNode('A');
      final b = await harness.addNode('B');
      await harness.addNode('C');
      await harness.addNode('D');

      // Publish messages and sync to server via A (issues receipt) + issue revocation for D
      await a.publish(type: 'bbs', body: {'msg': 'hello 1'});
      await b.publish(type: 'bbs', body: {'msg': 'hello 2'});
      await harness.syncPair('A', 'B');
      await harness.gatewaySync('A');
      await harness.issueAndIngestRevocation(
          targetNodeId: 'D', sourceNodeId: 'A');

      // Converge A, B, C
      await harness.syncPair('A', 'B');
      await harness.syncPair('B', 'C');
      await harness.syncPair('A', 'C');

      // Clear trace and run 4 additional full-mesh sync rounds with no new state
      final traceStartIdx = harness.traces.length;
      for (var round = 0; round < 4; round++) {
        clock.advance(const Duration(seconds: 5));
        await harness.syncPair('A', 'B');
        await harness.syncPair('B', 'C');
        await harness.syncPair('A', 'C');
      }

      final steadyEvents = harness.traces.sublist(traceStartIdx);
      final steadyAnalyzer = ChurnTraceAnalyzer(steadyEvents);

      // Zero DATA (0x13), RECEIPTS (0x14), or REVOCATIONS (0x15) frames during steady-state rounds
      expect(steadyAnalyzer.framesSentOfType(SessionFrameType.data).length,
          equals(0));
      expect(steadyAnalyzer.framesSentOfType(SessionFrameType.receipts).length,
          equals(0));
      expect(
          steadyAnalyzer.framesSentOfType(SessionFrameType.revocations).length,
          equals(0));

      // Verify Summary / Want frames remain compact
      for (final ev
          in steadyAnalyzer.framesSentOfType(SessionFrameType.summary)) {
        expect(ev.bytes!, lessThanOrEqualTo(512));
      }
      for (final ev in steadyAnalyzer.framesSentOfType(SessionFrameType.want)) {
        expect(ev.bytes!, lessThanOrEqualTo(512));
      }
    });

    test(
        'TC-AMP-04: Gateway Server Push & Pull Deduplication Under Mid-Request Cuts (IT-FI-06)',
        () async {
      const seed = 10104;
      final clock = MutableClock();
      final harness = await MeshHarness.create(seed: seed, clock: clock);
      addTearDown(harness.dispose);

      final m1 = await harness.addNode('M1');
      final m2 = await harness.addNode('M2');
      await harness.addNode('G1');
      await harness.addNode('G2');

      // M1 and M2 publish 5 messages each (10 total)
      final published = <Envelope>[];
      for (var i = 0; i < 5; i++) {
        published.add(await m1.publish(type: 'bbs', body: {'m': 'm1_$i'}));
        published.add(await m2.publish(type: 'bbs', body: {'m': 'm2_$i'}));
      }

      // Sync M1, M2 -> G1, G2 so both gateways hold all 10 messages (|G| = 2)
      await harness.syncPair('M1', 'G1');
      await harness.syncPair('M2', 'G1');
      await harness.syncPair('G1', 'G2');

      // 1. G1 pushes to server with IT-FI-06 cutBeforeReceiptResponse = true
      final g1First =
          await harness.gatewaySync('G1', cutBeforeReceiptResponse: true);
      expect(g1First.pushed, equals(10));

      // 2. G2 pushes to server before G1's receipts have propagated
      final g2First = await harness.gatewaySync('G2');
      expect(g2First.pushed, equals(10));
      expect(g2First.receiptsApplied, greaterThan(0));

      // 3. G1 reconnects with reconcileReceiptsBeforePush = true -> 0 re-uploads!
      final g1Retry =
          await harness.gatewaySync('G1', reconcileReceiptsBeforePush: true);
      expect(g1Retry.pushed, equals(0));

      // 4. Propagate receipts across mesh and verify subsequent gateway syncs push 0 envelopes
      await harness.syncPair('G2', 'M1');
      await harness.syncPair('G2', 'M2');
      expect((await harness.gatewaySync('G1')).pushed, equals(0));
      expect((await harness.gatewaySync('G2')).pushed, equals(0));

      final analyzer = ChurnTraceAnalyzer(harness.traces);
      expect(
        analyzer.maxServerPushesPerEnvelope(),
        lessThanOrEqualTo(2), // P_max <= |G| = 2
        reason: 'Seed $seed: Server pushes per envelope exceeded |G| = 2',
      );
    });
  });

  group('Category 2: Partial Sync & Mid-Session Cut Resume (IT-RES-01..02)',
      () {
    test('TC-RES-01: Byte-Offset Cut Sweep Retransmission Bound', () async {
      const seed = 20101;
      final cutBudgets = [256, 1024, 2500, 5000, 9000];

      for (final cutBytes in cutBudgets) {
        final clock = MutableClock();
        final harness =
            await MeshHarness.create(seed: seed + cutBytes, clock: clock);

        final a = await harness.addNode('A');
        final b = await harness.addNode('B');

        final envs = <Envelope>[];
        for (var seq = 1; seq <= 25; seq++) {
          envs.add(await a.publish(
            type: 'bbs',
            priority: seq == 25 ? 0 : (seq % 3), // seq 25 is SOS priority 0!
            body: {
              'seq': seq,
              'data': 'Payload content for sequence $seq ' * 4
            },
          ));
        }

        // Session 1: cut after `cutBytes`
        harness.cutLink(nodeA: 'A', nodeB: 'B', afterBytes: cutBytes);
        await harness.syncPair('A', 'B');

        // Count how many envelopes B committed during Session 1
        final committedInSession1 = <String>{};
        for (final env in envs) {
          if (await b.holdsMessage(env.messageId)) {
            committedInSession1.add(hex.encode(env.messageId));
          }
        }

        // Verify that B's VersionVector accurately reflects every committed envelope
        final vecAfterS1 = await b.store.getVersionVector();
        for (final env in envs) {
          final held = await b.holdsMessage(env.messageId);
          expect(vecAfterS1.has(hex.encode(a.memberPubkey), env.core.seq),
              equals(held));
        }

        // Session 2: uncut resume
        final traceIdxBeforeS2 = harness.traces.length;
        final res2 = await harness.syncPair('A', 'B');
        expect(res2['A']!.completedSuccessfully, isTrue);
        expect(res2['B']!.completedSuccessfully, isTrue);

        // Verify 0 envelopes committed in Session 1 were re-sent in Session 2
        final s2Events = harness.traces.sublist(traceIdxBeforeS2);
        for (final ev in s2Events) {
          if (ev.type == MeshEventType.envelopeReceived && ev.nodeId == 'B') {
            expect(
              committedInSession1.contains(ev.messageId),
              isFalse,
              reason:
                  'Cut $cutBytes: Envelope ${ev.messageId} committed in S1 was re-sent in S2',
            );
          }
        }

        // Verify all 25 envelopes are held by B after Session 2
        for (final env in envs) {
          expect(await b.holdsMessage(env.messageId), isTrue);
        }

        await harness.dispose();
      }
    });

    test(
        'TC-RES-02: 7-Phase State-Machine Cut Sweep & Store Consistency (with SQLite Reopen)',
        () async {
      const seed = 20102;
      final phasesToCut = <int>[
        SessionFrameType.handshake1,
        SessionFrameType.handshake2,
        SessionFrameType.handshake3,
        SessionFrameType.summary,
        SessionFrameType.want,
        SessionFrameType.revocations,
        SessionFrameType.receipts,
        SessionFrameType.data,
      ];

      final tempDir =
          await Directory.systemTemp.createTemp('msgp2p_tc_res_02_');
      addTearDown(() async {
        if (await tempDir.exists()) {
          await tempDir.delete(recursive: true);
        }
      });

      for (final frameType in phasesToCut) {
        final clock = MutableClock();
        final harness =
            await MeshHarness.create(seed: seed + frameType, clock: clock);
        final dbPathA = '${tempDir.path}/node_a_$frameType.sqlite';
        final dbPathB = '${tempDir.path}/node_b_$frameType.sqlite';

        final storeA = SqliteMessageStore.open(dbPathA);
        final storeB = SqliteMessageStore.open(dbPathB);

        final a = await harness.addNode('A', customStore: storeA);
        final b = await harness.addNode('B', customStore: storeB);
        await harness.addNode('C');

        // Seed A and B with messages, a server receipt, and a revocation for C
        final envA1 =
            await a.publish(type: 'sos', priority: 0, body: {'msg': 'A1'});
        final envA2 =
            await a.publish(type: 'bbs', priority: 2, body: {'msg': 'A2'});
        final envB1 =
            await b.publish(type: 'bbs', priority: 1, body: {'msg': 'B1'});
        await harness.gatewaySync('A');
        await harness.issueAndIngestRevocation(
            targetNodeId: 'C', sourceNodeId: 'A');

        // Session 1: cut right after sending `frameType`
        // Note: handshake2 is sent by responder (B), others by initiator (A)
        if (frameType == SessionFrameType.handshake2) {
          // Cut via byte budget right after msg1 + msg2 (~220 bytes)
          harness.cutLink(nodeA: 'A', nodeB: 'B', afterBytes: 220);
          await harness.syncPair('A', 'B');
        } else {
          await harness.syncPair('A', 'B', cutAfterSendingFrameType: frameType);
        }

        // Simulate crash/reopen of SQLite stores (IT-FI-07)
        storeA.close();
        storeB.close();
        final reopenedA = SqliteMessageStore.open(dbPathA);
        final reopenedB = SqliteMessageStore.open(dbPathB);
        await a.restart(reopenedStore: reopenedA);
        await b.restart(reopenedStore: reopenedB);

        // Verify store <-> VersionVector consistency immediately after cut + reopen
        final vecB = await b.store.getVersionVector();
        for (final env in [envA1, envA2, envB1]) {
          final inStore = await b.holdsMessage(env.messageId);
          final inVec = vecB.has(hex.encode(env.core.author), env.core.seq);
          expect(
            inVec,
            equals(inStore),
            reason:
                'FrameType 0x${frameType.toRadixString(16)}: Vector/store mismatch after cut',
          );
        }

        // Session 2: uncut sync converges completely
        final res2 = await harness.syncPair('A', 'B');
        expect(res2['A']!.completedSuccessfully, isTrue);
        expect(res2['B']!.completedSuccessfully, isTrue);

        expect(await b.holdsMessage(envA1.messageId), isTrue);
        expect(await b.holdsMessage(envA2.messageId), isTrue);
        expect(await a.holdsMessage(envB1.messageId), isTrue);

        reopenedA.close();
        reopenedB.close();
        await harness.dispose();
      }
    });
  });
}
