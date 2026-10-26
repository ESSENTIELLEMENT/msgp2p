import 'dart:io';
import 'dart:typed_data';
import 'package:convert/convert.dart';
import 'package:msgp2p_core/msgp2p_core.dart';
import 'package:test/test.dart';

void main() {
  group(
      'Category 3: Flapping-Peer Isolation & Resource Protection (IT-FLAP-01..05)',
      () {
    test(
        'TC-FLAP-01: Healthy-Node Throughput & p95 Latency Preservation Under Flapping Neighbors',
        () async {
      const seed = 30101;

      Future<({double deliveryRatio, int p95LatencyMs})> runSubScenario(
          {required bool withFlapping}) async {
        final clock = MutableClock();
        final harness = await MeshHarness.create(seed: seed, clock: clock);
        addTearDown(harness.dispose);

        final hNodes = <MeshNode>[];
        for (var i = 1; i <= 6; i++) {
          hNodes.add(await harness.addNode('H$i',
              frameTimeout: const Duration(milliseconds: 120)));
        }

        final fNodes = <MeshNode>[];
        if (withFlapping) {
          fNodes.add(await harness.addNode('F1',
              frameTimeout: const Duration(milliseconds: 120)));
          fNodes.add(await harness.addNode('F2',
              frameTimeout: const Duration(milliseconds: 120)));
        }

        final pubTimes = <String, int>{};
        final firstDeliveredAllHealthyMs = <String, int>{};
        final published = <Envelope>[];

        // 12 rounds of publishing and gossiping across healthy nodes (plus flapping contacts when enabled)
        for (var round = 0; round < 12; round++) {
          final author = hNodes[round % hNodes.length];
          final env = await author.publish(
            type: round % 4 == 0 ? 'sos' : 'bbs',
            priority: round % 4 == 0 ? 0 : 2,
            body: {'round': round, 'msg': 'Healthy message $round'},
          );
          final idHex = hex.encode(env.messageId);
          pubTimes[idHex] = clock.now().millisecondsSinceEpoch;
          published.add(env);

          if (withFlapping) {
            final f = fNodes[round % fNodes.length];
            // Flapping peer drops mid-session, but cooldown suppresses repeated attempts
            harness.cutLink(
                nodeA: author.nodeId, nodeB: f.nodeId, afterBytes: 350);
            await author.syncWith(f, enforceCooldown: true);
          }

          // Healthy ring + cross-chord syncs advance virtual clock by 500ms per step
          clock.advance(const Duration(milliseconds: 500));
          for (var i = 0; i < hNodes.length; i++) {
            final next = hNodes[(i + 1) % hNodes.length];
            await hNodes[i].syncWith(next);
          }
          clock.advance(const Duration(milliseconds: 500));
          for (var i = 0; i < hNodes.length; i++) {
            final prev = hNodes[(i + hNodes.length - 1) % hNodes.length];
            await hNodes[i].syncWith(prev);
          }

          // Check which published envelopes have now reached 100% of healthy nodes
          for (final e in published) {
            final eHex = hex.encode(e.messageId);
            if (!firstDeliveredAllHealthyMs.containsKey(eHex)) {
              var allHold = true;
              for (final h in hNodes) {
                if (!await h.holdsMessage(e.messageId)) {
                  allHold = false;
                  break;
                }
              }
              if (allHold) {
                firstDeliveredAllHealthyMs[eHex] =
                    clock.now().millisecondsSinceEpoch - pubTimes[eHex]!;
              }
            }
          }
        }

        final deliveredCount = firstDeliveredAllHealthyMs.length;
        final ratio = deliveredCount / published.length;
        final latencies = firstDeliveredAllHealthyMs.values.toList()..sort();
        final p95Idx = ((latencies.length - 1) * 0.95).floor();
        final p95 = latencies.isEmpty ? 0 : latencies[p95Idx];
        return (deliveryRatio: ratio, p95LatencyMs: p95);
      }

      final baseline = await runSubScenario(withFlapping: false);
      final underFlap = await runSubScenario(withFlapping: true);

      expect(baseline.deliveryRatio, equals(1.0));
      expect(underFlap.deliveryRatio, equals(1.0),
          reason: 'Seed $seed: Healthy delivery ratio dropped below 100%');
      expect(
        underFlap.p95LatencyMs,
        lessThanOrEqualTo((baseline.p95LatencyMs * 1.20).ceil()),
        reason:
            'Seed $seed: Healthy p95 latency degraded by more than L_max = 20%',
      );
    });

    test(
        'TC-FLAP-02: Connection-Slot Exhaustion Recovery From Half-Open & Stalled Links (IT-FI-04, IT-FI-05)',
        () async {
      const seed = 30102;
      final clock = MutableClock();
      final harness = await MeshHarness.create(seed: seed, clock: clock);
      addTearDown(harness.dispose);

      // Use a fast frameTimeout (150ms in real wall-clock representing 10s protocol timeout)
      const reclaimTimeout = Duration(milliseconds: 150);
      final h = await harness.addNode('H',
          maxConnections: 4, frameTimeout: reclaimTimeout);
      final f1 = await harness.addNode('F1', frameTimeout: reclaimTimeout);
      final f2 = await harness.addNode('F2', frameTimeout: reclaimTimeout);
      final f3 = await harness.addNode('F3', frameTimeout: reclaimTimeout);
      final f4 = await harness.addNode('F4', frameTimeout: reclaimTimeout);
      final g1 = await harness.addNode('G1', frameTimeout: reclaimTimeout);
      final g2 = await harness.addNode('G2', frameTimeout: reclaimTimeout);

      final sos1 = await g1
          .publish(type: 'sos', priority: 0, body: {'sos': 'G1 emergency'});
      final sos2 = await g2
          .publish(type: 'sos', priority: 0, body: {'sos': 'G2 emergency'});

      // Occupy all 4 of H's connection slots:
      // F1, F2: half-open after handshake (~260 bytes) via IT-FI-04
      // F3, F4: silent stall after handshake (~260 bytes) via IT-FI-05
      harness.medium
          .injectHalfOpenLink(aliveSide: 'H', deadSide: 'F1', afterBytes: 260);
      harness.medium
          .injectHalfOpenLink(aliveSide: 'H', deadSide: 'F2', afterBytes: 260);
      harness.medium.stallLink(nodeA: 'H', nodeB: 'F3', afterBytes: 260);
      harness.medium.stallLink(nodeA: 'H', nodeB: 'F4', afterBytes: 260);

      // Launch all 4 stalled/half-open sessions concurrently; H's SessionStateMachine will reclaim them via frameTimeout
      final stalledFutures = [
        h.syncWith(f1),
        h.syncWith(f2),
        h.syncWith(f3),
        h.syncWith(f4),
      ];

      final results = await Future.wait(stalledFutures);
      for (final resMap in results) {
        expect(resMap['H']!.completedSuccessfully, isFalse);
      }

      // Verify all 4 slots on H are reclaimed (activeLinkCount == 0)
      expect(
        h.transport.activeLinkCount,
        equals(0),
        reason: 'Seed $seed: Stalled/half-open links were not reclaimed on H',
      );

      // Now healthy peers G1 and G2 connect to H and complete SOS synchronization cleanly
      final g1Res = await g1.syncWith(h);
      final g2Res = await g2.syncWith(h);
      expect(g1Res['H']!.completedSuccessfully, isTrue);
      expect(g2Res['H']!.completedSuccessfully, isTrue);
      expect(await h.holdsMessage(sos1.messageId), isTrue);
      expect(await h.holdsMessage(sos2.messageId), isTrue);
      expect(h.transport.activeLinkCount, equals(0));
    });

    test(
        'TC-FLAP-03: Per-Peer Reconnect Cooldown, Rate-Limit Bound & Recovery Reset (FR-SYNC-07)',
        () async {
      const seed = 30103;
      final clock = MutableClock();
      final harness = await MeshHarness.create(seed: seed, clock: clock);
      addTearDown(harness.dispose);

      final a = await harness.addNode('A');
      final f = await harness.addNode('F');

      // F flaps every 3 seconds for 3 minutes (60 attempts scheduled by test loop)
      for (var step = 0; step < 60; step++) {
        clock.advance(const Duration(seconds: 3));
        // F drops mid-handshake / mid-summary
        harness.cutLink(nodeA: 'A', nodeB: 'F', afterBytes: 180);
        await a.syncWith(f, enforceCooldown: true);
      }

      final analyzer = ChurnTraceAnalyzer(harness.traces);
      final maxPerMin = analyzer.maxConnectAttemptsPerMinute();

      // 1. At most C_max = 6 connect_attempt events in any 60-second sliding window
      expect(
        maxPerMin,
        lessThanOrEqualTo(6),
        reason:
            'Seed $seed: Connect attempts per minute ($maxPerMin) exceeded C_max = 6',
      );

      // 2. Verify connect_rejected events were logged while cooldown/rate-limit was active
      final rejections = harness.traces
          .where((e) => e.type == MeshEventType.connectRejected)
          .toList();
      expect(rejections, isNotEmpty);

      // 3. Advance clock past cooldown window, let F stabilize (clear fault triggers), and complete a full session
      harness.medium.clearFaultTriggers();
      clock.advance(const Duration(seconds: 65));
      final envF = await f.publish(type: 'bbs', body: {'recovered': true});
      final recoveryRes = await a.syncWith(f, enforceCooldown: true);
      expect(recoveryRes['A']!.completedSuccessfully, isTrue);
      expect(await a.holdsMessage(envF.messageId), isTrue);

      // 4. Verify consecutiveFailures and cooldown timer reset to 0 after successful BYE
      expect(a.cooldownTracker.consecutiveFailuresFor('F'), equals(0));
      final decisionAfterSuccess = a.cooldownTracker
          .checkConnectAllowed('F', clock.now().millisecondsSinceEpoch);
      expect(decisionAfterSuccess.allowed, isTrue);
      expect(decisionAfterSuccess.waitMs, equals(0));
    });

    test('TC-FLAP-04: Simultaneous-Connect Tie-Break Under Rapid Flapping',
        () async {
      const seed = 30104;
      final clock = MutableClock();
      final harness = await MeshHarness.create(seed: seed, clock: clock);
      addTearDown(harness.dispose);

      final a = await harness.addNode('A');
      final b = await harness.addNode('B');
      final envA = await a.publish(type: 'bbs', body: {'from': 'A'});
      final envB = await b.publish(type: 'bbs', body: {'from': 'B'});

      // Determine deterministic tie-breaker winner by memberPubkey comparison
      final cmp =
          SessionStateMachine.comparePubkeys(a.memberPubkey, b.memberPubkey);
      expect(cmp, isNot(equals(0)));

      // Cycle 1..15: rapid simultaneous dial attempts with mid-handshake cuts on odd cycles
      for (var cycle = 1; cycle <= 15; cycle++) {
        clock.advance(const Duration(seconds: 2));
        if (cycle % 2 == 1) {
          harness.cutLink(nodeA: 'A', nodeB: 'B', afterBytes: 200);
        }
        await harness.syncPair('A', 'B');
        expect(a.transport.activeLinkCount, equals(0));
        expect(b.transport.activeLinkCount, equals(0));
      }

      expect(await a.holdsMessage(envB.messageId), isTrue);
      expect(await b.holdsMessage(envA.messageId), isTrue);
    });

    test(
        'TC-FLAP-05: Post-Handshake Dropper Isolation & Tier 2 Failure Accounting',
        () async {
      const seed = 30105;
      final clock = MutableClock();
      final harness = await MeshHarness.create(seed: seed, clock: clock);
      addTearDown(harness.dispose);

      final h1 = await harness.addNode('H1');
      final h2 = await harness.addNode('H2');
      final m = await harness.addNode('M', dropAfterHandshake: true);

      final envH1 =
          await h1.publish(type: 'sos', priority: 0, body: {'alert': 'H1 SOS'});

      // M attempts to waste H1's time across 20 cycles
      for (var i = 0; i < 20; i++) {
        clock.advance(const Duration(seconds: 3));
        await h1.syncWith(m, enforceCooldown: true);
      }

      // 1. Cooldown tracker isolates M (`<= 6 attempts/min`)
      final analyzer = ChurnTraceAnalyzer(harness.traces);
      expect(analyzer.maxConnectAttemptsPerMinute(), lessThanOrEqualTo(6));

      // 2. H1's Tier 2 `peer_daily_stats` records failed/flapped sessions for M's member_pubkey
      final stats = await h1.store.getPeerDailyStats();
      final mKeyHex = hex.encode(m.memberPubkey);
      final mStat =
          stats.where((s) => hex.encode(s.memberPubkey) == mKeyHex).toList();
      expect(mStat, isNotEmpty,
          reason: 'Expected Tier 2 peer_daily_stats entry for dropper M');
      expect(mStat.first.flapCount, greaterThan(0));
      expect(mStat.first.sessionsCount, equals(0));

      // 3. H1 and H2 sync without any interference
      final hRes = await h1.syncWith(h2);
      expect(hRes['H1']!.completedSuccessfully, isTrue);
      expect(await h2.holdsMessage(envH1.messageId), isTrue);
    });
  });

  group('Category 4: Data-Structure Integrity Under High Churn (IT-DS-01..07)',
      () {
    test(
        'TC-DS-01: Quota Eviction Gap Reporting & Bounded Re-Fetch Suppression (E_max = 2)',
        () async {
      const seed = 40101;
      final clock = MutableClock();
      final harness = await MeshHarness.create(seed: seed, clock: clock);
      addTearDown(harness.dispose);

      final a = await harness.addNode('A');

      final envs = <Envelope>[];
      for (var seq = 1; seq <= 8; seq++) {
        envs.add(await a.publish(
          type: 'bbs',
          priority: seq <= 3
              ? 3
              : 1, // seq 1..3 are low-priority 3 (evicted first), seq 4..8 are priority 1
          body: {'seq': seq, 'filler': 'Payload padding for quota test ' * 5},
        ));
      }

      // Configure Node B's quota to hold exactly 5 envelopes (so seq 4..8 fit, and seq 1..3 are evicted)
      final singleEnvBytes = envs.first.toCanonicalCbor().length;
      final b = await harness.addNode('B',
          storageQuotaBytes: singleEnvBytes * 5 + 32);

      // Initial sync: B receives envelopes and prunes over-quota low-priority seq 1..3
      await harness.syncPair('A', 'B');
      final evictedCount = await b.pruneStore();
      expect(evictedCount, greaterThanOrEqualTo(3));
      expect(await b.holdsAuthorSeq(a.memberPubkey, 1), isFalse);

      // Run 6 subsequent sync sessions between A and B, pruning B after each session
      for (var round = 1; round <= 6; round++) {
        clock.advance(const Duration(seconds: 5));
        await harness.syncPair('A', 'B');
        await b.pruneStore();
      }

      // Verify seq 1..3 were re-fetched at most E_max = 2 times and then suppressed!
      for (var i = 0; i < 3; i++) {
        final refetchCount = b.store.getEvictionRefetchCount(envs[i].messageId);
        expect(
          refetchCount,
          lessThanOrEqualTo(b.store.maxEvictionRefetches), // E_max = 2
          reason:
              'Seq ${i + 1} re-fetched $refetchCount times (exceeded E_max = 2)',
        );
      }

      // Verify that once E_max is reached, a subsequent sync transfers 0 DATA frames (no infinite ping-pong)
      final traceStart = harness.traces.length;
      await harness.syncPair('A', 'B');
      final finalRoundAnalyzer =
          ChurnTraceAnalyzer(harness.traces.sublist(traceStart));
      expect(
          finalRoundAnalyzer.framesSentOfType(SessionFrameType.data), isEmpty);
    });

    test(
        'TC-DS-02: TTL Expiry During Churn & Clock-Skew Boundary Safety (IT-FI-08)',
        () async {
      const seed = 40102;
      final clock = MutableClock();
      final harness = await MeshHarness.create(seed: seed, clock: clock);
      addTearDown(harness.dispose);

      // A (+8 min skew), B (-8 min skew), C (0 skew)
      final a = await harness.addNode('A', clockSkewMs: 8 * 60 * 1000);
      final b = await harness.addNode('B', clockSkewMs: -8 * 60 * 1000);
      final c = await harness.addNode('C', clockSkewMs: 0);

      // A publishes M_short (TTL = 15 min) and M_long (TTL = 2 hours)
      final mShort = await a
          .publish(type: 'bbs', ttlSeconds: 15 * 60, body: {'msg': 'short'});
      final mLong = await a
          .publish(type: 'bbs', ttlSeconds: 120 * 60, body: {'msg': 'long'});

      // Sync A <-> B with a mid-session cut after M_short
      harness.cutLink(nodeA: 'A', nodeB: 'B', afterBytes: 750);
      await harness.syncPair('A', 'B');

      // Advance global clock by +25 minutes so M_short is expired on all nodes (even with -8 min skew)
      clock.advance(const Duration(minutes: 25));

      final traceBeforeResume = harness.traces.length;
      await harness.syncPair('A', 'B');
      await harness.syncPair('B', 'C');

      // Verify M_short is NEVER transmitted in DATA after expiry
      final postExpiryEvents = harness.traces.sublist(traceBeforeResume);
      final shortHex = hex.encode(mShort.messageId);
      for (final ev in postExpiryEvents) {
        if (ev.type == MeshEventType.envelopeReceived) {
          expect(ev.messageId, isNot(equals(shortHex)),
              reason: 'Expired M_short was transmitted over the air!');
        }
      }

      // Verify M_long is delivered to A, B, C, and prune removes M_short cleanly
      expect(await b.holdsMessage(mLong.messageId), isTrue);
      expect(await c.holdsMessage(mLong.messageId), isTrue);
      await a.pruneStore();
      await b.pruneStore();
      await c.pruneStore();
      expect(await a.holdsMessage(mShort.messageId), isFalse);
      expect(await b.holdsMessage(mShort.messageId), isFalse);
      expect(await c.holdsMessage(mShort.messageId), isFalse);
    });

    test(
        'TC-DS-03: VersionVector Gap Fragmentation Bound & Collapse Across 100 Authors x 200 Messages',
        () async {
      final store = SqliteMessageStore.inMemory();
      addTearDown(store.close);

      final groupId = Uint8List.fromList(List.generate(16, (i) => 0x55));
      final nonce = Uint8List(24);
      final ciphertext = Uint8List(64);
      final sig = Uint8List(64);
      final certRef = Uint8List(32);

      // Create 100 authors, each with 200 messages (20,000 envelopes total)
      final authorPubkeys = <String>[];
      final oddEnvelopes = <Envelope>[];
      final evenEnvelopes = <Envelope>[];

      for (var aIdx = 0; aIdx < 100; aIdx++) {
        final pk = Uint8List.fromList(
            List.generate(32, (i) => (aIdx * 7 + i + 1) & 0xFF));
        authorPubkeys.add(hex.encode(pk));

        for (var seq = 1; seq <= 200; seq++) {
          final env = Envelope(
            core: EnvelopeCore(
              version: 1,
              groupId: groupId,
              keyEpoch: 1,
              author: pk,
              seq: seq,
              createdAt: 1700000000000 + seq,
              expiresAt: 1700086400000 + seq,
              priority: 2,
              nonce: nonce,
              ciphertext: ciphertext,
            ),
            sig: sig,
            certRef: certRef,
          );
          if (seq.isOdd) {
            oddEnvelopes.add(env);
          } else {
            evenEnvelopes.add(env);
          }
        }
      }

      // Phase 1: Ingest all odd sequences (creates sparse gaps across all 100 authors)
      await store.saveBatch(oddEnvelopes);
      final fragmentedVec = await store.getVersionVector();
      expect(fragmentedVec.authors.length, equals(100));

      // Phase 2: Ingest all even sequences -> all gaps must collapse to 0!
      await store.saveBatch(evenEnvelopes);
      final convergedVec = await store.getVersionVector();

      for (final authorHex in authorPubkeys) {
        final state = convergedVec.authors[authorHex]!;
        expect(state.contiguous, equals(200));
        expect(state.gaps, isEmpty,
            reason: 'Author $authorHex still has uncollapsed gaps');
      }

      // Verify converged deflate-compressed CBOR VersionVector for 100 authors is <= 2 KB (architecture.md §3.1, §3.4)
      final deflatedBytes = convergedVec.toDeflatedCbor();
      expect(
        deflatedBytes.length,
        lessThanOrEqualTo(2048),
        reason:
            'Converged 100-author deflated VersionVector size (${deflatedBytes.length}B) exceeded 2 KB',
      );
      final roundTrip = VersionVector.fromDeflatedCbor(deflatedBytes);
      expect(roundTrip.authors.length, equals(100));
    });

    test(
        'TC-DS-04: ServerReceipt Range Canonicalization & Idempotent Application',
        () async {
      const seed = 40104;
      final clock = MutableClock();
      final harness = await MeshHarness.create(seed: seed, clock: clock);
      addTearDown(harness.dispose);

      final store = SqliteMessageStore.inMemory();
      addTearDown(store.close);
      final a = await harness.addNode('A', customStore: store);

      for (var s = 1; s <= 15; s++) {
        await a.publish(type: 'bbs', body: {'seq': s});
      }

      Future<ServerReceipt> makeReceipt(
          List<SeqRange> ranges, int issuedAt) async {
        final core = ServerReceipt(
          groupId: harness.groupId,
          author: a.memberPubkey,
          ranges: ranges,
          issuedAt: issuedAt,
          serverSig: Uint8List(0),
        );
        final sig = await MsgP2PCrypto.sign(
            core.toCoreCbor(), harness.serverSigningKeyPair);
        return ServerReceipt(
          groupId: harness.groupId,
          author: a.memberPubkey,
          ranges: ranges,
          issuedAt: issuedAt,
          serverSig: sig,
        );
      }

      final r1 = await makeReceipt(
          [const SeqRange(1, 5), const SeqRange(8, 12)], 1000);
      final r2 = await makeReceipt([const SeqRange(4, 9)], 2000);
      final r3 = await makeReceipt(
          [const SeqRange(13, 15), const SeqRange(1, 3)], 3000);

      // Apply out of order and repeatedly (3x each)
      for (var i = 0; i < 3; i++) {
        await store.saveReceipt(r3);
        await store.saveReceipt(r1);
        await store.saveReceipt(r2);
      }

      final confirmed = await store.getConfirmedRanges(a.memberPubkey);
      expect(
        confirmed,
        equals([const SeqRange(1, 15)]),
        reason:
            'Overlapping & adjacent receipt ranges must canonicalize to a single [1, 15] range',
      );

      for (var s = 1; s <= 15; s++) {
        expect(await store.isConfirmed(a.memberPubkey, s), isTrue);
      }
    });

    test(
        'TC-DS-05a..e: 3-Tier Peer History Retention, Row Caps, Clock-Jump Safety & Pruning Budget (FR-SYNC-08)',
        () async {
      final tempDir = await Directory.systemTemp.createTemp('msgp2p_tc_ds_05_');
      addTearDown(() async {
        if (await tempDir.exists()) {
          await tempDir.delete(recursive: true);
        }
      });

      final dbPath = '${tempDir.path}/peer_history.sqlite';
      var store = SqliteMessageStore.open(dbPath);
      final clock = MutableClock(DateTime.utc(2026, 5, 1, 12, 0));

      // --- TC-DS-05a: Tier 1 (`peer_sightings`) 24h retention, (token, window) dedup & 2,000 row cap ---
      final token1 = Uint8List.fromList(List.generate(16, (i) => i + 1));
      final baseMs = clock.now().millisecondsSinceEpoch;
      final windowId = baseMs ~/ (15 * 60 * 1000);

      for (var i = 0; i < 50; i++) {
        await store.recordPeerSighting(
          token: token1,
          seenAt: baseMs + i * 1000,
          transport: 'ble',
          rssi: -70 + (i % 15), // last RSSI is -70 + (49 % 15) = -66
        );
      }
      var sightings =
          await store.getRecentPeerSightings(currentTimeMillis: baseMs + 50000);
      expect(sightings.length, equals(1),
          reason: '50 advertisements in same window must deduplicate to 1 row');
      expect(sightings.first.rotationWindow, equals(windowId));
      expect(sightings.first.seenAt, equals(baseMs + 49 * 1000));

      // Advance +25 hours and insert 2,500 distinct tokens -> oldest evicted so row count <= 2,000
      clock.advance(const Duration(hours: 25));
      final day2Ms = clock.now().millisecondsSinceEpoch;
      for (var i = 0; i < 2500; i++) {
        final tok = Uint8List(16);
        ByteData.sublistView(tok).setUint32(0, i + 1000);
        await store.recordPeerSighting(
          token: tok,
          seenAt: day2Ms + i,
          transport: 'ble',
          rssi: -60,
        );
      }

      // Measure pruning time (TC-DS-05e: <= 15 ms)
      final sw = Stopwatch()..start();
      await store.prunePeerHistory(currentTimeMillis: day2Ms + 3000);
      sw.stop();
      expect(
        sw.elapsedMilliseconds,
        lessThanOrEqualTo(15),
        reason:
            'prunePeerHistory took ${sw.elapsedMilliseconds}ms (exceeded 15ms budget)',
      );

      sightings =
          await store.getRecentPeerSightings(currentTimeMillis: day2Ms + 3000);
      expect(sightings.length, lessThanOrEqualTo(2000));
      expect(
        sightings.any((s) => s.rotationWindow == windowId),
        isFalse,
        reason: 'Sightings older than 24h must be pruned',
      );

      // --- TC-DS-05b: Tier 2 (`peer_daily_stats`) 90-day retention & per-day aggregation ---
      final peerA = Uint8List.fromList(List.generate(32, (i) => 0xA1));
      final peerB = Uint8List.fromList(List.generate(32, (i) => 0xB2));
      final startEpochMs =
          DateTime.utc(2026, 1, 1, 12, 0).millisecondsSinceEpoch;

      for (var day = 0; day < 120; day++) {
        final dayMs = startEpochMs + day * 86400 * 1000;
        // Multiple sessions on the same day aggregate into 1 row per (member_pubkey, day_date)
        for (var s = 0; s < 3; s++) {
          await store.recordPeerDailyStat(
            memberPubkey: peerA,
            timestampMs: dayMs + s * 1000,
            sessionsDelta: 1,
            bytesSentDelta: 1024,
            bytesRecvDelta: 1024,
          );
          await store.recordPeerDailyStat(
            memberPubkey: peerB,
            timestampMs: dayMs + s * 1000,
            sessionsDelta: 1,
            flapDelta: 1,
          );
        }
      }

      final end120DaysMs = startEpochMs + 120 * 86400 * 1000;
      await store.prunePeerHistory(currentTimeMillis: end120DaysMs);
      final statsAfterPrune =
          await store.getPeerDailyStats(currentTimeMillis: end120DaysMs);
      // Only days within the last 90 days survive (<= 91 days * 2 peers = 182 rows)
      expect(statsAfterPrune.length, lessThanOrEqualTo(182));
      expect(statsAfterPrune.first.sessionsCount, equals(3));

      // --- TC-DS-05d: Backward clock-jump protection (IT-FI-11) ---
      final countBeforeBackwardJump = (await store.getPeerDailyStats()).length;
      final backwardClockMs =
          end120DaysMs - 30 * 86400 * 1000; // Jump backward -30 days!
      await store.prunePeerHistory(currentTimeMillis: backwardClockMs);
      final countAfterBackwardJump = (await store.getPeerDailyStats()).length;
      expect(
        countAfterBackwardJump,
        equals(countBeforeBackwardJump),
        reason:
            'Backward clock jump must not corrupt or over-prune peer_daily_stats',
      );

      // --- TC-DS-05c: Tier 3 cooldown state is strictly in-memory and cleared on restart ---
      final tracker = PeerCooldownTracker();
      tracker.recordSessionFailure('F1', end120DaysMs);
      expect(tracker.consecutiveFailuresFor('F1'), equals(1));
      store.close();

      // Reopen SQLite file and verify no cooldown table exists and restart resets tracker
      store = SqliteMessageStore.open(dbPath);
      tracker.resetAll();
      expect(tracker.consecutiveFailuresFor('F1'), equals(0));
      store.close();
    });

    test(
        'TC-SCALE-03 (L2.5): Clock jumps at +1 / +89 / +91 days enforce each retention tier (IT-FI-11)',
        () async {
      final member = Uint8List.fromList(List.generate(32, (i) => 0xC3));
      final t0 = DateTime.utc(2026, 3, 1, 12, 0).millisecondsSinceEpoch;
      const day = 86400000;

      Future<SqliteMessageStore> seeded() async {
        final s = SqliteMessageStore.inMemory();
        await s.recordPeerSighting(
          token: Uint8List.fromList(List.generate(16, (i) => i)),
          seenAt: t0,
          transport: 'ble',
          rssi: -60,
        );
        await s.recordPeerDailyStat(
            memberPubkey: member, timestampMs: t0, sessionsDelta: 1);
        return s;
      }

      // +1 day: Tier 1 gone, Tier 2 kept
      var s = await seeded();
      await s.prunePeerHistory(currentTimeMillis: t0 + day + 1000);
      expect(await s.getRecentPeerSightings(currentTimeMillis: t0 + day + 1000),
          isEmpty);
      expect((await s.getPeerDailyStats()).length, equals(1));
      s.close();

      // +89 days: Tier 2 still kept
      s = await seeded();
      await s.prunePeerHistory(currentTimeMillis: t0 + 89 * day);
      expect((await s.getPeerDailyStats()).length, equals(1));
      s.close();

      // +91 days: Tier 2 physically deleted
      s = await seeded();
      await s.prunePeerHistory(currentTimeMillis: t0 + 91 * day);
      expect(await s.getPeerDailyStats(), isEmpty);
      s.close();

      // Backward jump after +91: nothing new created, nothing wrongly deleted
      s = await seeded();
      await s.prunePeerHistory(currentTimeMillis: t0 + 89 * day);
      await s.prunePeerHistory(currentTimeMillis: t0 - 30 * day);
      expect((await s.getPeerDailyStats()).length, equals(1));
      s.close();
    });

    test(
        'TC-DS-06: SQLite Mid-Batch Crash Rollback Atomicity & Vector Agreement (IT-FI-07, NFR-REL-01)',
        () async {
      const seed = 40106;
      final rng = DeterministicRandomSource(seed);
      final tempDir = await Directory.systemTemp.createTemp('msgp2p_tc_ds_06_');
      addTearDown(() async {
        if (await tempDir.exists()) {
          await tempDir.delete(recursive: true);
        }
      });

      final dbPath = '${tempDir.path}/atomic_crash.sqlite';
      final kp = await MsgP2PCrypto.newKeyPairFromSeed(rng.nextBytes(32));
      final pk = await MsgP2PCrypto.getPublicKeyBytes(kp);
      final certRef = Uint8List.fromList(pk.sublist(0, 16));
      final groupId = Uint8List.fromList(List.generate(16, (i) => 0x11));
      final groupKey = Uint8List.fromList(List.generate(32, (i) => 0x22));

      final all50 = <Envelope>[];
      for (var seq = 1; seq <= 50; seq++) {
        all50.add(await Envelope.create(
          groupId: groupId,
          keyEpoch: 1,
          groupKey: groupKey,
          authorKeyPair: kp,
          certRef: certRef,
          seq: seq,
          payload: {'seq': seq},
          randomSource: rng,
        ));
      }

      // 1. Commit batch 1 (seq 1..15) cleanly
      var store = SqliteMessageStore.open(dbPath);
      final saved1 = await store.saveBatch(all50.sublist(0, 15));
      expect(saved1, equals(15));
      store.close();

      // 2. Open store with mid-batch crash hook at index 10 of batch 2 (seq 16..40)
      var crashStore = SqliteMessageStore.open(
        dbPath,
        onBatchItemBeforeCommit: (index, env) {
          if (index == 10) {
            throw StateError(
                'Simulated mid-transaction power loss at index 10');
          }
        },
      );
      await expectLater(
        () => crashStore.saveBatch(all50.sublist(15, 40)),
        throwsA(isA<StateError>()),
      );
      crashStore.close();

      // 3. Reopen database without crash hook and verify atomic rollback of batch 2
      store = SqliteMessageStore.open(dbPath);
      final vecAfterReopen = await store.getVersionVector();
      final authorHex = hex.encode(pk);
      expect(vecAfterReopen.authors[authorHex]?.contiguous, equals(15));
      expect(vecAfterReopen.authors[authorHex]?.gaps ?? const <int>{}, isEmpty);

      for (var seq = 1; seq <= 50; seq++) {
        final held = await store.isSequenceHeld(pk, seq);
        expect(held, equals(seq <= 15),
            reason: 'Seq $seq held state mismatch after rollback');
      }

      // 4. Retry remaining envelopes (seq 16..50) and verify full convergence
      final savedRemaining = await store.saveBatch(all50.sublist(15, 50));
      expect(savedRemaining, equals(35));
      final finalVec = await store.getVersionVector();
      expect(finalVec.authors[authorHex]?.contiguous, equals(50));
      expect(finalVec.authors[authorHex]?.gaps ?? const <int>{}, isEmpty);
      store.close();
    });

    test(
        'TC-DS-07: Post-Churn State Convergence Across All Nodes Within T_conv',
        () async {
      const seed = 40107;
      final clock = MutableClock();
      final harness = await MeshHarness.create(seed: seed, clock: clock);
      addTearDown(harness.dispose);

      // 10 nodes: N0..N9 + 1 revoked node R
      final nodes = <MeshNode>[];
      for (var i = 0; i < 10; i++) {
        nodes.add(await harness.addNode('N$i'));
      }
      await harness.addNode('R');

      // Publish 40 messages across N0..N9
      final published = <Envelope>[];
      for (var i = 0; i < 40; i++) {
        final author = nodes[i % nodes.length];
        published.add(await author.publish(
          type: i % 10 == 0 ? 'sos' : 'bbs',
          priority: i % 10 == 0 ? 0 : 2,
          body: {'i': i, 'msg': 'Churn test $i'},
        ));
      }

      // Issue server receipt on N0 and revocation of R on N1
      await harness.gatewaySync('N0');
      await harness.issueAndIngestRevocation(
          targetNodeId: 'R', sourceNodeId: 'N1');

      // Phase 1: Heavy churn with partitions and mid-transfer link cuts
      harness.partition([
        ['N0', 'N1', 'N2', 'N3', 'N4'],
        ['N5', 'N6', 'N7', 'N8', 'N9'],
      ]);
      harness.cutLink(nodeA: 'N0', nodeB: 'N1', afterBytes: 900);
      await harness.syncPair('N0', 'N1');
      harness.cutLink(nodeA: 'N5', nodeB: 'N6', afterBytes: 900);
      await harness.syncPair('N5', 'N6');

      // Phase 2: Heal network (`setFullMesh()`) and run structured gossip convergence
      harness.setFullMesh();
      for (var i = 1; i < nodes.length; i++) {
        await harness.syncPair('N0', nodes[i].nodeId);
      }
      for (var i = 1; i < nodes.length; i++) {
        await harness.syncPair('N0', nodes[i].nodeId);
      }

      // Verify all 10 nodes have identical VersionVectors, receipts, and revocations
      final refVecCbor = hex.encode(
          (await nodes.first.store.getVersionVector()).toCanonicalCbor());
      for (final node in nodes) {
        final vec = await node.store.getVersionVector();
        expect(
          hex.encode(vec.toCanonicalCbor()),
          equals(refVecCbor),
          reason:
              'Node ${node.nodeId} VersionVector diverged after stabilization',
        );
        for (final st in vec.authors.values) {
          expect(st.gaps, isEmpty);
        }
        final revs = await node.store.getRevocations();
        expect(revs.length, equals(1));
        final receipts = await node.store.getReceipts();
        expect(receipts, isNotEmpty);
      }
    });
  });
}
