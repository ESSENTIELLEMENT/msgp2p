import 'dart:typed_data';
import 'package:msgp2p_core/msgp2p_core.dart';
import 'package:test/test.dart';

void main() {
  group('Layer 2.5 In-Process Multi-Node Harness (FR-TEST-08)', () {
    late MeshHarness harness;

    setUp(() async {
      harness = await MeshHarness.create(seed: 12345);
    });

    tearDown(() async {
      await harness.dispose();
    });

    test(
        'Scenario 1: 3-Node Relay (A -> B -> C) delivers SOS and normal messages across mesh',
        () async {
      final nodeA = await harness.addNode('A');
      final nodeB = await harness.addNode('B');
      final nodeC = await harness.addNode('C');

      // Topology: A <-> B <-> C (A cannot hear C)
      harness.setTopology({
        'A': {'B'},
        'B': {'A', 'C'},
        'C': {'B'},
      });

      // A publishes an emergency SOS (Priority 0) and a general update (Priority 2)
      final sosEnv = await nodeA.publish(
        type: 'sos_alert',
        body: {'title': 'Mountain rescue needed', 'lat': 35.36, 'lng': 138.72},
        priority: 0,
      );
      final infoEnv = await nodeA.publish(
        type: 'general_info',
        body: {'text': 'Water source clear at waypoint 4'},
        priority: 2,
      );

      // Initial state: Only A holds the messages (delivery ratio = 1/3)
      expect(await nodeA.holdsMessage(sosEnv.messageId), isTrue);
      expect(await nodeB.holdsMessage(sosEnv.messageId), isFalse);
      expect(await nodeC.holdsMessage(sosEnv.messageId), isFalse);
      expect(await harness.getDeliveryRatio(sosEnv.messageId),
          closeTo(0.333, 0.01));

      // Hop 1: A syncs with B
      final resHop1 = await harness.syncPair('A', 'B');
      expect(resHop1['A']!.completedSuccessfully, isTrue);
      expect(resHop1['B']!.completedSuccessfully, isTrue);
      expect(resHop1['A']!.envelopesSent, equals(2));
      expect(resHop1['B']!.envelopesReceived, equals(2));

      // B now holds and can decrypt both messages
      expect(await nodeB.holdsMessage(sosEnv.messageId), isTrue);
      expect(await nodeB.holdsMessage(infoEnv.messageId), isTrue);
      final decryptedSos = await nodeB.decryptPayload(sosEnv);
      expect(decryptedSos['title'], equals('Mountain rescue needed'));

      // Hop 2: B syncs with C (relay forwarding)
      final resHop2 = await harness.syncPair('B', 'C');
      expect(resHop2['B']!.completedSuccessfully, isTrue);
      expect(resHop2['C']!.completedSuccessfully, isTrue);
      expect(resHop2['B']!.envelopesSent, equals(2));
      expect(resHop2['C']!.envelopesReceived, equals(2));

      // C now holds both messages originating from A
      expect(await nodeC.holdsMessage(sosEnv.messageId), isTrue);
      expect(await nodeC.holdsMessage(infoEnv.messageId), isTrue);
      final decryptedInfo = await nodeC.decryptPayload(infoEnv);
      expect(decryptedInfo['text'], equals('Water source clear at waypoint 4'));

      // 100% convergence across the entire relay
      expect(await harness.getDeliveryRatio(sosEnv.messageId), equals(1.0));
      expect(await harness.getDeliveryRatio(infoEnv.messageId), equals(1.0));

      // Subsequent syncs transfer zero redundant messages
      final reSync = await harness.syncPair('B', 'C');
      expect(reSync['B']!.envelopesSent, equals(0));
      expect(reSync['C']!.envelopesReceived, equals(0));
    });

    test(
        'Scenario 2: Network partition and merge with bidirectional reconciliation',
        () async {
      final nodeA = await harness.addNode('A');
      final nodeB = await harness.addNode('B');
      final nodeC = await harness.addNode('C');
      final nodeD = await harness.addNode('D');

      // Partition into two disconnected clusters: [A, B] and [C, D]
      harness.partition([
        ['A', 'B'],
        ['C', 'D'],
      ]);

      // A publishes msgA; C publishes msgC
      final msgA = await nodeA.publish(
          type: 'post', body: {'from': 'cluster_1'}, priority: 2);
      final msgC = await nodeC.publish(
          type: 'post', body: {'from': 'cluster_2'}, priority: 2);

      // Intra-cluster syncs
      await harness.syncPair('A', 'B');
      await harness.syncPair('C', 'D');

      // Verify strict partition isolation
      expect(await nodeA.holdsMessage(msgA.messageId), isTrue);
      expect(await nodeB.holdsMessage(msgA.messageId), isTrue);
      expect(await nodeC.holdsMessage(msgA.messageId), isFalse);
      expect(await nodeD.holdsMessage(msgA.messageId), isFalse);

      expect(await nodeA.holdsMessage(msgC.messageId), isFalse);
      expect(await nodeB.holdsMessage(msgC.messageId), isFalse);
      expect(await nodeC.holdsMessage(msgC.messageId), isTrue);
      expect(await nodeD.holdsMessage(msgC.messageId), isTrue);

      // Heal partition (full mesh restored)
      harness.setFullMesh();

      // Bridge nodes B and C sync across the healed divide
      final bridgeResult = await harness.syncPair('B', 'C');
      expect(bridgeResult['B']!.completedSuccessfully, isTrue);
      expect(bridgeResult['C']!.completedSuccessfully, isTrue);
      expect(bridgeResult['B']!.envelopesSent, equals(1)); // B sends msgA to C
      expect(bridgeResult['C']!.envelopesSent, equals(1)); // C sends msgC to B

      // Spread to edges: A syncs with B, D syncs with C
      await harness.syncPair('A', 'B');
      await harness.syncPair('D', 'C');

      // Complete mesh convergence: all 4 nodes hold both messages
      for (final n in [nodeA, nodeB, nodeC, nodeD]) {
        expect(await n.holdsMessage(msgA.messageId), isTrue,
            reason: '${n.nodeId} should hold msgA');
        expect(await n.holdsMessage(msgC.messageId), isTrue,
            reason: '${n.nodeId} should hold msgC');
      }
      expect(await harness.getDeliveryRatio(msgA.messageId), equals(1.0));
      expect(await harness.getDeliveryRatio(msgC.messageId), equals(1.0));
    });

    test(
        'Scenario 3: Mid-transfer radio cut and resumable synchronization (FR-SYNC-04)',
        () async {
      final nodeA = await harness.addNode('A');
      final nodeB = await harness.addNode('B');

      // A creates 6 messages
      final published = <Envelope>[];
      for (var i = 1; i <= 6; i++) {
        final env = await nodeA.publish(
          type: 'data_chunk',
          body: {'index': i, 'padding': 'x' * 200},
          priority: 2,
        );
        published.add(env);
      }

      // Cut link after ~1200 bytes transmitted (mid-transfer drop)
      harness.cutLink(nodeA: 'A', nodeB: 'B', afterBytes: 2500);

      // First sync attempt will be interrupted
      final res1 = await harness.syncPair('A', 'B');
      expect(res1['A']!.completedSuccessfully, isFalse);

      // Crucial: Bob retained the messages received before the cut
      final bobCountAfterCut = await nodeB.store.getEnvelopeCount();
      expect(bobCountAfterCut, greaterThan(0));
      expect(bobCountAfterCut, lessThan(6));

      // Reconnect and sync again (link healed)
      final res2 = await harness.syncPair('A', 'B');
      expect(res2['A']!.completedSuccessfully, isTrue);
      expect(res2['B']!.completedSuccessfully, isTrue);

      // Alice sent ONLY the remaining missing envelopes, zero duplicate retransmission
      expect(res2['A']!.envelopesSent, equals(6 - bobCountAfterCut));
      expect(res2['B']!.envelopesReceived, equals(6 - bobCountAfterCut));

      // Bob now holds all 6 messages
      expect(await nodeB.store.getEnvelopeCount(), equals(6));
      for (final env in published) {
        expect(await nodeB.holdsMessage(env.messageId), isTrue);
      }
    });

    test(
        'Scenario 4: Server revocation notice propagates across mesh and updates stores',
        () async {
      final nodeA = await harness.addNode('A');
      final nodeB = await harness.addNode('B');
      final nodeC = await harness.addNode('C');

      harness.setTopology({
        'A': {'B'},
        'B': {'A', 'C'},
        'C': {'B'},
      });

      // Charlie publishes a post
      final charlieEnv = await nodeC
          .publish(type: 'post', body: {'msg': 'Charlie original post'});
      expect(await nodeC.holdsMessage(charlieEnv.messageId), isTrue);

      // Server revokes Charlie's key due to security compromise, notice ingested at Node A
      await harness.issueAndIngestRevocation(
        targetNodeId: 'C',
        sourceNodeId: 'A',
        reason: 'key_compromised',
      );

      expect(await nodeA.store.isRevoked(nodeC.memberPubkey), isTrue);
      expect(await nodeB.store.isRevoked(nodeC.memberPubkey), isFalse);

      // A syncs with B: Revocation notice is transferred during metadata phase
      final resAB = await harness.syncPair('A', 'B');
      expect(resAB['A']!.completedSuccessfully, isTrue);
      expect(resAB['A']!.revocationsSent, equals(1));
      expect(resAB['B']!.revocationsReceived, equals(1));
      expect(await nodeB.store.isRevoked(nodeC.memberPubkey), isTrue);

      // B syncs with C: Revocation notice propagates further
      final resBC = await harness.syncPair('B', 'C');
      expect(resBC['B']!.completedSuccessfully, isTrue);
      expect(resBC['B']!.revocationsSent, equals(1));
      expect(resBC['C']!.revocationsReceived, equals(1));
      expect(await nodeC.store.isRevoked(nodeC.memberPubkey), isTrue);
    });

    test('Scenario 5: Structured JSONL event trace export conforms to schema',
        () async {
      final nodeA = await harness.addNode('A');
      await harness.addNode('B');

      final env = await nodeA.publish(
          type: 'ping', body: {'hello': 'mesh'}, ttlSeconds: 10);
      expect(await nodeA.holdsAuthorSeq(nodeA.memberPubkey, 1), isTrue);

      await harness.syncPair('A', 'B');

      // Apply a server receipt and prune store on nodeA
      final receiptCore = ServerReceipt(
        groupId: harness.groupId,
        author: nodeA.memberPubkey,
        ranges: const [SeqRange(1, 1)],
        issuedAt: harness.clock.now().millisecondsSinceEpoch,
        serverSig: env.sig,
      );
      await nodeA.applyReceipt(receiptCore);
      await nodeA.pruneStore(retentionWindow: Duration.zero);

      final jsonl = harness.exportTraceJsonl();
      expect(jsonl, isNotEmpty);

      final parsedEvents = MeshHarness.parseTraceJsonl(jsonl);
      expect(parsedEvents.length, greaterThanOrEqualTo(7));

      final eventTypes = parsedEvents.map((e) => e.type.wireName).toSet();
      expect(
        eventTypes,
        containsAll([
          'published',
          'stored',
          'received',
          'session_start',
          'session_end',
          'receipt_applied',
          'evicted',
        ]),
      );
    });

    test('Scenario 6: Unified YAML Scenario execution on MeshHarness',
        () async {
      const yamlStr = '''
name: "In-Process Trail Relay"
duration_seconds: 120
seed: 99
group_id: "0102030405060708090a0b0c0d0e0f10"
nodes:
  - id: hiker_1
  - id: hiker_2
  - id: hiker_3
workload:
  - time_s: 5
    author: hiker_1
    type: sos
    priority: 0
    body:
      alert: "Sprained ankle"
contacts:
  - from: hiker_1
    to: hiker_2
    start_s: 10
    duration_s: 20
  - from: hiker_2
    to: hiker_3
    start_s: 40
    duration_s: 20
assertions:
  - delivered_to: [hiker_1, hiker_2, hiker_3]
''';
      final scenario = Scenario.fromYaml(yamlStr);
      final failures = await harness.runScenario(scenario);
      expect(failures, isEmpty);
    });

    test(
        'Scenario 7: BLE sync recommends Wi-Fi Aware upgrade and bulk sync transfers hash-addressed attachments',
        () async {
      final nodeA = await harness.addNode('A');
      final nodeB = await harness.addNode('B');

      final photoBytes =
          Uint8List.fromList(List.generate(4096, (i) => (i * 7) & 0xFF));
      final env = await nodeA.publish(
        type: 'bbs_post',
        body: {'text': 'Trail bridge damaged - see photo'},
        attachments: [(bytes: photoBytes, mime: 'image/jpeg')],
      );
      final attHash = env.core.attachments!.first.hash;
      expect(await nodeA.store.containsAttachmentBlob(attHash), isTrue);
      expect(await nodeB.store.containsAttachmentBlob(attHash), isFalse);

      // Step 1: Sync over BLE (transferAttachments: false)
      final bleRes =
          await harness.syncPair('A', 'B', transferAttachments: false);
      expect(bleRes['A']!.completedSuccessfully, isTrue);
      expect(bleRes['B']!.envelopesReceived, equals(1));
      expect(bleRes['B']!.attachmentsReceived, equals(0));
      // Both sides detect pending attachment bytes and recommend upgrading to Wi-Fi Aware
      expect(bleRes['A']!.upgradeRecommended, isTrue);
      expect(bleRes['B']!.upgradeRecommended, isTrue);
      expect(await nodeB.store.containsAttachmentBlob(attHash), isFalse);

      // Step 2: Upgrade session to Wi-Fi Aware (transferAttachments: true, MTU 1400)
      // Even though Node B already holds the envelope in its VersionVector, BLOB_WANT reconciles the missing blob!
      final awareRes = await harness.syncPair(
        'A',
        'B',
        transferAttachments: true,
        mtuOverride: 1400,
      );
      expect(awareRes['A']!.completedSuccessfully, isTrue);
      expect(awareRes['A']!.attachmentsSent, equals(1));
      expect(awareRes['B']!.attachmentsReceived, equals(1));
      expect(await nodeB.store.containsAttachmentBlob(attHash), isTrue);

      final transferredBlob = await nodeB.store.getAttachmentBlob(attHash);
      expect(transferredBlob!.bytes, equals(photoBytes));
    });
  });
}
