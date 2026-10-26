import 'dart:async';
import 'dart:typed_data';
import 'package:convert/convert.dart';
import 'package:cryptography/cryptography.dart' as cg;
import 'package:msgp2p_core/msgp2p_core.dart';
import 'event_queue.dart';
import 'link_profile.dart';
import 'metrics.dart';
import 'sim_server.dart';
import 'sim_transport.dart';

/// Top-level discrete-event simulator orchestrator (FR-TEST-02).
class Simulator {
  final Scenario scenario;
  final SimClock clock;
  final EventQueue eventQueue;
  final SimMedium medium;
  final RandomSource rng;
  final Map<String, LinkProfile> customProfiles;

  /// Optional live HTTP [GatewayClient] for end-to-end simulator <-> reference server testing.
  final GatewayClient? realGatewayClient;

  /// Optional server signing keypair (e.g. matching the PHP server's test vector seed).
  final cg.SimpleKeyPair? serverSigningKeyPair;

  /// Optional default group key (e.g. matching the PHP server's epoch 1 key).
  final Uint8List? defaultEpochKey;

  late final SimServer server;
  late final MeshHarness harness;
  final Map<String, MeshNode> simNodes = {};

  final Map<String, Envelope> _publishedMessages = {};
  final SimulationMetrics metrics;

  Simulator({
    required this.scenario,
    SimClock? clock,
    EventQueue? eventQueue,
    RandomSource? rng,
    this.customProfiles = const {},
    this.realGatewayClient,
    this.serverSigningKeyPair,
    this.defaultEpochKey,
  })  : clock = clock ?? SimClock(),
        eventQueue = eventQueue ?? EventQueue(),
        rng = rng ?? DeterministicRandomSource(scenario.seed),
        medium =
            SimMedium(rng: rng ?? DeterministicRandomSource(scenario.seed)),
        metrics =
            SimulationMetrics(totalWorkloadMessages: scenario.workload.length);

  /// Initializes the simulation environment and nodes.
  Future<void> initialize() async {
    server = await SimServer.create();

    harness = await MeshHarness.create(
      seed: scenario.seed,
      groupId: scenario.groupId,
      defaultEpochKey: defaultEpochKey,
      clock: clock,
      serverSigningKeyPair: serverSigningKeyPair,
    );

    // Create all scenario nodes
    final nodeSpecs = <String, ScenarioNode>{};
    for (final sNode in scenario.nodes) {
      nodeSpecs[sNode.id] = sNode;
      final profile = LinkProfile.byName(sNode.profile, customProfiles);
      final node = await harness.addNode(
        sNode.id,
        defaultMtu: profile.defaultMtu,
        storageQuotaBytes: sNode.storageQuotaBytes,
        clockSkewMs: sNode.clockSkewMs,
        dropAfterHandshake: sNode.flapping?.dropAfterHandshake ?? false,
      );
      simNodes[sNode.id] = node;
    }

    // If connected to a real GatewayClient, register each simulated node with the server
    if (realGatewayClient != null) {
      final groupIdHex = hex.encode(scenario.groupId);
      for (final node in simNodes.values) {
        final username = '${node.nodeId}_${scenario.seed}';
        const password = 'SimNodePassword2026!';
        try {
          await realGatewayClient!.register(
            username: username,
            password: password,
            groupId: groupIdHex,
            memberPubkey: node.memberPubkey,
            noisePubkey: node.noisePubkey,
          );
        } catch (_) {
          // Ignore if already registered in a shared test run
        }
        final loginRes = await realGatewayClient!.login(
          username: username,
          password: password,
        );
        // Save the server-issued certificate across all nodes so cert_ref is recognized
        for (final peer in simNodes.values) {
          await peer.store.saveCertificate(loginRes.membershipCert);
          await peer.store.saveCertificate(node.cert);
        }
      }
    }

    // Isolate by default (contacts dictate communication)
    harness.setTopology({});

    // Schedule contacts (start and end)
    for (final contact in scenario.contacts) {
      // At contact start: connect in medium and initiate sync
      eventQueue.schedule(contact.startMs, () async {
        final specA = nodeSpecs[contact.from];
        final specB = nodeSpecs[contact.to];

        // If contact requires Coded PHY (S=8) but either node is iOS / lacks Coded PHY, skip long-range link
        if (contact.profile == 'ble_coded_s8' &&
            ((specA != null && !specA.supportsCodedPhy) ||
                (specB != null && !specB.supportsCodedPhy))) {
          return;
        }

        harness.medium.setLink(contact.from, contact.to, true);
        final isDirectWifiAware = contact.profile == 'wifi_aware';
        final profile = LinkProfile.byName(contact.profile, customProfiles);

        final flapA = specA?.flapping;
        final flapB = specB?.flapping;
        final hasFlapping = flapA != null || flapB != null;

        // If either peer is configured as a flapping node and is currently in its off-duty window,
        // or cuts mid-contact before session completion, inject a byte-budget link cut.
        if (hasFlapping) {
          final onlineA = flapA == null || flapA.isOnlineAt(contact.startMs);
          final onlineB = flapB == null || flapB.isOnlineAt(contact.startMs);
          if (!onlineA || !onlineB) {
            // Cut mid-transfer after partial frame bytes
            harness.cutLink(
              nodeA: contact.from,
              nodeB: contact.to,
              afterBytes: 420 + (contact.startMs % 600),
            );
          }
        }

        final res = await harness.syncPair(
          contact.from,
          contact.to,
          transferAttachments: isDirectWifiAware,
          mtuOverride: profile.defaultMtu,
          enforceCooldown: hasFlapping,
        );
        final resA = res[contact.from];
        final resB = res[contact.to];

        if (resA != null) {
          metrics.totalBytesOnAir += resA.totalBytesSent > 0
              ? resA.totalBytesSent
              : (resA.envelopesSent * 350);
          metrics.duplicateEnvelopesReceived += resA.duplicateEnvelopesReceived;
          metrics.attachmentsTransferred += resA.attachmentsSent;
        }
        if (resB != null) {
          metrics.totalBytesOnAir += resB.totalBytesSent > 0
              ? resB.totalBytesSent
              : (resB.envelopesSent * 350);
          metrics.duplicateEnvelopesReceived += resB.duplicateEnvelopesReceived;
          metrics.attachmentsTransferred += resB.attachmentsSent;
        }

        // Check for automatic BLE -> Wi-Fi Aware session upgrade (v0.2)
        final shouldUpgrade = !isDirectWifiAware &&
            ((resA?.upgradeRecommended ?? false) ||
                (resB?.upgradeRecommended ?? false)) &&
            (specA?.supportsWifiAware ?? true) &&
            (specB?.supportsWifiAware ?? true);

        if (shouldUpgrade) {
          metrics.wifiAwareUpgrades++;
          final awareRes = await harness.syncPair(
            contact.from,
            contact.to,
            transferAttachments: true,
            mtuOverride: LinkProfile.wifiAware.defaultMtu,
          );
          final awareA = awareRes[contact.from];
          final awareB = awareRes[contact.to];
          if (awareA != null) {
            metrics.attachmentsTransferred += awareA.attachmentsSent;
            metrics.totalBytesOnAir += awareA.pendingUpgradeBytes;
          }
          if (awareB != null) {
            metrics.attachmentsTransferred += awareB.attachmentsSent;
            metrics.totalBytesOnAir += awareB.pendingUpgradeBytes;
          }
        }
      }, description: 'Contact start ${contact.from} <-> ${contact.to}');

      // At contact end: disconnect in medium
      eventQueue.schedule(contact.endMs, () async {
        harness.medium.setLink(contact.from, contact.to, false);
      }, description: 'Contact end ${contact.from} <-> ${contact.to}');
    }

    // Schedule workloads (message publishing)
    for (final work in scenario.workload) {
      eventQueue.schedule(work.timeMs, () async {
        final node = simNodes[work.author];
        if (node != null) {
          List<({Uint8List bytes, String mime})>? attachments;
          if (work.attachmentSizeBytes > 0) {
            attachments = [
              (
                bytes: rng.nextBytes(work.attachmentSizeBytes),
                mime: work.attachmentMime,
              ),
            ];
          }
          final env = await node.publish(
            type: work.type,
            body: work.body,
            priority: work.priority,
            attachments: attachments,
          );
          final idHex = hex.encode(env.messageId);
          _publishedMessages[idHex] = env;
        }
      }, description: 'Publish from ${work.author} (${work.type})');
    }

    // Schedule server gateways (upload to server and receive receipts)
    for (final gw in scenario.gateways) {
      eventQueue.schedule(gw.startMs, () async {
        final node = simNodes[gw.node];
        if (node != null) {
          final allEnvelopes = <Envelope>[];
          for (final env in _publishedMessages.values) {
            if (await node.holdsMessage(env.messageId)) {
              final confirmed =
                  await node.store.isConfirmed(env.core.author, env.core.seq);
              if (!confirmed) {
                allEnvelopes.add(env);
              }
            }
          }

          if (realGatewayClient != null) {
            final syncRes = await realGatewayClient!.sync(
              store: node.store,
              groupId: scenario.groupId,
              pendingEnvelopes: allEnvelopes,
            );
            if (syncRes.receiptsCount > 0) {
              harness.recordEvent(MeshTraceEvent(
                timestamp: clock.currentTimeMs,
                nodeId: node.nodeId,
                type: MeshEventType.receiptApplied,
                metadata: {
                  'count': syncRes.receiptsCount,
                  'source': 'REAL_SERVER'
                },
              ));
            }
          }

          for (final env in allEnvelopes) {
            harness.recordEvent(MeshTraceEvent(
              timestamp: clock.currentTimeMs,
              nodeId: node.nodeId,
              type: MeshEventType.serverPush,
              messageId: hex.encode(env.messageId),
              bytes: env.toCanonicalCbor().length,
            ));
          }

          final receipts = await server.pushEnvelopesBatch(
              allEnvelopes, clock.currentTimeMs);
          for (final receipt in [...server.issuedReceipts, ...receipts]) {
            await node.applyReceipt(receipt);
          }

          // Also pull any envelopes already on SimServer that the gateway doesn't hold yet
          for (final env in _publishedMessages.values) {
            final onServer = await server.store.containsEnvelope(env.messageId);
            if (onServer && !await node.holdsMessage(env.messageId)) {
              final saved = await node.store
                  .saveEnvelope(env, customStoredAt: clock.currentTimeMs);
              if (saved) {
                harness.recordEvent(MeshTraceEvent(
                  timestamp: clock.currentTimeMs,
                  nodeId: node.nodeId,
                  type: MeshEventType.serverPull,
                  messageId: hex.encode(env.messageId),
                  bytes: env.toCanonicalCbor().length,
                ));
              }
            }
          }
        }
      }, description: 'Gateway sync for node ${gw.node}');
    }
  }

  /// Runs the simulation until completion.
  Future<SimulationMetrics> run() async {
    await eventQueue.runUntil(scenario.durationMs);

    // Evaluate deliveries across nodes
    var idealBytes = 0;
    for (final entry in _publishedMessages.entries) {
      final idHex = entry.key;
      final env = entry.value;
      final envByteLen = env.toCanonicalCbor().length;
      var deliveredCount = 0;

      for (final sNode in scenario.nodes) {
        final node = simNodes[sNode.id];
        if (node != null && await node.holdsMessage(env.messageId)) {
          deliveredCount++;
        }
      }
      metrics.deliveriesByMessage[idHex] = deliveredCount;
      if (deliveredCount > 1) {
        idealBytes += (deliveredCount - 1) * envByteLen;
      }
    }
    metrics.idealPayloadBytes = idealBytes;

    final analyzer = ChurnTraceAnalyzer(harness.traces);
    metrics.maxDuplicatesPerNodeEnvelope =
        analyzer.maxDuplicatesPerNodeEnvelope();
    metrics.maxServerPushesPerEnvelope = analyzer.maxServerPushesPerEnvelope();
    metrics.maxConnectAttemptsPerMinute =
        analyzer.maxConnectAttemptsPerMinute();

    // Evaluate scenario assertions
    for (var i = 0; i < scenario.assertions.length; i++) {
      final assertion = scenario.assertions[i];
      for (final env in _publishedMessages.values) {
        if (assertion.deliveredTo.isNotEmpty) {
          for (final targetId in assertion.deliveredTo) {
            final targetNode = simNodes[targetId];
            final held = targetNode != null &&
                await targetNode.holdsMessage(env.messageId);
            if (!held) {
              metrics.assertionFailures.add(
                'Assertion #${i + 1} failed: Message ${hex.encode(env.messageId)} was not delivered to $targetId',
              );
            }
          }
        }
        if (assertion.attachmentsDeliveredTo.isNotEmpty &&
            env.core.attachments != null &&
            env.core.attachments!.isNotEmpty) {
          for (final targetId in assertion.attachmentsDeliveredTo) {
            final targetNode = simNodes[targetId];
            for (final att in env.core.attachments!) {
              final heldBlob = targetNode != null &&
                  await targetNode.store.containsAttachmentBlob(att.hash);
              if (!heldBlob) {
                metrics.assertionFailures.add(
                  'Assertion #${i + 1} failed: Attachment ${hex.encode(att.hash)} was not delivered to $targetId',
                );
              }
            }
          }
        }
      }
    }

    return metrics;
  }

  /// Exports structured event traces collected by the harness as JSON Lines.
  String exportTraceJsonl() => harness.exportTraceJsonl();

  /// Disposes all allocated nodes and resources.
  Future<void> dispose() async {
    await harness.dispose();
  }
}
