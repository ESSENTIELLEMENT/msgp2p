import 'dart:typed_data';
import 'package:convert/convert.dart';
import 'package:yaml/yaml.dart';

class FlappingConfig {
  final int periodMs;
  final double dutyCycle;
  final int jitterMs;
  final bool dropAfterHandshake;

  const FlappingConfig({
    this.periodMs = 6000,
    this.dutyCycle = 0.35,
    this.jitterMs = 500,
    this.dropAfterHandshake = false,
  });

  bool isOnlineAt(int timeMs, {int phaseOffsetMs = 0}) {
    final t = (timeMs + phaseOffsetMs) % periodMs;
    return t < (periodMs * dutyCycle).round();
  }
}

class ScenarioNode {
  final String id;
  final String profile;
  final String platform;
  final bool supportsCodedPhy;
  final bool supportsWifiAware;
  final FlappingConfig? flapping;
  final int clockSkewMs;
  final int? storageQuotaBytes;

  ScenarioNode({
    required this.id,
    this.profile = 'ble_1m',
    this.platform = 'android',
    bool? supportsCodedPhy,
    this.supportsWifiAware = true,
    this.flapping,
    this.clockSkewMs = 0,
    this.storageQuotaBytes,
  }) : supportsCodedPhy =
            supportsCodedPhy ?? (platform.toLowerCase() == 'android');
}

class ScenarioContact {
  final String from;
  final String to;
  final int startMs;
  final int durationMs;
  final String profile;

  int get endMs => startMs + durationMs;

  ScenarioContact({
    required this.from,
    required this.to,
    required this.startMs,
    required this.durationMs,
    this.profile = 'ble_1m',
  });
}

class ScenarioWorkload {
  final int timeMs;
  final String author;
  final String type;
  final int priority;
  final Map<String, dynamic> body;
  final int attachmentSizeBytes;
  final String attachmentMime;

  ScenarioWorkload({
    required this.timeMs,
    required this.author,
    required this.type,
    this.priority = 2,
    required this.body,
    this.attachmentSizeBytes = 0,
    this.attachmentMime = 'image/jpeg',
  });
}

class ScenarioGateway {
  final String node;
  final int startMs;
  final int durationMs;

  ScenarioGateway({
    required this.node,
    required this.startMs,
    required this.durationMs,
  });
}

class ScenarioAssertion {
  final String? messageFrom;
  final List<String> deliveredTo;
  final List<String> attachmentsDeliveredTo;
  final double minDeliveryRatio;
  final double maxDuplicatesRatio;

  ScenarioAssertion({
    this.messageFrom,
    this.deliveredTo = const [],
    this.attachmentsDeliveredTo = const [],
    this.minDeliveryRatio = 1.0,
    this.maxDuplicatesRatio = 0.0,
  });
}

/// Unified YAML Scenario definition shared across in-process MeshHarness,
/// discrete-event simulator (`msgp2p_sim`), and emulator test runners (FR-TEST-08).
class Scenario {
  final String name;
  final int durationMs;
  final int seed;
  final Uint8List groupId;
  final List<ScenarioNode> nodes;
  final List<ScenarioContact> contacts;
  final List<ScenarioWorkload> workload;
  final List<ScenarioGateway> gateways;
  final List<ScenarioAssertion> assertions;

  Scenario({
    required this.name,
    required this.durationMs,
    this.seed = 42,
    required this.groupId,
    required this.nodes,
    required this.contacts,
    required this.workload,
    this.gateways = const [],
    this.assertions = const [],
  });

  static Scenario fromYaml(String yamlString) {
    final doc = loadYaml(yamlString) as YamlMap;
    final name = doc['name']?.toString() ?? 'Unnamed Scenario';
    final durationSec = (doc['duration_seconds'] as num?)?.toInt() ?? 3600;
    final seed = (doc['seed'] as num?)?.toInt() ?? 42;

    final rawGid =
        doc['group_id']?.toString() ?? '0102030405060708090a0b0c0d0e0f10';
    final groupId = Uint8List.fromList(hex.decode(rawGid.replaceAll('-', '')));

    final rawNodes = doc['nodes'] as YamlList? ?? YamlList();
    final nodes = rawNodes.map((n) {
      if (n is YamlMap) {
        final platform = n['platform']?.toString() ?? 'android';
        FlappingConfig? flapping;
        final rawFlap = n['flapping'];
        if (rawFlap is YamlMap) {
          flapping = FlappingConfig(
            periodMs: (rawFlap['period_ms'] as num?)?.toInt() ?? 6000,
            dutyCycle: (rawFlap['duty_cycle'] as num?)?.toDouble() ?? 0.35,
            jitterMs: (rawFlap['jitter_ms'] as num?)?.toInt() ?? 500,
            dropAfterHandshake:
                (rawFlap['drop_after_handshake'] as bool?) ?? false,
          );
        }
        return ScenarioNode(
          id: n['id'].toString(),
          profile: n['profile']?.toString() ??
              (platform == 'ios' ? 'ios_ble' : 'ble_1m'),
          platform: platform,
          supportsCodedPhy: n['supports_coded_phy'] as bool?,
          supportsWifiAware: (n['supports_wifi_aware'] as bool?) ?? true,
          flapping: flapping,
          clockSkewMs: (n['clock_skew_ms'] as num?)?.toInt() ?? 0,
          storageQuotaBytes: (n['storage_quota_bytes'] as num?)?.toInt(),
        );
      }
      return ScenarioNode(id: n.toString());
    }).toList();

    final rawContacts = doc['contacts'] as YamlList? ?? YamlList();
    final contacts = rawContacts.map((c) {
      final map = c as YamlMap;
      final startS = (map['start_s'] as num?)?.toInt() ?? 0;
      final durS = (map['duration_s'] as num?)?.toInt() ?? 60;
      return ScenarioContact(
        from: map['from'].toString(),
        to: map['to'].toString(),
        startMs: startS * 1000,
        durationMs: durS * 1000,
        profile: map['profile']?.toString() ?? 'ble_1m',
      );
    }).toList();

    final rawWorkload = doc['workload'] as YamlList? ?? YamlList();
    final workload = rawWorkload.map((w) {
      final map = w as YamlMap;
      final timeS = (map['time_s'] as num?)?.toInt() ?? 0;
      final rawBody = map['body'];
      final body = (rawBody is YamlMap)
          ? rawBody.cast<String, dynamic>()
          : {'text': rawBody?.toString() ?? ''};

      return ScenarioWorkload(
        timeMs: timeS * 1000,
        author: map['author'].toString(),
        type: map['type']?.toString() ?? 'message',
        priority: (map['priority'] as num?)?.toInt() ?? 2,
        body: body,
        attachmentSizeBytes:
            (map['attachment_size_bytes'] as num?)?.toInt() ?? 0,
        attachmentMime: map['attachment_mime']?.toString() ?? 'image/jpeg',
      );
    }).toList();

    final rawGateways = doc['gateways'] as YamlList? ?? YamlList();
    final gateways = rawGateways.map((g) {
      final map = g as YamlMap;
      final startS = (map['start_s'] as num?)?.toInt() ?? 0;
      final durS = (map['duration_s'] as num?)?.toInt() ?? 300;
      return ScenarioGateway(
        node: map['node'].toString(),
        startMs: startS * 1000,
        durationMs: durS * 1000,
      );
    }).toList();

    final rawAssertions = doc['assertions'] as YamlList? ?? YamlList();
    final assertions = rawAssertions.map((a) {
      final map = a as YamlMap;
      final deliveredToList = (map['delivered_to'] as YamlList?)
              ?.map((e) => e.toString())
              .toList() ??
          <String>[];
      final attDeliveredToList = (map['attachments_delivered_to'] as YamlList?)
              ?.map((e) => e.toString())
              .toList() ??
          <String>[];
      return ScenarioAssertion(
        messageFrom: map['message_from']?.toString(),
        deliveredTo: deliveredToList,
        attachmentsDeliveredTo: attDeliveredToList,
        minDeliveryRatio:
            (map['min_delivery_ratio'] as num?)?.toDouble() ?? 1.0,
        maxDuplicatesRatio:
            (map['max_duplicates_ratio'] as num?)?.toDouble() ?? 0.0,
      );
    }).toList();

    return Scenario(
      name: name,
      durationMs: durationSec * 1000,
      seed: seed,
      groupId: groupId,
      nodes: nodes,
      contacts: contacts,
      workload: workload,
      gateways: gateways,
      assertions: assertions,
    );
  }
}
