import 'package:yaml/yaml.dart';

/// Calibrated radio link profile (FR-TEST-02, FR-TEST-06).
class LinkProfile {
  final String name;
  final int defaultMtu;
  final int throughputBps;
  final int transitLatencyMs;
  final int setupLatencyMs;
  final double packetLossRate;
  final double maxRangeMeters;

  const LinkProfile({
    required this.name,
    required this.defaultMtu,
    required this.throughputBps,
    required this.transitLatencyMs,
    required this.setupLatencyMs,
    required this.packetLossRate,
    required this.maxRangeMeters,
  });

  /// Factory preset for standard Bluetooth LE 1M PHY (v1.0 field-calibrated open LOS).
  static const LinkProfile ble1M = LinkProfile(
    name: 'ble_1m',
    defaultMtu: 512,
    throughputBps: 64200,
    transitLatencyMs: 36,
    setupLatencyMs: 1380,
    packetLossRate: 0.008,
    maxRangeMeters: 38.0,
  );

  /// Factory preset for Bluetooth LE 1M PHY in dense forest / trail switchback.
  static const LinkProfile ble1MForest = LinkProfile(
    name: 'ble_1m_forest',
    defaultMtu: 512,
    throughputBps: 48500,
    transitLatencyMs: 48,
    setupLatencyMs: 1650,
    packetLossRate: 0.018,
    maxRangeMeters: 22.0,
  );

  /// Factory preset for Bluetooth LE Coded PHY (S=8 long range, v1.0 field-calibrated open LOS).
  static const LinkProfile bleCodedS8 = LinkProfile(
    name: 'ble_coded_s8',
    defaultMtu: 256,
    throughputBps: 11800,
    transitLatencyMs: 115,
    setupLatencyMs: 2640,
    packetLossRate: 0.004,
    maxRangeMeters: 185.0,
  );

  /// Factory preset for Bluetooth LE Coded PHY (S=8) in dense forest.
  static const LinkProfile bleCodedS8Forest = LinkProfile(
    name: 'ble_coded_s8_forest',
    defaultMtu: 256,
    throughputBps: 9400,
    transitLatencyMs: 135,
    setupLatencyMs: 2890,
    packetLossRate: 0.009,
    maxRangeMeters: 110.0,
  );

  /// Factory preset for iOS CoreBluetooth (1M PHY, 185-byte GATT MTU / 512-byte L2CAP).
  static const LinkProfile iosBle = LinkProfile(
    name: 'ios_ble',
    defaultMtu: 185,
    throughputBps: 47800,
    transitLatencyMs: 42,
    setupLatencyMs: 1520,
    packetLossRate: 0.009,
    maxRangeMeters: 28.0,
  );

  /// Factory preset for Wi-Fi Aware high-throughput bulk sessions.
  static const LinkProfile wifiAware = LinkProfile(
    name: 'wifi_aware',
    defaultMtu: 1400,
    throughputBps: 2680000,
    transitLatencyMs: 14,
    setupLatencyMs: 740,
    packetLossRate: 0.001,
    maxRangeMeters: 52.0,
  );

  /// Looks up a profile by name from defaults or custom profiles.
  static LinkProfile byName(String name, [Map<String, LinkProfile>? custom]) {
    if (custom != null && custom.containsKey(name)) {
      return custom[name]!;
    }
    switch (name.toLowerCase()) {
      case 'ble_1m_forest':
        return ble1MForest;
      case 'ble_coded_s8_forest':
        return bleCodedS8Forest;
      case 'ble_coded_s8':
      case 'coded':
        return bleCodedS8;
      case 'ios_ble':
      case 'ios':
        return iosBle;
      case 'wifi_aware':
      case 'wifiaware':
        return wifiAware;
      case 'ble_1m':
      case 'ble':
      default:
        return ble1M;
    }
  }

  /// Parses YAML document into a map of link profiles.
  static Map<String, LinkProfile> parseYaml(String yamlString) {
    final doc = loadYaml(yamlString) as YamlMap;
    final map = <String, LinkProfile>{};
    for (final entry in doc.entries) {
      final key = entry.key.toString();
      final val = entry.value as YamlMap;
      map[key] = LinkProfile(
        name: val['name']?.toString() ?? key,
        defaultMtu: (val['default_mtu'] as num?)?.toInt() ?? 512,
        throughputBps: (val['throughput_bps'] as num?)?.toInt() ?? 60000,
        transitLatencyMs: (val['transit_latency_ms'] as num?)?.toInt() ?? 40,
        setupLatencyMs: (val['setup_latency_ms'] as num?)?.toInt() ?? 1500,
        packetLossRate: (val['packet_loss_rate'] as num?)?.toDouble() ?? 0.01,
        maxRangeMeters: (val['max_range_meters'] as num?)?.toDouble() ?? 30.0,
      );
    }
    return map;
  }
}
