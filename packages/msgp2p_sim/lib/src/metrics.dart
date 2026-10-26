import 'dart:convert';

/// Performance & convergence metrics collected during simulation (NFR-REL-02, NFR-PERF-01).
class SimulationMetrics {
  final int totalWorkloadMessages;
  final Map<String, int> deliveriesByMessage = {};
  final Map<String, int> deliveryLatencyMs = {};
  int totalBytesOnAir = 0;
  int idealPayloadBytes = 0;
  int duplicateEnvelopesReceived = 0;
  int maxDuplicatesPerNodeEnvelope = 0;
  int maxServerPushesPerEnvelope = 0;
  int maxConnectAttemptsPerMinute = 0;
  int wifiAwareUpgrades = 0;
  int attachmentsTransferred = 0;
  final List<String> assertionFailures = [];

  SimulationMetrics({required this.totalWorkloadMessages});

  double get amplificationRatio =>
      idealPayloadBytes <= 0 ? 1.0 : totalBytesOnAir / idealPayloadBytes;

  double get deliveryRatio => totalWorkloadMessages == 0
      ? 1.0
      : deliveriesByMessage.values.where((count) => count > 0).length /
          totalWorkloadMessages;

  Map<String, dynamic> toJson() => {
        'total_messages': totalWorkloadMessages,
        'overall_delivery_ratio': deliveryRatio,
        'total_bytes_on_air': totalBytesOnAir,
        'duplicates_received': duplicateEnvelopesReceived,
        'wifi_aware_upgrades': wifiAwareUpgrades,
        'attachments_transferred': attachmentsTransferred,
        'deliveries_by_message': deliveriesByMessage,
        'failures': assertionFailures,
      };

  String toJsonString() => const JsonEncoder.withIndent('  ').convert(toJson());
}
