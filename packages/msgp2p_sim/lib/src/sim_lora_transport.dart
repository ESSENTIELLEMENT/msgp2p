import 'dart:async';
import 'dart:typed_data';
import 'package:msgp2p_core/msgp2p_core.dart';
import 'link_profile.dart';
import 'sim_transport.dart';

/// Simulated physical LoRa transport implementing [BroadcastTransport] (e.g. SX1262 / Meshtastic).
class SimLoRaTransport extends SimTransport implements BroadcastTransport {
  final StreamController<BroadcastPacket> _broadcastRxController =
      StreamController<BroadcastPacket>.broadcast();
  final RandomSource _randomSource;

  SimLoRaTransport({
    required super.nodeAddress,
    required super.medium,
    super.profile = LinkProfile.loraSf7,
    RandomSource? randomSource,
  })  : _randomSource = randomSource ?? medium.rng,
        super(
          capabilities: TransportCapabilities(
            transportName: 'SimLoRa',
            defaultMtu: profile.defaultMtu,
            maxConnections: 1,
            supportsBulk: false,
            recommendedFrameTimeout: const Duration(seconds: 45),
            isBroadcastMedium: true,
          ),
        );

  @override
  Stream<BroadcastPacket> get broadcastRx => _broadcastRxController.stream;

  @override
  Future<void> sendBroadcast(Uint8List packet) async {
    if (packet.length > capabilities.defaultMtu) {
      throw ArgumentError(
          'Broadcast packet size ${packet.length} B exceeds MTU ${capabilities.defaultMtu} B');
    }

    // Packet loss calculation based on link profile
    final lossRoll = _randomSource.nextBytes(1)[0] / 256.0;
    if (lossRoll < profile.packetLossRate) {
      // Packet dropped over air
      return;
    }

    // Calculate airtime latency based on profile throughput
    final airtimeMs =
        (packet.length * 8 * 1000 / profile.throughputBps).ceil() +
            profile.transitLatencyMs;

    final eq = medium.eventQueue;
    if (eq != null) {
      final scheduledTime = eq.clock.currentTimeMs + airtimeMs;
      eq.schedule(
        scheduledTime,
        () async {
          medium.broadcastPacket(
            sourceAddress: nodeAddress,
            packet: packet,
          );
        },
        description:
            'LoRa Broadcast from $nodeAddress (${packet.length} bytes, airtime ${airtimeMs}ms)',
      );
    } else {
      medium.broadcastPacket(
        sourceAddress: nodeAddress,
        packet: packet,
      );
    }
  }

  @override
  void onIncomingBroadcast(BroadcastPacket packet) {
    if (!_broadcastRxController.isClosed) {
      _broadcastRxController.add(packet);
    }
  }

  @override
  Future<void> stop() async {
    await super.stop();
  }

  @override
  Future<void> dispose() async {
    await super.dispose();
    await _broadcastRxController.close();
  }
}
