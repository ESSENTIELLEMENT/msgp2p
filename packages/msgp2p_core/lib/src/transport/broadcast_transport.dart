import 'dart:async';
import 'dart:typed_data';
import 'package:meta/meta.dart';
import 'transport.dart';

/// A raw radio packet received over an unacknowledged broadcast medium (e.g. LoRa / Meshtastic).
@immutable
class BroadcastPacket {
  /// The raw packet bytes (payload).
  final Uint8List payload;

  /// Received Signal Strength Indicator in dBm (if available).
  final int? rssi;

  /// Signal-to-Noise Ratio in dB (characteristic of LoRa demodulation).
  final double? snr;

  /// Source hardware or node address (if available).
  final String? sourceAddress;

  const BroadcastPacket({
    required this.payload,
    this.rssi,
    this.snr,
    this.sourceAddress,
  });
}

/// Abstract radio transport supporting unacknowledged broadcast transmissions.
abstract interface class BroadcastTransport implements P2PTransport {
  /// Broadcasts a discrete raw packet over the physical radio medium to all nearby nodes.
  ///
  /// Throws [ArgumentError] if [packet].length exceeds [capabilities.defaultMtu].
  Future<void> sendBroadcast(Uint8List packet);

  /// Stream of unacknowledged broadcast packets received over the air.
  Stream<BroadcastPacket> get broadcastRx;
}
