import 'dart:async';
import 'dart:typed_data';
import 'package:meta/meta.dart';

/// Capabilities and limits of a specific [P2PTransport] radio.
@immutable
class TransportCapabilities {
  final String transportName;
  final int defaultMtu;
  final int maxConnections;
  final bool supportsBulk;

  const TransportCapabilities({
    required this.transportName,
    required this.defaultMtu,
    this.maxConnections = 4,
    this.supportsBulk = false,
  });
}

/// Scanning policy configuration.
@immutable
class ScanPolicy {
  final Duration interval;
  final Duration window;
  final bool aggressive;

  const ScanPolicy({
    this.interval = const Duration(seconds: 5),
    this.window = const Duration(seconds: 1),
    this.aggressive = false,
  });
}

/// Advertisement discovered from a nearby peer.
@immutable
class PeerAdvert {
  /// The 16-byte rotating anonymous beacon token (?5).
  final Uint8List token;

  /// Signal strength in dBm.
  final int rssi;

  /// Unique address or handle for connecting to this peer.
  final String peerAddress;

  /// Additional transport-specific metadata hints.
  final Map<String, dynamic> hints;

  const PeerAdvert({
    required this.token,
    required this.rssi,
    required this.peerAddress,
    this.hints = const {},
  });
}

/// Events emitted during the lifecycle of an active [PeerLink].
sealed class LinkEvent {
  const LinkEvent();
}

/// Emitted when the link is closed by either peer or a radio drop.
class LinkClosed extends LinkEvent {
  final String? reason;
  const LinkClosed([this.reason]);
}

/// Emitted when signal strength changes on an active link.
class RssiChanged extends LinkEvent {
  final int rssi;
  const RssiChanged(this.rssi);
}

/// Emitted when radio PHY changes (e.g. 1M -> Coded PHY on Android BLE).
class PhyChanged extends LinkEvent {
  final String phy;
  const PhyChanged(this.phy);
}

/// Bidirectional communication pipe between two connected peers.
abstract interface class PeerLink {
  /// Maximum packet payload size in bytes supported by this link.
  int get mtu;

  /// Stream of raw incoming byte chunks.
  Stream<Uint8List> get rx;

  /// Transmits a raw chunk of bytes across the link.
  /// Throws [ArgumentError] if [chunk].length > [mtu].
  Future<void> send(Uint8List chunk);

  /// Closes the connection cleanly.
  Future<void> close([String? reason]);

  /// True if this link is closed.
  bool get isClosed;

  /// Diagnostic and lifecycle events for this connection.
  Stream<LinkEvent> get events;
}

/// Abstract radio transport interface per architecture.md ?5.1 and FR-SDK-03.
abstract interface class P2PTransport {
  /// Radio capabilities (MTU, bulk support, max connections).
  TransportCapabilities get capabilities;

  /// Stream of nearby peer advertisements detected by scanning.
  Stream<PeerAdvert> get discovered;

  /// Starts broadcasting an anonymous rotating beacon token.
  Future<void> startAdvertising(Uint8List token);

  /// Stops broadcasting advertisement beacons.
  Future<void> stopAdvertising();

  /// Starts scanning for nearby peer advertisements.
  Future<void> startScanning([ScanPolicy policy = const ScanPolicy()]);

  /// Stops scanning for peer advertisements.
  Future<void> stopScanning();

  /// Stops both advertising and scanning, terminating all active operations.
  Future<void> stop();

  /// Establishes a point-to-point connection to a discovered peer.
  Future<PeerLink> connect(PeerAdvert peer);

  /// Stream of incoming connection requests accepted by this transport.
  Stream<PeerLink> get incoming;
}
