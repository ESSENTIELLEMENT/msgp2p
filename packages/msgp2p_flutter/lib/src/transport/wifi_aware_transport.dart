import 'dart:async';
import 'dart:typed_data';
import 'package:msgp2p_core/msgp2p_core.dart';
import '../platform/wifi_aware_radio_bridge.dart';

/// Concrete [PeerLink] representing an active Wi-Fi Aware (NAN) high-throughput data path.
class WifiAwarePeerLink implements PeerLink {
  final String peerAddress;

  @override
  final int mtu;

  final WifiAwareRadioBridge _bridge;
  final void Function() _onClosed;

  final StreamController<Uint8List> _rxController =
      StreamController<Uint8List>.broadcast();
  final StreamController<LinkEvent> _eventsController =
      StreamController<LinkEvent>.broadcast();

  bool _isClosed = false;

  WifiAwarePeerLink({
    required this.peerAddress,
    required this.mtu,
    required WifiAwareRadioBridge bridge,
    required void Function() onClosed,
  })  : _bridge = bridge,
        _onClosed = onClosed;

  @override
  bool get isClosed => _isClosed;

  @override
  Stream<Uint8List> get rx => _rxController.stream;

  @override
  Stream<LinkEvent> get events => _eventsController.stream;

  @override
  Future<void> send(Uint8List chunk) async {
    if (_isClosed) {
      throw StateError(
          'Cannot send on closed WifiAwarePeerLink ($peerAddress)');
    }
    if (chunk.length > mtu) {
      throw ArgumentError(
          'Chunk length (${chunk.length}) exceeds link MTU ($mtu)');
    }
    await _bridge.sendChunk(peerAddress, chunk);
  }

  void handleIncomingChunk(Uint8List bytes) {
    if (!_isClosed && !_rxController.isClosed) {
      _rxController.add(bytes);
    }
  }

  void handleRemoteClose(String reason) {
    if (_isClosed) return;
    _isClosed = true;
    _onClosed();
    if (!_eventsController.isClosed) {
      _eventsController.add(LinkClosed(reason));
      _eventsController.close();
    }
    if (!_rxController.isClosed) {
      _rxController.close();
    }
  }

  @override
  Future<void> close([String? reason]) async {
    if (_isClosed) return;
    _isClosed = true;
    _onClosed();
    await _bridge.disconnectPeer(peerAddress);
    if (!_eventsController.isClosed) {
      _eventsController.add(LinkClosed(reason ?? 'local_close'));
      await _eventsController.close();
    }
    if (!_rxController.isClosed) {
      await _rxController.close();
    }
  }
}

/// High-throughput Wi-Fi Aware (Neighbor Awareness Networking) implementation of [P2PTransport]
/// for Android 8+ (`WifiAwareManager`) and iOS 26+ (`WiFiAware` framework, iPhone 12+) (`v0.2`).
class WifiAwareTransport implements P2PTransport {
  final WifiAwareRadioBridge bridge;
  final String serviceId;

  @override
  final TransportCapabilities capabilities;

  final StreamController<PeerAdvert> _discoveredController =
      StreamController<PeerAdvert>.broadcast();
  final StreamController<PeerLink> _incomingController =
      StreamController<PeerLink>.broadcast();

  final Map<String, WifiAwarePeerLink> _openLinks = {};
  StreamSubscription<WifiAwareRadioEvent>? _bridgeSub;

  bool _isPublishing = false;
  bool _isSubscribing = false;

  WifiAwareTransport({
    WifiAwareRadioBridge? bridge,
    this.serviceId = 'msgp2p_bulk',
    this.capabilities = const TransportCapabilities(
      transportName: 'wifi_aware',
      defaultMtu: 1400,
      maxConnections: 4,
      supportsBulk: true,
    ),
  }) : bridge = bridge ?? MethodChannelWifiAwareRadioBridge() {
    _bridgeSub = this.bridge.events.listen(_onRadioEvent);
  }

  bool get isPublishing => _isPublishing;
  bool get isSubscribing => _isSubscribing;
  Map<String, WifiAwarePeerLink> get activeLinks =>
      Map.unmodifiable(_openLinks);

  void _onRadioEvent(WifiAwareRadioEvent event) {
    switch (event) {
      case WifiAwarePeerDiscoveredEvent():
        if (!_isSubscribing) return;
        if (!_discoveredController.isClosed) {
          _discoveredController.add(PeerAdvert(
            peerAddress: event.peerHandle,
            token: event.token,
            rssi: event.rssi,
            hints: {
              'transport': 'wifi_aware',
              'service_id': event.serviceId,
            },
          ));
        }

      case WifiAwareConnectedEvent():
        if (event.isIncoming) {
          final link = WifiAwarePeerLink(
            peerAddress: event.peerHandle,
            mtu: event.mtu,
            bridge: bridge,
            onClosed: () => _openLinks.remove(event.peerHandle),
          );
          _openLinks[event.peerHandle] = link;
          if (!_incomingController.isClosed) {
            _incomingController.add(link);
          }
        }

      case WifiAwareChunkReceivedEvent():
        _openLinks[event.peerHandle]?.handleIncomingChunk(event.bytes);

      case WifiAwareDisconnectedEvent():
        _openLinks.remove(event.peerHandle)?.handleRemoteClose(event.reason);
    }
  }

  @override
  Stream<PeerAdvert> get discovered => _discoveredController.stream;

  @override
  Stream<PeerLink> get incoming => _incomingController.stream;

  @override
  Future<void> startAdvertising(Uint8List token) async {
    _isPublishing = true;
    await bridge.publishService(token, serviceId: serviceId);
  }

  @override
  Future<void> stopAdvertising() async {
    _isPublishing = false;
    await bridge.stopPublishing();
  }

  @override
  Future<void> startScanning([ScanPolicy policy = const ScanPolicy()]) async {
    _isSubscribing = true;
    await bridge.subscribeService(serviceId: serviceId);
  }

  @override
  Future<void> stopScanning() async {
    _isSubscribing = false;
    await bridge.stopSubscribing();
  }

  @override
  Future<PeerLink> connect(PeerAdvert peer) async {
    if (_openLinks.length >= capabilities.maxConnections) {
      throw StateError(
          'Max connections (${capabilities.maxConnections}) reached on WifiAwareTransport');
    }

    final mtu = await bridge.connectPeer(peer.peerAddress);
    final link = WifiAwarePeerLink(
      peerAddress: peer.peerAddress,
      mtu: mtu,
      bridge: bridge,
      onClosed: () => _openLinks.remove(peer.peerAddress),
    );
    _openLinks[peer.peerAddress] = link;
    return link;
  }

  /// Tears down all active Wi-Fi Aware data paths and publish/subscribe sessions immediately
  /// after a bulk transfer completes to preserve battery.
  Future<void> teardownAfterTransfer() async {
    _isPublishing = false;
    _isSubscribing = false;
    for (final link in _openLinks.values.toList()) {
      await link.close('transfer_completed_teardown');
    }
    _openLinks.clear();
    await bridge.teardownAll();
  }

  @override
  Future<void> stop() async {
    await teardownAfterTransfer();
  }

  Future<void> dispose() async {
    await stop();
    await _bridgeSub?.cancel();
    await _discoveredController.close();
    await _incomingController.close();
    await bridge.dispose();
  }
}
