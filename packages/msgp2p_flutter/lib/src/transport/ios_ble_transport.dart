import 'dart:async';
import 'dart:typed_data';
import 'package:msgp2p_core/msgp2p_core.dart';
import '../platform/ble_radio_bridge.dart';

/// Concrete [PeerLink] representing an active iOS CoreBluetooth connection (L2CAP CoC or GATT).
class IosBlePeerLink implements PeerLink {
  final String peerAddress;

  @override
  final int mtu;

  final BleRadioBridge _bridge;
  final void Function() _onClosed;

  final StreamController<Uint8List> _rxController =
      StreamController<Uint8List>.broadcast();
  final StreamController<LinkEvent> _eventsController =
      StreamController<LinkEvent>.broadcast();

  bool _isClosed = false;

  IosBlePeerLink({
    required this.peerAddress,
    required this.mtu,
    required BleRadioBridge bridge,
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
      throw StateError('Cannot send on closed IosBlePeerLink ($peerAddress)');
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

  void handleRssiUpdate(int rssi) {
    if (!_isClosed && !_eventsController.isClosed) {
      _eventsController.add(RssiChanged(rssi));
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
    await _bridge.disconnect(peerAddress);
    if (!_eventsController.isClosed) {
      _eventsController.add(LinkClosed(reason ?? 'local_close'));
      await _eventsController.close();
    }
    if (!_rxController.isClosed) {
      await _rxController.close();
    }
  }
}

/// iOS CoreBluetooth implementation of [P2PTransport] supporting Central/Peripheral roles,
/// L2CAP CoC / GATT fallback, foreground participation, and best-effort background state restoration (`v0.2`).
class IosBleTransport implements P2PTransport {
  final BleRadioBridge bridge;

  @override
  final TransportCapabilities capabilities;

  final StreamController<PeerAdvert> _discoveredController =
      StreamController<PeerAdvert>.broadcast();
  final StreamController<PeerLink> _incomingController =
      StreamController<PeerLink>.broadcast();

  final Map<String, IosBlePeerLink> _openLinks = {};
  final Map<String, int> _discoveredPsmByAddress = {};
  StreamSubscription<BleRadioEvent>? _bridgeSub;

  bool _isAdvertising = false;
  bool _isScanning = false;
  bool _isInBackground = false;

  IosBleTransport({
    BleRadioBridge? bridge,
    this.capabilities = const TransportCapabilities(
      transportName: 'ios_ble',
      defaultMtu: 185,
      maxConnections: 4,
      supportsBulk: false,
    ),
  }) : bridge = bridge ?? MethodChannelBleRadioBridge() {
    _bridgeSub = this.bridge.events.listen(_onRadioEvent);
  }

  bool get isAdvertising => _isAdvertising;
  bool get isScanning => _isScanning;
  bool get isInBackground => _isInBackground;
  Map<String, IosBlePeerLink> get activeLinks => Map.unmodifiable(_openLinks);

  /// Updates whether the iOS app is currently in foreground (full CoreBluetooth advertising/scanning)
  /// or background (best-effort service-UUID filtered scanning and state restoration).
  Future<void> setBackgroundMode(bool inBackground) async {
    _isInBackground = inBackground;
    if (_isScanning) {
      await bridge.startScanning(
        scanCodedPhy: false,
        lowPower: inBackground,
      );
    }
  }

  void _onRadioEvent(BleRadioEvent event) {
    switch (event) {
      case PeerDiscoveredRadioEvent():
        if (!_isScanning) return;
        _discoveredPsmByAddress[event.address] = event.l2capPsm;
        if (!_discoveredController.isClosed) {
          _discoveredController.add(PeerAdvert(
            peerAddress: event.address,
            token: event.token,
            rssi: event.rssi,
            hints: {
              'phy': 'le_1m',
              'psm': event.l2capPsm,
              'platform': 'ios',
            },
          ));
        }

      case PeerConnectedRadioEvent():
        if (event.isIncoming) {
          final link = IosBlePeerLink(
            peerAddress: event.address,
            mtu: event.negotiatedMtu,
            bridge: bridge,
            onClosed: () => _openLinks.remove(event.address),
          );
          _openLinks[event.address] = link;
          if (!_incomingController.isClosed) {
            _incomingController.add(link);
          }
        }

      case ChunkReceivedRadioEvent():
        _openLinks[event.address]?.handleIncomingChunk(event.bytes);

      case RssiUpdatedRadioEvent():
        _openLinks[event.address]?.handleRssiUpdate(event.rssi);

      case PhyChangedRadioEvent():
        break; // CoreBluetooth manages PHY at OS level (1M/2M)

      case PeerDisconnectedRadioEvent():
        _openLinks.remove(event.address)?.handleRemoteClose(event.reason);
    }
  }

  @override
  Stream<PeerAdvert> get discovered => _discoveredController.stream;

  @override
  Stream<PeerLink> get incoming => _incomingController.stream;

  @override
  Future<void> startAdvertising(Uint8List token) async {
    _isAdvertising = true;
    await bridge.startAdvertising(token, preferCodedPhy: false);
  }

  @override
  Future<void> stopAdvertising() async {
    _isAdvertising = false;
    await bridge.stopAdvertising();
  }

  @override
  Future<void> startScanning([ScanPolicy policy = const ScanPolicy()]) async {
    _isScanning = true;
    await bridge.startScanning(
      scanCodedPhy: false,
      lowPower: _isInBackground || !policy.aggressive,
    );
  }

  @override
  Future<void> stopScanning() async {
    _isScanning = false;
    await bridge.stopScanning();
  }

  @override
  Future<PeerLink> connect(PeerAdvert peer) async {
    if (_openLinks.length >= capabilities.maxConnections) {
      throw StateError(
          'Max connections (${capabilities.maxConnections}) reached on IosBleTransport');
    }

    final psm = _discoveredPsmByAddress[peer.peerAddress] ?? 0;
    final mtu = await bridge.connect(peer.peerAddress, l2capPsm: psm);
    final link = IosBlePeerLink(
      peerAddress: peer.peerAddress,
      mtu: mtu,
      bridge: bridge,
      onClosed: () => _openLinks.remove(peer.peerAddress),
    );
    _openLinks[peer.peerAddress] = link;
    return link;
  }

  @override
  Future<void> stop() async {
    _isAdvertising = false;
    _isScanning = false;
    await bridge.stopAdvertising();
    await bridge.stopScanning();
    for (final link in _openLinks.values.toList()) {
      await link.close('transport_stopped');
    }
    _openLinks.clear();
  }

  Future<void> dispose() async {
    await stop();
    await _bridgeSub?.cancel();
    await _discoveredController.close();
    await _incomingController.close();
    await bridge.dispose();
  }
}
