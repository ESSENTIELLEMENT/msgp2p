import 'dart:async';
import 'dart:typed_data';
import 'package:msgp2p_core/msgp2p_core.dart';
import '../platform/ble_radio_bridge.dart';

/// Concrete [PeerLink] representing an active Android BLE connection (L2CAP CoC or GATT).
class AndroidBlePeerLink implements PeerLink {
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
  BlePhyMode _currentPhy = BlePhyMode.le1M;

  AndroidBlePeerLink({
    required this.peerAddress,
    required this.mtu,
    required BleRadioBridge bridge,
    required void Function() onClosed,
  })  : _bridge = bridge,
        _onClosed = onClosed;

  BlePhyMode get currentPhy => _currentPhy;

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
          'Cannot send on closed AndroidBlePeerLink ($peerAddress)');
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
    if (_isClosed) return;
    if (!_eventsController.isClosed) {
      _eventsController.add(RssiChanged(rssi));
    }
  }

  void handlePhyChange(BlePhyMode phy) {
    if (_isClosed) return;
    _currentPhy = phy;
    if (!_eventsController.isClosed) {
      _eventsController.add(PhyChanged(phy.wireName));
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

/// Android BLE implementation of [P2PTransport] supporting Extended Advertising,
/// L2CAP CoC / GATT byte links, and adaptive PHY switching (`FR-SDK-03`, `FR-SYNC-06`).
class AndroidBleTransport implements P2PTransport {
  final BleRadioBridge bridge;

  @override
  final TransportCapabilities capabilities;

  /// RSSI threshold below which Coded PHY (S=8 Long Range) is requested (FR-SYNC-06).
  final int codedPhyRssiThreshold;

  /// RSSI threshold at or above which high-speed 2M PHY is requested (FR-SYNC-06).
  final int highSpeedPhyRssiThreshold;

  final StreamController<PeerAdvert> _discoveredController =
      StreamController<PeerAdvert>.broadcast();
  final StreamController<PeerLink> _incomingController =
      StreamController<PeerLink>.broadcast();

  final Map<String, AndroidBlePeerLink> _openLinks = {};
  final Map<String, int> _discoveredPsmByAddress = {};
  StreamSubscription<BleRadioEvent>? _bridgeSub;

  bool _isAdvertising = false;
  bool _isScanning = false;

  AndroidBleTransport({
    BleRadioBridge? bridge,
    this.capabilities = const TransportCapabilities(
      transportName: 'android_ble',
      defaultMtu: 244,
      maxConnections: 4,
      supportsBulk: false,
    ),
    this.codedPhyRssiThreshold = -80,
    this.highSpeedPhyRssiThreshold = -75,
  }) : bridge = bridge ?? MethodChannelBleRadioBridge() {
    _bridgeSub = this.bridge.events.listen(_onRadioEvent);
  }

  bool get isAdvertising => _isAdvertising;
  bool get isScanning => _isScanning;
  Map<String, AndroidBlePeerLink> get activeLinks =>
      Map.unmodifiable(_openLinks);

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
              'phy': event.primaryPhy.wireName,
              'psm': event.l2capPsm,
            },
          ));
        }

      case PeerConnectedRadioEvent():
        if (event.isIncoming) {
          final link = AndroidBlePeerLink(
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
        final link = _openLinks[event.address];
        if (link != null) {
          link.handleRssiUpdate(event.rssi);
          _evaluateAdaptivePhy(link, event.rssi);
        }

      case PhyChangedRadioEvent():
        _openLinks[event.address]?.handlePhyChange(event.phy);

      case PeerDisconnectedRadioEvent():
        _openLinks.remove(event.address)?.handleRemoteClose(event.reason);
    }
  }

  /// Adaptive PHY selection (`FR-SYNC-06`):
  /// - RSSI < [codedPhyRssiThreshold] (-80 dBm) -> switch to Coded PHY S=8 for range resilience.
  /// - RSSI >= [highSpeedPhyRssiThreshold] (-75 dBm) -> switch to 2M PHY for fast sync throughput.
  Future<void> _evaluateAdaptivePhy(AndroidBlePeerLink link, int rssi) async {
    if (rssi < codedPhyRssiThreshold && link.currentPhy != BlePhyMode.codedS8) {
      link.handlePhyChange(BlePhyMode.codedS8);
      await bridge.requestPhy(link.peerAddress, BlePhyMode.codedS8);
    } else if (rssi >= highSpeedPhyRssiThreshold &&
        link.currentPhy != BlePhyMode.le2M) {
      link.handlePhyChange(BlePhyMode.le2M);
      await bridge.requestPhy(link.peerAddress, BlePhyMode.le2M);
    }
  }

  @override
  Stream<PeerAdvert> get discovered => _discoveredController.stream;

  @override
  Stream<PeerLink> get incoming => _incomingController.stream;

  @override
  Future<void> startAdvertising(Uint8List token) async {
    _isAdvertising = true;
    await bridge.startAdvertising(token, preferCodedPhy: true);
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
      scanCodedPhy: true,
      lowPower: !policy.aggressive,
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
          'Max connections (${capabilities.maxConnections}) reached on AndroidBleTransport');
    }

    final psm = _discoveredPsmByAddress[peer.peerAddress] ?? 0;
    final mtu = await bridge.connect(peer.peerAddress, l2capPsm: psm);
    final link = AndroidBlePeerLink(
      peerAddress: peer.peerAddress,
      mtu: mtu,
      bridge: bridge,
      onClosed: () => _openLinks.remove(peer.peerAddress),
    );
    _openLinks[peer.peerAddress] = link;

    // Apply initial PHY based on advertised RSSI
    await _evaluateAdaptivePhy(link, peer.rssi);

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
