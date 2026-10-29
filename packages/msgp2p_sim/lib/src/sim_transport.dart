import 'dart:async';
import 'dart:typed_data';
import 'package:msgp2p_core/msgp2p_core.dart';
import 'event_queue.dart';
import 'link_profile.dart';

/// Medium connecting [SimTransport] instances in discrete-event simulation.
class SimMedium {
  final Map<String, SimTransport> _transports = {};
  final EventQueue? eventQueue;
  final RandomSource rng;
  final Map<String, Set<String>> _contacts = {};
  bool _fullMesh = true;

  SimMedium({
    this.eventQueue,
    RandomSource? rng,
  }) : rng = rng ?? DeterministicRandomSource(42);

  void register(SimTransport transport) {
    _transports[transport.nodeAddress] = transport;
  }

  void unregister(SimTransport transport) {
    _transports.remove(transport.nodeAddress);
    _contacts.remove(transport.nodeAddress);
    for (final s in _contacts.values) {
      s.remove(transport.nodeAddress);
    }
  }

  bool canCommunicate(String a, String b) {
    if (a == b) return true;
    if (_fullMesh) return true;
    return _contacts[a]?.contains(b) ?? false;
  }

  void setFullMesh([bool fullMesh = true]) {
    _fullMesh = fullMesh;
    if (fullMesh) _contacts.clear();
  }

  void setContact(String a, String b, bool inContact) {
    if (_fullMesh) {
      _fullMesh = false;
      for (final k in _transports.keys) {
        _contacts[k] = _transports.keys.where((o) => o != k).toSet();
      }
    }
    if (inContact) {
      _contacts.putIfAbsent(a, () => {}).add(b);
      _contacts.putIfAbsent(b, () => {}).add(a);
    } else {
      _contacts[a]?.remove(b);
      _contacts[b]?.remove(a);
    }
  }

  void broadcastAdvert({
    required String sourceAddress,
    required Uint8List token,
    int rssi = -65,
    Map<String, dynamic> hints = const {},
  }) {
    final advert = PeerAdvert(
      token: token,
      rssi: rssi,
      peerAddress: sourceAddress,
      hints: hints,
    );

    for (final entry in _transports.entries) {
      if (entry.key != sourceAddress &&
          entry.value.isScanning &&
          canCommunicate(sourceAddress, entry.key)) {
        entry.value._deliverAdvert(advert);
      }
    }
  }

  /// Broadcasts an unacknowledged radio packet to all nodes currently in contact.
  void broadcastPacket({
    required String sourceAddress,
    required Uint8List packet,
    int? rssi,
    double? snr,
  }) {
    for (final entry in _transports.entries) {
      if (entry.key != sourceAddress &&
          canCommunicate(sourceAddress, entry.key)) {
        entry.value.onIncomingBroadcast(BroadcastPacket(
          payload: packet,
          rssi: rssi ?? -85,
          snr: snr ?? 7.5,
          sourceAddress: sourceAddress,
        ));
      }
    }
  }

  Future<SimPeerLink> establishConnection({
    required SimTransport initiator,
    required String targetAddress,
    LinkProfile? profile,
  }) async {
    final target = _transports[targetAddress];
    if (target == null) {
      throw StateError(
          'Target node $targetAddress is not registered on SimMedium');
    }

    if (!canCommunicate(initiator.nodeAddress, targetAddress)) {
      throw StateError(
          'No contact between ${initiator.nodeAddress} and $targetAddress');
    }

    if (initiator.activeLinkCount >= initiator.capabilities.maxConnections) {
      throw StateError(
          'Initiator ${initiator.nodeAddress} reached max connections');
    }
    if (target.activeLinkCount >= target.capabilities.maxConnections) {
      throw StateError('Target $targetAddress reached max connections');
    }

    final effectiveProfile = profile ?? initiator.profile;
    final effectiveMtu =
        (initiator.capabilities.defaultMtu < target.capabilities.defaultMtu)
            ? initiator.capabilities.defaultMtu
            : target.capabilities.defaultMtu;

    final linkAtoB = SimPeerLink(
      medium: this,
      localAddress: initiator.nodeAddress,
      remoteAddress: targetAddress,
      mtu: effectiveMtu,
      profile: effectiveProfile,
      rng: rng,
    );

    final linkBtoA = SimPeerLink(
      medium: this,
      localAddress: targetAddress,
      remoteAddress: initiator.nodeAddress,
      mtu: effectiveMtu,
      profile: effectiveProfile,
      rng: rng,
    );

    linkAtoB._peerLink = linkBtoA;
    linkBtoA._peerLink = linkAtoB;

    initiator._trackLink(linkAtoB);
    target._trackLink(linkBtoA);

    target._deliverIncoming(linkBtoA);

    return linkAtoB;
  }
}

/// Simulated PeerLink with link profile constraints (MTU, loss rate, transit delay).
class SimPeerLink implements PeerLink {
  final SimMedium medium;
  final String localAddress;
  final String remoteAddress;
  final LinkProfile profile;
  final RandomSource rng;

  @override
  final int mtu;

  SimPeerLink? _peerLink;
  SimPeerLink? get peerLink => _peerLink;

  bool _isClosed = false;
  final StreamController<Uint8List> _rxController =
      StreamController<Uint8List>.broadcast();
  final StreamController<LinkEvent> _eventController =
      StreamController<LinkEvent>.broadcast();

  int totalBytesSent = 0;

  SimPeerLink({
    required this.medium,
    required this.localAddress,
    required this.remoteAddress,
    required this.mtu,
    required this.profile,
    required this.rng,
  });

  @override
  Stream<Uint8List> get rx => _rxController.stream;

  @override
  Stream<LinkEvent> get events => _eventController.stream;

  @override
  bool get isClosed => _isClosed;

  @override
  Future<void> send(Uint8List chunk) async {
    if (_isClosed) {
      throw StateError('Cannot send on closed SimPeerLink');
    }
    if (chunk.length > mtu) {
      throw ArgumentError('Chunk size (${chunk.length}) exceeds MTU ($mtu)');
    }

    final peer = _peerLink;
    if (peer == null || peer._isClosed) {
      throw StateError('Remote peer disconnected');
    }

    // Check packet loss using seeded RNG
    if (profile.packetLossRate > 0.0) {
      final roll = (rng.nextBytes(1)[0] & 0xFF) / 255.0;
      if (roll < profile.packetLossRate) {
        return; // Dropped by simulation
      }
    }

    totalBytesSent += chunk.length;
    final payloadCopy = Uint8List.fromList(chunk);

    if (medium.eventQueue != null && profile.transitLatencyMs > 0) {
      // Schedule delivery in virtual time
      final deliverAt =
          medium.eventQueue!.clock.currentTimeMs + profile.transitLatencyMs;
      medium.eventQueue!.schedule(deliverAt, () async {
        if (!_isClosed && !peer._isClosed) {
          peer._rxController.add(payloadCopy);
        }
      });
    } else if (profile.transitLatencyMs > 0) {
      await Future.delayed(Duration(milliseconds: profile.transitLatencyMs));
      if (!_isClosed && !peer._isClosed) {
        peer._rxController.add(payloadCopy);
      }
    } else {
      peer._rxController.add(payloadCopy);
    }
  }

  @override
  Future<void> close([String? reason]) async {
    if (_isClosed) return;
    _isClosed = true;

    _eventController.add(LinkClosed(reason));
    await _rxController.close();
    await _eventController.close();

    final peer = _peerLink;
    if (peer != null && !peer._isClosed) {
      await peer.close(reason ?? 'Remote closed');
    }
  }
}

/// Simulated [P2PTransport] passing contract test suite and driven by contact plans.
class SimTransport implements P2PTransport {
  final String nodeAddress;
  final SimMedium medium;
  final LinkProfile profile;

  @override
  final TransportCapabilities capabilities;

  bool _isAdvertising = false;
  bool _isScanning = false;
  Uint8List? _activeToken;

  final Set<SimPeerLink> _activeLinks = {};
  final StreamController<PeerAdvert> _discoveredController =
      StreamController<PeerAdvert>.broadcast();
  final StreamController<PeerLink> _incomingController =
      StreamController<PeerLink>.broadcast();

  SimTransport({
    required this.nodeAddress,
    required this.medium,
    this.profile = LinkProfile.ble1M,
    TransportCapabilities? capabilities,
  }) : capabilities = capabilities ??
            TransportCapabilities(
              transportName: profile.name,
              defaultMtu: profile.defaultMtu,
              maxConnections: 4,
              supportsBulk: profile.name == 'wifi_aware',
            ) {
    medium.register(this);
  }

  bool get isAdvertising => _isAdvertising;
  bool get isScanning => _isScanning;
  Uint8List? get activeToken => _activeToken;
  int get activeLinkCount => _activeLinks.where((l) => !l.isClosed).length;

  @override
  Stream<PeerAdvert> get discovered => _discoveredController.stream;

  @override
  Stream<PeerLink> get incoming => _incomingController.stream;

  void _trackLink(SimPeerLink link) {
    _activeLinks.add(link);
    link.events.listen((e) {
      if (e is LinkClosed) {
        _activeLinks.remove(link);
      }
    });
  }

  @override
  Future<void> startAdvertising(Uint8List token) async {
    _isAdvertising = true;
    _activeToken = token;
    medium.broadcastAdvert(
      sourceAddress: nodeAddress,
      token: token,
      rssi: -50,
    );
  }

  @override
  Future<void> stopAdvertising() async {
    _isAdvertising = false;
    _activeToken = null;
  }

  @override
  Future<void> startScanning([ScanPolicy policy = const ScanPolicy()]) async {
    _isScanning = true;
    for (final other in medium._transports.values) {
      if (other.nodeAddress != nodeAddress &&
          other.isAdvertising &&
          other.activeToken != null &&
          medium.canCommunicate(other.nodeAddress, nodeAddress)) {
        _deliverAdvert(PeerAdvert(
          token: other.activeToken!,
          rssi: -55,
          peerAddress: other.nodeAddress,
        ));
      }
    }
  }

  @override
  Future<void> stopScanning() async {
    _isScanning = false;
  }

  @override
  Future<void> stop() async {
    await stopAdvertising();
    await stopScanning();
    final links = List<SimPeerLink>.from(_activeLinks);
    for (final link in links) {
      await link.close('transport_stopped');
    }
    _activeLinks.clear();
  }

  @override
  Future<PeerLink> connect(PeerAdvert peer) async {
    return medium.establishConnection(
      initiator: this,
      targetAddress: peer.peerAddress,
      profile: profile,
    );
  }

  void _deliverAdvert(PeerAdvert advert) {
    if (_isScanning && !_discoveredController.isClosed) {
      _discoveredController.add(advert);
    }
  }

  void _deliverIncoming(PeerLink link) {
    if (!_incomingController.isClosed) {
      _incomingController.add(link);
    }
  }

  /// Hook invoked by [SimMedium] when an unacknowledged broadcast packet arrives.
  void onIncomingBroadcast(BroadcastPacket packet) {}

  Future<void> dispose() async {
    await stop();
    medium.unregister(this);
    await _discoveredController.close();
    await _incomingController.close();
  }
}
