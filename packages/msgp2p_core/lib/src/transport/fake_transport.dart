import 'dart:async';
import 'dart:typed_data';
import '../crypto/random_source.dart';
import 'transport.dart';

enum _FaultTriggerMode { cut, silentStall, halfOpen }

/// Threshold trigger to simulate physical radio cut, silent stall, or half-open link
/// after a certain number of bytes (`IT-FI-02`, `IT-FI-04`, `IT-FI-05`).
class _CutTrigger {
  final String nodeA;
  final String nodeB;
  int remainingBytes;
  final _FaultTriggerMode mode;

  _CutTrigger(
    this.nodeA,
    this.nodeB,
    this.remainingBytes, {
    this.mode = _FaultTriggerMode.cut,
  });

  bool matches(String a, String b) {
    return (nodeA == a && nodeB == b) || (nodeA == b && nodeB == a);
  }
}

class _DirectionalLinkConfig {
  final double dropRate;
  final Duration latency;

  const _DirectionalLinkConfig({
    this.dropRate = 0.0,
    this.latency = Duration.zero,
  });
}

/// Simulates a shared radio environment connecting multiple [FakeTransport] instances.
/// Supports dynamic topology graphs, runtime partitions, seeded loss/latency,
/// mid-transfer link cutting (`IT-FI-02`), half-open links (`IT-FI-04`),
/// silent stalls (`IT-FI-05`), and directional asymmetric links (`IT-FI-09`).
class FakeMedium {
  final Map<String, FakeTransport> _transports = {};
  final List<FakePeerLink> _activeLinks = [];
  final List<_CutTrigger> _cutTriggers = [];
  final Map<String, _DirectionalLinkConfig> _directionalConfigs = {};

  bool _fullMesh = true;
  final Map<String, Set<String>> _allowedLinks = {};

  final RandomSource rng;

  FakeMedium({RandomSource? rng}) : rng = rng ?? DeterministicRandomSource(42);

  /// Registers a transport on this medium.
  void register(FakeTransport transport) {
    _transports[transport.nodeAddress] = transport;
  }

  /// Unregisters a transport from this medium.
  void unregister(FakeTransport transport) {
    _transports.remove(transport.nodeAddress);
    _allowedLinks.remove(transport.nodeAddress);
    for (final set in _allowedLinks.values) {
      set.remove(transport.nodeAddress);
    }
  }

  /// Checks if [from] can communicate with [to] according to current topology.
  bool canHear(String from, String to) {
    if (from == to) return true;
    if (_fullMesh) return true;
    return _allowedLinks[from]?.contains(to) ?? false;
  }

  /// Configures medium as a full mesh where all nodes hear each other.
  void setFullMesh() {
    _fullMesh = true;
    _allowedLinks.clear();
  }

  /// Sets an explicit adjacency graph: {node: {connectedPeers}}.
  void setTopology(Map<String, Set<String>> topology) {
    _fullMesh = false;
    _allowedLinks.clear();
    for (final entry in topology.entries) {
      _allowedLinks[entry.key] = Set.from(entry.value);
    }
  }

  /// Connects or disconnects a bidirectional link between [a] and [b].
  void setLink(String a, String b, bool connected) {
    if (_fullMesh) {
      _fullMesh = false;
      for (final k in _transports.keys) {
        _allowedLinks[k] =
            _transports.keys.where((other) => other != k).toSet();
      }
    }
    if (connected) {
      _allowedLinks.putIfAbsent(a, () => {}).add(b);
      _allowedLinks.putIfAbsent(b, () => {}).add(a);
    } else {
      _allowedLinks[a]?.remove(b);
      _allowedLinks[b]?.remove(a);
    }
  }

  /// Divides network into isolated clusters. Nodes within the same cluster can hear
  /// each other; nodes across different clusters cannot.
  void partition(List<List<String>> clusters) {
    _fullMesh = false;
    _allowedLinks.clear();
    for (final cluster in clusters) {
      for (final node in cluster) {
        _allowedLinks[node] = cluster.where((other) => other != node).toSet();
      }
    }
  }

  /// Forcibly cuts active or future links between [nodeA] and [nodeB].
  /// If [afterBytes] is provided, cut occurs after [afterBytes] cumulative bytes are transmitted.
  void cutLink({
    required String nodeA,
    required String nodeB,
    int? afterBytes,
  }) {
    if (afterBytes == null || afterBytes <= 0) {
      // Immediate cut of all active links between nodeA and nodeB
      final toClose = _activeLinks
          .where((l) =>
              (l.localAddress == nodeA && l.remoteAddress == nodeB) ||
              (l.localAddress == nodeB && l.remoteAddress == nodeA))
          .toList();
      for (final link in toClose) {
        link.close('simulated_cut');
      }
    } else {
      _cutTriggers.removeWhere((t) => t.matches(nodeA, nodeB));
      _cutTriggers.add(_CutTrigger(nodeA, nodeB, afterBytes));
    }
  }

  /// Injects a silent stall (`IT-FI-05`): link stays open (no `LinkClosed` emitted)
  /// but stops delivering bytes immediately or after [afterBytes].
  void stallLink({
    required String nodeA,
    required String nodeB,
    int? afterBytes,
  }) {
    if (afterBytes == null || afterBytes <= 0) {
      for (final link in _activeLinks) {
        if ((link.localAddress == nodeA && link.remoteAddress == nodeB) ||
            (link.localAddress == nodeB && link.remoteAddress == nodeA)) {
          link._isSilentlyStalled = true;
        }
      }
    } else {
      _cutTriggers.removeWhere((t) => t.matches(nodeA, nodeB));
      _cutTriggers.add(
        _CutTrigger(
          nodeA,
          nodeB,
          afterBytes,
          mode: _FaultTriggerMode.silentStall,
        ),
      );
    }
  }

  /// Injects a half-open link (`IT-FI-04`): [deadSide] closes its local end and frees its slot,
  /// while [aliveSide] sees the link still open with no `LinkClosed` event delivered.
  void injectHalfOpenLink({
    required String aliveSide,
    required String deadSide,
    int? afterBytes,
  }) {
    if (afterBytes == null || afterBytes <= 0) {
      final deadLinks = _activeLinks
          .where(
              (l) => l.localAddress == deadSide && l.remoteAddress == aliveSide)
          .toList();
      for (final deadLink in deadLinks) {
        deadLink.closeHalfOpenLocalOnly('half_open_dead_side');
      }
      final aliveLinks = _activeLinks
          .where(
              (l) => l.localAddress == aliveSide && l.remoteAddress == deadSide)
          .toList();
      for (final aliveLink in aliveLinks) {
        aliveLink._isHalfOpenAliveSide = true;
      }
    } else {
      _cutTriggers.removeWhere((t) => t.matches(aliveSide, deadSide));
      _cutTriggers.add(
        _CutTrigger(
          aliveSide,
          deadSide,
          afterBytes,
          mode: _FaultTriggerMode.halfOpen,
        ),
      );
    }
  }

  /// Configures directional asymmetric packet loss and latency from [from] to [to] (`IT-FI-09`).
  void setAsymmetricLinkConfig({
    required String from,
    required String to,
    double dropRate = 0.0,
    Duration latency = Duration.zero,
  }) {
    _directionalConfigs['$from->$to'] = _DirectionalLinkConfig(
      dropRate: dropRate,
      latency: latency,
    );
    for (final link in _activeLinks) {
      if (link.localAddress == from && link.remoteAddress == to) {
        link.dropRate = dropRate;
        link.latency = latency;
      }
    }
  }

  /// Clears any pending one-shot cut/stall/half-open triggers between [nodeA] and [nodeB] (or all if omitted).
  void clearFaultTriggers({String? nodeA, String? nodeB}) {
    if (nodeA == null || nodeB == null) {
      _cutTriggers.clear();
    } else {
      _cutTriggers.removeWhere((t) => t.matches(nodeA, nodeB));
    }
  }

  void _onBytesTransferred(FakePeerLink link, int byteCount) {
    for (final trigger in List<_CutTrigger>.from(_cutTriggers)) {
      if (trigger.matches(link.localAddress, link.remoteAddress)) {
        trigger.remainingBytes -= byteCount;
        if (trigger.remainingBytes <= 0) {
          _cutTriggers.remove(trigger);
          switch (trigger.mode) {
            case _FaultTriggerMode.cut:
              link.close('simulated_cut');
            case _FaultTriggerMode.silentStall:
              link._isSilentlyStalled = true;
              link._peerLink?._isSilentlyStalled = true;
            case _FaultTriggerMode.halfOpen:
              // trigger.nodeA is aliveSide, trigger.nodeB is deadSide
              final aliveLink =
                  link.localAddress == trigger.nodeA ? link : link._peerLink;
              final deadLink =
                  link.localAddress == trigger.nodeB ? link : link._peerLink;
              aliveLink?._isHalfOpenAliveSide = true;
              deadLink?.closeHalfOpenLocalOnly('half_open_dead_side');
          }
        }
      }
    }
  }

  /// Broadcasts an advertisement from [sourceAddress] to all currently scanning nodes that can hear it.
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
          canHear(sourceAddress, entry.key)) {
        entry.value._deliverAdvert(advert);
      }
    }
  }

  /// Initiates a point-to-point connection from [initiator] to [targetAddress].
  Future<FakePeerLink> establishConnection({
    required FakeTransport initiator,
    required String targetAddress,
    int mtu = 512,
  }) async {
    final target = _transports[targetAddress];
    if (target == null) {
      throw StateError(
          'Target node $targetAddress is not present on FakeMedium');
    }

    if (!canHear(initiator.nodeAddress, targetAddress)) {
      throw StateError(
          'Topology does not permit connection between ${initiator.nodeAddress} and $targetAddress');
    }

    if (initiator.activeLinkCount >= initiator.capabilities.maxConnections) {
      throw StateError(
          'Initiator ${initiator.nodeAddress} reached max connections (${initiator.capabilities.maxConnections})');
    }
    if (target.activeLinkCount >= target.capabilities.maxConnections) {
      throw StateError(
          'Target $targetAddress reached max connections (${target.capabilities.maxConnections})');
    }

    final effectiveMtu =
        (initiator.capabilities.defaultMtu < target.capabilities.defaultMtu)
            ? initiator.capabilities.defaultMtu
            : target.capabilities.defaultMtu;

    final linkAtoB = FakePeerLink(
      medium: this,
      localAddress: initiator.nodeAddress,
      remoteAddress: targetAddress,
      mtu: effectiveMtu,
      rng: rng,
    );

    final linkBtoA = FakePeerLink(
      medium: this,
      localAddress: targetAddress,
      remoteAddress: initiator.nodeAddress,
      mtu: effectiveMtu,
      rng: rng,
    );

    final cfgAtoB =
        _directionalConfigs['${initiator.nodeAddress}->$targetAddress'];
    if (cfgAtoB != null) {
      linkAtoB.dropRate = cfgAtoB.dropRate;
      linkAtoB.latency = cfgAtoB.latency;
    }
    final cfgBtoA =
        _directionalConfigs['$targetAddress->${initiator.nodeAddress}'];
    if (cfgBtoA != null) {
      linkBtoA.dropRate = cfgBtoA.dropRate;
      linkBtoA.latency = cfgBtoA.latency;
    }

    // Cross-wire the links
    linkAtoB._peerLink = linkBtoA;
    linkBtoA._peerLink = linkAtoB;

    _activeLinks.add(linkAtoB);
    _activeLinks.add(linkBtoA);

    initiator._trackLink(linkAtoB);
    target._trackLink(linkBtoA);

    // Deliver incoming link to target
    target._deliverIncoming(linkBtoA);

    return linkAtoB;
  }
}

/// In-memory bidirectional link implementation for [FakeTransport].
class FakePeerLink implements PeerLink {
  final FakeMedium? medium;
  final String localAddress;
  final String remoteAddress;
  final RandomSource? rng;

  @override
  final int mtu;

  FakePeerLink? _peerLink;
  FakePeerLink? get peerLink => _peerLink;
  bool _isClosed = false;
  bool _isSilentlyStalled = false;
  bool _isHalfOpenAliveSide = false;

  final StreamController<Uint8List> _rxController =
      StreamController<Uint8List>.broadcast();
  final StreamController<LinkEvent> _eventController =
      StreamController<LinkEvent>.broadcast();

  /// Optional simulation hook: drop packet probability (0.0 to 1.0).
  double dropRate = 0.0;

  /// Optional simulation hook: one-way transit latency.
  Duration latency = Duration.zero;

  FakePeerLink({
    this.medium,
    required this.localAddress,
    required this.remoteAddress,
    required this.mtu,
    this.rng,
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
      throw StateError('Cannot send on closed PeerLink');
    }
    if (chunk.length > mtu) {
      throw ArgumentError(
          'Chunk size (${chunk.length}) exceeds link MTU ($mtu)');
    }

    // IT-FI-04 / IT-FI-05: If silently stalled or half-open alive side, blackhole bytes without throwing
    if (_isSilentlyStalled || _isHalfOpenAliveSide) {
      return;
    }

    final peer = _peerLink;
    if (peer == null || peer._isClosed) {
      throw StateError('Remote peer disconnected');
    }

    if (dropRate > 0.0) {
      final roll = ((rng?.nextBytes(1)[0] ?? 0) & 0xFF) / 255.0;
      if (roll < dropRate) {
        // Packet dropped by simulation
        return;
      }
    }

    final payloadCopy = Uint8List.fromList(chunk);
    medium?._onBytesTransferred(this, chunk.length);

    if (_isClosed ||
        peer._isClosed ||
        _isSilentlyStalled ||
        _isHalfOpenAliveSide) {
      return;
    }

    if (latency > Duration.zero) {
      await Future.delayed(latency);
      if (!_isClosed &&
          !peer._isClosed &&
          !_isSilentlyStalled &&
          !_isHalfOpenAliveSide) {
        peer._rxController.add(payloadCopy);
      }
    } else {
      peer._rxController.add(payloadCopy);
    }
  }

  /// Closes ONLY this local endpoint without notifying [_peerLink] (`IT-FI-04` half-open link).
  Future<void> closeHalfOpenLocalOnly([String? reason]) async {
    if (_isClosed) return;
    _isClosed = true;
    _peerLink?._isHalfOpenAliveSide = true;
    medium?._activeLinks.remove(this);
    _eventController.add(LinkClosed(reason));
    await _rxController.close();
    await _eventController.close();
  }

  @override
  Future<void> close([String? reason]) async {
    if (_isClosed) return;
    _isClosed = true;

    medium?._activeLinks.remove(this);
    _eventController.add(LinkClosed(reason));
    await _rxController.close();
    await _eventController.close();

    final peer = _peerLink;
    if (peer != null && !peer._isClosed) {
      await peer.close(reason ?? 'Remote closed');
    }
  }

  /// Diagnostic helper to inject simulated link events.
  void simulateEvent(LinkEvent event) {
    if (!_isClosed) {
      _eventController.add(event);
    }
  }
}

/// Pure Dart in-memory [P2PTransport] implementation for unit tests and simulation.
class FakeTransport implements P2PTransport {
  final String nodeAddress;
  final FakeMedium medium;

  @override
  final TransportCapabilities capabilities;

  bool _isAdvertising = false;
  bool _isScanning = false;
  Uint8List? _activeToken;

  final Set<FakePeerLink> _activeLinks = {};
  final StreamController<PeerAdvert> _discoveredController =
      StreamController<PeerAdvert>.broadcast();
  final StreamController<PeerLink> _incomingController =
      StreamController<PeerLink>.broadcast();

  FakeTransport({
    required this.nodeAddress,
    required this.medium,
    this.capabilities = const TransportCapabilities(
      transportName: 'fake_radio',
      defaultMtu: 512,
      maxConnections: 4,
      supportsBulk: false,
    ),
  }) {
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

  void _trackLink(FakePeerLink link) {
    _activeLinks.add(link);
    link.events.listen((event) {
      if (event is LinkClosed) {
        _activeLinks.remove(link);
      }
    });
  }

  @override
  Future<void> startAdvertising(Uint8List token) async {
    _isAdvertising = true;
    _activeToken = token;
    // Broadcast advertisement to all current scanners that can hear this node
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
    // When starting scanning, check for existing advertisers on the medium within hearing range
    for (final other in medium._transports.values) {
      if (other.nodeAddress != nodeAddress &&
          other.isAdvertising &&
          other.activeToken != null &&
          medium.canHear(other.nodeAddress, nodeAddress)) {
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
    final links = List<FakePeerLink>.from(_activeLinks);
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
      mtu: capabilities.defaultMtu,
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

  /// Disposes this transport and removes it from the medium.
  Future<void> dispose() async {
    await stop();
    medium.unregister(this);
    await _discoveredController.close();
    await _incomingController.close();
  }
}
