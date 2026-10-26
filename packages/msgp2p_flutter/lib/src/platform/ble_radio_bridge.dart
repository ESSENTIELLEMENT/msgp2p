import 'dart:async';
import 'package:flutter/services.dart';
import 'package:meta/meta.dart';

/// Supported BLE PHY modes on Android 8.0+ (API 26+) (FR-SYNC-06).
enum BlePhyMode {
  le1M('le_1m'),
  le2M('le_2m'),
  codedS8('le_coded_s8');

  final String wireName;
  const BlePhyMode(this.wireName);

  static BlePhyMode fromWireName(String name) {
    for (final mode in BlePhyMode.values) {
      if (mode.wireName == name || mode.name == name) {
        return mode;
      }
    }
    return BlePhyMode.le1M;
  }
}

/// Sealed hierarchy of low-level radio events emitted by native BLE adapter (FR-SDK-02).
@immutable
sealed class BleRadioEvent {
  const BleRadioEvent();
}

/// Emitted when a BLE advertisement carrying a group beacon token is scanned.
class PeerDiscoveredRadioEvent extends BleRadioEvent {
  final String address;
  final Uint8List token;
  final int rssi;
  final BlePhyMode primaryPhy;
  final int l2capPsm;

  const PeerDiscoveredRadioEvent({
    required this.address,
    required this.token,
    required this.rssi,
    this.primaryPhy = BlePhyMode.le1M,
    this.l2capPsm = 0,
  });
}

/// Emitted when a BLE L2CAP CoC or GATT link is established with a peer.
class PeerConnectedRadioEvent extends BleRadioEvent {
  final String address;
  final bool isIncoming;
  final int negotiatedMtu;
  final bool isL2capCoc;

  const PeerConnectedRadioEvent({
    required this.address,
    required this.isIncoming,
    required this.negotiatedMtu,
    this.isL2capCoc = true,
  });
}

/// Emitted when a raw byte chunk arrives from a connected peer.
class ChunkReceivedRadioEvent extends BleRadioEvent {
  final String address;
  final Uint8List bytes;

  const ChunkReceivedRadioEvent({
    required this.address,
    required this.bytes,
  });
}

/// Emitted when a connected peer's RSSI is sampled.
class RssiUpdatedRadioEvent extends BleRadioEvent {
  final String address;
  final int rssi;

  const RssiUpdatedRadioEvent({
    required this.address,
    required this.rssi,
  });
}

/// Emitted when the controller updates TX/RX PHY for a peer connection.
class PhyChangedRadioEvent extends BleRadioEvent {
  final String address;
  final BlePhyMode phy;

  const PhyChangedRadioEvent({
    required this.address,
    required this.phy,
  });
}

/// Emitted when a peer connection closes or drops.
class PeerDisconnectedRadioEvent extends BleRadioEvent {
  final String address;
  final String reason;

  const PeerDisconnectedRadioEvent({
    required this.address,
    this.reason = 'remote_disconnect',
  });
}

/// Thin byte-level bridge interface to native platform BLE hardware (FR-SDK-02).
///
/// Native implementations MUST NOT parse protocol frames or manage sync states;
/// they only advertise, scan, connect, move byte chunks, and report radio events.
abstract interface class BleRadioBridge {
  /// Stream of asynchronous radio events from native layer.
  Stream<BleRadioEvent> get events;

  /// Starts BLE advertising with the 16-byte rotating [token].
  Future<void> startAdvertising(Uint8List token, {bool preferCodedPhy = true});

  /// Stops BLE advertising.
  Future<void> stopAdvertising();

  /// Starts BLE scanning for group advertisements.
  Future<void> startScanning({bool scanCodedPhy = true, bool lowPower = false});

  /// Stops BLE scanning.
  Future<void> stopScanning();

  /// Opens an L2CAP CoC (or GATT fallback) connection to [address].
  /// Returns the negotiated MTU in bytes.
  Future<int> connect(String address, {int l2capPsm = 0});

  /// Closes the connection to [address].
  Future<void> disconnect(String address);

  /// Sends a raw byte [chunk] to [address].
  Future<void> sendChunk(String address, Uint8List chunk);

  /// Requests a PHY switch (e.g. Coded S=8 vs 2M PHY) on the link to [address] (FR-SYNC-06).
  Future<void> requestPhy(String address, BlePhyMode phy);

  /// Starts the Android 14+ `connectedDevice` foreground service for continuous BLE sync.
  Future<bool> startForegroundService({String title, String content});

  /// Stops the foreground service.
  Future<void> stopForegroundService();

  /// Disposes bridge resources.
  Future<void> dispose();
}

/// Production [BleRadioBridge] backed by Flutter `MethodChannel` and `EventChannel`.
class MethodChannelBleRadioBridge implements BleRadioBridge {
  static const MethodChannel _methodChannel =
      MethodChannel('org.msgp2p/ble_commands');
  static const EventChannel _eventChannel =
      EventChannel('org.msgp2p/ble_events');

  final StreamController<BleRadioEvent> _eventsController =
      StreamController<BleRadioEvent>.broadcast();
  StreamSubscription<dynamic>? _eventSub;

  MethodChannelBleRadioBridge() {
    _eventSub = _eventChannel.receiveBroadcastStream().listen((dynamic raw) {
      if (raw is Map) {
        final ev = _parseEvent(raw.cast<String, dynamic>());
        if (ev != null && !_eventsController.isClosed) {
          _eventsController.add(ev);
        }
      }
    });
  }

  BleRadioEvent? _parseEvent(Map<String, dynamic> map) {
    final type = map['event'] as String? ?? '';
    final address = map['address'] as String? ?? '';
    switch (type) {
      case 'peer_discovered':
        return PeerDiscoveredRadioEvent(
          address: address,
          token: map['token'] as Uint8List? ?? Uint8List(0),
          rssi: map['rssi'] as int? ?? -70,
          primaryPhy: BlePhyMode.fromWireName(map['phy'] as String? ?? 'le_1m'),
          l2capPsm: map['psm'] as int? ?? 0,
        );
      case 'peer_connected':
        return PeerConnectedRadioEvent(
          address: address,
          isIncoming: map['is_incoming'] as bool? ?? false,
          negotiatedMtu: map['mtu'] as int? ?? 244,
          isL2capCoc: map['is_l2cap'] as bool? ?? true,
        );
      case 'chunk_received':
        return ChunkReceivedRadioEvent(
          address: address,
          bytes: map['bytes'] as Uint8List? ?? Uint8List(0),
        );
      case 'rssi_updated':
        return RssiUpdatedRadioEvent(
          address: address,
          rssi: map['rssi'] as int? ?? -70,
        );
      case 'phy_changed':
        return PhyChangedRadioEvent(
          address: address,
          phy: BlePhyMode.fromWireName(map['phy'] as String? ?? 'le_1m'),
        );
      case 'peer_disconnected':
        return PeerDisconnectedRadioEvent(
          address: address,
          reason: map['reason'] as String? ?? 'remote_disconnect',
        );
      default:
        return null;
    }
  }

  @override
  Stream<BleRadioEvent> get events => _eventsController.stream;

  @override
  Future<void> startAdvertising(Uint8List token,
      {bool preferCodedPhy = true}) async {
    await _methodChannel.invokeMethod<void>('startAdvertising', {
      'token': token,
      'preferCodedPhy': preferCodedPhy,
    });
  }

  @override
  Future<void> stopAdvertising() async {
    await _methodChannel.invokeMethod<void>('stopAdvertising');
  }

  @override
  Future<void> startScanning(
      {bool scanCodedPhy = true, bool lowPower = false}) async {
    await _methodChannel.invokeMethod<void>('startScanning', {
      'scanCodedPhy': scanCodedPhy,
      'lowPower': lowPower,
    });
  }

  @override
  Future<void> stopScanning() async {
    await _methodChannel.invokeMethod<void>('stopScanning');
  }

  @override
  Future<int> connect(String address, {int l2capPsm = 0}) async {
    final mtu = await _methodChannel.invokeMethod<int>('connect', {
      'address': address,
      'psm': l2capPsm,
    });
    return mtu ?? 244;
  }

  @override
  Future<void> disconnect(String address) async {
    await _methodChannel.invokeMethod<void>('disconnect', {'address': address});
  }

  @override
  Future<void> sendChunk(String address, Uint8List chunk) async {
    await _methodChannel.invokeMethod<void>('sendChunk', {
      'address': address,
      'bytes': chunk,
    });
  }

  @override
  Future<void> requestPhy(String address, BlePhyMode phy) async {
    await _methodChannel.invokeMethod<void>('requestPhy', {
      'address': address,
      'phy': phy.wireName,
    });
  }

  @override
  Future<bool> startForegroundService({
    String title = 'msgp2p Off-Grid Sync Active',
    String content = 'Relaying group messages over Bluetooth LE',
  }) async {
    final ok =
        await _methodChannel.invokeMethod<bool>('startForegroundService', {
      'title': title,
      'content': content,
    });
    return ok ?? true;
  }

  @override
  Future<void> stopForegroundService() async {
    await _methodChannel.invokeMethod<void>('stopForegroundService');
  }

  @override
  Future<void> dispose() async {
    await _eventSub?.cancel();
    await _eventsController.close();
  }
}

/// Shared virtual radio medium connecting multiple [LoopbackBleRadioBridge] instances
/// for deterministic contract testing and emulator-free UI testing (FR-TEST-03).
class LoopbackBleMedium {
  final Map<String, LoopbackBleRadioBridge> _bridges = {};
  final Map<String, Uint8List> _advertisingTokens = {};
  final Set<String> _scanningNodes = {};
  final int defaultMtu;
  final int maxConnectionsPerNode;

  LoopbackBleMedium({
    this.defaultMtu = 244,
    this.maxConnectionsPerNode = 4,
  });

  LoopbackBleRadioBridge createBridge(String address) {
    final bridge = LoopbackBleRadioBridge(address: address, medium: this);
    _bridges[address] = bridge;
    return bridge;
  }

  void _onStartAdvertising(String address, Uint8List token) {
    _advertisingTokens[address] = Uint8List.fromList(token);
    for (final scannerAddr in _scanningNodes) {
      if (scannerAddr != address) {
        _bridges[scannerAddr]?.emitEvent(PeerDiscoveredRadioEvent(
          address: address,
          token: Uint8List.fromList(token),
          rssi: -62,
          primaryPhy: BlePhyMode.codedS8,
          l2capPsm: 128,
        ));
      }
    }
  }

  void _onStopAdvertising(String address) {
    _advertisingTokens.remove(address);
  }

  void _onStartScanning(String scannerAddr) {
    _scanningNodes.add(scannerAddr);
    final scanner = _bridges[scannerAddr];
    if (scanner == null) return;
    for (final entry in _advertisingTokens.entries) {
      if (entry.key != scannerAddr) {
        scanner.emitEvent(PeerDiscoveredRadioEvent(
          address: entry.key,
          token: Uint8List.fromList(entry.value),
          rssi: -62,
          primaryPhy: BlePhyMode.codedS8,
          l2capPsm: 128,
        ));
      }
    }
  }

  void _onStopScanning(String scannerAddr) {
    _scanningNodes.remove(scannerAddr);
  }
}

/// In-memory [BleRadioBridge] implementation for testing [AndroidBleTransport]
/// against the `P2PTransport` contract suite without physical Bluetooth hardware.
class LoopbackBleRadioBridge implements BleRadioBridge {
  final String address;
  final LoopbackBleMedium medium;

  final StreamController<BleRadioEvent> _eventsController =
      StreamController<BleRadioEvent>.broadcast();

  final Set<String> activeConnections = {};
  final Map<String, BlePhyMode> activePhys = {};
  bool isForegroundServiceRunning = false;

  LoopbackBleRadioBridge({
    required this.address,
    required this.medium,
  });

  void emitEvent(BleRadioEvent event) {
    if (!_eventsController.isClosed) {
      _eventsController.add(event);
    }
  }

  /// Simulates an RSSI change from [peerAddress] to test adaptive PHY switching (FR-SYNC-06).
  void simulateRssiChange(String peerAddress, int rssi) {
    emitEvent(RssiUpdatedRadioEvent(address: peerAddress, rssi: rssi));
  }

  @override
  Stream<BleRadioEvent> get events => _eventsController.stream;

  @override
  Future<void> startAdvertising(Uint8List token,
      {bool preferCodedPhy = true}) async {
    medium._onStartAdvertising(address, token);
  }

  @override
  Future<void> stopAdvertising() async {
    medium._onStopAdvertising(address);
  }

  @override
  Future<void> startScanning(
      {bool scanCodedPhy = true, bool lowPower = false}) async {
    medium._onStartScanning(address);
  }

  @override
  Future<void> stopScanning() async {
    medium._onStopScanning(address);
  }

  @override
  Future<int> connect(String targetAddress, {int l2capPsm = 0}) async {
    final target = medium._bridges[targetAddress];
    if (target == null) {
      throw StateError('Target BLE peer $targetAddress is not reachable');
    }
    if (activeConnections.length >= medium.maxConnectionsPerNode) {
      throw StateError(
          'Max BLE connections (${medium.maxConnectionsPerNode}) reached on $address');
    }
    if (target.activeConnections.length >= medium.maxConnectionsPerNode) {
      throw StateError('Max BLE connections reached on target $targetAddress');
    }

    activeConnections.add(targetAddress);
    target.activeConnections.add(address);
    activePhys[targetAddress] = BlePhyMode.le1M;
    target.activePhys[address] = BlePhyMode.le1M;

    target.emitEvent(PeerConnectedRadioEvent(
      address: address,
      isIncoming: true,
      negotiatedMtu: medium.defaultMtu,
      isL2capCoc: true,
    ));

    return medium.defaultMtu;
  }

  @override
  Future<void> disconnect(String targetAddress) async {
    final wasConnected = activeConnections.remove(targetAddress);
    final target = medium._bridges[targetAddress];
    target?.activeConnections.remove(address);

    if (wasConnected) {
      emitEvent(PeerDisconnectedRadioEvent(
          address: targetAddress, reason: 'local_close'));
      target?.emitEvent(
          PeerDisconnectedRadioEvent(address: address, reason: 'remote_close'));
    }
  }

  @override
  Future<void> sendChunk(String targetAddress, Uint8List chunk) async {
    if (!activeConnections.contains(targetAddress)) {
      throw StateError('Cannot send chunk: link to $targetAddress is closed');
    }
    if (chunk.length > medium.defaultMtu) {
      throw ArgumentError(
          'Chunk (${chunk.length} B) exceeds negotiated MTU (${medium.defaultMtu} B)');
    }
    final target = medium._bridges[targetAddress];
    if (target == null || !target.activeConnections.contains(address)) {
      throw StateError('Target $targetAddress disconnected');
    }
    final copy = Uint8List.fromList(chunk);
    scheduleMicrotask(() {
      target.emitEvent(ChunkReceivedRadioEvent(address: address, bytes: copy));
    });
  }

  @override
  Future<void> requestPhy(String targetAddress, BlePhyMode phy) async {
    activePhys[targetAddress] = phy;
    emitEvent(PhyChangedRadioEvent(address: targetAddress, phy: phy));
    final target = medium._bridges[targetAddress];
    if (target != null && target.activeConnections.contains(address)) {
      target.activePhys[address] = phy;
      target.emitEvent(PhyChangedRadioEvent(address: address, phy: phy));
    }
  }

  @override
  Future<bool> startForegroundService({
    String title = 'msgp2p Off-Grid Sync Active',
    String content = 'Relaying group messages over Bluetooth LE',
  }) async {
    isForegroundServiceRunning = true;
    return true;
  }

  @override
  Future<void> stopForegroundService() async {
    isForegroundServiceRunning = false;
  }

  @override
  Future<void> dispose() async {
    await stopAdvertising();
    await stopScanning();
    for (final peer in activeConnections.toList()) {
      await disconnect(peer);
    }
    await _eventsController.close();
  }
}
