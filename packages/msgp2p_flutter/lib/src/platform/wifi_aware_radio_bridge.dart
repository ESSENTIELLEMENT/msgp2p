import 'dart:async';
import 'package:flutter/services.dart';
import 'package:meta/meta.dart';

/// Sealed hierarchy of low-level radio events emitted by the native Wi-Fi Aware adapter (FR-SDK-02).
@immutable
sealed class WifiAwareRadioEvent {
  const WifiAwareRadioEvent();
}

/// Emitted when a Wi-Fi Aware (NAN) peer publishing the group service is discovered.
class WifiAwarePeerDiscoveredEvent extends WifiAwareRadioEvent {
  final String peerHandle;
  final String serviceId;
  final Uint8List token;
  final int rssi;

  const WifiAwarePeerDiscoveredEvent({
    required this.peerHandle,
    required this.serviceId,
    required this.token,
    this.rssi = -55,
  });
}

/// Emitted when a Wi-Fi Aware high-throughput data path is established with a peer.
class WifiAwareConnectedEvent extends WifiAwareRadioEvent {
  final String peerHandle;
  final bool isIncoming;
  final int mtu;

  const WifiAwareConnectedEvent({
    required this.peerHandle,
    required this.isIncoming,
    this.mtu = 1400,
  });
}

/// Emitted when a raw byte chunk arrives over a Wi-Fi Aware data path.
class WifiAwareChunkReceivedEvent extends WifiAwareRadioEvent {
  final String peerHandle;
  final Uint8List bytes;

  const WifiAwareChunkReceivedEvent({
    required this.peerHandle,
    required this.bytes,
  });
}

/// Emitted when a Wi-Fi Aware data path closes or is torn down.
class WifiAwareDisconnectedEvent extends WifiAwareRadioEvent {
  final String peerHandle;
  final String reason;

  const WifiAwareDisconnectedEvent({
    required this.peerHandle,
    this.reason = 'remote_disconnect',
  });
}

/// Thin byte-level bridge to native Wi-Fi Aware hardware:
/// Android `WifiAwareManager` (API 26+) and iOS 26+ `WiFiAware` framework (`FR-SDK-02`).
abstract interface class WifiAwareRadioBridge {
  /// Stream of asynchronous Wi-Fi Aware radio events.
  Stream<WifiAwareRadioEvent> get events;

  /// Checks whether the device supports Wi-Fi Aware.
  Future<bool> isSupported();

  /// Publishes a Wi-Fi Aware service carrying the 16-byte [token].
  Future<bool> publishService(Uint8List token,
      {String serviceId = 'msgp2p_bulk'});

  /// Stops publishing the Wi-Fi Aware service.
  Future<void> stopPublishing();

  /// Subscribes to discover peers publishing [serviceId].
  Future<bool> subscribeService({String serviceId = 'msgp2p_bulk'});

  /// Stops subscribing to Wi-Fi Aware services.
  Future<void> stopSubscribing();

  /// Opens a high-throughput Wi-Fi Aware data path to [peerHandle].
  /// Returns the negotiated MTU (typically 1400 bytes).
  Future<int> connectPeer(String peerHandle);

  /// Closes the Wi-Fi Aware data path to [peerHandle].
  Future<void> disconnectPeer(String peerHandle);

  /// Sends a raw byte [chunk] over the Wi-Fi Aware data path to [peerHandle].
  Future<void> sendChunk(String peerHandle, Uint8List chunk);

  /// Immediately tears down all active Wi-Fi Aware data paths and discovery sessions
  /// after bulk transfer completes to conserve battery.
  Future<void> teardownAll();

  /// Disposes bridge resources.
  Future<void> dispose();
}

/// Production [WifiAwareRadioBridge] backed by Flutter `MethodChannel` and `EventChannel`.
class MethodChannelWifiAwareRadioBridge implements WifiAwareRadioBridge {
  static const MethodChannel _methodChannel =
      MethodChannel('org.msgp2p/wifi_aware_commands');
  static const EventChannel _eventChannel =
      EventChannel('org.msgp2p/wifi_aware_events');

  final StreamController<WifiAwareRadioEvent> _eventsController =
      StreamController<WifiAwareRadioEvent>.broadcast();
  StreamSubscription<dynamic>? _eventSub;

  MethodChannelWifiAwareRadioBridge() {
    _eventSub = _eventChannel.receiveBroadcastStream().listen((dynamic raw) {
      if (raw is Map) {
        final ev = _parseEvent(raw.cast<String, dynamic>());
        if (ev != null && !_eventsController.isClosed) {
          _eventsController.add(ev);
        }
      }
    });
  }

  WifiAwareRadioEvent? _parseEvent(Map<String, dynamic> map) {
    final type = map['event'] as String? ?? '';
    final peerHandle = map['peer_handle'] as String? ?? '';
    switch (type) {
      case 'peer_discovered':
        return WifiAwarePeerDiscoveredEvent(
          peerHandle: peerHandle,
          serviceId: map['service_id'] as String? ?? 'msgp2p_bulk',
          token: map['token'] as Uint8List? ?? Uint8List(0),
          rssi: map['rssi'] as int? ?? -55,
        );
      case 'peer_connected':
        return WifiAwareConnectedEvent(
          peerHandle: peerHandle,
          isIncoming: map['is_incoming'] as bool? ?? false,
          mtu: map['mtu'] as int? ?? 1400,
        );
      case 'chunk_received':
        return WifiAwareChunkReceivedEvent(
          peerHandle: peerHandle,
          bytes: map['bytes'] as Uint8List? ?? Uint8List(0),
        );
      case 'peer_disconnected':
        return WifiAwareDisconnectedEvent(
          peerHandle: peerHandle,
          reason: map['reason'] as String? ?? 'remote_disconnect',
        );
      default:
        return null;
    }
  }

  @override
  Stream<WifiAwareRadioEvent> get events => _eventsController.stream;

  @override
  Future<bool> isSupported() async {
    final ok = await _methodChannel.invokeMethod<bool>('isSupported');
    return ok ?? false;
  }

  @override
  Future<bool> publishService(Uint8List token,
      {String serviceId = 'msgp2p_bulk'}) async {
    final ok = await _methodChannel.invokeMethod<bool>('publishService', {
      'serviceId': serviceId,
      'token': token,
    });
    return ok ?? true;
  }

  @override
  Future<void> stopPublishing() async {
    await _methodChannel.invokeMethod<void>('stopPublishing');
  }

  @override
  Future<bool> subscribeService({String serviceId = 'msgp2p_bulk'}) async {
    final ok = await _methodChannel.invokeMethod<bool>('subscribeService', {
      'serviceId': serviceId,
    });
    return ok ?? true;
  }

  @override
  Future<void> stopSubscribing() async {
    await _methodChannel.invokeMethod<void>('stopSubscribing');
  }

  @override
  Future<int> connectPeer(String peerHandle) async {
    final mtu = await _methodChannel.invokeMethod<int>('connectPeer', {
      'peerHandle': peerHandle,
    });
    return mtu ?? 1400;
  }

  @override
  Future<void> disconnectPeer(String peerHandle) async {
    await _methodChannel.invokeMethod<void>('disconnectPeer', {
      'peerHandle': peerHandle,
    });
  }

  @override
  Future<void> sendChunk(String peerHandle, Uint8List chunk) async {
    await _methodChannel.invokeMethod<void>('sendChunk', {
      'peerHandle': peerHandle,
      'bytes': chunk,
    });
  }

  @override
  Future<void> teardownAll() async {
    await _methodChannel.invokeMethod<void>('teardownAll');
  }

  @override
  Future<void> dispose() async {
    await _eventSub?.cancel();
    await _eventsController.close();
  }
}

/// Shared virtual Wi-Fi Aware medium connecting multiple [LoopbackWifiAwareRadioBridge]
/// instances for deterministic contract testing and BLE -> Wi-Fi Aware upgrade tests (`FR-TEST-03`).
class LoopbackWifiAwareMedium {
  final Map<String, LoopbackWifiAwareRadioBridge> _bridges = {};
  final Map<String, ({String serviceId, Uint8List token})> _publishedServices =
      {};
  final Map<String, String> _subscribingNodes = {};
  final int defaultMtu;
  final int maxConnectionsPerNode;

  LoopbackWifiAwareMedium({
    this.defaultMtu = 1400,
    this.maxConnectionsPerNode = 4,
  });

  LoopbackWifiAwareRadioBridge createBridge(String peerHandle) {
    final bridge = LoopbackWifiAwareRadioBridge(
      peerHandle: peerHandle,
      medium: this,
    );
    _bridges[peerHandle] = bridge;
    return bridge;
  }

  void _onPublish(String handle, String serviceId, Uint8List token) {
    _publishedServices[handle] = (
      serviceId: serviceId,
      token: Uint8List.fromList(token),
    );
    for (final entry in _subscribingNodes.entries) {
      if (entry.key != handle && entry.value == serviceId) {
        _bridges[entry.key]?.emitEvent(WifiAwarePeerDiscoveredEvent(
          peerHandle: handle,
          serviceId: serviceId,
          token: Uint8List.fromList(token),
          rssi: -52,
        ));
      }
    }
  }

  void _onStopPublish(String handle) {
    _publishedServices.remove(handle);
  }

  void _onSubscribe(String subscriberHandle, String serviceId) {
    _subscribingNodes[subscriberHandle] = serviceId;
    final sub = _bridges[subscriberHandle];
    if (sub == null) return;
    for (final entry in _publishedServices.entries) {
      if (entry.key != subscriberHandle && entry.value.serviceId == serviceId) {
        sub.emitEvent(WifiAwarePeerDiscoveredEvent(
          peerHandle: entry.key,
          serviceId: entry.value.serviceId,
          token: Uint8List.fromList(entry.value.token),
          rssi: -52,
        ));
      }
    }
  }

  void _onStopSubscribe(String subscriberHandle) {
    _subscribingNodes.remove(subscriberHandle);
  }
}

/// In-memory [WifiAwareRadioBridge] for testing [WifiAwareTransport] and session upgrades.
class LoopbackWifiAwareRadioBridge implements WifiAwareRadioBridge {
  final String peerHandle;
  final LoopbackWifiAwareMedium medium;
  final bool supported;

  final StreamController<WifiAwareRadioEvent> _eventsController =
      StreamController<WifiAwareRadioEvent>.broadcast();

  final Set<String> activeDataPaths = {};
  bool isPublishing = false;
  bool isSubscribing = false;
  int teardownCount = 0;

  LoopbackWifiAwareRadioBridge({
    required this.peerHandle,
    required this.medium,
    this.supported = true,
  });

  void emitEvent(WifiAwareRadioEvent event) {
    if (!_eventsController.isClosed) {
      _eventsController.add(event);
    }
  }

  @override
  Stream<WifiAwareRadioEvent> get events => _eventsController.stream;

  @override
  Future<bool> isSupported() async => supported;

  @override
  Future<bool> publishService(Uint8List token,
      {String serviceId = 'msgp2p_bulk'}) async {
    if (!supported) return false;
    isPublishing = true;
    medium._onPublish(peerHandle, serviceId, token);
    return true;
  }

  @override
  Future<void> stopPublishing() async {
    isPublishing = false;
    medium._onStopPublish(peerHandle);
  }

  @override
  Future<bool> subscribeService({String serviceId = 'msgp2p_bulk'}) async {
    if (!supported) return false;
    isSubscribing = true;
    medium._onSubscribe(peerHandle, serviceId);
    return true;
  }

  @override
  Future<void> stopSubscribing() async {
    isSubscribing = false;
    medium._onStopSubscribe(peerHandle);
  }

  @override
  Future<int> connectPeer(String targetHandle) async {
    final target = medium._bridges[targetHandle];
    if (target == null) {
      throw StateError(
          'Target Wi-Fi Aware peer $targetHandle is not reachable');
    }
    if (activeDataPaths.length >= medium.maxConnectionsPerNode) {
      throw StateError(
          'Max Wi-Fi Aware connections (${medium.maxConnectionsPerNode}) reached on $peerHandle');
    }
    if (target.activeDataPaths.length >= medium.maxConnectionsPerNode) {
      throw StateError(
          'Max Wi-Fi Aware connections reached on target $targetHandle');
    }

    activeDataPaths.add(targetHandle);
    target.activeDataPaths.add(peerHandle);

    target.emitEvent(WifiAwareConnectedEvent(
      peerHandle: peerHandle,
      isIncoming: true,
      mtu: medium.defaultMtu,
    ));

    return medium.defaultMtu;
  }

  @override
  Future<void> disconnectPeer(String targetHandle) async {
    final wasOpen = activeDataPaths.remove(targetHandle);
    final target = medium._bridges[targetHandle];
    target?.activeDataPaths.remove(peerHandle);

    if (wasOpen) {
      emitEvent(WifiAwareDisconnectedEvent(
          peerHandle: targetHandle, reason: 'local_close'));
      target?.emitEvent(WifiAwareDisconnectedEvent(
          peerHandle: peerHandle, reason: 'remote_close'));
    }
  }

  @override
  Future<void> sendChunk(String targetHandle, Uint8List chunk) async {
    if (!activeDataPaths.contains(targetHandle)) {
      throw StateError(
          'Cannot send chunk: Wi-Fi Aware data path to $targetHandle is closed');
    }
    if (chunk.length > medium.defaultMtu) {
      throw ArgumentError(
          'Chunk (${chunk.length} B) exceeds Wi-Fi Aware MTU (${medium.defaultMtu} B)');
    }
    final target = medium._bridges[targetHandle];
    if (target == null || !target.activeDataPaths.contains(peerHandle)) {
      throw StateError('Target Wi-Fi Aware peer $targetHandle disconnected');
    }
    final copy = Uint8List.fromList(chunk);
    scheduleMicrotask(() {
      target.emitEvent(
          WifiAwareChunkReceivedEvent(peerHandle: peerHandle, bytes: copy));
    });
  }

  @override
  Future<void> teardownAll() async {
    teardownCount++;
    await stopPublishing();
    await stopSubscribing();
    for (final peer in activeDataPaths.toList()) {
      await disconnectPeer(peer);
    }
  }

  @override
  Future<void> dispose() async {
    await teardownAll();
    await _eventsController.close();
  }
}
