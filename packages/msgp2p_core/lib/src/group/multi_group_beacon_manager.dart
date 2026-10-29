import 'dart:async';
import 'dart:typed_data';
import 'package:convert/convert.dart';
import '../crypto/beacon_token.dart';
import '../transport/transport.dart';
import 'group_membership.dart';

/// Manages multi-group rotating beacon advertising and token matching for multi-tenant nodes.
class MultiGroupBeaconManager {
  final P2PTransport transport;
  final Duration advertisingRotationPeriod;
  final Map<String, (GroupMembership, BeaconTokenGenerator)> _groups = {};

  Timer? _rotationTimer;
  int _currentGroupIndex = 0;
  bool _isAdvertising = false;

  MultiGroupBeaconManager({
    required this.transport,
    this.advertisingRotationPeriod = const Duration(seconds: 2),
  });

  /// Registers a group membership for beacon rotation and scan matching.
  void registerGroup(GroupMembership membership) {
    final hexId = membership.groupIdHex;
    final generator = BeaconTokenGenerator(
      groupBeaconKey: membership.groupBeaconKey,
    );
    _groups[hexId] = (membership, generator);
  }

  /// Removes a group membership.
  void unregisterGroup(Uint8List groupId) {
    final hexId = hex.encode(groupId).toLowerCase();
    _groups.remove(hexId);
    if (_currentGroupIndex >= _groups.length) {
      _currentGroupIndex = 0;
    }
  }

  /// All registered group memberships.
  List<GroupMembership> get registeredGroups =>
      _groups.values.map((e) => e.$1).toList();

  /// Matches a discovered 16-byte [candidateToken] against all registered groups.
  ///
  /// Returns the matching [GroupMembership] or `null` if no registered group matches.
  GroupMembership? matchToken(Uint8List candidateToken,
      [int? unixTimeSeconds]) {
    if (candidateToken.length != 16) return null;

    for (final entry in _groups.values) {
      final membership = entry.$1;
      final generator = entry.$2;
      if (generator.verifyToken(candidateToken, unixTimeSeconds)) {
        return membership;
      }
    }
    return null;
  }

  /// Starts round-robin advertising across all registered groups.
  Future<void> startAdvertising() async {
    if (_isAdvertising || _groups.isEmpty) return;
    _isAdvertising = true;

    await _rotateAndAdvertise();
    _rotationTimer = Timer.periodic(advertisingRotationPeriod, (_) async {
      await _rotateAndAdvertise();
    });
  }

  /// Stops beacon advertising.
  Future<void> stopAdvertising() async {
    _isAdvertising = false;
    _rotationTimer?.cancel();
    _rotationTimer = null;
    await transport.stopAdvertising();
  }

  Future<void> _rotateAndAdvertise() async {
    if (!_isAdvertising || _groups.isEmpty) return;

    final groupList = _groups.values.toList();
    if (_currentGroupIndex >= groupList.length) {
      _currentGroupIndex = 0;
    }

    final activeEntry = groupList[_currentGroupIndex];
    final generator = activeEntry.$2;
    final token = generator.generateToken();

    try {
      await transport.startAdvertising(token);
    } catch (_) {
      // Transport advertising error (e.g. radio busy)
    }

    _currentGroupIndex = (_currentGroupIndex + 1) % groupList.length;
  }

  void dispose() {
    stopAdvertising();
  }
}
