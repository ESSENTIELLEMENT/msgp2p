/// Clock validation rules and tolerance constants per protocol/wire-format.md §4.4 & §8.
class ClockRules {
  ClockRules._();

  /// 10 minutes maximum tolerance for messages timestamped in the future (ms).
  static const int maxFutureClockDriftMs = 600000;

  /// Default message retention TTL: 24 hours (ms).
  static const int defaultMessageTtlMs = 86400000;

  /// Default beacon rotation interval: 15 minutes (seconds).
  static const int beaconRotationIntervalSeconds = 900;

  /// Returns true if [createdAt] is more than [maxFutureClockDriftMs] into the future.
  static bool isTooFarInFuture(int createdAt, [int? currentTimeMillis]) {
    final now = currentTimeMillis ?? DateTime.now().millisecondsSinceEpoch;
    return createdAt > (now + maxFutureClockDriftMs);
  }

  /// Returns true if [expiresAt] has already passed.
  static bool isExpired(int expiresAt, [int? currentTimeMillis]) {
    final now = currentTimeMillis ?? DateTime.now().millisecondsSinceEpoch;
    return expiresAt <= now;
  }

  /// Validates both creation and expiration timestamps against [currentTimeMillis] (wire-format §4.4).
  ///
  /// Criteria:
  /// 1. [createdAt] <= [currentTimeMillis] + 10 minutes.
  /// 2. [expiresAt] > [currentTimeMillis].
  /// 3. [createdAt] <= [expiresAt].
  static bool isValidMessageTime({
    required int createdAt,
    required int expiresAt,
    int? currentTimeMillis,
  }) {
    final now = currentTimeMillis ?? DateTime.now().millisecondsSinceEpoch;
    if (isTooFarInFuture(createdAt, now)) return false;
    if (isExpired(expiresAt, now)) return false;
    if (createdAt > expiresAt) return false;
    return true;
  }
}

/// Clock interface to allow deterministic virtual-time simulation and test injection.
abstract class Clock {
  DateTime now();
}

/// System wall-clock implementation for production runtime.
class SystemClock implements Clock {
  const SystemClock();

  @override
  DateTime now() => DateTime.now();
}

/// Controllable virtual clock for deterministic multi-node simulation (FR-TEST-08).
class VirtualClock implements Clock {
  DateTime _current;

  VirtualClock(DateTime initial) : _current = initial;

  @override
  DateTime now() => _current;

  void advance(Duration duration) {
    _current = _current.add(duration);
  }

  void setTime(DateTime time) {
    _current = time;
  }
}
