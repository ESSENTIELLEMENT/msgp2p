/// Ephemeral in-memory (Tier 3) per-peer reconnect cooldown and rate-limit tracker
/// (`FR-SYNC-07`, `IT-FLAP-03`, `IT-DS-05c`, `architecture.md §4`).
///
/// Enforces:
/// 1. Exponential back-off after failed, timed-out, or prematurely dropped sessions.
/// 2. A hard sliding-window cap of [maxAttemptsPerMinute] (`C_max`, default 6) connect
///    attempts per minute to any single peer.
/// 3. Immediate reset of consecutive failures and cooldown timer when a session
///    completes (`BYE` exchanged).
/// 4. Purely in-memory state: cleared when the node restarts (`IT-DS-05c`).
class PeerCooldownState {
  int consecutiveFailures = 0;
  int totalFlaps = 0;
  int nextAllowedConnectMs = 0;
  final List<int> recentAttemptTimestampsMs = [];
}

class PeerCooldownTracker {
  /// Maximum connect attempts allowed to a single peer within any 60-second window (`C_max`).
  final int maxAttemptsPerMinute;

  /// Initial back-off duration after the first failed/dropped session.
  final int baseCooldownMs;

  /// Maximum back-off ceiling.
  final int maxCooldownMs;

  /// Exponential multiplier per consecutive failure.
  final double backoffFactor;

  final Map<String, PeerCooldownState> _states = {};

  PeerCooldownTracker({
    this.maxAttemptsPerMinute = 6,
    this.baseCooldownMs = 2000,
    this.maxCooldownMs = 60000,
    this.backoffFactor = 2.0,
  });

  /// Evaluates whether this node is currently permitted to initiate a connection to [peerId]
  /// at [nowMs].
  ({bool allowed, String? reason, int waitMs}) checkConnectAllowed(
    String peerId,
    int nowMs,
  ) {
    final state = _states[peerId];
    if (state == null) {
      return (allowed: true, reason: null, waitMs: 0);
    }

    // Prune sliding-window timestamps older than 60 seconds (handle backward clock jumps safely)
    state.recentAttemptTimestampsMs.removeWhere(
      (t) => nowMs - t >= 60000 || t > nowMs,
    );

    if (state.recentAttemptTimestampsMs.length >= maxAttemptsPerMinute) {
      final oldestInWindow = state.recentAttemptTimestampsMs.first;
      final rateWait = (oldestInWindow + 60000) - nowMs;
      return (
        allowed: false,
        reason: 'rate_limit_exceeded',
        waitMs: rateWait > 0 ? rateWait : 1000,
      );
    }

    if (nowMs < state.nextAllowedConnectMs) {
      return (
        allowed: false,
        reason: 'cooldown_active',
        waitMs: state.nextAllowedConnectMs - nowMs,
      );
    }

    return (allowed: true, reason: null, waitMs: 0);
  }

  /// Records that a connection attempt to [peerId] was initiated at [nowMs].
  int recordConnectAttempt(String peerId, int nowMs) {
    final state = _states.putIfAbsent(peerId, PeerCooldownState.new);
    state.recentAttemptTimestampsMs.removeWhere(
      (t) => nowMs - t >= 60000 || t > nowMs,
    );
    state.recentAttemptTimestampsMs.add(nowMs);
    return state.recentAttemptTimestampsMs.length;
  }

  /// Records that a connection or session with [peerId] failed, timed out, or dropped before `BYE`.
  /// Computes and applies the next exponential cooldown deadline.
  int recordSessionFailure(String peerId, int nowMs, {bool isFlap = true}) {
    final state = _states.putIfAbsent(peerId, PeerCooldownState.new);
    state.consecutiveFailures++;
    if (isFlap) {
      state.totalFlaps++;
    }

    var delay = baseCooldownMs.toDouble();
    for (var i = 1; i < state.consecutiveFailures; i++) {
      delay *= backoffFactor;
      if (delay >= maxCooldownMs) {
        delay = maxCooldownMs.toDouble();
        break;
      }
    }
    final cooldownMs = delay.round().clamp(baseCooldownMs, maxCooldownMs);
    state.nextAllowedConnectMs = nowMs + cooldownMs;
    return cooldownMs;
  }

  /// Resets the consecutive failure count and exponential cooldown timer for [peerId]
  /// after a synchronization session completes cleanly (`IT-FLAP-03`).
  void recordSessionSuccess(String peerId) {
    final state = _states[peerId];
    if (state != null) {
      state.consecutiveFailures = 0;
      state.nextAllowedConnectMs = 0;
      state.recentAttemptTimestampsMs.clear();
    }
  }

  /// Returns the current consecutive failure count for [peerId] (0 if healthy).
  int consecutiveFailuresFor(String peerId) =>
      _states[peerId]?.consecutiveFailures ?? 0;

  /// Returns the number of attempts recorded for [peerId] in the last 60 seconds at [nowMs].
  int attemptsInLastMinute(String peerId, int nowMs) {
    final state = _states[peerId];
    if (state == null) return 0;
    state.recentAttemptTimestampsMs.removeWhere(
      (t) => nowMs - t >= 60000 || t > nowMs,
    );
    return state.recentAttemptTimestampsMs.length;
  }

  /// Clears all in-memory cooldown state (simulating node restart per `IT-DS-05c`).
  void resetAll() {
    _states.clear();
  }
}
