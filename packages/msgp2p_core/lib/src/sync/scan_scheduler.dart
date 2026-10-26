import '../transport/transport.dart';

/// Adaptive radio scan duty-cycle scheduler (`NFR-PWR-01`).
///
/// Implements exponential back-off on the scan interval when no peers are discovered
/// across consecutive scan windows to conserve battery (`NFR-PWR-02`: target <= 10% per 8 h),
/// and immediately resets to the baseline interval whenever a group peer is discovered.
class AdaptiveScanScheduler {
  /// Baseline scan interval when peers have recently been seen.
  final Duration baseInterval;

  /// Maximum scan interval ceiling during extended isolation.
  final Duration maxInterval;

  /// Active radio listening window per scan cycle.
  final Duration scanWindow;

  /// Exponential multiplier applied after each empty scan cycle (default 2.0).
  final double backoffFactor;

  int _emptyScanCycles = 0;

  AdaptiveScanScheduler({
    this.baseInterval = const Duration(seconds: 5),
    this.maxInterval = const Duration(seconds: 160),
    this.scanWindow = const Duration(seconds: 1),
    this.backoffFactor = 2.0,
  }) : assert(backoffFactor >= 1.0, 'backoffFactor must be >= 1.0');

  /// Number of consecutive scan cycles where no peer advertisements were seen.
  int get emptyScanCycles => _emptyScanCycles;

  /// Computes the current [ScanPolicy] based on recent peer discovery history.
  ScanPolicy get currentPolicy {
    var intervalMs = baseInterval.inMilliseconds.toDouble();
    for (var i = 0; i < _emptyScanCycles; i++) {
      intervalMs *= backoffFactor;
      if (intervalMs >= maxInterval.inMilliseconds) {
        intervalMs = maxInterval.inMilliseconds.toDouble();
        break;
      }
    }
    return ScanPolicy(
      interval: Duration(milliseconds: intervalMs.round()),
      window: scanWindow,
      aggressive: _emptyScanCycles == 0,
    );
  }

  /// Current duty cycle ratio (`window / interval`), e.g. `0.20` at baseline `1s / 5s`
  /// down to `0.00625` (`0.625%`) at `1s / 160s`.
  double get currentDutyCycleRatio {
    final policy = currentPolicy;
    if (policy.interval.inMilliseconds <= 0) return 1.0;
    return policy.window.inMilliseconds / policy.interval.inMilliseconds;
  }

  /// Records a completed scan cycle in which zero group peers were discovered,
  /// advancing the exponential back-off step.
  ScanPolicy recordEmptyScanCycle() {
    _emptyScanCycles++;
    return currentPolicy;
  }

  /// Records that at least one valid group peer advertisement was discovered,
  /// immediately resetting the scan interval back to [baseInterval].
  ScanPolicy recordPeerDiscovered() {
    _emptyScanCycles = 0;
    return currentPolicy;
  }
}
