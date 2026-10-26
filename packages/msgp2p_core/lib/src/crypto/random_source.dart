import 'dart:math' as math;
import 'dart:typed_data';

/// Abstraction for random byte generation.
///
/// Allows injecting cryptographically secure random bytes in production,
/// and deterministic, seeded pseudorandom bytes in simulations and tests.
abstract interface class RandomSource {
  /// Generates a [Uint8List] containing [length] random bytes.
  Uint8List nextBytes(int length);
}

/// System CSPRNG implementation using [math.Random.secure].
class SystemRandomSource implements RandomSource {
  final math.Random _random;

  SystemRandomSource() : _random = math.Random.secure();

  @override
  Uint8List nextBytes(int length) {
    final bytes = Uint8List(length);
    for (var i = 0; i < length; i++) {
      bytes[i] = _random.nextInt(256);
    }
    return bytes;
  }
}

/// Deterministic, reproducible pseudorandom source for simulation and tests.
class DeterministicRandomSource implements RandomSource {
  final math.Random _random;

  DeterministicRandomSource(int seed) : _random = math.Random(seed);

  @override
  Uint8List nextBytes(int length) {
    final bytes = Uint8List(length);
    for (var i = 0; i < length; i++) {
      bytes[i] = _random.nextInt(256);
    }
    return bytes;
  }
}
