import 'dart:typed_data';
import 'package:crypto/crypto.dart' as standard_crypto;
import 'package:meta/meta.dart';

/// Rotating anonymous BLE beacon discovery token generator and verifier
/// as specified in protocol/wire-format.md §5.
///
/// Rotation interval: 900 seconds (15 minutes).
/// Token: first 16 bytes of HMAC-SHA256(key = groupBeaconKey, msg = uint32_be(timeWindow)).
@immutable
class BeaconTokenGenerator {
  /// Default rotation interval in seconds (15 minutes).
  static const int defaultRotationIntervalSeconds = 900;

  final Uint8List groupBeaconKey;
  final int rotationIntervalSeconds;

  const BeaconTokenGenerator({
    required this.groupBeaconKey,
    this.rotationIntervalSeconds = defaultRotationIntervalSeconds,
  });

  /// Computes the time window index for [unixTimeSeconds].
  static int computeTimeWindow(int unixTimeSeconds,
      [int intervalSeconds = defaultRotationIntervalSeconds]) {
    return unixTimeSeconds ~/ intervalSeconds;
  }

  /// Computes the 16-byte beacon token for a specific [timeWindow].
  static Uint8List computeToken(Uint8List key, int timeWindow) {
    final bdata = ByteData(4)..setUint32(0, timeWindow, Endian.big);
    final windowBytes = bdata.buffer.asUint8List();

    final hmac = standard_crypto.Hmac(standard_crypto.sha256, key);
    final digest = hmac.convert(windowBytes);

    return Uint8List.fromList(digest.bytes.sublist(0, 16));
  }

  /// Generates the active 16-byte beacon token for [unixTimeSeconds] (defaults to current time).
  Uint8List generateToken([int? unixTimeSeconds]) {
    final nowSeconds =
        unixTimeSeconds ?? (DateTime.now().millisecondsSinceEpoch ~/ 1000);
    final window = computeTimeWindow(nowSeconds, rotationIntervalSeconds);
    return computeToken(groupBeaconKey, window);
  }

  /// Verifies a received [candidateToken] against the current [timeWindow] and [timeWindow - 1]
  /// to account for clock drift (§5.2).
  bool verifyToken(Uint8List candidateToken, [int? unixTimeSeconds]) {
    if (candidateToken.length != 16) return false;

    final nowSeconds =
        unixTimeSeconds ?? (DateTime.now().millisecondsSinceEpoch ~/ 1000);
    final currentWindow =
        computeTimeWindow(nowSeconds, rotationIntervalSeconds);

    final currentToken = computeToken(groupBeaconKey, currentWindow);
    if (_constantTimeEquals(candidateToken, currentToken)) {
      return true;
    }

    final previousToken = computeToken(groupBeaconKey, currentWindow - 1);
    if (_constantTimeEquals(candidateToken, previousToken)) {
      return true;
    }

    return false;
  }

  static bool _constantTimeEquals(Uint8List a, Uint8List b) {
    if (a.length != b.length) return false;
    var result = 0;
    for (var i = 0; i < a.length; i++) {
      result |= a[i] ^ b[i];
    }
    return result == 0;
  }
}
