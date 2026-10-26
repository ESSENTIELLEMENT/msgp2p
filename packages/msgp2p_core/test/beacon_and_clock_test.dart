import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';
import 'package:convert/convert.dart';
import 'package:msgp2p_core/msgp2p_core.dart';
import 'package:test/test.dart';

void main() {
  late Map<String, dynamic> beaconVectorData;
  late Uint8List groupBeaconKey;

  setUpAll(() {
    var dir = Directory.current;
    while (!File('${dir.path}/protocol/test-vectors/beacon_tokens.json')
        .existsSync()) {
      final parent = dir.parent;
      if (parent.path == dir.path) {
        throw StateError('Cannot find protocol/test-vectors/');
      }
      dir = parent;
    }
    final vDir = '${dir.path}/protocol/test-vectors';
    beaconVectorData =
        jsonDecode(File('$vDir/beacon_tokens.json').readAsStringSync());
    groupBeaconKey = Uint8List.fromList(
        hex.decode(beaconVectorData['group_beacon_key_hex']));
  });

  group('Rotating Anonymous Beacon Tokens (FR-SEC-07)', () {
    test('Exact match with protocol/test-vectors/beacon_tokens.json samples',
        () {
      final generator = BeaconTokenGenerator(groupBeaconKey: groupBeaconKey);
      final samples = beaconVectorData['samples'] as List;

      for (final sample in samples) {
        final timestamp = sample['timestamp_seconds'] as int;
        final expectedWindow = sample['time_window'] as int;
        final expectedHex = sample['token_16_bytes_hex'] as String;

        final computedWindow =
            BeaconTokenGenerator.computeTimeWindow(timestamp);
        expect(computedWindow, equals(expectedWindow));

        final token = generator.generateToken(timestamp);
        expect(hex.encode(token), equals(expectedHex));

        // Self-verification for the current window
        expect(generator.verifyToken(token, timestamp), isTrue);
      }
    });

    test('Rotation interval: token changes after crossing 900-second window',
        () {
      final generator = BeaconTokenGenerator(groupBeaconKey: groupBeaconKey);
      final windowStart = 1970913 * 900; // 1773821700
      final token0 = generator.generateToken(windowStart);

      // Within same 900s window -> same token
      final tokenSameWindow = generator.generateToken(windowStart + 899);
      expect(tokenSameWindow, equals(token0));

      // After crossing 900s boundary -> new token
      final tokenNextWindow = generator.generateToken(windowStart + 900);
      expect(tokenNextWindow, isNot(equals(token0)));
    });

    test(
        'Verification accepts current window and previous window (drift tolerance)',
        () {
      final generator = BeaconTokenGenerator(groupBeaconKey: groupBeaconKey);
      final window0Time = 1970913 * 900; // window 1970913
      final window1Time = 1970914 * 900; // window 1970914

      final tokenWindow0 = generator.generateToken(window0Time);
      final tokenWindow1 = generator.generateToken(window1Time);

      // During window 1:
      // Current token (window 1) MUST pass
      expect(generator.verifyToken(tokenWindow1, window1Time), isTrue);

      // Previous token (window 0) MUST pass due to 1-window drift tolerance
      expect(generator.verifyToken(tokenWindow0, window1Time), isTrue);

      // Token from two windows ago (window - 2) MUST be rejected
      final tokenOlder = generator.generateToken((1970913 - 1) * 900);
      expect(generator.verifyToken(tokenOlder, window1Time), isFalse);

      // Future token (window + 1) MUST be rejected
      final tokenFuture = generator.generateToken((1970914 + 1) * 900);
      expect(generator.verifyToken(tokenFuture, window1Time), isFalse);

      // Corrupted token MUST be rejected
      final corrupt = Uint8List.fromList(tokenWindow1);
      corrupt[0] ^= 0xFF;
      expect(generator.verifyToken(corrupt, window1Time), isFalse);
    });
  });

  group('Clock Rules & Validation (FR-SEC-08)', () {
    const int now = 10000000;

    test('Valid timestamps within tolerances pass', () {
      // Message created 5 minutes ago, expiring in 24 hours
      final createdAt = now - 300000;
      final expiresAt = now + ClockRules.defaultMessageTtlMs;

      expect(
          ClockRules.isValidMessageTime(
            createdAt: createdAt,
            expiresAt: expiresAt,
            currentTimeMillis: now,
          ),
          isTrue);
    });

    test(
        'Future timestamp within 10-minute drift passes, beyond 10 minutes fails',
        () {
      final expiresAt = now + ClockRules.defaultMessageTtlMs;

      // Exactly 10 minutes into future -> acceptable
      final maxAllowedFuture = now + ClockRules.maxFutureClockDriftMs;
      expect(ClockRules.isTooFarInFuture(maxAllowedFuture, now), isFalse);
      expect(
          ClockRules.isValidMessageTime(
            createdAt: maxAllowedFuture,
            expiresAt: expiresAt,
            currentTimeMillis: now,
          ),
          isTrue);

      // 10 minutes + 1 ms into future -> REJECTED
      final excessiveFuture = maxAllowedFuture + 1;
      expect(ClockRules.isTooFarInFuture(excessiveFuture, now), isTrue);
      expect(
          ClockRules.isValidMessageTime(
            createdAt: excessiveFuture,
            expiresAt: expiresAt,
            currentTimeMillis: now,
          ),
          isFalse);
    });

    test('Expired timestamps are rejected', () {
      final createdAt = now - 100000;

      // Expired at current time -> REJECTED
      expect(ClockRules.isExpired(now, now), isTrue);
      expect(
          ClockRules.isValidMessageTime(
            createdAt: createdAt,
            expiresAt: now,
            currentTimeMillis: now,
          ),
          isFalse);

      // Expired in past -> REJECTED
      expect(ClockRules.isExpired(now - 1, now), isTrue);
      expect(
          ClockRules.isValidMessageTime(
            createdAt: createdAt,
            expiresAt: now - 1,
            currentTimeMillis: now,
          ),
          isFalse);
    });

    test('Inverted timestamps (createdAt > expiresAt) are rejected', () {
      expect(
          ClockRules.isValidMessageTime(
            createdAt: now + 5000,
            expiresAt: now + 4000,
            currentTimeMillis: now,
          ),
          isFalse);
    });
  });
}
