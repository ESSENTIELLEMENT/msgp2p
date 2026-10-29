import 'dart:async';

import 'package:flutter/foundation.dart' show visibleForTesting;
import 'package:flutter/services.dart';
import 'package:msgp2p_core/msgp2p_core.dart';

/// A [KeyVault] in the platform keystore (`FR-ID-01`; proposal 0001, step 2b; Discussion #10):
///
/// - **Android:** the seeds are encrypted with AES-256-GCM under a non-exportable Android Keystore key and kept
///   in `noBackupFilesDir`, written atomically. A file that reaches another device anyway (a backup or transfer
///   tool that ignores `no_backup`) cannot be decrypted there: [KeyVaultUnavailableError].
/// - **iOS:** a Keychain item with `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` (never in backups or on
///   another device). Keychain items survive uninstalling the app, so the vault also keeps a marker file in the
///   app's own data: an item found without its marker is left over from an earlier install and is replaced by
///   a new identity (otherwise the empty store would refuse to author after every reinstall).
///
/// Dart creates the candidate seeds; the native side keeps the stored ones if any and stores the candidate only
/// when there are none, atomically across isolates. Each [name] is a separate identity.
///
/// Errors: [KeyVaultCorruptedError] (stored bytes malformed), [KeyVaultUnavailableError] (stored seeds that this
/// device cannot decrypt; the host should [erase] and start again), [PlatformException] for anything else, such
/// as `LOCKED` (iOS before the first unlock after a restart; retry later, do not erase).
class PlatformKeyVault implements KeyVault {
  static const MethodChannel defaultChannel =
      MethodChannel('org.msgp2p/key_vault');

  /// Identity name: 1 to 64 of `A-Z a-z 0-9 _ -`. Used in the Keychain account, Keystore alias and file names.
  final String name;
  final MethodChannel _channel;
  final RandomSource _random;
  Future<KeyVaultLoad>? _loaded;
  Future<void> _queue = Future<void>.value();

  PlatformKeyVault(
      {this.name = 'default', MethodChannel? channel, RandomSource? random})
      : _channel = channel ?? defaultChannel,
        _random = random ?? SystemRandomSource() {
    if (!RegExp(r'^[A-Za-z0-9_-]{1,64}$').hasMatch(name)) {
      throw ArgumentError.value(name, 'name', 'must match [A-Za-z0-9_-]{1,64}');
    }
  }

  @override
  Future<KeyVaultLoad> loadOrCreate() {
    final loaded = _loaded;
    if (loaded != null) {
      return loaded.then((r) => (seeds: r.seeds, created: false));
    }
    final future = _loaded = _serial(_loadOrCreateNative);
    // A failed load is not cached, so the host can retry (for example after the first unlock).
    future.then((_) {}, onError: (Object _) {
      if (identical(_loaded, future)) _loaded = null;
    });
    return future;
  }

  @override
  Future<void> erase() {
    _loaded = null;
    return _serial(() => _call<void>('erase', {'name': name}));
  }

  Future<KeyVaultLoad> _loadOrCreateNative() async {
    final candidate = encodeSeeds(IdentitySeeds.generate(_random));
    final reply = await _call<Map<Object?, Object?>>(
        'loadOrCreate', {'name': name, 'candidate': candidate});
    final bytes = reply?['seeds'];
    final created = reply?['created'];
    if (bytes is! Uint8List || created is! bool) {
      throw const KeyVaultCorruptedError('malformed reply from the platform');
    }
    return (seeds: decodeSeeds(bytes), created: created);
  }

  Future<T?> _call<T>(String method, Map<String, Object> args) async {
    try {
      return await _channel.invokeMethod<T>(method, args);
    } on PlatformException catch (e) {
      switch (e.code) {
        case 'CORRUPTED':
          throw KeyVaultCorruptedError(e.message ?? 'stored seeds unreadable');
        case 'UNAVAILABLE':
          throw KeyVaultUnavailableError(
              e.message ?? 'stored seeds cannot be decrypted on this device');
      }
      rethrow;
    }
  }

  /// One native call at a time from this object (the native side is atomic across objects and isolates).
  Future<T> _serial<T>(Future<T> Function() action) {
    final result = _queue.then((_) => action());
    _queue = result.then((_) {}, onError: (Object _) {});
    return result;
  }

  /// Stored form, opaque to the native side: version byte, then the signing and Noise seeds.
  @visibleForTesting
  static Uint8List encodeSeeds(IdentitySeeds seeds) {
    seeds.validate();
    return Uint8List(65)
      ..[0] = seeds.version
      ..setRange(1, 33, seeds.signing)
      ..setRange(33, 65, seeds.noise);
  }

  @visibleForTesting
  static IdentitySeeds decodeSeeds(Uint8List bytes) {
    if (bytes.length != 65) {
      throw KeyVaultCorruptedError(
          'stored seeds have ${bytes.length} bytes, expected 65');
    }
    if (bytes[0] != 1) {
      throw KeyVaultCorruptedError(
          'unsupported identity seeds version ${bytes[0]}');
    }
    final seeds = IdentitySeeds(
      version: bytes[0],
      signing: Uint8List.fromList(bytes.sublist(1, 33)),
      noise: Uint8List.fromList(bytes.sublist(33, 65)),
    );
    seeds.validate();
    return seeds;
  }
}
