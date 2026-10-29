import 'dart:async';
import 'dart:typed_data';

import '../crypto/random_source.dart';

/// The long-lived identity of this device (`FR-ID-01`): the seeds of its Ed25519 signing key and its X25519
/// Noise key. Proposal 0001, step 2; decisions in Discussion #10.
class IdentitySeeds {
  /// Format version of the stored seeds (starts at 1).
  final int version;

  /// 32-byte Ed25519 seed (envelope signatures).
  final Uint8List signing;

  /// 32-byte X25519 seed (Noise-XX sessions).
  final Uint8List noise;

  const IdentitySeeds(
      {this.version = 1, required this.signing, required this.noise})
      : assert(version >= 1);

  /// Fresh seeds from a CSPRNG.
  factory IdentitySeeds.generate(RandomSource random) =>
      IdentitySeeds(signing: random.nextBytes(32), noise: random.nextBytes(32));

  /// Throws [KeyVaultCorruptedError] unless both seeds are 32 bytes and the version is known.
  void validate() {
    if (version != 1) {
      throw KeyVaultCorruptedError(
          'unsupported identity seeds version $version');
    }
    if (signing.length != 32 || noise.length != 32) {
      throw const KeyVaultCorruptedError(
          'identity seeds must be 32 bytes each');
    }
  }
}

/// What [KeyVault.loadOrCreate] returns: the seeds, and whether this call created them.
typedef KeyVaultLoad = ({IdentitySeeds seeds, bool created});

/// Keeps this device's identity across restarts (`FR-ID-01`). The SDK never stores seeds itself.
///
/// Contract (`test/key_vault_contract.dart`, run against every implementation):
/// - [loadOrCreate] returns the same seeds on every call until [erase]; the first call creates them and reports
///   `created: true`, later calls `created: false`;
/// - concurrent first calls create one identity only;
/// - unreadable or malformed stored seeds throw [KeyVaultCorruptedError], never silently a new identity (a new
///   identity is decided by the host, through [erase]);
/// - storage is device-only: an identity must never reach a second device (two devices with one identity would
///   author conflicting `(author, seq)` pairs).
abstract interface class KeyVault {
  Future<KeyVaultLoad> loadOrCreate();

  /// Forgets the identity (sign-out, device reset). The next [loadOrCreate] creates a new one.
  Future<void> erase();
}

/// The stored seeds cannot be read or are malformed (truncated, wrong length, unknown version).
class KeyVaultCorruptedError implements Exception {
  final String message;

  const KeyVaultCorruptedError(this.message);

  @override
  String toString() => 'KeyVaultCorruptedError: $message';
}

/// The stored seeds exist but cannot be decrypted on this device, typically because a backup carried the
/// encrypted file to another device while the keystore key stayed behind. The host should call
/// [KeyVault.erase] and start with a new identity (Discussion #10).
class KeyVaultUnavailableError implements Exception {
  final String message;

  const KeyVaultUnavailableError(this.message);

  @override
  String toString() => 'KeyVaultUnavailableError: $message';
}

/// In-memory vault for tests and short-lived nodes: an identity that lasts as long as the object.
class MemoryKeyVault implements KeyVault {
  final RandomSource _random;
  Future<IdentitySeeds>? _seeds;

  /// How many identities this vault has created (the contract suite checks that concurrent first calls
  /// create one).
  int createdCount = 0;

  MemoryKeyVault({RandomSource? random})
      : _random = random ?? SystemRandomSource();

  /// A vault holding fixed [seeds] (demos and tests that issue certificates for known keys). Like a generated
  /// identity, the first call reports `created: true`: an in-memory identity goes with a new store.
  MemoryKeyVault.fromSeeds(IdentitySeeds seeds, {RandomSource? random})
      : _random = random ?? SystemRandomSource(),
        _given = seeds;

  IdentitySeeds? _given;

  @override
  Future<KeyVaultLoad> loadOrCreate() async {
    final existing = _seeds;
    if (existing != null) return (seeds: await existing, created: false);
    final given = _given;
    if (given != null) {
      _given = null;
      final seeds = _seeds = Future.value(given);
      createdCount++;
      return (seeds: await seeds, created: true);
    }
    // Set synchronously, so concurrent first calls share this future.
    final created = _seeds = Future.value(IdentitySeeds.generate(_random));
    createdCount++;
    return (seeds: await created, created: true);
  }

  @override
  Future<void> erase() async => _seeds = null;
}
