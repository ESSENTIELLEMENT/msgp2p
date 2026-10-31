import 'dart:typed_data';

import 'package:convert/convert.dart';
import 'package:cryptography/cryptography.dart' as cg;
import 'package:meta/meta.dart';

import '../crypto/crypto.dart';
import '../crypto/noise_handshake.dart';
import '../crypto/random_source.dart';
import '../gateway/gateway_api.dart';
import '../model/certificate.dart';
import '../model/revocation.dart';
import '../sync/clock_rules.dart';
import 'key_vault.dart';

bool _constantTimeBytesEqual(Uint8List a, Uint8List b) {
  if (a.length != b.length) return false;
  var diff = 0;
  for (var i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff == 0;
}

/// Public keys derived from a device's long-lived [IdentitySeeds] (`FR-ID-01..02`, Proposal 0001, Step 4).
@immutable
class MemberPublicKeys {
  final Uint8List _signing;
  final Uint8List _noise;

  /// Creates validated 32-byte Ed25519 [signing] and X25519 [noise] public keys.
  factory MemberPublicKeys({
    required List<int> signing,
    required List<int> noise,
  }) {
    if (signing.length != 32) {
      throw ArgumentError.value(
        signing.length,
        'signing.length',
        'Ed25519 signing public key must be 32 bytes, got ${signing.length}',
      );
    }
    if (noise.length != 32) {
      throw ArgumentError.value(
        noise.length,
        'noise.length',
        'X25519 Noise public key must be 32 bytes, got ${noise.length}',
      );
    }
    return MemberPublicKeys._(
      Uint8List.fromList(signing),
      Uint8List.fromList(noise),
    );
  }

  const MemberPublicKeys._(this._signing, this._noise);

  /// Derives the 32-byte Ed25519 and X25519 public keys from [seeds].
  static Future<MemberPublicKeys> fromSeeds(IdentitySeeds seeds) async {
    seeds.validate();
    final signKp = await MsgP2PCrypto.newKeyPairFromSeed(seeds.signing);
    final signPk = await MsgP2PCrypto.getPublicKeyBytes(signKp);
    final noiseKp = await cg.X25519().newKeyPairFromSeed(seeds.noise);
    final noisePk = await NoiseHandshake.getPublicKeyBytes(noiseKp);
    return MemberPublicKeys._(signPk, noisePk);
  }

  /// 32-byte Ed25519 signing public key (defensive copy).
  Uint8List get signing => Uint8List.fromList(_signing);

  /// 32-byte X25519 Noise static public key (defensive copy).
  Uint8List get noise => Uint8List.fromList(_noise);

  /// Lowercase hex encoding of [signing].
  String get signingHex => hex.encode(_signing);

  /// Lowercase hex encoding of [noise].
  String get noiseHex => hex.encode(_noise);

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is MemberPublicKeys &&
          _constantTimeBytesEqual(_signing, other._signing) &&
          _constantTimeBytesEqual(_noise, other._noise);

  @override
  int get hashCode =>
      Object.hash(Object.hashAll(_signing), Object.hashAll(_noise));

  @override
  String toString() =>
      'MemberPublicKeys(signing: ${signingHex.substring(0, 8)}…, '
      'noise: ${noiseHex.substring(0, 8)}…)';
}

/// Key class for symmetric group payload encryption (Proposal 0001, §3, P4, §9.4).
enum KeyRole {
  /// Full member key: human members hold `member` (and `tracker`) keys to author and read group traffic.
  member,

  /// Write-only device key: trackers (e.g. dog collars, drones) hold only `tracker` keys so they can
  /// author telemetry and relay `member`-encrypted traffic without decrypting it.
  tracker,
}

/// Symmetric group encryption key granted for a specific [epoch] and [role] (Proposal 0001, §3, §9.4).
@immutable
class GrantedKey {
  /// Key epoch identifier (`> 0`), unique across the server and never reused (§9.4).
  final int epoch;

  /// Role class of this key (`member` or `tracker`).
  final KeyRole role;

  final Uint8List _key;

  /// Optional validity horizon (milliseconds since Unix epoch) reported by the server.
  final int? validUntil;

  /// Creates a validated 32-byte XChaCha20-Poly1305 [GrantedKey].
  factory GrantedKey({
    required int epoch,
    KeyRole role = KeyRole.member,
    required List<int> key,
    int? validUntil,
  }) {
    if (epoch <= 0) {
      throw ArgumentError.value(
        epoch,
        'epoch',
        'GrantedKey epoch must be a positive integer (> 0)',
      );
    }
    if (key.length != 32) {
      throw ArgumentError.value(
        key.length,
        'key.length',
        'GrantedKey must be 32 bytes for XChaCha20-Poly1305, got ${key.length}',
      );
    }
    return GrantedKey._(
      epoch: epoch,
      role: role,
      key: Uint8List.fromList(key),
      validUntil: validUntil,
    );
  }

  const GrantedKey._({
    required this.epoch,
    required this.role,
    required Uint8List key,
    this.validUntil,
  }) : _key = key;

  /// 32-byte symmetric key material (defensive copy).
  Uint8List get key => Uint8List.fromList(_key);

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is GrantedKey &&
          epoch == other.epoch &&
          role == other.role &&
          validUntil == other.validUntil &&
          _constantTimeBytesEqual(_key, other._key);

  @override
  int get hashCode =>
      Object.hash(epoch, role, validUntil, Object.hashAll(_key));
}

/// Failure classification for [MembershipException].
enum MembershipErrorKind {
  /// Authentication failed or the caller is not permitted in the requested group (HTTP 401/403).
  unauthorized,

  /// The member's signing public key has been revoked from the group.
  revoked,

  /// The requested group or endpoint was not found (HTTP 404).
  notFound,

  /// The returned grant failed cryptographic verification, group/key binding, or schema validation.
  invalidGrant,

  /// Transient network, I/O, or upstream server error (e.g. HTTP 5xx).
  transport,
}

/// Typed exception thrown by [MembershipSource.fetch] or [MembershipGrant.verify].
class MembershipException implements Exception {
  final MembershipErrorKind kind;
  final String message;
  final Object? cause;

  const MembershipException(
    this.kind,
    this.message, {
    this.cause,
  });

  @override
  String toString() => 'MembershipException(${kind.name}): $message';
}

/// Provisioned membership credentials, group keys, beacon key, and active revocations for a group
/// (`FR-ID-02`, `FR-SEC-02`; Proposal 0001, §3 & §9.1).
@immutable
class MembershipGrant {
  /// Server-signed membership certificate binding the device's Ed25519 and X25519 public keys.
  final MembershipCert cert;

  /// Symmetric encryption keys granted to this member (`KeyRole.member` and/or `KeyRole.tracker`).
  final List<GrantedKey> keys;

  final Uint8List _beaconKey;

  /// Active server-signed revocation notices for the group, delivered inline so the node learns
  /// revoked peers atomically with rotated keys and can gossip them into the mesh (§9.1).
  final List<RevocationNotice> revocations;

  /// Recommended wall-clock timestamp after which the host should refresh this grant.
  final DateTime refreshAfter;

  factory MembershipGrant({
    required MembershipCert cert,
    required List<GrantedKey> keys,
    required List<int> beaconKey,
    List<RevocationNotice> revocations = const [],
    required DateTime refreshAfter,
  }) {
    if (beaconKey.length != 32) {
      throw ArgumentError.value(
        beaconKey.length,
        'beaconKey.length',
        'Group beacon key must be 32 bytes, got ${beaconKey.length}',
      );
    }
    final seenEpochs = <int>{};
    for (final k in keys) {
      if (!seenEpochs.add(k.epoch)) {
        throw ArgumentError.value(
          k.epoch,
          'keys',
          'Duplicate key epoch ${k.epoch} in MembershipGrant (epochs must be unique, §9.4)',
        );
      }
    }
    return MembershipGrant._(
      cert: cert,
      keys: List<GrantedKey>.unmodifiable(keys),
      beaconKey: Uint8List.fromList(beaconKey),
      revocations: List<RevocationNotice>.unmodifiable(revocations),
      refreshAfter: refreshAfter,
    );
  }

  const MembershipGrant._({
    required this.cert,
    required this.keys,
    required Uint8List beaconKey,
    required this.revocations,
    required this.refreshAfter,
  }) : _beaconKey = beaconKey;

  /// 32-byte group HMAC beacon key used for rotating BLE advertising tokens (`FR-SEC-07`).
  Uint8List get beaconKey => Uint8List.fromList(_beaconKey);

  /// All granted symmetric keys indexed by their unique [GrantedKey.epoch].
  Map<int, Uint8List> get keysByEpoch => {
        for (final k in keys) k.epoch: k.key,
      };

  /// Selects the active key for authoring new envelopes:
  /// prefers the highest-epoch [KeyRole.member] key if present, falling back to the
  /// highest-epoch [KeyRole.tracker] key for write-only tracker devices (Proposal 0001, P4).
  GrantedKey? get activeAuthoringKey {
    GrantedKey? bestMember;
    GrantedKey? bestTracker;
    for (final k in keys) {
      if (k.role == KeyRole.member) {
        if (bestMember == null || k.epoch > bestMember.epoch) {
          bestMember = k;
        }
      } else {
        if (bestTracker == null || k.epoch > bestTracker.epoch) {
          bestTracker = k;
        }
      }
    }
    return bestMember ?? bestTracker;
  }

  /// Cryptographically verifies this grant against [pinnedServerKey], [expectedGroup],
  /// [expectedKeys], and [clock] before trusting or storing its contents.
  ///
  /// Throws [MembershipException] (`invalidGrant` or `revoked`) if any check fails.
  Future<void> verify({
    required GroupId expectedGroup,
    required MemberPublicKeys expectedKeys,
    required Uint8List pinnedServerKey,
    Clock? clock,
  }) async {
    if (pinnedServerKey.length != 32) {
      throw ArgumentError.value(
        pinnedServerKey.length,
        'pinnedServerKey.length',
        'Pinned server Ed25519 public key must be 32 bytes',
      );
    }
    if (keys.isEmpty) {
      throw const MembershipException(
        MembershipErrorKind.invalidGrant,
        'MembershipGrant must contain at least one GrantedKey',
      );
    }

    final groupBytes = expectedGroup.bytes;
    if (!_constantTimeBytesEqual(cert.groupId, groupBytes)) {
      throw const MembershipException(
        MembershipErrorKind.invalidGrant,
        'Certificate group_id does not match requested group',
      );
    }
    if (!_constantTimeBytesEqual(cert.memberPubkey, expectedKeys.signing)) {
      throw const MembershipException(
        MembershipErrorKind.invalidGrant,
        'Certificate member_pubkey does not match device signing public key',
      );
    }
    if (!_constantTimeBytesEqual(cert.noisePubkey, expectedKeys.noise)) {
      throw const MembershipException(
        MembershipErrorKind.invalidGrant,
        'Certificate noise_pubkey does not match device Noise public key',
      );
    }

    final nowMs = (clock ?? const SystemClock()).now().millisecondsSinceEpoch;
    if (cert.isExpired(nowMs)) {
      throw const MembershipException(
        MembershipErrorKind.invalidGrant,
        'Certificate in MembershipGrant is already expired',
      );
    }
    if (!await cert.verify(pinnedServerKey)) {
      throw const MembershipException(
        MembershipErrorKind.invalidGrant,
        'Certificate Ed25519 signature verification failed against pinnedServerKey',
      );
    }

    final ownSigning = expectedKeys.signing;
    for (final rev in revocations) {
      if (!_constantTimeBytesEqual(rev.groupId, groupBytes)) {
        throw const MembershipException(
          MembershipErrorKind.invalidGrant,
          'RevocationNotice group_id in MembershipGrant does not match requested group',
        );
      }
      if (!await rev.verify(pinnedServerKey)) {
        throw const MembershipException(
          MembershipErrorKind.invalidGrant,
          'RevocationNotice Ed25519 signature verification failed against pinnedServerKey',
        );
      }
      if (_constantTimeBytesEqual(rev.memberPubkey, ownSigning)) {
        throw MembershipException(
          MembershipErrorKind.revoked,
          'Member signing key has been revoked (${rev.reason})',
        );
      }
    }
  }
}

/// Port from which a node obtains its [MembershipCert], symmetric group keys, beacon key,
/// and active group revocations (`FR-ID-02`, `FR-SEC-02`; Proposal 0001, Step 4).
///
/// Host applications implement this interface against their own backend / OAuth / session stack;
/// standalone deployments use `ReferenceMembershipSource` from `package:msgp2p_reference_auth`.
abstract interface class MembershipSource {
  /// Fetches a [MembershipGrant] for [group] binding this device's [keys].
  Future<MembershipGrant> fetch(GroupId group, MemberPublicKeys keys);
}

class _EnrolledMember {
  final String userId;
  final int certRole;
  final Set<KeyRole> allowedKeyRoles;

  const _EnrolledMember({
    required this.userId,
    required this.certRole,
    required this.allowedKeyRoles,
  });
}

class _MemoryGroupState {
  final Uint8List beaconKey;
  final List<GrantedKey> keys = [];
  final List<RevocationNotice> revocations = [];
  final Set<String> revokedSigningHex = {};
  final Map<String, _EnrolledMember> enrolledBySigningHex = {};

  _MemoryGroupState({required this.beaconKey});
}

/// Pure-Dart in-memory [MembershipSource] authority for unit tests, contract suites, and simulations.
class MemoryMembershipSource implements MembershipSource {
  final cg.SimpleKeyPair serverSigningKeyPair;
  final Clock clock;
  final RandomSource _random;
  final Duration certTtl;
  final Duration grantTtl;

  /// When `true` (default), unknown non-revoked members are automatically enrolled on [fetch].
  /// When `false`, only members registered via [enrollMember] may obtain a grant.
  final bool autoApprove;

  final Map<GroupId, _MemoryGroupState> _groups = {};
  int _nextEpoch = 1;
  int _nextUserNumber = 1;

  MemoryMembershipSource({
    required this.serverSigningKeyPair,
    this.clock = const SystemClock(),
    RandomSource? random,
    this.certTtl = const Duration(days: 7),
    this.grantTtl = const Duration(hours: 12),
    this.autoApprove = true,
  }) : _random = random ?? SystemRandomSource();

  /// Convenience factory generating a deterministic or random server Ed25519 key pair.
  static Future<MemoryMembershipSource> create({
    Uint8List? serverSeed,
    Clock clock = const SystemClock(),
    RandomSource? random,
    Duration certTtl = const Duration(days: 7),
    Duration grantTtl = const Duration(hours: 12),
    bool autoApprove = true,
  }) async {
    final rng = random ?? SystemRandomSource();
    final kp = await MsgP2PCrypto.newKeyPairFromSeed(
      serverSeed ?? rng.nextBytes(32),
    );
    return MemoryMembershipSource(
      serverSigningKeyPair: kp,
      clock: clock,
      random: rng,
      certTtl: certTtl,
      grantTtl: grantTtl,
      autoApprove: autoApprove,
    );
  }

  /// 32-byte Ed25519 public key of this authority.
  Future<Uint8List> get serverPublicKey =>
      MsgP2PCrypto.getPublicKeyBytes(serverSigningKeyPair);

  _MemoryGroupState _ensureGroup(
    GroupId group, {
    Uint8List? initialGroupKey,
    Uint8List? initialBeaconKey,
  }) {
    return _groups.putIfAbsent(group, () {
      final state = _MemoryGroupState(
        beaconKey: initialBeaconKey != null
            ? Uint8List.fromList(initialBeaconKey)
            : _random.nextBytes(32),
      );
      final nowMs = clock.now().millisecondsSinceEpoch;
      state.keys.add(
        GrantedKey(
          epoch: _nextEpoch++,
          role: KeyRole.member,
          key: initialGroupKey ?? _random.nextBytes(32),
          validUntil: nowMs + const Duration(days: 30).inMilliseconds,
        ),
      );
      return state;
    });
  }

  /// Configures [group] with optional explicit initial key material.
  void configureGroup(
    GroupId group, {
    Uint8List? initialGroupKey,
    Uint8List? initialBeaconKey,
  }) {
    _ensureGroup(
      group,
      initialGroupKey: initialGroupKey,
      initialBeaconKey: initialBeaconKey,
    );
  }

  /// Returns a copy of the 32-byte beacon key for [group].
  Uint8List beaconKeyFor(GroupId group) =>
      Uint8List.fromList(_ensureGroup(group).beaconKey);

  /// Returns the current list of [GrantedKey]s for [group].
  List<GrantedKey> keysFor(GroupId group) =>
      List<GrantedKey>.unmodifiable(_ensureGroup(group).keys);

  /// Enrolls or updates an allowed member in [group] identified by 32-byte Ed25519 [signingPubkey].
  void enrollMember(
    GroupId group,
    List<int> signingPubkey, {
    String? userId,
    int certRole = 0,
    Set<KeyRole> allowedKeyRoles = const {KeyRole.member, KeyRole.tracker},
  }) {
    if (signingPubkey.length != 32) {
      throw ArgumentError.value(
        signingPubkey.length,
        'signingPubkey.length',
        'Ed25519 signing public key must be 32 bytes',
      );
    }
    if (allowedKeyRoles.isEmpty) {
      throw ArgumentError.value(
        allowedKeyRoles,
        'allowedKeyRoles',
        'allowedKeyRoles cannot be empty',
      );
    }
    final state = _ensureGroup(group);
    final sigHex = hex.encode(signingPubkey);
    state.enrolledBySigningHex[sigHex] = _EnrolledMember(
      userId: userId ?? 'usr_${_nextUserNumber++}',
      certRole: certRole,
      allowedKeyRoles: Set<KeyRole>.unmodifiable(allowedKeyRoles),
    );
  }

  /// Rotates/adds a symmetric key for [group] with a globally unique monotonically increasing epoch (§9.4).
  GrantedKey rotateKey(
    GroupId group, {
    KeyRole role = KeyRole.member,
    List<int>? key,
  }) {
    final state = _ensureGroup(group);
    final nowMs = clock.now().millisecondsSinceEpoch;
    final granted = GrantedKey(
      epoch: _nextEpoch++,
      role: role,
      key: key ?? _random.nextBytes(32),
      validUntil: nowMs + const Duration(days: 30).inMilliseconds,
    );
    state.keys.add(granted);
    return granted;
  }

  /// Signs a [RevocationNotice] for [memberPubkey] in [group], records it in the group's active
  /// revocations (§9.1), and rotates the group key epoch by default (`FR-ID-05`, `FR-SEC-02`).
  Future<RevocationNotice> revokeMember(
    GroupId group,
    List<int> memberPubkey, {
    String reason = 'compromised_credential',
    bool rotateGroupKey = true,
  }) async {
    if (memberPubkey.length != 32) {
      throw ArgumentError.value(
        memberPubkey.length,
        'memberPubkey.length',
        'Member Ed25519 public key must be 32 bytes',
      );
    }
    final state = _ensureGroup(group);
    final pkBytes = Uint8List.fromList(memberPubkey);
    final nowMs = clock.now().millisecondsSinceEpoch;
    final core = RevocationNotice(
      groupId: group.bytes,
      memberPubkey: pkBytes,
      revokedAt: nowMs,
      reason: reason,
      serverSig: Uint8List(64),
    );
    final sig = await MsgP2PCrypto.sign(
      core.toCoreCbor(),
      serverSigningKeyPair,
    );
    final signed = RevocationNotice(
      groupId: group.bytes,
      memberPubkey: pkBytes,
      revokedAt: nowMs,
      reason: reason,
      serverSig: sig,
    );
    state.revocations.add(signed);
    state.revokedSigningHex.add(hex.encode(pkBytes));
    if (rotateGroupKey) {
      rotateKey(group, role: KeyRole.member);
    }
    return signed;
  }

  @override
  Future<MembershipGrant> fetch(GroupId group, MemberPublicKeys keys) async {
    final state = _ensureGroup(group);
    final sigHex = keys.signingHex;

    if (state.revokedSigningHex.contains(sigHex)) {
      throw const MembershipException(
        MembershipErrorKind.revoked,
        'Member public key has been revoked from this group',
      );
    }

    var enrolled = state.enrolledBySigningHex[sigHex];
    if (enrolled == null) {
      if (!autoApprove) {
        throw const MembershipException(
          MembershipErrorKind.unauthorized,
          'Member public key is not enrolled in this group',
        );
      }
      enrolled = _EnrolledMember(
        userId: 'usr_${_nextUserNumber++}',
        certRole: 0,
        allowedKeyRoles: const {KeyRole.member, KeyRole.tracker},
      );
      state.enrolledBySigningHex[sigHex] = enrolled;
    }

    var filteredKeys = state.keys
        .where((k) => enrolled!.allowedKeyRoles.contains(k.role))
        .toList();
    if (filteredKeys.isEmpty &&
        enrolled.allowedKeyRoles.contains(KeyRole.tracker)) {
      // Ensure a tracker-only member receives at least one tracker key (P4, §9.4).
      filteredKeys = [rotateKey(group, role: KeyRole.tracker)];
    }

    final now = clock.now();
    final nowMs = now.millisecondsSinceEpoch;
    final expiresAtMs = nowMs + certTtl.inMilliseconds;

    final unsignedCert = MembershipCert(
      groupId: group.bytes,
      userId: enrolled.userId,
      memberPubkey: keys.signing,
      noisePubkey: keys.noise,
      role: enrolled.certRole,
      issuedAt: nowMs,
      expiresAt: expiresAtMs,
      serverSig: Uint8List(64),
    );
    final certSig = await MsgP2PCrypto.sign(
      unsignedCert.toCoreCbor(),
      serverSigningKeyPair,
    );
    final signedCert = MembershipCert(
      groupId: group.bytes,
      userId: enrolled.userId,
      memberPubkey: keys.signing,
      noisePubkey: keys.noise,
      role: enrolled.certRole,
      issuedAt: nowMs,
      expiresAt: expiresAtMs,
      serverSig: certSig,
    );

    final effectiveRefreshTtl = grantTtl < certTtl ? grantTtl : certTtl;
    return MembershipGrant(
      cert: signedCert,
      keys: filteredKeys,
      beaconKey: state.beaconKey,
      revocations: state.revocations,
      refreshAfter: now.toUtc().add(effectiveRefreshTtl),
    );
  }
}
