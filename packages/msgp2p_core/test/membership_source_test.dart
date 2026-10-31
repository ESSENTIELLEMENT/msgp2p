import 'dart:typed_data';

import 'package:msgp2p_core/msgp2p_core.dart';
import 'package:test/test.dart';

import 'membership_source_contract.dart';

class _FixedClock implements Clock {
  DateTime _now;
  _FixedClock(this._now);

  @override
  DateTime now() => _now;

  void advance(Duration d) {
    _now = _now.add(d);
  }
}

void main() {
  final groupA = GroupId.fromHex('a0b1c2d3e4f50123456789abcdef0123');
  final groupB = GroupId.fromHex('11223344556677889900aabbccddeeff');

  runMembershipSourceContractTests('MemoryMembershipSource (autoApprove)',
      () async {
    final authority = await MemoryMembershipSource.create(
      serverSeed: Uint8List.fromList(List.filled(32, 0x42)),
    );
    final serverPk = await authority.serverPublicKey;
    var seedCounter = 1;

    return MembershipSourceContext(
      groupId: groupA,
      serverPublicKey: serverPk,
      createMember: (label) async {
        final s = seedCounter++;
        final seeds = IdentitySeeds(
          signing: Uint8List.fromList(List.filled(32, s)),
          noise: Uint8List.fromList(List.filled(32, s + 100)),
        );
        final keys = await MemberPublicKeys.fromSeeds(seeds);
        return (source: authority, seeds: seeds, keys: keys);
      },
      revokeMember: (memberPk, {String reason = 'compromised_credential'}) =>
          authority.revokeMember(groupA, memberPk, reason: reason),
    );
  });

  runMembershipSourceContractTests(
      'MemoryMembershipSource (explicit enrollment)', () async {
    final authority = await MemoryMembershipSource.create(
      serverSeed: Uint8List.fromList(List.filled(32, 0x43)),
      autoApprove: false,
    );
    final serverPk = await authority.serverPublicKey;
    var seedCounter = 10;

    return MembershipSourceContext(
      groupId: groupA,
      serverPublicKey: serverPk,
      createMember: (label) async {
        final s = seedCounter++;
        final seeds = IdentitySeeds(
          signing: Uint8List.fromList(List.filled(32, s)),
          noise: Uint8List.fromList(List.filled(32, s + 100)),
        );
        final keys = await MemberPublicKeys.fromSeeds(seeds);
        authority.enrollMember(groupA, keys.signing, userId: 'usr_$label');
        return (source: authority, seeds: seeds, keys: keys);
      },
      revokeMember: (memberPk, {String reason = 'compromised_credential'}) =>
          authority.revokeMember(groupA, memberPk, reason: reason),
    );
  });

  group('MemberPublicKeys, GrantedKey & MembershipGrant value invariants', () {
    test('MemberPublicKeys enforces 32-byte lengths and defensive copies',
        () async {
      expect(
        () => MemberPublicKeys(signing: Uint8List(31), noise: Uint8List(32)),
        throwsArgumentError,
      );
      expect(
        () => MemberPublicKeys(signing: Uint8List(32), noise: Uint8List(33)),
        throwsArgumentError,
      );

      final rawSign = Uint8List.fromList(List.filled(32, 0x11));
      final rawNoise = Uint8List.fromList(List.filled(32, 0x22));
      final keys = MemberPublicKeys(signing: rawSign, noise: rawNoise);

      rawSign[0] = 0xFF;
      keys.signing[0] = 0xEE;
      expect(keys.signing[0], equals(0x11));

      final same = MemberPublicKeys(
        signing: Uint8List.fromList(List.filled(32, 0x11)),
        noise: Uint8List.fromList(List.filled(32, 0x22)),
      );
      expect(keys, equals(same));
      expect(keys.hashCode, equals(same.hashCode));
    });

    test('GrantedKey enforces positive epoch, 32-byte key, and defensive copy',
        () {
      expect(
        () => GrantedKey(epoch: 0, key: Uint8List(32)),
        throwsArgumentError,
      );
      expect(
        () => GrantedKey(epoch: -1, key: Uint8List(32)),
        throwsArgumentError,
      );
      expect(
        () => GrantedKey(epoch: 1, key: Uint8List(16)),
        throwsArgumentError,
      );

      final raw = Uint8List.fromList(List.filled(32, 0x7A));
      final gk = GrantedKey(epoch: 5, role: KeyRole.tracker, key: raw);
      raw[0] = 0x00;
      gk.key[0] = 0xFF;
      expect(gk.key[0], equals(0x7A));
      expect(gk.role, equals(KeyRole.tracker));
    });

    test(
        'MembershipGrant rejects duplicate epochs, non-32-byte beaconKey, and selects activeAuthoringKey by role',
        () async {
      final authority = await MemoryMembershipSource.create(
        serverSeed: Uint8List.fromList(List.filled(32, 0x51)),
      );
      final seeds = IdentitySeeds(
        signing: Uint8List.fromList(List.filled(32, 1)),
        noise: Uint8List.fromList(List.filled(32, 2)),
      );
      final keys = await MemberPublicKeys.fromSeeds(seeds);
      final base = await authority.fetch(groupA, keys);

      expect(
        () => MembershipGrant(
          cert: base.cert,
          keys: [
            GrantedKey(epoch: 3, role: KeyRole.member, key: Uint8List(32)),
            GrantedKey(epoch: 3, role: KeyRole.tracker, key: Uint8List(32)),
          ],
          beaconKey: Uint8List(32),
          refreshAfter: base.refreshAfter,
        ),
        throwsArgumentError,
      );

      expect(
        () => MembershipGrant(
          cert: base.cert,
          keys: base.keys,
          beaconKey: Uint8List(16),
          refreshAfter: base.refreshAfter,
        ),
        throwsArgumentError,
      );

      // Human member holding member(epoch 2) + tracker(epoch 5) still authors with member(epoch 2)
      final memberGrant = MembershipGrant(
        cert: base.cert,
        keys: [
          GrantedKey(epoch: 1, role: KeyRole.member, key: Uint8List(32)),
          GrantedKey(epoch: 2, role: KeyRole.member, key: Uint8List(32)),
          GrantedKey(epoch: 5, role: KeyRole.tracker, key: Uint8List(32)),
        ],
        beaconKey: Uint8List(32),
        refreshAfter: base.refreshAfter,
      );
      expect(memberGrant.activeAuthoringKey!.epoch, equals(2));
      expect(memberGrant.activeAuthoringKey!.role, equals(KeyRole.member));
      expect(memberGrant.keysByEpoch.keys, containsAll([1, 2, 5]));

      // Write-only tracker holding only tracker keys authors with highest tracker epoch (P4)
      final trackerGrant = MembershipGrant(
        cert: base.cert,
        keys: [
          GrantedKey(epoch: 4, role: KeyRole.tracker, key: Uint8List(32)),
          GrantedKey(epoch: 7, role: KeyRole.tracker, key: Uint8List(32)),
        ],
        beaconKey: Uint8List(32),
        refreshAfter: base.refreshAfter,
      );
      expect(trackerGrant.activeAuthoringKey!.epoch, equals(7));
      expect(trackerGrant.activeAuthoringKey!.role, equals(KeyRole.tracker));
    });
  });

  group(
      'MembershipGrant.verify security checks & MemoryMembershipSource P4/§9.4',
      () {
    late _FixedClock clock;
    late MemoryMembershipSource authority;
    late Uint8List serverPk;
    late MemberPublicKeys aliceKeys;
    late MemberPublicKeys bobKeys;

    setUp(() async {
      clock = _FixedClock(DateTime.utc(2026, 10, 31, 12));
      authority = await MemoryMembershipSource.create(
        serverSeed: Uint8List.fromList(List.filled(32, 0x99)),
        clock: clock,
      );
      serverPk = await authority.serverPublicKey;
      aliceKeys = await MemberPublicKeys.fromSeeds(
        IdentitySeeds(
          signing: Uint8List.fromList(List.filled(32, 0xA1)),
          noise: Uint8List.fromList(List.filled(32, 0xA2)),
        ),
      );
      bobKeys = await MemberPublicKeys.fromSeeds(
        IdentitySeeds(
          signing: Uint8List.fromList(List.filled(32, 0xB1)),
          noise: Uint8List.fromList(List.filled(32, 0xB2)),
        ),
      );
    });

    test('rejects forged certificate signature or wrong pinnedServerKey',
        () async {
      final grant = await authority.fetch(groupA, aliceKeys);
      final wrongServerKp = await MsgP2PCrypto.newKeyPairFromSeed(
        Uint8List.fromList(List.filled(32, 0xFE)),
      );
      final wrongServerPk = await MsgP2PCrypto.getPublicKeyBytes(wrongServerKp);

      await expectLater(
        grant.verify(
          expectedGroup: groupA,
          expectedKeys: aliceKeys,
          pinnedServerKey: wrongServerPk,
          clock: clock,
        ),
        throwsA(
          isA<MembershipException>().having(
            (e) => e.kind,
            'kind',
            MembershipErrorKind.invalidGrant,
          ),
        ),
      );
    });

    test(
        'rejects group mismatch, public key mismatch, expired cert, empty keys',
        () async {
      final grant = await authority.fetch(groupA, aliceKeys);

      // Wrong group
      await expectLater(
        grant.verify(
          expectedGroup: groupB,
          expectedKeys: aliceKeys,
          pinnedServerKey: serverPk,
          clock: clock,
        ),
        throwsA(isA<MembershipException>()),
      );

      // Mismatched signing or noise public keys
      await expectLater(
        grant.verify(
          expectedGroup: groupA,
          expectedKeys: bobKeys,
          pinnedServerKey: serverPk,
          clock: clock,
        ),
        throwsA(isA<MembershipException>()),
      );
      final wrongNoiseKeys = MemberPublicKeys(
        signing: aliceKeys.signing,
        noise: bobKeys.noise,
      );
      await expectLater(
        grant.verify(
          expectedGroup: groupA,
          expectedKeys: wrongNoiseKeys,
          pinnedServerKey: serverPk,
          clock: clock,
        ),
        throwsA(isA<MembershipException>()),
      );

      // Expired certificate
      clock.advance(const Duration(days: 8));
      await expectLater(
        grant.verify(
          expectedGroup: groupA,
          expectedKeys: aliceKeys,
          pinnedServerKey: serverPk,
          clock: clock,
        ),
        throwsA(isA<MembershipException>()),
      );

      // Empty keys
      clock = _FixedClock(DateTime.utc(2026, 10, 31, 12));
      final emptyKeysGrant = MembershipGrant(
        cert: grant.cert,
        keys: const [],
        beaconKey: grant.beaconKey,
        refreshAfter: grant.refreshAfter,
      );
      await expectLater(
        emptyKeysGrant.verify(
          expectedGroup: groupA,
          expectedKeys: aliceKeys,
          pinnedServerKey: serverPk,
          clock: clock,
        ),
        throwsA(isA<MembershipException>()),
      );
    });

    test(
        'rejects forged RevocationNotice, wrong-group RevocationNotice, and self-revocation',
        () async {
      final base = await authority.fetch(groupA, aliceKeys);

      // Forged revocation signature
      final forgedRev = RevocationNotice(
        groupId: groupA.bytes,
        memberPubkey: bobKeys.signing,
        revokedAt: clock.now().millisecondsSinceEpoch,
        reason: 'forged',
        serverSig: Uint8List.fromList(List.filled(64, 0xCC)),
      );
      final forgedGrant = MembershipGrant(
        cert: base.cert,
        keys: base.keys,
        beaconKey: base.beaconKey,
        revocations: [forgedRev],
        refreshAfter: base.refreshAfter,
      );
      await expectLater(
        forgedGrant.verify(
          expectedGroup: groupA,
          expectedKeys: aliceKeys,
          pinnedServerKey: serverPk,
          clock: clock,
        ),
        throwsA(
          isA<MembershipException>().having(
            (e) => e.kind,
            'kind',
            MembershipErrorKind.invalidGrant,
          ),
        ),
      );

      // Validly signed revocation for a DIFFERENT group
      final groupBRev = await authority.revokeMember(groupB, bobKeys.signing);
      final wrongGroupRevGrant = MembershipGrant(
        cert: base.cert,
        keys: base.keys,
        beaconKey: base.beaconKey,
        revocations: [groupBRev],
        refreshAfter: base.refreshAfter,
      );
      await expectLater(
        wrongGroupRevGrant.verify(
          expectedGroup: groupA,
          expectedKeys: aliceKeys,
          pinnedServerKey: serverPk,
          clock: clock,
        ),
        throwsA(
          isA<MembershipException>().having(
            (e) => e.kind,
            'kind',
            MembershipErrorKind.invalidGrant,
          ),
        ),
      );

      // Validly signed revocation targeting Alice's OWN signing key
      final aliceSelfRev =
          await authority.revokeMember(groupA, aliceKeys.signing);
      final selfRevokedGrant = MembershipGrant(
        cert: base.cert,
        keys: base.keys,
        beaconKey: base.beaconKey,
        revocations: [aliceSelfRev],
        refreshAfter: base.refreshAfter,
      );
      await expectLater(
        selfRevokedGrant.verify(
          expectedGroup: groupA,
          expectedKeys: aliceKeys,
          pinnedServerKey: serverPk,
          clock: clock,
        ),
        throwsA(
          isA<MembershipException>().having(
            (e) => e.kind,
            'kind',
            MembershipErrorKind.revoked,
          ),
        ),
      );
    });

    test(
        'MemoryMembershipSource enforces globally unique epochs across groups (§9.4) and tracker-only grants (P4)',
        () async {
      final strictAuthority = await MemoryMembershipSource.create(
        serverSeed: Uint8List.fromList(List.filled(32, 0x77)),
        autoApprove: false,
      );

      // Unenrolled member is rejected with unauthorized
      await expectLater(
        strictAuthority.fetch(groupA, aliceKeys),
        throwsA(
          isA<MembershipException>().having(
            (e) => e.kind,
            'kind',
            MembershipErrorKind.unauthorized,
          ),
        ),
      );

      // Enroll Alice as full member in groupA and groupB, and Bob as tracker-only in groupA
      strictAuthority.enrollMember(groupA, aliceKeys.signing, userId: 'aliceA');
      strictAuthority.enrollMember(groupB, aliceKeys.signing, userId: 'aliceB');
      strictAuthority.enrollMember(
        groupA,
        bobKeys.signing,
        userId: 'dog_collar_1',
        certRole: 3,
        allowedKeyRoles: const {KeyRole.tracker},
      );

      final grantA1 = await strictAuthority.fetch(groupA, aliceKeys);
      final grantB1 = await strictAuthority.fetch(groupB, aliceKeys);
      expect(
        grantA1.keys.map((k) => k.epoch).toSet().intersection(
              grantB1.keys.map((k) => k.epoch).toSet(),
            ),
        isEmpty,
        reason: 'Key epochs must never be reused across groups (§9.4)',
      );

      // Tracker receives ONLY KeyRole.tracker keys and cert role 3
      final trackerGrant = await strictAuthority.fetch(groupA, bobKeys);
      expect(trackerGrant.cert.role, equals(3));
      expect(trackerGrant.keys, isNotEmpty);
      expect(
        trackerGrant.keys.every((k) => k.role == KeyRole.tracker),
        isTrue,
      );

      // Human member refreshing groupA receives BOTH member and tracker keys so it can read tracker telemetry
      final grantA2 = await strictAuthority.fetch(groupA, aliceKeys);
      expect(
        grantA2.keys.map((k) => k.role).toSet(),
        containsAll([KeyRole.member, KeyRole.tracker]),
      );
      expect(grantA2.activeAuthoringKey!.role, equals(KeyRole.member));
    });
  });
}
