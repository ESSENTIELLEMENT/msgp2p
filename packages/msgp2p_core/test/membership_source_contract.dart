import 'dart:typed_data';

import 'package:convert/convert.dart';
import 'package:msgp2p_core/msgp2p_core.dart';
import 'package:test/test.dart';

/// Provisioned member handle used by [runMembershipSourceContractTests].
typedef ContractMemberHandle = ({
  MembershipSource source,
  IdentitySeeds seeds,
  MemberPublicKeys keys,
});

/// Adapter fixture context for [runMembershipSourceContractTests].
class MembershipSourceContext {
  final GroupId groupId;
  final Uint8List serverPublicKey;
  final Clock clock;

  /// Creates an isolated member client and key pair for [memberLabel] in [groupId].
  final Future<ContractMemberHandle> Function(String memberLabel) createMember;

  /// Optional hook that revokes [memberPubkey] in [groupId] and rotates the group key epoch.
  final Future<RevocationNotice> Function(
    Uint8List memberPubkey, {
    String reason,
  })? revokeMember;

  /// Optional teardown hook invoked after each contract test.
  final Future<void> Function()? dispose;

  const MembershipSourceContext({
    required this.groupId,
    required this.serverPublicKey,
    this.clock = const SystemClock(),
    required this.createMember,
    this.revokeMember,
    this.dispose,
  });
}

/// Shared contract test suite for [MembershipSource] implementations (Proposal 0001, Step 4 & §8).
void runMembershipSourceContractTests(
  String name,
  Future<MembershipSourceContext> Function() setup,
) {
  group('MembershipSource contract ($name)', () {
    late MembershipSourceContext ctx;

    setUp(() async {
      ctx = await setup();
    });

    tearDown(() async {
      if (ctx.dispose != null) {
        await ctx.dispose!();
      }
    });

    test(
        'fetch provisions a cryptographically verifiable grant bound to group and device keys',
        () async {
      final alice = await ctx.createMember('alice');
      final grant = await alice.source.fetch(ctx.groupId, alice.keys);

      await grant.verify(
        expectedGroup: ctx.groupId,
        expectedKeys: alice.keys,
        pinnedServerKey: ctx.serverPublicKey,
        clock: ctx.clock,
      );

      expect(grant.cert.groupId, equals(ctx.groupId.bytes));
      expect(grant.cert.memberPubkey, equals(alice.keys.signing));
      expect(grant.cert.noisePubkey, equals(alice.keys.noise));
      expect(await grant.cert.verify(ctx.serverPublicKey), isTrue);
      expect(
        grant.cert.isExpired(ctx.clock.now().millisecondsSinceEpoch),
        isFalse,
      );
      expect(grant.beaconKey, hasLength(32));
      expect(grant.keys, isNotEmpty);
      expect(grant.activeAuthoringKey, isNotNull);
      expect(grant.activeAuthoringKey!.key, hasLength(32));
      expect(grant.activeAuthoringKey!.epoch, greaterThan(0));
      expect(
        grant.refreshAfter.isAfter(
          ctx.clock.now().subtract(const Duration(seconds: 1)),
        ),
        isTrue,
      );
    });

    test('repeated fetch calls are idempotent and refresh credentials cleanly',
        () async {
      final alice = await ctx.createMember('alice_refresh');
      final first = await alice.source.fetch(ctx.groupId, alice.keys);
      final second = await alice.source.fetch(ctx.groupId, alice.keys);

      await second.verify(
        expectedGroup: ctx.groupId,
        expectedKeys: alice.keys,
        pinnedServerKey: ctx.serverPublicKey,
        clock: ctx.clock,
      );

      expect(second.cert.userId, equals(first.cert.userId));
      expect(second.cert.memberPubkey, equals(alice.keys.signing));
      expect(second.cert.noisePubkey, equals(alice.keys.noise));
      expect(second.beaconKey, equals(first.beaconKey));
      expect(
        second.activeAuthoringKey!.key,
        equals(first.activeAuthoringKey!.key),
      );
    });

    test(
        'two members receive distinct identity certificates and interoperable group keys',
        () async {
      final alice = await ctx.createMember('alice_interop');
      final bob = await ctx.createMember('bob_interop');

      final aliceGrant = await alice.source.fetch(ctx.groupId, alice.keys);
      final bobGrant = await bob.source.fetch(ctx.groupId, bob.keys);

      expect(aliceGrant.cert.userId, isNot(equals(bobGrant.cert.userId)));
      expect(
        hex.encode(aliceGrant.cert.certRef),
        isNot(equals(hex.encode(bobGrant.cert.certRef))),
      );
      expect(aliceGrant.beaconKey, equals(bobGrant.beaconKey));

      final authoringKey = aliceGrant.activeAuthoringKey!;
      final aliceKeyPair =
          await MsgP2PCrypto.newKeyPairFromSeed(alice.seeds.signing);
      final env = await Envelope.create(
        groupId: ctx.groupId.bytes,
        keyEpoch: authoringKey.epoch,
        groupKey: authoringKey.key,
        authorKeyPair: aliceKeyPair,
        certRef: aliceGrant.cert.certRef,
        seq: 1,
        payload: const {
          'type': 'bbs_post',
          'body': {'text': 'Hello via MembershipSource'},
        },
      );

      expect(await env.verifySignature(), isTrue);
      final bobDecryptionKey = bobGrant.keysByEpoch[env.core.keyEpoch];
      expect(bobDecryptionKey, isNotNull);
      final decrypted = await env.decryptPayload(bobDecryptionKey!);
      expect((decrypted['body'] as Map)['text'], 'Hello via MembershipSource');
    });

    test(
        'revoking a member rotates key epoch, delivers signed RevocationNotice in grant (§9.1), and blocks revoked member',
        () async {
      if (ctx.revokeMember == null) return;

      final alice = await ctx.createMember('alice_rev');
      final mallory = await ctx.createMember('mallory_rev');

      final initialAliceGrant =
          await alice.source.fetch(ctx.groupId, alice.keys);
      final initialEpoch = initialAliceGrant.activeAuthoringKey!.epoch;
      await mallory.source.fetch(ctx.groupId, mallory.keys);

      final issuedRev = await ctx.revokeMember!(
        mallory.keys.signing,
        reason: 'compromised_device',
      );
      expect(await issuedRev.verify(ctx.serverPublicKey), isTrue);

      final refreshedAliceGrant =
          await alice.source.fetch(ctx.groupId, alice.keys);
      await refreshedAliceGrant.verify(
        expectedGroup: ctx.groupId,
        expectedKeys: alice.keys,
        pinnedServerKey: ctx.serverPublicKey,
        clock: ctx.clock,
      );

      expect(
        refreshedAliceGrant.activeAuthoringKey!.epoch,
        greaterThan(initialEpoch),
      );
      final matchingRevs = refreshedAliceGrant.revocations.where(
        (r) => hex.encode(r.memberPubkey) == mallory.keys.signingHex,
      );
      expect(matchingRevs, isNotEmpty);
      expect(
        await matchingRevs.first.verify(ctx.serverPublicKey),
        isTrue,
      );

      await expectLater(
        mallory.source.fetch(ctx.groupId, mallory.keys),
        throwsA(
          isA<MembershipException>().having(
            (e) => e.kind,
            'kind',
            MembershipErrorKind.revoked,
          ),
        ),
      );
    });
  });
}
