import 'dart:io';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart' as cg;
import 'package:msgp2p_core/msgp2p_core.dart';
import 'package:test/test.dart';

import 'key_vault_contract.dart';

/// Proposal 0001, step 2 (Discussion #10): the KeyVault port, the store guard, and the persistent author
/// sequence counter.
void main() {
  runKeyVaultContractTests('MemoryKeyVault', () => MemoryKeyVault());

  group('IdentitySeeds', () {
    test('validate accepts 32-byte seeds and rejects others', () {
      IdentitySeeds(signing: Uint8List(32), noise: Uint8List(32)).validate();
      expect(
          () => IdentitySeeds(signing: Uint8List(31), noise: Uint8List(32))
              .validate(),
          throwsA(isA<KeyVaultCorruptedError>()));
      expect(
          () => IdentitySeeds(
                  version: 2, signing: Uint8List(32), noise: Uint8List(32))
              .validate(),
          throwsA(isA<KeyVaultCorruptedError>()));
    });
  });

  final groupId = Uint8List(16);
  final groupKey = Uint8List.fromList(List.generate(32, (i) => i));
  final certRef = Uint8List(32);

  Future<(cg.SimpleKeyPair, Uint8List)> identity(int fill) async {
    final kp = await MsgP2PCrypto.newKeyPairFromSeed(
        Uint8List.fromList(List.filled(32, fill)));
    return (kp, await MsgP2PCrypto.getPublicKeyBytes(kp));
  }

  Future<Envelope> envelope(cg.SimpleKeyPair author, int seq,
          {Duration ttl = const Duration(hours: 24)}) =>
      Envelope.create(
        groupId: groupId,
        keyEpoch: 1,
        groupKey: groupKey,
        authorKeyPair: author,
        certRef: certRef,
        seq: seq,
        payload: {
          'type': 'test',
          'body': {'n': seq}
        },
        ttl: ttl,
      );

  for (final (name, make) in <(String, MessageStore Function())>[
    ('MemoryMessageStore', MemoryMessageStore.new),
    ('SqliteMessageStore', () => SqliteMessageStore.inMemory()),
  ]) {
    group('store guard ($name)', () {
      test(
          'a new identity and a new store: the owner is recorded, seq starts at 1',
          () async {
        final store = make();
        final (_, pk) = await identity(1);
        expect(
            await guardStoreIdentity(
                store: store, ownerPubkey: pk, created: true),
            0);
        expect(await store.getOwnerPubkey(), pk);
      });

      test('an existing identity with its own store: the last seq', () async {
        final store = make();
        final (kp, pk) = await identity(1);
        await guardStoreIdentity(store: store, ownerPubkey: pk, created: true);
        await store.saveOwnEnvelope(await envelope(kp, 1));
        await store.saveOwnEnvelope(await envelope(kp, 2));
        expect(
            await guardStoreIdentity(
                store: store, ownerPubkey: pk, created: false),
            2);
      });

      test('an existing identity with an empty store: refused (storeEmpty)',
          () async {
        final (_, pk) = await identity(1);
        expect(
            () => guardStoreIdentity(
                store: make(), ownerPubkey: pk, created: false),
            throwsA(isA<UnsynchronizedIdentityException>().having(
                (e) => e.reason,
                'reason',
                UnsynchronizedIdentityReason.storeEmpty)));
      });

      test(
          "an existing identity with another identity's store: refused (ownerMismatch)",
          () async {
        final store = make();
        final (_, a) = await identity(1);
        final (_, b) = await identity(2);
        await guardStoreIdentity(store: store, ownerPubkey: a, created: true);
        expect(
            () => guardStoreIdentity(
                store: store, ownerPubkey: b, created: false),
            throwsA(isA<UnsynchronizedIdentityException>().having(
                (e) => e.reason,
                'reason',
                UnsynchronizedIdentityReason.ownerMismatch)));
      });

      test('a new identity over an old store: adopted, seq starts again',
          () async {
        final store = make();
        final (oldKp, oldPk) = await identity(1);
        final (_, newPk) = await identity(2);
        await guardStoreIdentity(
            store: store, ownerPubkey: oldPk, created: true);
        await store.saveOwnEnvelope(await envelope(oldKp, 1));
        expect(
            await guardStoreIdentity(
                store: store, ownerPubkey: newPk, created: true),
            0);
        expect(await store.getOwnerPubkey(), newPk);
        expect(await store.getEnvelopeCount(), 1,
            reason: 'the old envelopes stay as relayed copies');
      });
    });

    group('author sequence counter ($name)', () {
      test('raised with each own envelope, never lowered by pruning', () async {
        final store = make();
        final (kp, pk) = await identity(1);
        await store.setOwner(pk);
        final now = DateTime.now().millisecondsSinceEpoch;
        expect(
            await store.saveOwnEnvelope(
                await envelope(kp, 1, ttl: const Duration(seconds: 1))),
            isTrue);
        expect(
            await store.saveOwnEnvelope(
                await envelope(kp, 2, ttl: const Duration(seconds: 1))),
            isTrue);
        expect(await store.getAuthorSeq(), 2);

        await store.prune(
            currentTimeMillis: now + const Duration(hours: 1).inMilliseconds);
        expect(await store.getEnvelopeCount(), 0, reason: 'both expired');
        expect(await store.getAuthorSeq(), 2,
            reason: 'a pruned sequence is still used');
      });

      test('a duplicate (author, seq) is refused and leaves the counter',
          () async {
        final store = make();
        final (kp, pk) = await identity(1);
        await store.setOwner(pk);
        await store.saveOwnEnvelope(await envelope(kp, 3));
        expect(await store.saveOwnEnvelope(await envelope(kp, 3)), isFalse);
        expect(await store.getAuthorSeq(), 3);
      });

      test("another author's envelope is not an own envelope", () async {
        final store = make();
        final (_, pk) = await identity(1);
        final (other, _) = await identity(2);
        await store.setOwner(pk);
        expect(() async => store.saveOwnEnvelope(await envelope(other, 1)),
            throwsStateError);
        expect(await store.getAuthorSeq(), 0);
      });

      test('setting the same owner again keeps the counter', () async {
        final store = make();
        final (kp, pk) = await identity(1);
        await store.setOwner(pk);
        await store.saveOwnEnvelope(await envelope(kp, 5));
        await store.setOwner(pk);
        expect(await store.getAuthorSeq(), 5);
      });
    });
  }

  test('SQLite: owner and counter survive reopening the file', () async {
    final dir = Directory.systemTemp.createTempSync('msgp2p_identity');
    addTearDown(() => dir.deleteSync(recursive: true));
    final path = '${dir.path}/store.db';
    final (kp, pk) = await identity(1);

    final first = SqliteMessageStore.open(path);
    await guardStoreIdentity(store: first, ownerPubkey: pk, created: true);
    await first.saveOwnEnvelope(await envelope(kp, 1));
    await first.saveOwnEnvelope(await envelope(kp, 2));
    first.close();

    final reopened = SqliteMessageStore.open(path);
    addTearDown(reopened.close);
    expect(
        await guardStoreIdentity(
            store: reopened, ownerPubkey: pk, created: false),
        2);
  });
}
