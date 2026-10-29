import 'dart:typed_data';

import 'package:cryptography/cryptography.dart' as cg;
import 'package:flutter_test/flutter_test.dart';
import 'package:msgp2p_flutter/msgp2p_flutter.dart';

/// Proposal 0001, step 2 (Discussion #10): a node keeps its identity through a KeyVault, continues its
/// sequence numbers from the store after a restart, and refuses to author when the store does not belong to
/// the identity.
void main() {
  final groupId = Uint8List.fromList(List.generate(16, (i) => i + 1));
  final groupKey = Uint8List.fromList(List.generate(32, (i) => i + 10));
  final medium = LoopbackBleMedium();
  var nodes = 0;

  IdentitySeeds seedsOf(int byte) => IdentitySeeds(
        signing: Uint8List.fromList(List.filled(32, byte)),
        noise: Uint8List.fromList(List.filled(32, byte + 50)),
      );

  /// A node whose certificate is made for [seeds] (publish only references the certificate; its server
  /// signature is not checked when authoring).
  Future<MsgP2PNode> start(
      KeyVault vault, IdentitySeeds seeds, MessageStore store) async {
    final memberPk = await MsgP2PCrypto.getPublicKeyBytes(
        await MsgP2PCrypto.newKeyPairFromSeed(seeds.signing));
    final noisePk = await NoiseHandshake.getPublicKeyBytes(
        await cg.X25519().newKeyPairFromSeed(seeds.noise));
    return MsgP2PNode.initialize(
      config: MsgP2PConfig(
        serverEndpoint: Uri.parse('http://localhost:8000/api/v1'),
        serverPublicKey: Uint8List(32),
        groupId: groupId,
      ),
      store: store,
      transport:
          AndroidBleTransport(bridge: medium.createBridge('node${nodes++}')),
      keyVault: vault,
      initialCert: MembershipCert(
        groupId: groupId,
        userId: 'me',
        memberPubkey: memberPk,
        noisePubkey: noisePk,
        role: 0,
        issuedAt: 0,
        expiresAt: DateTime.now().millisecondsSinceEpoch + 86400000,
        serverSig: Uint8List(64),
      ),
      initialGroupKeys: {1: groupKey},
    );
  }

  test('restart: same identity, the sequence continues from the store',
      () async {
    final seeds = seedsOf(1);
    final vault = MemoryKeyVault.fromSeeds(seeds);
    final store = MemoryMessageStore();

    final first = await start(vault, seeds, store);
    expect((await first.publish(type: 't', body: {})).core.seq, 1);
    expect((await first.publish(type: 't', body: {})).core.seq, 2);

    final restarted = await start(vault, seeds, store);
    expect(restarted.memberPubkey, first.memberPubkey);
    expect((await restarted.publish(type: 't', body: {})).core.seq, 3);
    expect(await store.getAuthorSeq(), 3);
  });

  test('concurrent publishes get consecutive sequence numbers', () async {
    final seeds = seedsOf(2);
    final node = await start(
        MemoryKeyVault.fromSeeds(seeds), seeds, MemoryMessageStore());
    final envelopes = await Future.wait(
        List.generate(5, (_) => node.publish(type: 't', body: {})));
    expect(envelopes.map((e) => e.core.seq).toList()..sort(), [1, 2, 3, 4, 5]);
  });

  test('an existing identity with an empty store is refused', () async {
    final seeds = seedsOf(3);
    final vault = MemoryKeyVault.fromSeeds(seeds);
    await start(vault, seeds, MemoryMessageStore());
    await expectLater(
        start(vault, seeds, MemoryMessageStore()),
        throwsA(isA<UnsynchronizedIdentityException>().having((e) => e.reason,
            'reason', UnsynchronizedIdentityReason.storeEmpty)));
  });

  test('after erase the vault gives a new identity, which adopts the store',
      () async {
    final seeds = seedsOf(4);
    final vault = MemoryKeyVault.fromSeeds(seeds);
    final store = MemoryMessageStore();
    final first = await start(vault, seeds, store);
    await vault.erase();
    final second = await start(vault, seeds, store);
    expect(second.memberPubkey, isNot(first.memberPubkey));
    expect(await store.getOwnerPubkey(), second.memberPubkey);
  });
}
