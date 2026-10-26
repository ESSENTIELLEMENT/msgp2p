import 'dart:typed_data';
import 'package:cryptography/cryptography.dart' as cg;
import 'package:msgp2p_core/msgp2p_core.dart';

/// In-memory model of reference central server gateway for simulation (FR-SRV-01..03).
class SimServer {
  final cg.SimpleKeyPair serverKeyPair;
  final Uint8List serverPubkey;
  final MemoryMessageStore store = MemoryMessageStore();
  final List<ServerReceipt> issuedReceipts = [];

  SimServer._({
    required this.serverKeyPair,
    required this.serverPubkey,
  });

  static Future<SimServer> create([Uint8List? seed]) async {
    final effectiveSeed = seed ?? (Uint8List(32)..fillRange(0, 32, 0xEE));
    final kp = await MsgP2PCrypto.newKeyPairFromSeed(effectiveSeed);
    final pk = await MsgP2PCrypto.getPublicKeyBytes(kp);
    return SimServer._(serverKeyPair: kp, serverPubkey: pk);
  }

  /// Ingests messages pushed by a gateway node and generates signed [ServerReceipt]s for all authors.
  Future<List<ServerReceipt>> pushEnvelopesBatch(
    List<Envelope> envelopes,
    int currentTimeMs,
  ) async {
    if (envelopes.isEmpty) return const [];

    final byAuthor = <String, List<int>>{};
    final authorBytesByKey = <String, Uint8List>{};
    for (final env in envelopes) {
      final valid = await env.verifySignature();
      if (valid) {
        await store.saveEnvelope(env, customStoredAt: currentTimeMs);
        final key = String.fromCharCodes(env.core.author);
        authorBytesByKey[key] = env.core.author;
        byAuthor.putIfAbsent(key, () => []).add(env.core.seq);
      }
    }

    if (byAuthor.isEmpty) return const [];

    final receipts = <ServerReceipt>[];
    for (final entry in byAuthor.entries) {
      final authorBytes = authorBytesByKey[entry.key]!;
      final seqs = entry.value..sort();
      final mergedRanges =
          SeqRange.mergeRanges(seqs.map((s) => SeqRange(s, s)).toList());

      final core = ServerReceipt(
        groupId: envelopes.first.core.groupId,
        author: authorBytes,
        ranges: mergedRanges,
        issuedAt: currentTimeMs,
        serverSig: Uint8List(0),
      );
      final sig = await MsgP2PCrypto.sign(core.toCoreCbor(), serverKeyPair);
      final receipt = ServerReceipt(
        groupId: envelopes.first.core.groupId,
        author: authorBytes,
        ranges: mergedRanges,
        issuedAt: currentTimeMs,
        serverSig: sig,
      );

      issuedReceipts.add(receipt);
      await store.saveReceipt(receipt);
      receipts.add(receipt);
    }
    return receipts;
  }

  /// Legacy single-receipt wrapper for backwards compatibility.
  Future<ServerReceipt?> pushEnvelopes(
      List<Envelope> envelopes, int currentTimeMs) async {
    final list = await pushEnvelopesBatch(envelopes, currentTimeMs);
    return list.isEmpty ? null : list.first;
  }
}
