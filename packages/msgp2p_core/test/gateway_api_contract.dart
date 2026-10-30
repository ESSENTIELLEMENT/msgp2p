import 'dart:convert';
import 'dart:typed_data';
import 'package:cryptography/cryptography.dart';
import 'package:msgp2p_core/msgp2p_core.dart';
import 'package:test/test.dart';

/// Context provided to the [GatewayApi] contract suite.
class GatewayApiContext {
  final GatewayApi api;
  final GroupId groupId;
  final SimpleKeyPair authorKeyPair;
  final Uint8List groupKey;
  final MembershipCert cert;

  GatewayApiContext({
    required this.api,
    required this.groupId,
    required this.authorKeyPair,
    required this.groupKey,
    required this.cert,
  });
}

/// The `GatewayApi` contract suite (Proposal 0001, Step 3).
///
/// Runs against every [GatewayApi] implementation ([MemoryGatewayApi], [GatewayClient], etc.).
void runGatewayApiContractTests(
  String name,
  Future<GatewayApiContext> Function() setup,
) {
  group('GatewayApi contract ($name)', () {
    late GatewayApiContext ctx;

    setUp(() async {
      ctx = await setup();
    });

    test('push accepts envelopes and returns accepted IDs and receipts',
        () async {
      final env1 = await Envelope.create(
        groupId: ctx.groupId.bytes,
        keyEpoch: 1,
        groupKey: ctx.groupKey,
        authorKeyPair: ctx.authorKeyPair,
        certRef: ctx.cert.certRef,
        seq: 1,
        ttl: const Duration(hours: 24),
        priority: 0,
        payload: {
          'type': 'sos',
          'body': 'Emergency at sector 4',
        },
      );

      final env2 = await Envelope.create(
        groupId: ctx.groupId.bytes,
        keyEpoch: 1,
        groupKey: ctx.groupKey,
        authorKeyPair: ctx.authorKeyPair,
        certRef: ctx.cert.certRef,
        seq: 2,
        ttl: const Duration(hours: 24),
        priority: 2,
        payload: {
          'type': 'chat',
          'body': 'All clear',
        },
      );

      final pushResult = await ctx.api.push(
        ctx.groupId,
        [env1, env2],
        certificates: [ctx.cert],
      );

      expect(pushResult.acceptedIds, contains(env1.messageIdHex));
      expect(pushResult.acceptedIds, contains(env2.messageIdHex));
      expect(pushResult.rejected, isEmpty);
    });

    test('pull returns missing envelopes newer than version vector', () async {
      final env1 = await Envelope.create(
        groupId: ctx.groupId.bytes,
        keyEpoch: 1,
        groupKey: ctx.groupKey,
        authorKeyPair: ctx.authorKeyPair,
        certRef: ctx.cert.certRef,
        seq: 1,
        ttl: const Duration(hours: 24),
        priority: 0,
        payload: {'msg': 'First'},
      );

      final env2 = await Envelope.create(
        groupId: ctx.groupId.bytes,
        keyEpoch: 1,
        groupKey: ctx.groupKey,
        authorKeyPair: ctx.authorKeyPair,
        certRef: ctx.cert.certRef,
        seq: 2,
        ttl: const Duration(hours: 24),
        priority: 1,
        payload: {'msg': 'Second'},
      );

      await ctx.api.push(ctx.groupId, [env1, env2], certificates: [ctx.cert]);

      // 1. Pull with empty vector -> returns both
      final emptyPull = await ctx.api.pull(ctx.groupId, VersionVector());
      expect(emptyPull.envelopes.map((e) => e.messageIdHex),
          containsAll([env1.messageIdHex, env2.messageIdHex]));

      // 2. Pull with vector acknowledging seq 1 -> returns only seq 2
      final authorPk = await ctx.authorKeyPair.extractPublicKey();
      final authorHex = Uint8List.fromList(authorPk.bytes)
          .map((b) => b.toRadixString(16).padLeft(2, '0'))
          .join();
      final partialVector = VersionVector()..add(authorHex, 1);

      final deltaPull = await ctx.api.pull(ctx.groupId, partialVector);
      final deltaSeqs = deltaPull.envelopes.map((e) => e.core.seq).toList();
      expect(deltaSeqs, contains(2));
      expect(deltaSeqs, isNot(contains(1)));
    });

    test('uploadAttachment and downloadAttachment round-trip blob bytes',
        () async {
      final payloadBytes =
          Uint8List.fromList(utf8.encode('Image test data for SAR'));
      final ref = AttachmentRef.fromBytes(
        bytes: payloadBytes,
        mime: 'image/png',
      );

      await ctx.api.uploadAttachment(ctx.groupId, ref, payloadBytes);

      final downloaded = await ctx.api.downloadAttachment(ctx.groupId, ref);
      expect(downloaded.hash, equals(ref.hash));
      expect(downloaded.mime, equals(ref.mime));
      expect(downloaded.bytes, equals(payloadBytes));
    });

    test('receipts retrieves receipts for the group', () async {
      final receipts = await ctx.api.receipts(ctx.groupId);
      expect(receipts, isA<List<ServerReceipt>>());
    });

    test('revocations retrieves revocation notices for the group', () async {
      final revs = await ctx.api.revocations(ctx.groupId);
      expect(revs, isA<List<RevocationNotice>>());
    });
  });
}
