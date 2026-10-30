import 'dart:convert';
import 'dart:typed_data';
import 'package:convert/convert.dart';
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
  final Uint8List serverPublicKey;
  final SimpleKeyPair serverKeyPair;
  final Future<void> Function(RevocationNotice notice)? seedRevocation;
  final Future<void> Function()? dispose;

  GatewayApiContext({
    required this.api,
    required this.groupId,
    required this.authorKeyPair,
    required this.groupKey,
    required this.cert,
    required this.serverPublicKey,
    required this.serverKeyPair,
    this.seedRevocation,
    this.dispose,
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
    final otherGroup = GroupId.fromHex('ffffffffffffffffffffffffffffffff');

    setUp(() async {
      ctx = await setup();
    });

    tearDown(() async {
      if (ctx.dispose != null) {
        await ctx.dispose!();
      }
    });

    test(
        'push accepts envelopes, returns verifiable receipts, and deduplicates re-pushes',
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

      expect(pushResult.acceptedIds,
          containsAll([env1.messageIdHex, env2.messageIdHex]));
      expect(pushResult.rejected, isEmpty);
      expect(pushResult.receipts, isNotEmpty);
      for (final r in pushResult.receipts) {
        expect(await r.verify(ctx.serverPublicKey), isTrue);
      }

      final receiptsBeforeDup = await ctx.api.receipts(ctx.groupId);

      // Re-pushing env1 is idempotent: accepted, no duplicate envelope or receipt stored
      final dupPush = await ctx.api.push(
        ctx.groupId,
        [env1],
        certificates: [ctx.cert],
      );
      expect(dupPush.acceptedIds, contains(env1.messageIdHex));

      final pulled = await ctx.api.pull(ctx.groupId, VersionVector());
      expect(pulled.envelopes, hasLength(2));

      final receiptsAfterDup = await ctx.api.receipts(ctx.groupId);
      expect(receiptsAfterDup, hasLength(receiptsBeforeDup.length));
    });

    test('push rejects envelopes addressed to a different group', () async {
      final foreignEnv = await Envelope.create(
        groupId: otherGroup.bytes,
        keyEpoch: 1,
        groupKey: ctx.groupKey,
        authorKeyPair: ctx.authorKeyPair,
        certRef: ctx.cert.certRef,
        seq: 1,
        ttl: const Duration(hours: 24),
        priority: 1,
        payload: {'msg': 'wrong group'},
      );

      final res = await ctx.api.push(ctx.groupId, [foreignEnv]);
      expect(res.acceptedIds, isEmpty);
      expect(res.rejected.map((r) => r.messageId),
          contains(foreignEnv.messageIdHex));

      final pulled = await ctx.api.pull(ctx.groupId, VersionVector());
      expect(pulled.envelopes, isEmpty);
    });

    test(
        'pull orders by priority, computes serverVector, and paginates hasMore accurately',
        () async {
      final baseTime = DateTime.now().millisecondsSinceEpoch;
      final env1 = await Envelope.create(
        groupId: ctx.groupId.bytes,
        keyEpoch: 1,
        groupKey: ctx.groupKey,
        authorKeyPair: ctx.authorKeyPair,
        certRef: ctx.cert.certRef,
        seq: 1,
        customCreatedAt: baseTime,
        ttl: const Duration(hours: 24),
        priority: 2,
        payload: {'msg': 'First normal'},
      );
      final env2 = await Envelope.create(
        groupId: ctx.groupId.bytes,
        keyEpoch: 1,
        groupKey: ctx.groupKey,
        authorKeyPair: ctx.authorKeyPair,
        certRef: ctx.cert.certRef,
        seq: 2,
        customCreatedAt: baseTime + 100,
        ttl: const Duration(hours: 24),
        priority: 2,
        payload: {'msg': 'Second normal'},
      );
      final envSos = await Envelope.create(
        groupId: ctx.groupId.bytes,
        keyEpoch: 1,
        groupKey: ctx.groupKey,
        authorKeyPair: ctx.authorKeyPair,
        certRef: ctx.cert.certRef,
        seq: 3,
        customCreatedAt: baseTime + 200,
        ttl: const Duration(hours: 24),
        priority: 0, // SOS must arrive first
        payload: {'msg': 'Urgent SOS'},
      );

      await ctx.api.push(
        ctx.groupId,
        [env1, env2, envSos],
        certificates: [ctx.cert],
      );

      final authorPk = await ctx.authorKeyPair.extractPublicKey();
      final authorHex = hex.encode(authorPk.bytes);

      // 1. Page 1 with empty vector and limit 2 -> SOS (seq 3) first, hasMore == true
      final page1 = await ctx.api.pull(ctx.groupId, VersionVector(), limit: 2);
      expect(page1.envelopes, hasLength(2));
      expect(page1.envelopes.first.core.seq, equals(3));
      expect(page1.hasMore, isTrue);
      expect(page1.serverVector, isNotNull);
      expect(page1.serverVector!.has(authorHex, 1), isTrue);
      expect(page1.serverVector!.has(authorHex, 2), isTrue);
      expect(page1.serverVector!.has(authorHex, 3), isTrue);

      // 2. Client already holds seq 1, requests limit 2 -> remaining missing is 2 (seq 3, seq 2), so hasMore MUST be false
      final partialVector = VersionVector()..add(authorHex, 1);
      final deltaPull =
          await ctx.api.pull(ctx.groupId, partialVector, limit: 2);
      expect(
          deltaPull.envelopes.map((e) => e.core.seq).toList(), equals([3, 2]));
      expect(deltaPull.hasMore, isFalse);
    });

    test(
        'receipts retrieves group receipts and enforces strict since > timestamp filtering',
        () async {
      final env = await Envelope.create(
        groupId: ctx.groupId.bytes,
        keyEpoch: 1,
        groupKey: ctx.groupKey,
        authorKeyPair: ctx.authorKeyPair,
        certRef: ctx.cert.certRef,
        seq: 1,
        ttl: const Duration(hours: 24),
        priority: 1,
        payload: {'msg': 'Receipt test'},
      );
      await ctx.api.push(ctx.groupId, [env], certificates: [ctx.cert]);

      final allReceipts = await ctx.api.receipts(ctx.groupId);
      expect(allReceipts, isNotEmpty);
      final latestTs = allReceipts.last.issuedAt;

      final beforeTs = await ctx.api.receipts(ctx.groupId, since: latestTs - 1);
      expect(beforeTs, isNotEmpty);

      // Polling with since == latestTs must NOT re-return items at latestTs
      final atTs = await ctx.api.receipts(ctx.groupId, since: latestTs);
      expect(atTs, isEmpty);

      // Group isolation
      expect(await ctx.api.receipts(otherGroup), isEmpty);
    });

    test(
        'revocations retrieves notices and enforces strict since > timestamp filtering',
        () async {
      expect(await ctx.api.revocations(ctx.groupId), isEmpty);
      if (ctx.seedRevocation == null) return;

      Future<RevocationNotice> makeNotice(int fill, int revokedAt) async {
        final core = RevocationNotice(
          groupId: ctx.groupId.bytes,
          memberPubkey: Uint8List.fromList(List.filled(32, fill)),
          revokedAt: revokedAt,
          reason: 'compromised',
          serverSig: Uint8List(64),
        );
        final sig =
            await MsgP2PCrypto.sign(core.toCoreCbor(), ctx.serverKeyPair);
        return RevocationNotice(
          groupId: core.groupId,
          memberPubkey: core.memberPubkey,
          revokedAt: core.revokedAt,
          reason: core.reason,
          serverSig: sig,
        );
      }

      final rev1 = await makeNotice(0xaa, 1000);
      final rev2 = await makeNotice(0xbb, 2000);
      await ctx.seedRevocation!(rev2);
      await ctx.seedRevocation!(rev1);

      final all = await ctx.api.revocations(ctx.groupId);
      expect(all.map((r) => r.revokedAt).toList(), equals([1000, 2000]));

      final afterFirst = await ctx.api.revocations(ctx.groupId, since: 1000);
      expect(afterFirst.map((r) => r.revokedAt).toList(), equals([2000]));

      final afterSecond = await ctx.api.revocations(ctx.groupId, since: 2000);
      expect(afterSecond, isEmpty);

      expect(await ctx.api.revocations(otherGroup), isEmpty);
    });

    test(
        'attachments round-trip, verify SHA-256 integrity, 404 when missing, and isolate groups',
        () async {
      final payloadBytes =
          Uint8List.fromList(utf8.encode('Image test data for SAR'));
      final ref = AttachmentRef.fromBytes(
        bytes: payloadBytes,
        mime: 'image/png',
      );

      // Corrupted upload (mismatched bytes) is rejected
      final corruptedBytes =
          Uint8List.fromList(utf8.encode('Tampered SAR data'));
      await expectLater(
        () => ctx.api.uploadAttachment(ctx.groupId, ref, corruptedBytes),
        throwsA(anyOf(isA<ArgumentError>(), isA<GatewayException>())),
      );

      // Unknown download throws 404 GatewayException
      await expectLater(
        () => ctx.api.downloadAttachment(ctx.groupId, ref),
        throwsA(isA<GatewayException>()
            .having((e) => e.statusCode, 'statusCode', 404)),
      );

      // Valid upload and download round-trip
      await ctx.api.uploadAttachment(ctx.groupId, ref, payloadBytes);
      final downloaded = await ctx.api.downloadAttachment(ctx.groupId, ref);
      expect(downloaded.hash, equals(ref.hash));
      expect(downloaded.mime, equals(ref.mime));
      expect(downloaded.bytes, equals(payloadBytes));

      // Cross-group isolation: otherGroup cannot download ctx.groupId's attachment
      await expectLater(
        () => ctx.api.downloadAttachment(otherGroup, ref),
        throwsA(isA<GatewayException>()
            .having((e) => e.statusCode, 'statusCode', 404)),
      );
    });

    test(
        'syncStore synchronizes envelopes, receipts, and attachments across two stores',
        () async {
      final aliceStore = MemoryMessageStore();
      await aliceStore.saveCertificate(ctx.cert);

      final blobBytes =
          Uint8List.fromList(utf8.encode('Topographic contour map'));
      final attRef = AttachmentRef.fromBytes(
        bytes: blobBytes,
        mime: 'application/octet-stream',
      );
      await aliceStore.saveAttachmentBlob(
        hash: attRef.hash,
        mime: attRef.mime,
        bytes: blobBytes,
      );

      final env = await Envelope.create(
        groupId: ctx.groupId.bytes,
        keyEpoch: 1,
        groupKey: ctx.groupKey,
        authorKeyPair: ctx.authorKeyPair,
        certRef: ctx.cert.certRef,
        seq: 1,
        ttl: const Duration(hours: 12),
        priority: 0,
        payload: {'type': 'sos', 'msg': 'Map attached'},
        attachments: [attRef],
      );
      await aliceStore.saveEnvelope(env);

      final aliceSync = await ctx.api.syncStore(
        store: aliceStore,
        groupId: ctx.groupId,
        pendingEnvelopes: [env],
      );
      expect(aliceSync.pushedCount, equals(1));
      expect(aliceSync.acceptedCount, equals(1));
      expect(aliceSync.attachmentsUploaded, equals(1));
      expect(await aliceStore.isConfirmed(env.core.author, 1), isTrue);

      final bobStore = MemoryMessageStore();
      final bobSync = await ctx.api.syncStore(
        store: bobStore,
        groupId: ctx.groupId,
      );
      expect(bobSync.pulledCount, equals(1));
      expect(bobSync.attachmentsDownloaded, equals(1));
      expect(await bobStore.containsEnvelope(env.messageId), isTrue);
      expect(await bobStore.containsAttachmentBlob(attRef.hash), isTrue);
      expect(await bobStore.isConfirmed(env.core.author, 1), isTrue);
    });
  });
}
