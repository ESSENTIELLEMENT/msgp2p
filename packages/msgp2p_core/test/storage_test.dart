import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';
import 'package:convert/convert.dart';
import 'package:msgp2p_core/msgp2p_core.dart';
import 'package:test/test.dart';

void main() {
  late Uint8List alicePk;
  late Uint8List aliceSeed;
  late Uint8List bobPk;
  late Uint8List bobSeed;
  late Uint8List groupId;
  late Uint8List groupKey;

  setUpAll(() {
    var dir = Directory.current;
    while (!File('${dir.path}/protocol/test-vectors/crypto_keys.json')
        .existsSync()) {
      final parent = dir.parent;
      if (parent.path == dir.path) {
        throw StateError('Cannot find protocol/test-vectors/');
      }
      dir = parent;
    }
    final vDir = '${dir.path}/protocol/test-vectors';

    final cryptoKeys =
        jsonDecode(File('$vDir/crypto_keys.json').readAsStringSync());
    alicePk =
        Uint8List.fromList(hex.decode(cryptoKeys['alice']['public_key_hex']));
    aliceSeed = Uint8List.fromList(hex.decode(cryptoKeys['alice']['seed_hex']));
    bobPk = Uint8List.fromList(hex.decode(cryptoKeys['bob']['public_key_hex']));
    bobSeed = Uint8List.fromList(hex.decode(cryptoKeys['bob']['seed_hex']));
    groupId = Uint8List.fromList(hex.decode(cryptoKeys['group_id_hex']));
    groupKey =
        Uint8List.fromList(hex.decode(cryptoKeys['group_key_epoch_1_hex']));
  });

  Future<Envelope> makeEnvelope({
    required Uint8List authorSeed,
    required int seq,
    int priority = 2,
    int? createdAt,
    Duration ttl = const Duration(hours: 24),
  }) async {
    final kp = await MsgP2PCrypto.newKeyPairFromSeed(authorSeed);
    return Envelope.create(
      groupId: groupId,
      keyEpoch: 1,
      authorKeyPair: kp,
      seq: seq,
      customCreatedAt: createdAt,
      ttl: ttl,
      priority: priority,
      groupKey: groupKey,
      payload: {'text': 'msg $seq'},
      certRef: Uint8List(32),
    );
  }

  void runMessageStoreContractTests(
    String backendName,
    MessageStore Function({int maxStorageBytes}) createStore,
    void Function(MessageStore store) disposeStore,
  ) {
    group('$backendName - Core CRUD & Invariants', () {
      test('Saves envelope and prevents duplicates', () async {
        final store = createStore();
        addTearDown(() => disposeStore(store));

        final env = await makeEnvelope(authorSeed: aliceSeed, seq: 1);

        expect(await store.containsEnvelope(env.messageId), isFalse);
        expect(await store.isSequenceHeld(alicePk, 1), isFalse);

        final saved = await store.saveEnvelope(env);
        expect(saved, isTrue);
        expect(store.currentStorageBytes, greaterThan(0));
        expect(await store.getEnvelopeCount(), equals(1));

        expect(await store.containsEnvelope(env.messageId), isTrue);
        expect(await store.isSequenceHeld(alicePk, 1), isTrue);

        // Duplicate insertion must return false and not inflate storage
        final initialBytes = store.currentStorageBytes;
        final duplicateSaved = await store.saveEnvelope(env);
        expect(duplicateSaved, isFalse);
        expect(store.currentStorageBytes, equals(initialBytes));
        expect(await store.getEnvelopeCount(), equals(1));

        final fetched = await store.getEnvelope(env.messageId);
        expect(fetched, isNotNull);
        expect(fetched!.messageId, equals(env.messageId));
      });

      test('Batch ingestion saves unique envelopes', () async {
        final store = createStore();
        addTearDown(() => disposeStore(store));

        final env1 = await makeEnvelope(authorSeed: aliceSeed, seq: 1);
        final env2 = await makeEnvelope(authorSeed: aliceSeed, seq: 2);

        final count = await store.saveBatch([env1, env2, env1]);
        expect(count, equals(2));
        expect(await store.getEnvelopeCount(), equals(2));
      });

      test('Query envelopes by author and SeqRanges', () async {
        final store = createStore();
        addTearDown(() => disposeStore(store));

        final envs = <Envelope>[];
        for (var s = 1; s <= 5; s++) {
          envs.add(await makeEnvelope(authorSeed: aliceSeed, seq: s));
        }
        await store.saveBatch(envs);

        // Query ranges [1, 2] and [4, 5] (expecting seq 1, 2, 4, 5)
        final queried = await store.getEnvelopesByAuthorAndRanges(
          alicePk,
          [const SeqRange(1, 2), const SeqRange(4, 5)],
        );

        expect(queried.map((e) => e.core.seq).toList(), equals([1, 2, 4, 5]));
      });

      test('Computes exact VersionVector matching held sequences', () async {
        final store = createStore();
        addTearDown(() => disposeStore(store));

        final aliceHex = hex.encode(alicePk);
        final bobHex = hex.encode(bobPk);

        // Alice has 1, 2, 4 (contiguous: 2, gap: 4)
        await store
            .saveEnvelope(await makeEnvelope(authorSeed: aliceSeed, seq: 1));
        await store
            .saveEnvelope(await makeEnvelope(authorSeed: aliceSeed, seq: 2));
        await store
            .saveEnvelope(await makeEnvelope(authorSeed: aliceSeed, seq: 4));

        // Bob has 1, 2, 3 (contiguous: 3, gaps: empty)
        await store
            .saveEnvelope(await makeEnvelope(authorSeed: bobSeed, seq: 1));
        await store
            .saveEnvelope(await makeEnvelope(authorSeed: bobSeed, seq: 2));
        await store
            .saveEnvelope(await makeEnvelope(authorSeed: bobSeed, seq: 3));

        final vv = await store.getVersionVector();

        expect(vv.authors[aliceHex]!.contiguous, equals(2));
        expect(vv.authors[aliceHex]!.gaps, equals({4}));
        expect(vv.has(aliceHex, 1), isTrue);
        expect(vv.has(aliceHex, 2), isTrue);
        expect(vv.has(aliceHex, 3), isFalse);
        expect(vv.has(aliceHex, 4), isTrue);

        expect(vv.authors[bobHex]!.contiguous, equals(3));
        expect(vv.authors[bobHex]!.gaps, isEmpty);
      });
    });

    group('$backendName - Receipts, Certs & Revocations', () {
      test('ServerReceipt marks sequence confirmation and isConfirmed check',
          () async {
        final store = createStore();
        addTearDown(() => disposeStore(store));

        final env1 = await makeEnvelope(authorSeed: aliceSeed, seq: 1);
        final env2 = await makeEnvelope(authorSeed: aliceSeed, seq: 2);
        await store.saveBatch([env1, env2]);

        expect(await store.isConfirmed(alicePk, 1), isFalse);
        expect(await store.isConfirmed(alicePk, 2), isFalse);

        final receipt = ServerReceipt(
          version: 1,
          groupId: groupId,
          author: alicePk,
          ranges: [const SeqRange(1, 1)],
          issuedAt: DateTime.now().millisecondsSinceEpoch,
          serverSig: Uint8List(64),
        );

        await store.saveReceipt(receipt);

        expect(await store.isConfirmed(alicePk, 1), isTrue);
        expect(await store.isConfirmed(alicePk, 2), isFalse);

        final receipts = await store.getReceipts();
        expect(receipts.length, equals(1));
        expect(receipts.first.author, equals(alicePk));

        final filteredReceipts =
            await store.getReceipts(sinceTimestamp: receipt.issuedAt);
        expect(filteredReceipts.length, equals(1));
        final futureReceipts =
            await store.getReceipts(sinceTimestamp: receipt.issuedAt + 10000);
        expect(futureReceipts, isEmpty);
      });

      test('Stores and retrieves MembershipCert and RevocationNotice',
          () async {
        final store = createStore();
        addTearDown(() => disposeStore(store));

        final cert = MembershipCert(
          version: 1,
          groupId: groupId,
          userId: 'alice',
          memberPubkey: alicePk,
          noisePubkey: Uint8List(32),
          role: 0,
          issuedAt: 1000,
          expiresAt: 2000,
          serverSig: Uint8List(64),
        );
        await store.saveCertificate(cert);

        final fetchedCert = await store.getCertificate(cert.certRef);
        expect(fetchedCert, isNotNull);
        expect(fetchedCert!.userId, equals('alice'));

        expect(await store.isRevoked(bobPk), isFalse);
        final revocation = RevocationNotice(
          version: 1,
          groupId: groupId,
          memberPubkey: bobPk,
          revokedAt: 1500,
          reason: 'lost key',
          serverSig: Uint8List(64),
        );
        await store.saveRevocation(revocation);

        expect(await store.isRevoked(bobPk), isTrue);
        final revocations = await store.getRevocations();
        expect(revocations.length, equals(1));
      });
    });

    group('$backendName - Quota Management & Eviction (FR-SYNC-05)', () {
      test('Pass 1: Prunes expired messages', () async {
        final store = createStore();
        addTearDown(() => disposeStore(store));

        const now = 100000;

        // Expired message (expiresAt <= now)
        final expiredEnv = await makeEnvelope(
          authorSeed: aliceSeed,
          seq: 1,
          createdAt: 50000,
          ttl:
              const Duration(milliseconds: 40000), // expires at 90000 <= 100000
        );
        // Valid unexpired message
        final validEnv = await makeEnvelope(
          authorSeed: aliceSeed,
          seq: 2,
          createdAt: 95000,
          ttl: const Duration(
              milliseconds: 105000), // expires at 200000 > 100000
        );

        await store.saveBatch([expiredEnv, validEnv]);
        expect(await store.getEnvelopeCount(), equals(2));

        final pruned = await store.prune(currentTimeMillis: now);
        expect(pruned, equals(1));
        expect(await store.getEnvelopeCount(), equals(1));
        expect(await store.containsEnvelope(expiredEnv.messageId), isFalse);
        expect(await store.containsEnvelope(validEnv.messageId), isTrue);
      });

      test('Pass 2: Prunes confirmed messages older than retention window',
          () async {
        final store = createStore();
        addTearDown(() => disposeStore(store));

        const now = 100000;
        final env = await makeEnvelope(
          authorSeed: aliceSeed,
          seq: 1,
          createdAt: 10000,
        );
        await store.saveEnvelope(env, customStoredAt: 10000);

        // Confirm with server receipt
        await store.saveReceipt(ServerReceipt(
          version: 1,
          groupId: groupId,
          author: alicePk,
          ranges: [const SeqRange(1, 1)],
          issuedAt: 20000,
          serverSig: Uint8List(64),
        ));

        // With a 10-second retention window, confirmed message stored at 10000 is pruned at now=100000
        final pruned = await store.prune(
          currentTimeMillis: now,
          retentionWindow: const Duration(seconds: 10),
        );
        expect(pruned, equals(1));
        expect(await store.getEnvelopeCount(), equals(0));
      });

      test(
          'Pass 3: Evicts by priority order (Low first, then Normal, then High; preserves SOS)',
          () async {
        // Create store with tiny quota (500 bytes - holds roughly 2 envelopes)
        final store = createStore(maxStorageBytes: 500);
        addTearDown(() => disposeStore(store));

        const now = 100000;
        final sos = await makeEnvelope(
          authorSeed: aliceSeed,
          seq: 1,
          priority: 0, // SOS
          createdAt: 1000,
        );
        final high = await makeEnvelope(
          authorSeed: aliceSeed,
          seq: 2,
          priority: 1, // High
          createdAt: 2000,
        );
        final normal = await makeEnvelope(
          authorSeed: aliceSeed,
          seq: 3,
          priority: 2, // Normal
          createdAt: 3000,
        );
        final low = await makeEnvelope(
          authorSeed: aliceSeed,
          seq: 4,
          priority: 3, // Low
          createdAt: 4000,
        );

        await store.saveBatch([sos, high, normal, low]);
        expect(await store.getEnvelopeCount(), equals(4));
        expect(store.currentStorageBytes, greaterThan(store.maxStorageBytes));

        // Run prune under storage pressure
        final prunedCount = await store.prune(currentTimeMillis: now);
        expect(prunedCount, greaterThanOrEqualTo(2));

        // Low (priority 3) and Normal (priority 2) should be evicted first.
        expect(await store.containsEnvelope(low.messageId), isFalse);
        expect(await store.containsEnvelope(normal.messageId), isFalse);
        // SOS (priority 0) MUST be preserved!
        expect(await store.containsEnvelope(sos.messageId), isTrue);
      });

      test(
          'Pass 3b: Last-resort SOS eviction when storage quota is smaller than SOS messages',
          () async {
        final store = createStore(maxStorageBytes: 10);
        addTearDown(() => disposeStore(store));

        final sos1 = await makeEnvelope(
            authorSeed: aliceSeed, seq: 1, priority: 0, createdAt: 1000);
        final sos2 = await makeEnvelope(
            authorSeed: aliceSeed, seq: 2, priority: 0, createdAt: 2000);
        await store.saveBatch([sos1, sos2]);

        final evicted = await store.prune(currentTimeMillis: 5000);
        expect(evicted, equals(2));
        expect(await store.getEnvelopeCount(), equals(0));
      });
    });

    group('$backendName - Hash-Addressed Attachment Blobs (v0.2)', () {
      test(
          'Stores, verifies SHA-256 hash, and detects missing attachment blobs',
          () async {
        final store = createStore();
        addTearDown(() => disposeStore(store));

        final blobBytes =
            Uint8List.fromList(List.generate(512, (i) => (i * 13) & 0xFF));
        final attRef =
            AttachmentRef.fromBytes(bytes: blobBytes, mime: 'image/jpeg');
        expect(attRef.verifyBytes(blobBytes), isTrue);

        final authorKeyPair = await MsgP2PCrypto.newKeyPairFromSeed(aliceSeed);
        final env = await Envelope.create(
          groupId: groupId,
          keyEpoch: 1,
          groupKey: groupKey,
          authorKeyPair: authorKeyPair,
          certRef: Uint8List(32),
          seq: 1,
          payload: {
            'type': 'bbs_post',
            'body': {'text': 'Photo attached'}
          },
          attachments: [attRef],
        );

        await store.saveEnvelope(env);

        // Before blob is saved, getMissingAttachments returns the reference
        final missing1 = await store.getMissingAttachments();
        expect(missing1.length, equals(1));
        expect(missing1.first.hash, equals(attRef.hash));
        expect(await store.containsAttachmentBlob(attRef.hash), isFalse);

        // Tampered bytes must be rejected
        final tampered = Uint8List.fromList(blobBytes);
        tampered[0] ^= 0xFF;
        await expectLater(
          () => store.saveAttachmentBlob(
            hash: attRef.hash,
            mime: 'image/jpeg',
            bytes: tampered,
          ),
          throwsArgumentError,
        );

        // Valid bytes are stored and deduplicated
        expect(
          await store.saveAttachmentBlob(
            hash: attRef.hash,
            mime: 'image/jpeg',
            bytes: blobBytes,
          ),
          isTrue,
        );
        expect(
          await store.saveAttachmentBlob(
            hash: attRef.hash,
            mime: 'image/jpeg',
            bytes: blobBytes,
          ),
          isFalse,
        );
        expect(await store.containsAttachmentBlob(attRef.hash), isTrue);

        final storedBlob = await store.getAttachmentBlob(attRef.hash);
        expect(storedBlob, isNotNull);
        expect(storedBlob!.bytes, equals(blobBytes));
        expect(storedBlob.mime, equals('image/jpeg'));

        final missing2 = await store.getMissingAttachments();
        expect(missing2, isEmpty);
      });
    });
  }

  runMessageStoreContractTests(
    'MemoryMessageStore',
    ({int maxStorageBytes = 100 * 1024 * 1024}) =>
        MemoryMessageStore(maxStorageBytes: maxStorageBytes),
    (_) {},
  );

  runMessageStoreContractTests(
    'SqliteMessageStore (inMemory)',
    ({int maxStorageBytes = 100 * 1024 * 1024}) =>
        SqliteMessageStore.inMemory(maxStorageBytes: maxStorageBytes),
    (store) => (store as SqliteMessageStore).close(),
  );

  group(
      'SqliteMessageStore - WAL Mode, Persistence & Atomic Batch Rollback (NFR-REL-01)',
      () {
    late Directory tempDir;

    setUp(() async {
      tempDir = await Directory.systemTemp.createTemp('msgp2p_sqlite_test_');
    });

    tearDown(() async {
      if (await tempDir.exists()) {
        await tempDir.delete(recursive: true);
      }
    });

    test(
        'File-backed database enables WAL journal mode and persists data across reopen',
        () async {
      final dbPath = '${tempDir.path}/store.db';
      final store1 = SqliteMessageStore.open(dbPath);

      expect(store1.journalMode, equals('wal'));

      final env1 = await makeEnvelope(authorSeed: aliceSeed, seq: 1);
      final env2 = await makeEnvelope(authorSeed: aliceSeed, seq: 2);
      await store1.saveBatch([env1, env2]);
      store1.close();

      // Reopen from disk and verify envelopes and version vector survived
      final store2 = SqliteMessageStore.open(dbPath);
      addTearDown(store2.close);

      expect(await store2.getEnvelopeCount(), equals(2));
      expect(await store2.containsEnvelope(env1.messageId), isTrue);
      expect(await store2.containsEnvelope(env2.messageId), isTrue);

      final vv = await store2.getVersionVector();
      expect(vv.authors[hex.encode(alicePk)]!.contiguous, equals(2));
    });

    test(
        'Atomic batch ingestion rolls back entire batch on mid-batch crash/error (NFR-REL-01)',
        () async {
      final dbPath = '${tempDir.path}/crash_test.db';
      final env1 = await makeEnvelope(authorSeed: aliceSeed, seq: 1);
      final env2 = await makeEnvelope(authorSeed: aliceSeed, seq: 2);
      final env3 = await makeEnvelope(authorSeed: aliceSeed, seq: 3);

      // Save env1 in a committed transaction first
      final store = SqliteMessageStore.open(
        dbPath,
        onBatchItemBeforeCommit: (index, _) {
          if (index == 1) {
            throw StateError(
                'Simulated mid-batch power loss / IO fault after second item');
          }
        },
      );
      addTearDown(store.close);

      await store.saveEnvelope(env1);
      expect(await store.getEnvelopeCount(), equals(1));

      // Attempt batch [env2, env3] which throws on index == 1 (env3)
      await expectLater(
        () => store.saveBatch([env2, env3]),
        throwsA(isA<StateError>()),
      );

      // Neither env2 nor env3 should be present; only env1 remains
      expect(await store.getEnvelopeCount(), equals(1));
      expect(await store.containsEnvelope(env1.messageId), isTrue);
      expect(await store.containsEnvelope(env2.messageId), isFalse);
      expect(await store.containsEnvelope(env3.messageId), isFalse);
    });
  });
}
