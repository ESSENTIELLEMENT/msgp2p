import 'dart:async';
import 'dart:io';
import 'dart:typed_data';
import 'package:convert/convert.dart';
import 'package:cryptography/cryptography.dart' as cg;
import 'package:msgp2p_core/msgp2p_core.dart';
import 'package:test/test.dart';

/// Bidirectional in-memory pipe connecting two [PeerLink]s for unit testing.
class DirectPeerLinkPair {
  late final DirectPeerLink a;
  late final DirectPeerLink b;

  DirectPeerLinkPair({int mtu = 512}) {
    final aToB = StreamController<Uint8List>.broadcast();
    final bToA = StreamController<Uint8List>.broadcast();
    a = DirectPeerLink._(
      mtu: mtu,
      rxStream: bToA.stream,
      txSink: aToB,
    );
    b = DirectPeerLink._(
      mtu: mtu,
      rxStream: aToB.stream,
      txSink: bToA,
    );
    a._peer = b;
    b._peer = a;
  }
}

class DirectPeerLink implements PeerLink {
  @override
  final int mtu;
  final Stream<Uint8List> rxStream;
  final StreamController<Uint8List> txSink;
  final StreamController<LinkEvent> _eventsController =
      StreamController<LinkEvent>.broadcast();

  DirectPeerLink? _peer;
  bool _isClosed = false;

  DirectPeerLink._({
    required this.mtu,
    required this.rxStream,
    required this.txSink,
  });

  @override
  Stream<Uint8List> get rx => rxStream;

  @override
  Stream<LinkEvent> get events => _eventsController.stream;

  @override
  bool get isClosed => _isClosed;

  @override
  Future<void> send(Uint8List chunk) async {
    if (_isClosed) throw StateError('Link is closed');
    if (chunk.length > mtu) {
      throw ArgumentError('Chunk size ${chunk.length} > MTU $mtu');
    }
    txSink.add(chunk);
  }

  @override
  Future<void> close([String? reason]) async {
    if (_isClosed) return;
    _isClosed = true;
    _eventsController.add(LinkClosed(reason));
    await _eventsController.close();
    await txSink.close();
    if (_peer != null && !_peer!._isClosed) {
      await _peer!.close(reason ?? 'Remote closed');
    }
  }
}

/// Fake transport for testing beacon advertising rotation.
class BeaconTestTransport implements P2PTransport {
  final List<Uint8List> advertisedTokens = [];
  bool isAdvertising = false;

  @override
  TransportCapabilities get capabilities => const TransportCapabilities(
        transportName: 'BeaconTest',
        defaultMtu: 512,
      );

  @override
  Future<void> startAdvertising(Uint8List token) async {
    isAdvertising = true;
    advertisedTokens.add(token);
  }

  @override
  Future<void> stopAdvertising() async {
    isAdvertising = false;
  }

  @override
  Stream<PeerAdvert> get discovered => const Stream.empty();
  @override
  Stream<PeerLink> get incoming => const Stream.empty();
  @override
  Future<void> startScanning([ScanPolicy policy = const ScanPolicy()]) async {}
  @override
  Future<void> stopScanning() async {}
  @override
  Future<void> stop() async => stopAdvertising();
  @override
  Future<PeerLink> connect(PeerAdvert peer) => throw UnimplementedError();
}

void main() {
  group('Multiple Groups per Device (Multi-Tenancy) Suite', () {
    late Directory tempDir;
    late Uint8List serverSeed;
    late cg.SimpleKeyPair serverKeyPair;
    late Uint8List serverPublicKey;

    late Uint8List group1Id;
    late Uint8List group2Id;
    late Uint8List group1Key;
    late Uint8List group2Key;
    late Uint8List group1BeaconKey;
    late Uint8List group2BeaconKey;

    late cg.SimpleKeyPair aliceKeyPair;
    late Uint8List alicePk;
    late cg.SimpleKeyPair aliceNoiseKeyPair;
    late Uint8List aliceNoisePk;

    late cg.SimpleKeyPair bobKeyPair;
    late Uint8List bobPk;
    late cg.SimpleKeyPair bobNoiseKeyPair;
    late Uint8List bobNoisePk;

    late MembershipCert aliceCertGroup1;
    late MembershipCert aliceCertGroup2;
    late MembershipCert bobCertGroup1;
    late MembershipCert bobCertGroup2;

    setUpAll(() async {
      tempDir = Directory.systemTemp.createTempSync('msgp2p_multi_group_');
      serverSeed = Uint8List.fromList(List.filled(32, 5));
      serverKeyPair = await MsgP2PCrypto.newKeyPairFromSeed(serverSeed);
      serverPublicKey = await MsgP2PCrypto.getPublicKeyBytes(serverKeyPair);

      group1Id =
          Uint8List.fromList(hex.decode('11111111111111111111111111111111'));
      group2Id =
          Uint8List.fromList(hex.decode('22222222222222222222222222222222'));

      group1Key = Uint8List.fromList(List.filled(32, 0x11));
      group2Key = Uint8List.fromList(List.filled(32, 0x22));

      group1BeaconKey = Uint8List.fromList(List.filled(32, 0xA1));
      group2BeaconKey = Uint8List.fromList(List.filled(32, 0xB2));

      aliceKeyPair = await MsgP2PCrypto.newKeyPairFromSeed(
          Uint8List.fromList(List.filled(32, 1)));
      alicePk = await MsgP2PCrypto.getPublicKeyBytes(aliceKeyPair);
      aliceNoiseKeyPair = await cg.X25519().newKeyPair();
      aliceNoisePk = await NoiseHandshake.getPublicKeyBytes(aliceNoiseKeyPair);

      bobKeyPair = await MsgP2PCrypto.newKeyPairFromSeed(
          Uint8List.fromList(List.filled(32, 2)));
      bobPk = await MsgP2PCrypto.getPublicKeyBytes(bobKeyPair);
      bobNoiseKeyPair = await cg.X25519().newKeyPair();
      bobNoisePk = await NoiseHandshake.getPublicKeyBytes(bobNoiseKeyPair);

      final now = DateTime.now().millisecondsSinceEpoch;

      // Issue certs for Alice in Group 1 & Group 2
      Future<MembershipCert> makeCert(
        Uint8List grpId,
        String userId,
        Uint8List signingPk,
        Uint8List noisePk,
      ) async {
        final coreMap = {
          'v': 1,
          'group_id': grpId,
          'user_id': userId,
          'member_pubkey': signingPk,
          'noise_pubkey': noisePk,
          'role': 0,
          'issued_at': now,
          'expires_at': now + 86400000,
        };
        final cbor = CanonicalCbor.encode(coreMap);
        final sig = await MsgP2PCrypto.sign(cbor, serverKeyPair);
        return MembershipCert(
          version: 1,
          groupId: grpId,
          userId: userId,
          memberPubkey: signingPk,
          noisePubkey: noisePk,
          role: 0,
          issuedAt: now,
          expiresAt: now + 86400000,
          serverSig: sig,
        );
      }

      aliceCertGroup1 =
          await makeCert(group1Id, 'alice_g1', alicePk, aliceNoisePk);
      aliceCertGroup2 =
          await makeCert(group2Id, 'alice_g2', alicePk, aliceNoisePk);
      bobCertGroup1 = await makeCert(group1Id, 'bob_g1', bobPk, bobNoisePk);
      bobCertGroup2 = await makeCert(group2Id, 'bob_g2', bobPk, bobNoisePk);
    });

    tearDownAll(() {
      try {
        tempDir.deleteSync(recursive: true);
      } catch (_) {}
    });

    test(
        '1. GroupStorePool isolates message sequences and database files per group',
        () async {
      final pool = GroupStorePool.sqlite(baseDirectory: tempDir.path);

      final store1 = await pool.getStore(group1Id);
      final store2 = await pool.getStore(group2Id);

      final now = DateTime.now().millisecondsSinceEpoch;

      // Alice authors seq = 1 in Group 1
      final envGroup1 = await Envelope.create(
        groupId: group1Id,
        keyEpoch: 1,
        groupKey: group1Key,
        authorKeyPair: aliceKeyPair,
        certRef: aliceCertGroup1.certRef,
        seq: 1,
        payload: {'group': 'family', 'text': 'Hello Family'},
        customCreatedAt: now,
      );
      final saved1 = await store1.saveEnvelope(envGroup1);
      expect(saved1, isTrue);

      // Alice authors seq = 1 in Group 2 (Same author & seq, different group!)
      final envGroup2 = await Envelope.create(
        groupId: group2Id,
        keyEpoch: 1,
        groupKey: group2Key,
        authorKeyPair: aliceKeyPair,
        certRef: aliceCertGroup2.certRef,
        seq: 1,
        payload: {'group': 'sar', 'text': 'SAR Team Online'},
        customCreatedAt: now,
      );

      // In a single-database design this would fail with UNIQUE(author, seq) collision.
      // In Store-per-Group pool, it stores cleanly with complete isolation!
      final saved2 = await store2.saveEnvelope(envGroup2);
      expect(saved2, isTrue);

      // Verify vectors are isolated
      final vec1 = await store1.getVersionVector();
      final vec2 = await store2.getVersionVector();

      expect(vec1.has(hex.encode(alicePk), 1), isTrue);
      expect(vec2.has(hex.encode(alicePk), 1), isTrue);

      // Retrieve and check payloads
      final loaded1 = (await store1.getEnvelope(envGroup1.messageId))!;
      final dec1 = await loaded1.decryptPayload(group1Key);
      expect(dec1['group'], equals('family'));

      final loaded2 = (await store2.getEnvelope(envGroup2.messageId))!;
      final dec2 = await loaded2.decryptPayload(group2Key);
      expect(dec2['group'], equals('sar'));

      // Check DB files exist on disk
      final file1 =
          File('${tempDir.path}/messages_group_${hex.encode(group1Id)}.db');
      final file2 =
          File('${tempDir.path}/messages_group_${hex.encode(group2Id)}.db');
      expect(file1.existsSync(), isTrue);
      expect(file2.existsSync(), isTrue);

      await pool.closeAll();
    });

    test(
        '2. MultiGroupBeaconManager rotates tokens and matches candidate adverts',
        () async {
      final transport = BeaconTestTransport();
      final beaconMgr = MultiGroupBeaconManager(
        transport: transport,
        advertisingRotationPeriod: const Duration(milliseconds: 50),
      );

      final membership1 = GroupMembership(
        groupId: group1Id,
        cert: aliceCertGroup1,
        groupBeaconKey: group1BeaconKey,
        store: MemoryMessageStore(),
      );
      final membership2 = GroupMembership(
        groupId: group2Id,
        cert: aliceCertGroup2,
        groupBeaconKey: group2BeaconKey,
        store: MemoryMessageStore(),
      );

      beaconMgr.registerGroup(membership1);
      beaconMgr.registerGroup(membership2);

      // 1. Verify token matching for scanning
      final gen1 = BeaconTokenGenerator(groupBeaconKey: group1BeaconKey);
      final token1 = gen1.generateToken();

      final gen2 = BeaconTokenGenerator(groupBeaconKey: group2BeaconKey);
      final token2 = gen2.generateToken();

      final unknownToken = Uint8List.fromList(List.filled(16, 0xEE));

      expect(beaconMgr.matchToken(token1)?.groupIdHex,
          equals(membership1.groupIdHex));
      expect(beaconMgr.matchToken(token2)?.groupIdHex,
          equals(membership2.groupIdHex));
      expect(beaconMgr.matchToken(unknownToken), isNull);

      // 2. Start advertising rotation and verify round-robin tokens
      await beaconMgr.startAdvertising();
      await Future.delayed(const Duration(milliseconds: 160));
      await beaconMgr.stopAdvertising();

      expect(transport.advertisedTokens.length, greaterThanOrEqualTo(2));
      // First token matches Group 1
      expect(beaconMgr.matchToken(transport.advertisedTokens[0])?.groupIdHex,
          equals(membership1.groupIdHex));
      // Second token matches Group 2
      expect(beaconMgr.matchToken(transport.advertisedTokens[1])?.groupIdHex,
          equals(membership2.groupIdHex));

      beaconMgr.dispose();
    });

    test(
        '3. MultiGroupSyncCoordinator executes sequential group sessions over a single link',
        () async {
      final aliceStoreG1 = MemoryMessageStore();
      final aliceStoreG2 = MemoryMessageStore();
      final bobStoreG1 = MemoryMessageStore();
      final bobStoreG2 = MemoryMessageStore();

      final aliceGroup1 = GroupMembership(
        groupId: group1Id,
        cert: aliceCertGroup1,
        groupBeaconKey: group1BeaconKey,
        store: aliceStoreG1,
      );
      final aliceGroup2 = GroupMembership(
        groupId: group2Id,
        cert: aliceCertGroup2,
        groupBeaconKey: group2BeaconKey,
        store: aliceStoreG2,
      );

      final bobGroup1 = GroupMembership(
        groupId: group1Id,
        cert: bobCertGroup1,
        groupBeaconKey: group1BeaconKey,
        store: bobStoreG1,
      );
      final bobGroup2 = GroupMembership(
        groupId: group2Id,
        cert: bobCertGroup2,
        groupBeaconKey: group2BeaconKey,
        store: bobStoreG2,
      );

      final now = DateTime.now().millisecondsSinceEpoch;

      // Alice has a message in Group 1
      final env1 = await Envelope.create(
        groupId: group1Id,
        keyEpoch: 1,
        groupKey: group1Key,
        authorKeyPair: aliceKeyPair,
        certRef: aliceCertGroup1.certRef,
        seq: 1,
        payload: {'chat': 'Dinner at 7'},
        customCreatedAt: now,
      );
      await aliceStoreG1.saveEnvelope(env1);

      // Alice has a message in Group 2
      final env2 = await Envelope.create(
        groupId: group2Id,
        keyEpoch: 1,
        groupKey: group2Key,
        authorKeyPair: aliceKeyPair,
        certRef: aliceCertGroup2.certRef,
        seq: 1,
        payload: {'sar': 'Grid B-4 Clear'},
        customCreatedAt: now,
      );
      await aliceStoreG2.saveEnvelope(env2);

      // Connect Alice and Bob over a single DirectPeerLink
      final linkPair = DirectPeerLinkPair(mtu: 512);

      final aliceCoord = MultiGroupSyncCoordinator(
        staticKeyPair: aliceNoiseKeyPair,
        pinnedServerKey: serverPublicKey,
      );
      final bobCoord = MultiGroupSyncCoordinator(
        staticKeyPair: bobNoiseKeyPair,
        pinnedServerKey: serverPublicKey,
      );

      // Both execute sequential sync for [Group 1, Group 2] over their respective link ends
      final aliceFuture = aliceCoord.syncAcrossSharedGroups(
        link: linkPair.a,
        isInitiator: true,
        groups: [aliceGroup1, aliceGroup2],
      );
      final bobFuture = bobCoord.syncAcrossSharedGroups(
        link: linkPair.b,
        isInitiator: false,
        groups: [bobGroup1, bobGroup2],
      );

      final results = await Future.wait([aliceFuture, bobFuture]);
      final aliceResults = results[0];
      final bobResults = results[1];

      // Both groups must be synchronized
      expect(aliceResults, hasLength(2));
      expect(bobResults, hasLength(2));

      expect(aliceResults[0].completedSuccessfully, isTrue);
      expect(aliceResults[1].completedSuccessfully, isTrue);
      expect(bobResults[0].completedSuccessfully, isTrue);
      expect(bobResults[1].completedSuccessfully, isTrue);

      // Verify Bob received both messages in their respective isolated stores
      final bobHasG1 = await bobStoreG1.getEnvelope(env1.messageId);
      expect(bobHasG1, isNotNull);
      final decG1 = await bobHasG1!.decryptPayload(group1Key);
      expect(decG1['chat'], equals('Dinner at 7'));

      final bobHasG2 = await bobStoreG2.getEnvelope(env2.messageId);
      expect(bobHasG2, isNotNull);
      final decG2 = await bobHasG2!.decryptPayload(group2Key);
      expect(decG2['sar'], equals('Grid B-4 Clear'));

      // Link is cleanly closed after all groups synchronized
      expect(linkPair.a.isClosed, isTrue);
      expect(linkPair.b.isClosed, isTrue);
    });
  });
}
