import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:convert/convert.dart';
import 'package:cryptography/cryptography.dart' as cg;
import 'package:msgp2p_core/msgp2p_core.dart';
import 'package:msgp2p_reference_auth/msgp2p_reference_auth.dart';
import 'package:test/test.dart';

import '../../msgp2p_core/test/membership_source_contract.dart';

class _MockUserRecord {
  final String userId;
  final String username;
  final String password;
  final GroupId groupId;
  final MembershipCert cert;

  const _MockUserRecord({
    required this.userId,
    required this.username,
    required this.password,
    required this.groupId,
    required this.cert,
  });
}

/// Stateful in-memory reference auth HTTP backend implementing `/auth/register`,
/// `/auth/login`, and `/sync/revocations` over [MockHttpExecutor].
class _FakeReferenceAuthBackend {
  final cg.SimpleKeyPair serverKeyPair;
  final Uint8List serverPublicKey;
  final Map<String, _MockUserRecord> _usersByName = {};
  final Map<GroupId, List<GrantedKey>> _keysByGroup = {};
  final Map<GroupId, Uint8List> _beaconByGroup = {};
  final Map<GroupId, List<RevocationNotice>> _revocationsByGroup = {};

  int _nextUserNum = 1;
  int _nextEpoch = 1;
  int getRevocationsCalls = 0;
  bool embedRevocationsInLogin = false;

  _FakeReferenceAuthBackend._({
    required this.serverKeyPair,
    required this.serverPublicKey,
  });

  static Future<_FakeReferenceAuthBackend> create({int seedByte = 0x33}) async {
    final kp = await MsgP2PCrypto.newKeyPairFromSeed(
      Uint8List.fromList(List.filled(32, seedByte)),
    );
    final pk = await MsgP2PCrypto.getPublicKeyBytes(kp);
    return _FakeReferenceAuthBackend._(serverKeyPair: kp, serverPublicKey: pk);
  }

  void _ensureGroup(GroupId group) {
    _beaconByGroup.putIfAbsent(
      group,
      () => Uint8List.fromList(List.generate(32, (i) => (i + 0x50) & 0xFF)),
    );
    _keysByGroup.putIfAbsent(group, () {
      final nowMs = DateTime.now().millisecondsSinceEpoch;
      return [
        GrantedKey(
          epoch: _nextEpoch++,
          role: KeyRole.member,
          key: Uint8List.fromList(List.generate(32, (i) => (i + 0x10) & 0xFF)),
          validUntil: nowMs + const Duration(days: 30).inMilliseconds,
        ),
      ];
    });
  }

  void addGroupKey(GroupId group, GrantedKey key) {
    _ensureGroup(group);
    _keysByGroup[group]!.add(key);
  }

  Future<RevocationNotice> revokeMember(
    GroupId group,
    Uint8List memberPubkey, {
    String reason = 'compromised_credential',
  }) async {
    _ensureGroup(group);
    final nowMs = DateTime.now().millisecondsSinceEpoch;
    final core = RevocationNotice(
      groupId: group.bytes,
      memberPubkey: memberPubkey,
      revokedAt: nowMs,
      reason: reason,
      serverSig: Uint8List(64),
    );
    final sig = await MsgP2PCrypto.sign(core.toCoreCbor(), serverKeyPair);
    final rev = RevocationNotice(
      groupId: group.bytes,
      memberPubkey: memberPubkey,
      revokedAt: nowMs,
      reason: reason,
      serverSig: sig,
    );
    _revocationsByGroup.putIfAbsent(group, () => []).add(rev);
    _keysByGroup[group]!.add(
      GrantedKey(
        epoch: _nextEpoch++,
        role: KeyRole.member,
        key: Uint8List.fromList(
          List.generate(32, (i) => (_nextEpoch + i * 7) & 0xFF),
        ),
        validUntil: nowMs + const Duration(days: 30).inMilliseconds,
      ),
    );
    return rev;
  }

  MockHttpExecutor get executor =>
      MockHttpExecutor((method, url, headers, body) async {
        final path = url.path.replaceFirst('/api/v1', '');
        final reqJson = (body != null && body.isNotEmpty)
            ? jsonDecode(utf8.decode(body)) as Map<String, dynamic>
            : const <String, dynamic>{};

        if (method == 'POST' && path == '/auth/register') {
          final username = (reqJson['username'] as String? ?? '').trim();
          final password = reqJson['password'] as String? ?? '';
          final groupHex = reqJson['group_id'] as String? ?? '';
          final memberHex = reqJson['member_pubkey'] as String? ?? '';
          final noiseHex = reqJson['noise_pubkey'] as String? ?? '';

          if (_usersByName.containsKey(username)) {
            return _jsonReply(400, {
              'error': 'INTERNAL_ERROR',
              'message': 'Username already exists',
            });
          }
          if (username.length < 3 ||
              password.length < 8 ||
              groupHex.length != 32 ||
              memberHex.length != 64 ||
              noiseHex.length != 64) {
            return _jsonReply(400, {
              'error': 'BAD_REQUEST',
              'message': 'Invalid registration parameters',
            });
          }

          final group = GroupId.fromHex(groupHex);
          _ensureGroup(group);
          final userId = 'usr_mock_${_nextUserNum++}';
          final nowMs = DateTime.now().millisecondsSinceEpoch;
          final expMs = nowMs + const Duration(days: 7).inMilliseconds;
          final certCore = MembershipCert(
            groupId: group.bytes,
            userId: userId,
            memberPubkey: Uint8List.fromList(hex.decode(memberHex)),
            noisePubkey: Uint8List.fromList(hex.decode(noiseHex)),
            role: 0,
            issuedAt: nowMs,
            expiresAt: expMs,
            serverSig: Uint8List(64),
          );
          final sig =
              await MsgP2PCrypto.sign(certCore.toCoreCbor(), serverKeyPair);
          final signedCert = MembershipCert(
            groupId: group.bytes,
            userId: userId,
            memberPubkey: certCore.memberPubkey,
            noisePubkey: certCore.noisePubkey,
            role: 0,
            issuedAt: nowMs,
            expiresAt: expMs,
            serverSig: sig,
          );

          _usersByName[username] = _MockUserRecord(
            userId: userId,
            username: username,
            password: password,
            groupId: group,
            cert: signedCert,
          );
          return _jsonReply(200, {'user_id': userId, 'status': 'ACTIVE'});
        }

        if (method == 'POST' && path == '/auth/login') {
          final username = (reqJson['username'] as String? ?? '').trim();
          final password = reqJson['password'] as String? ?? '';
          final user = _usersByName[username];
          if (user == null || user.password != password) {
            return _jsonReply(401, {
              'error': 'UNAUTHORIZED',
              'message': 'Invalid username or password',
            });
          }
          _ensureGroup(user.groupId);
          final keys = _keysByGroup[user.groupId]!;
          final revs = _revocationsByGroup[user.groupId] ?? const [];

          return _jsonReply(200, {
            'access_token': 'tok_${user.userId}',
            'expires_in': 86400,
            'server_pubkey': hex.encode(serverPublicKey),
            'membership_cert': {
              'raw_cbor_base64': base64Encode(user.cert.toFullCbor()),
            },
            'group_beacon_key': hex.encode(_beaconByGroup[user.groupId]!),
            'group_keys': [
              for (final k in keys)
                {
                  'epoch': k.epoch,
                  'role': k.role.name,
                  'key_hex': hex.encode(k.key),
                  if (k.validUntil != null) 'valid_until': k.validUntil,
                },
            ],
            if (embedRevocationsInLogin)
              'revocations': [
                for (final r in revs)
                  {'raw_cbor_base64': base64Encode(r.toFullCbor())},
              ],
          });
        }

        if (method == 'GET' && path == '/sync/revocations') {
          final auth = headers['authorization'] ?? '';
          if (!auth.startsWith('Bearer tok_')) {
            return _jsonReply(401, {
              'error': 'UNAUTHORIZED',
              'message': 'Missing bearer token',
            });
          }
          getRevocationsCalls++;
          final groupHex = url.queryParameters['group_id'] ?? '';
          final group = GroupId.fromHex(groupHex);
          final revs = _revocationsByGroup[group] ?? const [];
          return _jsonReply(200, {
            'revocations': [
              for (final r in revs)
                {'raw_cbor_base64': base64Encode(r.toFullCbor())},
            ],
          });
        }

        return _jsonReply(404, {
          'error': 'NOT_FOUND',
          'message': 'Route $method $path not found',
        });
      });

  static HttpReply _jsonReply(int status, Map<String, dynamic> body) {
    return HttpReply(
      statusCode: status,
      headers: const {'content-type': 'application/json'},
      body: Uint8List.fromList(utf8.encode(jsonEncode(body))),
    );
  }
}

void main() {
  final defaultGroup = GroupId.fromHex('a0b1c2d3e4f50123456789abcdef0123');

  // 1. Shared contract suite over MockHttpExecutor (fast, socket-free)
  runMembershipSourceContractTests(
      'ReferenceMembershipSource (MockHttpExecutor)', () async {
    final backend = await _FakeReferenceAuthBackend.create();
    var memberSeq = 1;

    return MembershipSourceContext(
      groupId: defaultGroup,
      serverPublicKey: backend.serverPublicKey,
      createMember: (label) async {
        final n = memberSeq++;
        final seeds = IdentitySeeds(
          signing: Uint8List.fromList(List.filled(32, n)),
          noise: Uint8List.fromList(List.filled(32, n + 80)),
        );
        final keys = await MemberPublicKeys.fromSeeds(seeds);
        final source = ReferenceMembershipSource(
          baseUrl: 'http://mock.local/api/v1/',
          username: 'user_${label}_$n',
          password: 'PasswordMock123!',
          httpExecutor: backend.executor,
          pinnedServerKey: backend.serverPublicKey,
        );
        return (source: source, seeds: seeds, keys: keys);
      },
      revokeMember: (memberPk, {String reason = 'compromised_credential'}) =>
          backend.revokeMember(defaultGroup, memberPk, reason: reason),
    );
  });

  // 2. Unit & security edge-case tests
  group('ReferenceMembershipSource security & edge cases', () {
    late _FakeReferenceAuthBackend backend;
    late MemberPublicKeys aliceKeys;

    setUp(() async {
      backend = await _FakeReferenceAuthBackend.create(seedByte: 0x44);
      aliceKeys = await MemberPublicKeys.fromSeeds(
        IdentitySeeds(
          signing: Uint8List.fromList(List.filled(32, 0x11)),
          noise: Uint8List.fromList(List.filled(32, 0x22)),
        ),
      );
    });

    test('autoRegister: false rejects unregistered account until register()',
        () async {
      final source = ReferenceMembershipSource(
        baseUrl: 'http://mock.local/api/v1',
        username: 'manual_alice',
        password: 'ManualPassword123!',
        httpExecutor: backend.executor,
        pinnedServerKey: backend.serverPublicKey,
        autoRegister: false,
      );

      await expectLater(
        source.fetch(defaultGroup, aliceKeys),
        throwsA(
          isA<MembershipException>().having(
            (e) => e.kind,
            'kind',
            MembershipErrorKind.unauthorized,
          ),
        ),
      );

      final userId = await source.register(defaultGroup, aliceKeys);
      expect(userId, startsWith('usr_'));

      final grant = await source.fetch(defaultGroup, aliceKeys);
      expect(grant.cert.userId, equals(userId));
    });

    test(
        'wrong password on existing account preserves 401 unauthorized even when autoRegister: true',
        () async {
      final goodSource = ReferenceMembershipSource(
        baseUrl: 'http://mock.local/api/v1',
        username: 'existing_alice',
        password: 'CorrectPassword123!',
        httpExecutor: backend.executor,
        pinnedServerKey: backend.serverPublicKey,
      );
      await goodSource.fetch(defaultGroup, aliceKeys);

      final badPasswordSource = ReferenceMembershipSource(
        baseUrl: 'http://mock.local/api/v1',
        username: 'existing_alice',
        password: 'WrongPassword999!',
        httpExecutor: backend.executor,
        pinnedServerKey: backend.serverPublicKey,
        autoRegister: true,
      );

      await expectLater(
        badPasswordSource.fetch(defaultGroup, aliceKeys),
        throwsA(
          isA<MembershipException>().having(
            (e) => e.kind,
            'kind',
            MembershipErrorKind.unauthorized,
          ),
        ),
      );
    });

    test(
        'inline revocations in /auth/login skip extra GET and KeyRole.tracker keys parse cleanly',
        () async {
      backend.embedRevocationsInLogin = true;
      backend.addGroupKey(
        defaultGroup,
        GrantedKey(
          epoch: 10,
          role: KeyRole.tracker,
          key: Uint8List.fromList(List.filled(32, 0xAB)),
        ),
      );
      final revokedPeerPk = Uint8List.fromList(List.filled(32, 0xEE));
      await backend.revokeMember(defaultGroup, revokedPeerPk);

      final gateway = GatewayClient(
        baseUrl: 'http://mock.local/api/v1',
        httpExecutor: backend.executor,
      );
      String? callbackToken;
      final source = ReferenceMembershipSource(
        baseUrl: 'http://mock.local/api/v1',
        username: 'inline_alice',
        password: 'InlinePassword123!',
        httpExecutor: backend.executor,
        pinnedServerKey: backend.serverPublicKey,
        gatewayClient: gateway,
        onAccessToken: (token, _) => callbackToken = token,
      );

      final grant = await source.fetch(defaultGroup, aliceKeys);
      expect(backend.getRevocationsCalls, equals(0));
      expect(grant.revocations, hasLength(1));
      expect(grant.revocations.single.memberPubkey, equals(revokedPeerPk));
      expect(
        grant.keys.any((k) => k.epoch == 10 && k.role == KeyRole.tracker),
        isTrue,
      );
      expect(gateway.authToken, isNotNull);
      expect(gateway.authToken, equals(callbackToken));
      expect(source.lastAccessToken, equals(gateway.authToken));
      expect(source.lastServerPublicKey, equals(backend.serverPublicKey));
    });

    test(
        'pinnedServerKey mismatch rejects grant and does not overwrite gatewayClient.authToken',
        () async {
      final wrongPinned = Uint8List.fromList(List.filled(32, 0xFF));
      final gateway = GatewayClient(
        baseUrl: 'http://mock.local/api/v1',
        authToken: 'initial_token',
        httpExecutor: backend.executor,
      );
      final source = ReferenceMembershipSource(
        baseUrl: 'http://mock.local/api/v1',
        username: 'pinned_alice',
        password: 'PinnedPassword123!',
        httpExecutor: backend.executor,
        pinnedServerKey: wrongPinned,
        gatewayClient: gateway,
      );

      await expectLater(
        source.fetch(defaultGroup, aliceKeys),
        throwsA(
          isA<MembershipException>().having(
            (e) => e.kind,
            'kind',
            MembershipErrorKind.invalidGrant,
          ),
        ),
      );
      expect(gateway.authToken, equals('initial_token'));
      expect(source.lastAccessToken, isNull);
    });

    test(
        'non-JSON 502 reverse-proxy error maps to MembershipErrorKind.transport',
        () async {
      final html502Executor = MockHttpExecutor((_, __, ___, ____) async {
        return HttpReply(
          statusCode: 502,
          headers: const {'content-type': 'text/html'},
          body: Uint8List.fromList(utf8.encode('<html>502 Bad Gateway</html>')),
        );
      });
      final source = ReferenceMembershipSource(
        baseUrl: 'http://mock.local/api/v1',
        username: 'proxy_alice',
        password: 'ProxyPassword123!',
        httpExecutor: html502Executor,
      );

      await expectLater(
        source.fetch(defaultGroup, aliceKeys),
        throwsA(
          isA<MembershipException>().having(
            (e) => e.kind,
            'kind',
            MembershipErrorKind.transport,
          ),
        ),
      );
    });
  });

  // 3. End-to-End Contract & Gateway Sync Suite against the real PHP Reference Server
  group('PHP Reference Server E2E (ReferenceMembershipSource)', () {
    late Process phpServer;
    const port = 8996;
    const baseUrl = 'http://127.0.0.1:$port/api/v1';
    final serverPinnedKey = Uint8List.fromList(
      hex.decode(
          'cfbb7b389c637893cb03da870625f9763a7143ec93513e3661ee3a5e47335f97'),
    );
    var groupSeq = 1;
    var userSeq = 1;

    setUpAll(() async {
      final migrateRes = await Process.run(
        'php',
        [
          '-r',
          'require_once "server/php/vendor/autoload.php"; '
              'MsgP2P\\Server\\Database::resetDatabase("msgp2p_test");',
        ],
        workingDirectory: '../../',
      );
      expect(
        migrateRes.exitCode,
        equals(0),
        reason: 'Failed to reset msgp2p_test database: ${migrateRes.stderr}',
      );

      phpServer = await Process.start(
        'php',
        ['-S', '127.0.0.1:$port', '-t', 'server/php/public'],
        environment: {'DB_NAME': 'msgp2p_test'},
        workingDirectory: '../../',
      );
      await Future<void>.delayed(const Duration(milliseconds: 300));
    });

    tearDownAll(() {
      phpServer.kill();
    });

    runMembershipSourceContractTests(
        'ReferenceMembershipSource (PHP Reference Server)', () async {
      final gNum = groupSeq++;
      final groupBytes = Uint8List(16)
        ..setRange(0, 4, [0xAA, 0xBB, 0xCC, gNum & 0xFF]);
      final group = GroupId(groupBytes);
      final sourcesToClose = <ReferenceMembershipSource>[];
      GatewayClient? adminGateway;

      return MembershipSourceContext(
        groupId: group,
        serverPublicKey: serverPinnedKey,
        createMember: (label) async {
          final u = userSeq++;
          final seeds = IdentitySeeds(
            signing: Uint8List.fromList(
              List.generate(32, (i) => (u * 13 + i) & 0xFF),
            ),
            noise: Uint8List.fromList(
              List.generate(32, (i) => (u * 29 + i + 7) & 0xFF),
            ),
          );
          final keys = await MemberPublicKeys.fromSeeds(seeds);
          final gw = adminGateway ??= GatewayClient(baseUrl: baseUrl);
          final source = ReferenceMembershipSource(
            baseUrl: baseUrl,
            username: 'ref_${label}_$u',
            password: 'RefServerPassword123!',
            pinnedServerKey: serverPinnedKey,
            gatewayClient: gw,
          );
          sourcesToClose.add(source);
          return (source: source, seeds: seeds, keys: keys);
        },
        revokeMember: (memberPk,
            {String reason = 'compromised_credential'}) async {
          final res = await adminGateway!.revokeMember(
            groupId: group.hexString,
            memberPubkey: memberPk,
            reason: reason,
          );
          return res.revocation;
        },
        dispose: () async {
          for (final s in sourcesToClose) {
            s.close();
          }
          adminGateway?.close();
        },
      );
    });

    test(
        'ReferenceMembershipSource wires GatewayClient bearer token for full push/pull E2E sync',
        () async {
      final group = GroupId.fromHex('d0e1f2031425364758697a8b9c0d1e2f');

      final aliceSeeds = IdentitySeeds(
        signing: Uint8List.fromList(List.filled(32, 0x61)),
        noise: Uint8List.fromList(List.filled(32, 0x62)),
      );
      final aliceKeys = await MemberPublicKeys.fromSeeds(aliceSeeds);
      final aliceKeyPair =
          await MsgP2PCrypto.newKeyPairFromSeed(aliceSeeds.signing);
      final aliceGateway = GatewayClient(baseUrl: baseUrl);
      final aliceAuth = ReferenceMembershipSource(
        baseUrl: baseUrl,
        username: 'e2e_sync_alice',
        password: 'SyncAlicePassword123!',
        pinnedServerKey: serverPinnedKey,
        gatewayClient: aliceGateway,
      );

      final bobSeeds = IdentitySeeds(
        signing: Uint8List.fromList(List.filled(32, 0x71)),
        noise: Uint8List.fromList(List.filled(32, 0x72)),
      );
      final bobKeys = await MemberPublicKeys.fromSeeds(bobSeeds);
      final bobGateway = GatewayClient(baseUrl: baseUrl);
      final bobAuth = ReferenceMembershipSource(
        baseUrl: baseUrl,
        username: 'e2e_sync_bob',
        password: 'SyncBobPassword123!',
        pinnedServerKey: serverPinnedKey,
        gatewayClient: bobGateway,
      );

      addTearDown(() {
        aliceAuth.close();
        aliceGateway.close();
        bobAuth.close();
        bobGateway.close();
      });

      final aliceGrant = await aliceAuth.fetch(group, aliceKeys);
      final bobGrant = await bobAuth.fetch(group, bobKeys);
      expect(aliceGateway.authToken, isNotEmpty);
      expect(bobGateway.authToken, isNotEmpty);

      final aliceStore = MemoryMessageStore();
      await aliceStore.saveCertificate(aliceGrant.cert);

      final authoringKey = aliceGrant.activeAuthoringKey!;
      final env = await Envelope.create(
        groupId: group.bytes,
        keyEpoch: authoringKey.epoch,
        groupKey: authoringKey.key,
        authorKeyPair: aliceKeyPair,
        certRef: aliceGrant.cert.certRef,
        seq: 1,
        priority: 0,
        payload: const {
          'type': 'sos',
          'body': {'alert': 'Ridge evacuation point'},
        },
      );
      await aliceStore.saveEnvelope(env);

      final aliceSync = await aliceGateway.syncStore(
        store: aliceStore,
        groupId: group,
        pinnedServerKey: serverPinnedKey,
        pendingEnvelopes: [env],
      );
      expect(aliceSync.acceptedCount, equals(1));

      final bobStore = MemoryMessageStore();
      await bobStore.saveCertificate(bobGrant.cert);
      final bobSync = await bobGateway.syncStore(
        store: bobStore,
        groupId: group,
        pinnedServerKey: serverPinnedKey,
      );
      expect(bobSync.pulledCount, equals(1));

      final pulled = await bobStore.getEnvelope(env.messageId);
      expect(pulled, isNotNull);
      final decrypted = await pulled!.decryptPayload(
        bobGrant.keysByEpoch[pulled.core.keyEpoch]!,
      );
      expect(
        (decrypted['body'] as Map)['alert'],
        equals('Ridge evacuation point'),
      );
    });
  });
}
