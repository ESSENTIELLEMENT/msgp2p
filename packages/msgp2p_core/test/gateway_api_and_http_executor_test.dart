import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';
import 'package:convert/convert.dart';
import 'package:cryptography/cryptography.dart';
import 'package:msgp2p_core/msgp2p_core.dart';
import 'package:test/test.dart';
import 'gateway_api_contract.dart';

Future<MembershipCert> _createCert({
  required Uint8List groupId,
  required String userId,
  required Uint8List memberPubkey,
  required Uint8List noisePubkey,
  required SimpleKeyPair serverKeyPair,
}) async {
  final now = DateTime.now().millisecondsSinceEpoch;
  final certCore = MembershipCert(
    groupId: groupId,
    userId: userId,
    memberPubkey: memberPubkey,
    noisePubkey: noisePubkey,
    role: 0,
    issuedAt: now - 1000,
    expiresAt: now + (7 * 86400 * 1000),
    serverSig: Uint8List(64),
  );
  final sig = await MsgP2PCrypto.sign(certCore.toCoreCbor(), serverKeyPair);
  return MembershipCert(
    groupId: groupId,
    userId: userId,
    memberPubkey: memberPubkey,
    noisePubkey: noisePubkey,
    role: 0,
    issuedAt: certCore.issuedAt,
    expiresAt: certCore.expiresAt,
    serverSig: sig,
  );
}

/// Translates `GatewayClient` JSON HTTP wire requests onto a backing [MemoryGatewayApi],
/// allowing the full `GatewayApi` contract suite to exercise `GatewayClient` over both
/// [MockHttpExecutor] and [IoHttpExecutor] + real `dart:io` [HttpServer].
Future<HttpReply> _dispatchGatewayHttpRequest(
  MemoryGatewayApi backend,
  String method,
  Uri url,
  Map<String, String> headers,
  Uint8List? body,
) async {
  HttpReply jsonReply(int status, Map<String, dynamic> payload) => HttpReply(
        statusCode: status,
        headers: const {'content-type': 'application/json'},
        body: Uint8List.fromList(utf8.encode(jsonEncode(payload))),
      );

  try {
    if (method == 'POST' && url.path.endsWith('/sync/push')) {
      final json = jsonDecode(utf8.decode(body!)) as Map<String, dynamic>;
      final group = GroupId.fromHex(json['group_id'] as String);
      final envs = (json['envelopes'] as List)
          .map((e) => Envelope.fromCbor(base64Decode(e as String)))
          .toList();
      final certs = (json['certificates'] as List?)
          ?.map((c) => MembershipCert.fromCbor(base64Decode(c as String)))
          .toList();
      final res = await backend.push(group, envs, certificates: certs);
      return jsonReply(200, {
        'accepted_ids': res.acceptedIds,
        'rejected': res.rejected
            .map((r) => {'message_id': r.messageId, 'reason': r.reason})
            .toList(),
        'receipts': res.receipts
            .map((r) => {'raw_cbor_base64': base64Encode(r.toFullCbor())})
            .toList(),
      });
    }

    if (method == 'GET' && url.path.endsWith('/sync/pull')) {
      final group = GroupId.fromHex(url.queryParameters['group_id']!);
      final vecB64 = url.queryParameters['vector'] ?? '';
      final vec = vecB64.isEmpty
          ? VersionVector()
          : VersionVector.fromCbor(base64Decode(vecB64));
      final limit = int.tryParse(url.queryParameters['limit'] ?? '');
      final res = await backend.pull(group, vec, limit: limit);
      return jsonReply(200, {
        'envelopes': res.envelopes
            .map((e) => base64Encode(e.toCanonicalCbor()))
            .toList(),
        'has_more': res.hasMore,
        if (res.serverVector != null)
          'server_vector': base64Encode(res.serverVector!.toCanonicalCbor()),
      });
    }

    if (method == 'GET' && url.path.endsWith('/sync/receipts')) {
      final group = GroupId.fromHex(url.queryParameters['group_id']!);
      final since = int.tryParse(url.queryParameters['since'] ?? '0');
      final list = await backend.receipts(group, since: since);
      return jsonReply(200, {
        'receipts': list
            .map((r) => {'raw_cbor_base64': base64Encode(r.toFullCbor())})
            .toList(),
      });
    }

    if (method == 'GET' && url.path.endsWith('/sync/revocations')) {
      final group = GroupId.fromHex(url.queryParameters['group_id']!);
      final since = int.tryParse(url.queryParameters['since'] ?? '0');
      final list = await backend.revocations(group, since: since);
      return jsonReply(200, {
        'revocations': list
            .map((r) => {'raw_cbor_base64': base64Encode(r.toFullCbor())})
            .toList(),
      });
    }

    if (method == 'POST' && url.path.endsWith('/sync/attachments')) {
      final json = jsonDecode(utf8.decode(body!)) as Map<String, dynamic>;
      final group = GroupId.fromHex(json['group_id'] as String);
      final hash = Uint8List.fromList(hex.decode(json['hash'] as String));
      final mime = json['mime'] as String;
      final bytes = base64Decode(json['data_base64'] as String);
      final ref = AttachmentRef(hash: hash, size: bytes.length, mime: mime);
      await backend.uploadAttachment(group, ref, bytes);
      return jsonReply(200, {'stored': true});
    }

    if (method == 'GET' && url.path.endsWith('/sync/attachments')) {
      final group = GroupId.fromHex(url.queryParameters['group_id']!);
      final hash = Uint8List.fromList(hex.decode(url.queryParameters['hash']!));
      final ref =
          AttachmentRef(hash: hash, size: 0, mime: 'application/octet-stream');
      final blob = await backend.downloadAttachment(group, ref);
      return jsonReply(200, {
        'hash': hex.encode(blob.hash),
        'mime': blob.mime,
        'size': blob.bytes.length,
        'data_base64': base64Encode(blob.bytes),
      });
    }

    return jsonReply(404, {'error': 'NOT_FOUND', 'message': 'Route not found'});
  } on GatewayException catch (e) {
    return jsonReply(e.statusCode, {'error': e.error, 'message': e.message});
  }
}

void main() {
  group('GroupId domain type', () {
    final rawBytes = Uint8List.fromList(List.generate(16, (i) => i + 1));
    const rawHex = '0102030405060708090a0b0c0d0e0f10';

    test('constructs from bytes, validates 16-byte length, and formats hex',
        () {
      final gid = GroupId(rawBytes);
      expect(gid.bytes, equals(rawBytes));
      expect(gid.hexString, equals(rawHex));
      expect(gid.toString(), equals(rawHex));

      // Prevents mixing 32-byte public keys with 16-byte group IDs on primary constructor too
      expect(() => GroupId(Uint8List(32)), throwsArgumentError);
    });

    test('defensively copies input and output bytes to preserve immutability',
        () {
      final mutable = Uint8List.fromList(rawBytes);
      final gid = GroupId(mutable);
      final map = <GroupId, String>{gid: 'alpha'};

      // Mutating caller's input buffer must NOT alter GroupId or corrupt Map lookup
      mutable[0] = 0xff;
      expect(gid.bytes[0], equals(1));
      expect(map[GroupId.fromHex(rawHex)], equals('alpha'));

      // Mutating returned gid.bytes copy must NOT alter GroupId or corrupt Map lookup
      final outCopy = gid.bytes;
      outCopy[0] = 0xaa;
      expect(gid.bytes[0], equals(1));
      expect(map[GroupId.fromHex(rawHex)], equals('alpha'));
    });

    test('constructs from valid hex string with optional 0x/0X prefix', () {
      final gid = GroupId.fromHex(rawHex);
      expect(gid.bytes, equals(rawBytes));
      expect(gid.hexString, equals(rawHex));

      expect(GroupId.fromHex('0x$rawHex'), equals(gid));
      expect(GroupId.fromHex('0X${rawHex.toUpperCase()}'), equals(gid));
    });

    test('GroupId.from parses GroupId, String, and List<int>', () {
      final g1 = GroupId(rawBytes);
      expect(GroupId.from(g1), equals(g1));
      expect(GroupId.from(rawHex), equals(g1));
      expect(GroupId.from(rawBytes.toList()), equals(g1));

      expect(() => GroupId.from(123), throwsArgumentError);
    });

    test('rejects byte lists and hex strings of invalid length or characters',
        () {
      expect(() => GroupId.fromBytes([1, 2, 3]), throwsArgumentError);
      expect(() => GroupId.fromBytes(List.generate(17, (i) => i)),
          throwsArgumentError);
      expect(() => GroupId.fromHex('abcd'), throwsArgumentError);
      expect(() => GroupId.fromHex('abc'), throwsArgumentError);
      expect(() => GroupId.fromHex(''), throwsArgumentError);
      expect(() => GroupId.fromHex('zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz'),
          throwsArgumentError);
    });

    test('value equality and hashCode', () {
      final g1 = GroupId.fromHex(rawHex);
      final g2 = GroupId.fromBytes(rawBytes);
      final g3 = GroupId.fromHex('ffffffffffffffffffffffffffffffff');

      expect(g1, equals(g2));
      expect(g1.hashCode, equals(g2.hashCode));
      expect(g1, isNot(equals(g3)));
    });
  });

  group('HttpReply and HttpExecutor', () {
    test('HttpReply properties, UTF-8 decoding, and case-insensitive header()',
        () {
      final body = Uint8List.fromList(utf8.encode('{"status":"ok"}'));
      final reply = HttpReply(
        statusCode: 200,
        headers: const {'Content-Type': 'application/json'},
        body: body,
      );

      expect(reply.statusCode, 200);
      expect(reply.isSuccess, isTrue);
      expect(reply.bodyAsString, '{"status":"ok"}');
      expect(reply.header('content-type'), 'application/json');
      expect(reply.header('CONTENT-TYPE'), 'application/json');
      expect(reply.header('x-missing'), isNull);

      final errReply = HttpReply(statusCode: 404, body: Uint8List(0));
      expect(errReply.isSuccess, isFalse);
    });

    test('MockHttpExecutor captures request details and responds', () async {
      String? capturedMethod;
      Uri? capturedUrl;
      Map<String, String>? capturedHeaders;
      Uint8List? capturedBody;

      final executor = MockHttpExecutor((method, url, headers, body) async {
        capturedMethod = method;
        capturedUrl = url;
        capturedHeaders = headers;
        capturedBody = body;
        return HttpReply(
          statusCode: 201,
          body: Uint8List.fromList(utf8.encode('{"created":true}')),
        );
      });

      final reply = await executor.send(
        'POST',
        Uri.parse('https://example.com/api/test'),
        headers: {'x-custom': 'val'},
        body: Uint8List.fromList(utf8.encode('ping')),
      );

      expect(capturedMethod, 'POST');
      expect(capturedUrl.toString(), 'https://example.com/api/test');
      expect(capturedHeaders?['x-custom'], 'val');
      expect(utf8.decode(capturedBody!), 'ping');
      expect(reply.statusCode, 201);
      expect(reply.bodyAsString, '{"created":true}');
    });

    test(
        'IoHttpExecutor sends requests and preserves injected external HttpClient on close()',
        () async {
      final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
      server.listen((req) async {
        if (req.method == 'POST' && req.uri.path == '/echo') {
          final body = await utf8.decoder.bind(req).join();
          req.response.statusCode = 200;
          req.response.headers.set('content-type', 'application/json');
          req.response.write('{"echo":$body}');
          await req.response.close();
        } else {
          req.response.statusCode = 404;
          await req.response.close();
        }
      });

      final sharedHttpClient = HttpClient();
      final borrowedExecutor = IoHttpExecutor(client: sharedHttpClient);
      final url =
          Uri.parse('http://${server.address.host}:${server.port}/echo');
      try {
        final reply = await borrowedExecutor.send(
          'POST',
          url,
          headers: {'content-type': 'application/json'},
          body: Uint8List.fromList(utf8.encode('"hello msgp2p"')),
        );
        expect(reply.statusCode, 200);
        expect(reply.bodyAsString, '{"echo":"hello msgp2p"}');
        expect(reply.header('Content-Type'), contains('application/json'));

        // Closing borrowedExecutor must NOT close sharedHttpClient
        borrowedExecutor.close(force: true);
        final secondReq = await sharedHttpClient.postUrl(url);
        secondReq.write('"still open"');
        final secondRes = await secondReq.close();
        expect(secondRes.statusCode, 200);
        await secondRes.drain<void>();
      } finally {
        sharedHttpClient.close(force: true);
        await server.close(force: true);
      }
    });
  });

  // 1. Run GatewayApi contract suite on MemoryGatewayApi
  runGatewayApiContractTests('MemoryGatewayApi', () async {
    final groupId = GroupId(List.filled(16, 0x42));
    final ed25519 = Ed25519();
    final authorKp = await ed25519.newKeyPair();
    final authorPk = await authorKp.extractPublicKey();
    final serverKp = await ed25519.newKeyPair();
    final serverPk = await serverKp.extractPublicKey();
    final serverPubkey = Uint8List.fromList(serverPk.bytes);

    final cert = await _createCert(
      groupId: groupId.bytes,
      userId: 'user_alice',
      memberPubkey: Uint8List.fromList(authorPk.bytes),
      noisePubkey: Uint8List(32),
      serverKeyPair: serverKp,
    );

    final api = MemoryGatewayApi(
      serverPublicKey: serverPubkey,
      serverSigningKeyPair: serverKp,
    );

    return GatewayApiContext(
      api: api,
      groupId: groupId,
      authorKeyPair: authorKp,
      groupKey: Uint8List(32),
      cert: cert,
      serverPublicKey: serverPubkey,
      serverKeyPair: serverKp,
      seedRevocation: (notice) async => api.addRevocation(groupId, notice),
    );
  });

  // 2. Run GatewayApi contract suite on GatewayClient + MockHttpExecutor
  runGatewayApiContractTests('GatewayClient (MockHttpExecutor)', () async {
    final groupId = GroupId(List.filled(16, 0x43));
    final ed25519 = Ed25519();
    final authorKp = await ed25519.newKeyPair();
    final authorPk = await authorKp.extractPublicKey();
    final serverKp = await ed25519.newKeyPair();
    final serverPk = await serverKp.extractPublicKey();
    final serverPubkey = Uint8List.fromList(serverPk.bytes);

    final cert = await _createCert(
      groupId: groupId.bytes,
      userId: 'user_alice',
      memberPubkey: Uint8List.fromList(authorPk.bytes),
      noisePubkey: Uint8List(32),
      serverKeyPair: serverKp,
    );

    final backend = MemoryGatewayApi(
      serverPublicKey: serverPubkey,
      serverSigningKeyPair: serverKp,
    );
    final client = GatewayClient(
      baseUrl: 'https://gateway.example.org/api/v1',
      authToken: 'contract_token',
      httpExecutor: MockHttpExecutor(
        (method, url, headers, body) =>
            _dispatchGatewayHttpRequest(backend, method, url, headers, body),
      ),
    );

    return GatewayApiContext(
      api: client,
      groupId: groupId,
      authorKeyPair: authorKp,
      groupKey: Uint8List(32),
      cert: cert,
      serverPublicKey: serverPubkey,
      serverKeyPair: serverKp,
      seedRevocation: (notice) async => backend.addRevocation(groupId, notice),
      dispose: () async => client.close(),
    );
  });

  // 3. Run GatewayApi contract suite on GatewayClient + IoHttpExecutor over local HttpServer
  runGatewayApiContractTests('GatewayClient (IoHttpExecutor + HttpServer)',
      () async {
    final groupId = GroupId(List.filled(16, 0x44));
    final ed25519 = Ed25519();
    final authorKp = await ed25519.newKeyPair();
    final authorPk = await authorKp.extractPublicKey();
    final serverKp = await ed25519.newKeyPair();
    final serverPk = await serverKp.extractPublicKey();
    final serverPubkey = Uint8List.fromList(serverPk.bytes);

    final cert = await _createCert(
      groupId: groupId.bytes,
      userId: 'user_alice',
      memberPubkey: Uint8List.fromList(authorPk.bytes),
      noisePubkey: Uint8List(32),
      serverKeyPair: serverKp,
    );

    final backend = MemoryGatewayApi(
      serverPublicKey: serverPubkey,
      serverSigningKeyPair: serverKp,
    );
    final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
    server.listen((req) async {
      final reqBytes = BytesBuilder(copy: false);
      await for (final chunk in req) {
        reqBytes.add(chunk);
      }
      final headers = <String, String>{};
      req.headers.forEach((k, v) => headers[k.toLowerCase()] = v.join(', '));
      final reply = await _dispatchGatewayHttpRequest(
        backend,
        req.method,
        req.uri,
        headers,
        reqBytes.takeBytes(),
      );
      req.response.statusCode = reply.statusCode;
      reply.headers.forEach((k, v) => req.response.headers.set(k, v));
      req.response.add(reply.body);
      await req.response.close();
    });

    final client = GatewayClient(
      baseUrl: 'http://${server.address.host}:${server.port}/api/v1',
      authToken: 'live_socket_token',
    );

    return GatewayApiContext(
      api: client,
      groupId: groupId,
      authorKeyPair: authorKp,
      groupKey: Uint8List(32),
      cert: cert,
      serverPublicKey: serverPubkey,
      serverKeyPair: serverKp,
      seedRevocation: (notice) async => backend.addRevocation(groupId, notice),
      dispose: () async {
        client.close();
        await server.close(force: true);
      },
    );
  });

  group('GatewayClient error handling & named helpers', () {
    final groupId = GroupId(List.filled(16, 0x55));

    test('handles 401 JSON Unauthorized throwing GatewayException', () async {
      final client = GatewayClient(
        baseUrl: 'https://gateway.example.org',
        httpExecutor: MockHttpExecutor((method, url, headers, body) async {
          return HttpReply(
            statusCode: 401,
            body: Uint8List.fromList(utf8
                .encode('{"error":"UNAUTHORIZED","message":"Invalid token"}')),
          );
        }),
      );

      await expectLater(
        () => client.pull(groupId, VersionVector()),
        throwsA(isA<GatewayException>()
            .having((e) => e.statusCode, 'statusCode', 401)
            .having((e) => e.error, 'error', 'UNAUTHORIZED')),
      );
    });

    test(
        'handles non-JSON 502 HTML and empty 404 responses throwing GatewayException instead of FormatException',
        () async {
      final html502Client = GatewayClient(
        baseUrl: 'https://gateway.example.org',
        httpExecutor: MockHttpExecutor((method, url, headers, body) async {
          return HttpReply(
            statusCode: 502,
            headers: const {'content-type': 'text/html'},
            body: Uint8List.fromList(
                utf8.encode('<html><body>502 Bad Gateway</body></html>')),
          );
        }),
      );

      await expectLater(
        () => html502Client.pull(groupId, VersionVector()),
        throwsA(isA<GatewayException>()
            .having((e) => e.statusCode, 'statusCode', 502)
            .having((e) => e.error, 'error', 'HTTP_502')),
      );

      final empty404Client = GatewayClient(
        baseUrl: 'https://gateway.example.org',
        httpExecutor: MockHttpExecutor((method, url, headers, body) async {
          return HttpReply(statusCode: 404, body: Uint8List(0));
        }),
      );

      await expectLater(
        () => empty404Client.receipts(groupId),
        throwsA(isA<GatewayException>()
            .having((e) => e.statusCode, 'statusCode', 404)
            .having((e) => e.error, 'error', 'HTTP_404')),
      );
    });

    test(
        'downloadAttachment rejects tampered server payload with ATTACHMENT_HASH_MISMATCH',
        () async {
      final expectedBytes = Uint8List.fromList(utf8.encode('authentic blob'));
      final ref = AttachmentRef.fromBytes(
        bytes: expectedBytes,
        mime: 'application/octet-stream',
      );

      final client = GatewayClient(
        baseUrl: 'https://gateway.example.org',
        httpExecutor: MockHttpExecutor((method, url, headers, body) async {
          return HttpReply(
            statusCode: 200,
            body: Uint8List.fromList(utf8.encode(jsonEncode({
              'mime': 'application/octet-stream',
              'data_base64': base64Encode(utf8.encode('MITM tampered blob')),
            }))),
          );
        }),
      );

      await expectLater(
        () => client.downloadAttachment(groupId, ref),
        throwsA(isA<GatewayException>()
            .having((e) => e.error, 'error', 'ATTACHMENT_HASH_MISMATCH')),
      );
    });

    test('named-parameter convenience helpers forward to GatewayApi methods',
        () async {
      var pushCalled = false;
      var pullCalled = false;
      var receiptsCalled = false;
      var revsCalled = false;
      var attUploadCalled = false;
      var attDownloadCalled = false;

      final attBytes = Uint8List.fromList(utf8.encode('helper blob'));
      final attHash = MsgP2PCrypto.sha256(attBytes);

      final client = GatewayClient(
        baseUrl: 'https://gateway.example.org',
        httpExecutor: MockHttpExecutor((method, url, headers, body) async {
          if (url.path == '/sync/push') {
            pushCalled = true;
            return HttpReply(
              statusCode: 200,
              body: Uint8List.fromList(utf8
                  .encode('{"accepted_ids":[],"rejected":[],"receipts":[]}')),
            );
          } else if (url.path == '/sync/pull') {
            pullCalled = true;
            return HttpReply(
              statusCode: 200,
              body: Uint8List.fromList(
                  utf8.encode('{"envelopes":[],"has_more":false}')),
            );
          } else if (url.path == '/sync/receipts') {
            receiptsCalled = true;
            return HttpReply(
              statusCode: 200,
              body: Uint8List.fromList(utf8.encode('{"receipts":[]}')),
            );
          } else if (url.path == '/sync/revocations') {
            revsCalled = true;
            return HttpReply(
              statusCode: 200,
              body: Uint8List.fromList(utf8.encode('{"revocations":[]}')),
            );
          } else if (method == 'POST' && url.path == '/sync/attachments') {
            attUploadCalled = true;
            return HttpReply(
              statusCode: 200,
              body: Uint8List.fromList(utf8.encode('{"stored":true}')),
            );
          } else if (method == 'GET' && url.path == '/sync/attachments') {
            attDownloadCalled = true;
            return HttpReply(
              statusCode: 200,
              body: Uint8List.fromList(utf8.encode(jsonEncode({
                'mime': 'text/plain',
                'data_base64': base64Encode(attBytes),
              }))),
            );
          }
          return HttpReply(statusCode: 404, body: Uint8List(0));
        }),
      );

      await client.pushEnvelopes(groupId: groupId.hexString, envelopes: []);
      expect(pushCalled, isTrue);

      await client.pullDelta(
          groupId: groupId.hexString, vector: VersionVector());
      expect(pullCalled, isTrue);

      await client.getReceipts(groupId: groupId.hexString);
      expect(receiptsCalled, isTrue);

      await client.getRevocations(groupId: groupId.hexString);
      expect(revsCalled, isTrue);

      await client.uploadAttachmentBlob(
        groupId: groupId.hexString,
        hash: attHash,
        mime: 'text/plain',
        bytes: attBytes,
      );
      expect(attUploadCalled, isTrue);

      final blob = await client.downloadAttachmentBlob(
        groupId: groupId.hexString,
        hash: attHash,
      );
      expect(attDownloadCalled, isTrue);
      expect(blob.bytes, equals(attBytes));
    });
  });

  group('GatewayApiSync.syncStore cryptographic verification', () {
    final groupId = GroupId(List.filled(16, 0x77));
    final otherGroupId = GroupId(List.filled(16, 0x88));

    test('rejects non-32-byte pinnedServerKey', () async {
      final api = MemoryGatewayApi();
      final store = MemoryMessageStore();
      await expectLater(
        () => api.syncStore(
          store: store,
          groupId: groupId,
          pinnedServerKey: Uint8List(16),
        ),
        throwsArgumentError,
      );
    });

    test(
        'drops forged or wrong-group receipts, revocations, and invalid/revoked/expired/future envelopes',
        () async {
      final ed25519 = Ed25519();
      final serverKp = await ed25519.newKeyPair();
      final serverPubkey =
          Uint8List.fromList((await serverKp.extractPublicKey()).bytes);
      final attackerServerKp = await ed25519.newKeyPair();

      final aliceKp = await ed25519.newKeyPair();
      final alicePubkey =
          Uint8List.fromList((await aliceKp.extractPublicKey()).bytes);
      final revokedKp = await ed25519.newKeyPair();
      final revokedPubkey =
          Uint8List.fromList((await revokedKp.extractPublicKey()).bytes);
      final innocentKp = await ed25519.newKeyPair();
      final innocentPubkey =
          Uint8List.fromList((await innocentKp.extractPublicKey()).bytes);

      final fixedNowMs = 1700000000000;
      final clock =
          VirtualClock(DateTime.fromMillisecondsSinceEpoch(fixedNowMs));
      final groupKey = Uint8List.fromList(List.filled(32, 0x33));
      final certRef = Uint8List.fromList(List.filled(32, 0x11));

      // Outbound envelope pushed by Alice
      final pushedEnv = await Envelope.create(
        groupId: groupId.bytes,
        keyEpoch: 1,
        groupKey: groupKey,
        authorKeyPair: aliceKp,
        certRef: certRef,
        seq: 1,
        customCreatedAt: fixedNowMs,
        ttl: const Duration(hours: 24),
        payload: {'type': 'post', 'body': 'outbound'},
      );

      // Valid inbound envelope authored by innocent member
      final validPulledEnv = await Envelope.create(
        groupId: groupId.bytes,
        keyEpoch: 1,
        groupKey: groupKey,
        authorKeyPair: innocentKp,
        certRef: certRef,
        seq: 1,
        customCreatedAt: fixedNowMs,
        ttl: const Duration(hours: 24),
        payload: {'type': 'post', 'body': 'valid inbound'},
      );

      // Tampered signature envelope
      final tamperedSigEnv = Envelope(
        core: validPulledEnv.core,
        sig: Uint8List(64), // invalid zeroed signature
        certRef: validPulledEnv.certRef,
      );

      // Wrong-group envelope (valid signature, wrong group_id)
      final wrongGroupEnv = await Envelope.create(
        groupId: otherGroupId.bytes,
        keyEpoch: 1,
        groupKey: groupKey,
        authorKeyPair: innocentKp,
        certRef: certRef,
        seq: 2,
        customCreatedAt: fixedNowMs,
        ttl: const Duration(hours: 24),
        payload: {'type': 'post', 'body': 'wrong group'},
      );

      // Envelope authored by revoked member
      final revokedAuthorEnv = await Envelope.create(
        groupId: groupId.bytes,
        keyEpoch: 1,
        groupKey: groupKey,
        authorKeyPair: revokedKp,
        certRef: certRef,
        seq: 1,
        customCreatedAt: fixedNowMs,
        ttl: const Duration(hours: 24),
        payload: {'type': 'post', 'body': 'from revoked author'},
      );

      // Expired envelope
      final expiredEnv = await Envelope.create(
        groupId: groupId.bytes,
        keyEpoch: 1,
        groupKey: groupKey,
        authorKeyPair: innocentKp,
        certRef: certRef,
        seq: 3,
        customCreatedAt: fixedNowMs - 7200000,
        ttl: const Duration(hours: 1),
        payload: {'type': 'post', 'body': 'expired'},
      );

      // Future-drifted envelope (> 10 minutes ahead)
      final futureEnv = await Envelope.create(
        groupId: groupId.bytes,
        keyEpoch: 1,
        groupKey: groupKey,
        authorKeyPair: innocentKp,
        certRef: certRef,
        seq: 4,
        customCreatedAt: fixedNowMs + (15 * 60 * 1000),
        ttl: const Duration(hours: 24),
        payload: {'type': 'post', 'body': 'too far in future'},
      );

      Future<ServerReceipt> signReceipt({
        required Uint8List gid,
        required Uint8List author,
        required int seq,
        required SimpleKeyPair signer,
      }) async {
        final core = ServerReceipt(
          groupId: gid,
          author: author,
          ranges: [SeqRange(seq, seq)],
          issuedAt: fixedNowMs,
          serverSig: Uint8List(64),
        );
        final sig = await MsgP2PCrypto.sign(core.toCoreCbor(), signer);
        return ServerReceipt(
          groupId: core.groupId,
          author: core.author,
          ranges: core.ranges,
          issuedAt: core.issuedAt,
          serverSig: sig,
        );
      }

      Future<RevocationNotice> signRevocation({
        required Uint8List gid,
        required Uint8List member,
        required SimpleKeyPair signer,
      }) async {
        final core = RevocationNotice(
          groupId: gid,
          memberPubkey: member,
          revokedAt: fixedNowMs,
          reason: 'compromised',
          serverSig: Uint8List(64),
        );
        final sig = await MsgP2PCrypto.sign(core.toCoreCbor(), signer);
        return RevocationNotice(
          groupId: core.groupId,
          memberPubkey: core.memberPubkey,
          revokedAt: core.revokedAt,
          reason: core.reason,
          serverSig: sig,
        );
      }

      // Forged receipt on push (signed by attackerServerKp) -> must NOT confirm Alice seq 1
      final forgedPushReceipt = await signReceipt(
        gid: groupId.bytes,
        author: alicePubkey,
        seq: 1,
        signer: attackerServerKp,
      );
      // Wrong-group receipt (signed by legitimate serverKp, but for otherGroupId) -> must be dropped
      final wrongGroupReceipt = await signReceipt(
        gid: otherGroupId.bytes,
        author: alicePubkey,
        seq: 1,
        signer: serverKp,
      );
      // Forged receipt from receipts() endpoint -> must be dropped
      final forgedPolledReceipt = await signReceipt(
        gid: groupId.bytes,
        author: alicePubkey,
        seq: 1,
        signer: attackerServerKp,
      );
      // Valid receipt for innocentPubkey seq 1 -> must be accepted
      final validReceipt = await signReceipt(
        gid: groupId.bytes,
        author: innocentPubkey,
        seq: 1,
        signer: serverKp,
      );

      // Forged revocation against innocentPubkey (signed by attackerServerKp) -> must be dropped
      final forgedRevocation = await signRevocation(
        gid: groupId.bytes,
        member: innocentPubkey,
        signer: attackerServerKp,
      );
      // Wrong-group revocation against alicePubkey -> must be dropped
      final wrongGroupRevocation = await signRevocation(
        gid: otherGroupId.bytes,
        member: alicePubkey,
        signer: serverKp,
      );
      // Valid revocation against revokedPubkey -> must be accepted and block revokedAuthorEnv
      final validRevocation = await signRevocation(
        gid: groupId.bytes,
        member: revokedPubkey,
        signer: serverKp,
      );

      final maliciousClient = GatewayClient(
        baseUrl: 'http://untrusted-gateway.local/api/v1',
        httpExecutor: MockHttpExecutor((method, url, headers, body) async {
          HttpReply jsonReply(Map<String, dynamic> payload) => HttpReply(
                statusCode: 200,
                headers: const {'content-type': 'application/json'},
                body: Uint8List.fromList(utf8.encode(jsonEncode(payload))),
              );

          if (url.path.endsWith('/sync/push')) {
            return jsonReply({
              'accepted_ids': [pushedEnv.messageIdHex],
              'rejected': <Map<String, dynamic>>[],
              'receipts': [
                {
                  'raw_cbor_base64':
                      base64Encode(forgedPushReceipt.toFullCbor())
                },
                {
                  'raw_cbor_base64':
                      base64Encode(wrongGroupReceipt.toFullCbor())
                },
              ],
            });
          }
          if (url.path.endsWith('/sync/receipts')) {
            return jsonReply({
              'receipts': [
                {
                  'raw_cbor_base64':
                      base64Encode(forgedPolledReceipt.toFullCbor())
                },
                {'raw_cbor_base64': base64Encode(validReceipt.toFullCbor())},
              ],
            });
          }
          if (url.path.endsWith('/sync/revocations')) {
            return jsonReply({
              'revocations': [
                {
                  'raw_cbor_base64': base64Encode(forgedRevocation.toFullCbor())
                },
                {
                  'raw_cbor_base64':
                      base64Encode(wrongGroupRevocation.toFullCbor())
                },
                {'raw_cbor_base64': base64Encode(validRevocation.toFullCbor())},
              ],
            });
          }
          if (url.path.endsWith('/sync/pull')) {
            return jsonReply({
              'envelopes': [
                tamperedSigEnv,
                wrongGroupEnv,
                revokedAuthorEnv,
                expiredEnv,
                futureEnv,
                validPulledEnv,
              ].map((e) => base64Encode(e.toCanonicalCbor())).toList(),
              'has_more': false,
            });
          }
          return HttpReply(statusCode: 404, body: Uint8List(0));
        }),
      );

      final store = MemoryMessageStore();
      await store.saveEnvelope(pushedEnv, customStoredAt: fixedNowMs);

      final res = await maliciousClient.sync(
        store: store,
        groupId: groupId,
        pinnedServerKey: serverPubkey,
        pendingEnvelopes: [pushedEnv],
        clock: clock,
      );

      // Forged/wrong-group receipts dropped; only validReceipt accepted
      expect(res.receiptsCount, equals(1));
      expect(await store.isConfirmed(alicePubkey, 1), isFalse);
      expect(await store.isConfirmed(innocentPubkey, 1), isTrue);

      // Forged/wrong-group revocations dropped; only validRevocation accepted
      expect(res.revocationsCount, equals(1));
      expect(await store.isRevoked(innocentPubkey), isFalse);
      expect(await store.isRevoked(alicePubkey), isFalse);
      expect(await store.isRevoked(revokedPubkey), isTrue);

      // Only validPulledEnv saved; tampered, wrong-group, revoked, expired, and future dropped
      expect(res.pulledCount, equals(1));
      expect(await store.containsEnvelope(validPulledEnv.messageId), isTrue);
      expect(await store.containsEnvelope(wrongGroupEnv.messageId), isFalse);
      expect(await store.containsEnvelope(revokedAuthorEnv.messageId), isFalse);
      expect(await store.containsEnvelope(expiredEnv.messageId), isFalse);
      expect(await store.containsEnvelope(futureEnv.messageId), isFalse);
    });
  });
}
