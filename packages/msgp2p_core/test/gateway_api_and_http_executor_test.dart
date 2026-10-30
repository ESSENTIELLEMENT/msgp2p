import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';
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
    issuedAt: now - 1000,
    expiresAt: now + (7 * 86400 * 1000),
    serverSig: sig,
  );
}

void main() {
  group('GroupId domain type', () {
    final rawBytes = Uint8List.fromList(List.generate(16, (i) => i + 1));
    final rawHex = '0102030405060708090a0b0c0d0e0f10';

    test('constructs from bytes and formats hex', () {
      final gid = GroupId(rawBytes);
      expect(gid.bytes, equals(rawBytes));
      expect(gid.hexString, equals(rawHex));
      expect(gid.toString(), equals(rawHex));
    });

    test('constructs from valid hex string', () {
      final gid = GroupId.fromHex(rawHex);
      expect(gid.bytes, equals(rawBytes));
      expect(gid.hexString, equals(rawHex));

      // Supports optional 0x prefix
      final gidWith0x = GroupId.fromHex('0x$rawHex');
      expect(gidWith0x, equals(gid));
    });

    test('GroupId.from parses GroupId, String, and List<int>', () {
      final g1 = GroupId(rawBytes);
      expect(GroupId.from(g1), equals(g1));
      expect(GroupId.from(rawHex), equals(g1));
      expect(GroupId.from(rawBytes.toList()), equals(g1));

      expect(() => GroupId.from(123), throwsArgumentError);
    });

    test('rejects byte lists and hex strings of invalid length', () {
      expect(() => GroupId.fromBytes([1, 2, 3]), throwsArgumentError);
      expect(() => GroupId.fromBytes(List.generate(17, (i) => i)),
          throwsArgumentError);
      expect(() => GroupId.fromHex('abcd'), throwsArgumentError);
      expect(() => GroupId.fromHex(''), throwsArgumentError);
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
    test('HttpReply properties and UTF-8 body decoding', () {
      final body = Uint8List.fromList(utf8.encode('{"status":"ok"}'));
      final reply = HttpReply(
        statusCode: 200,
        headers: {'content-type': 'application/json'},
        body: body,
      );

      expect(reply.statusCode, 200);
      expect(reply.isSuccess, isTrue);
      expect(reply.bodyAsString, '{"status":"ok"}');
      expect(reply.headers['content-type'], 'application/json');

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

    test('IoHttpExecutor sends requests against local HttpServer', () async {
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

      final executor = IoHttpExecutor();
      try {
        final url =
            Uri.parse('http://${server.address.host}:${server.port}/echo');
        final reply = await executor.send(
          'POST',
          url,
          headers: {'content-type': 'application/json'},
          body: Uint8List.fromList(utf8.encode('"hello msgp2p"')),
        );

        expect(reply.statusCode, 200);
        expect(reply.isSuccess, isTrue);
        expect(reply.bodyAsString, '{"echo":"hello msgp2p"}');
        expect(reply.headers['content-type'], contains('application/json'));
      } finally {
        executor.close();
        await server.close(force: true);
      }
    });
  });

  // Run GatewayApi contract suite on MemoryGatewayApi
  runGatewayApiContractTests('MemoryGatewayApi', () async {
    final groupId = GroupId(Uint8List.fromList(List.generate(16, (i) => 0x42)));
    final ed25519 = Ed25519();
    final authorKp = await ed25519.newKeyPair();
    final authorPk = await authorKp.extractPublicKey();

    final serverKp = await ed25519.newKeyPair();
    final serverPk = await serverKp.extractPublicKey();

    final cert = await _createCert(
      groupId: groupId.bytes,
      userId: 'user_alice',
      memberPubkey: Uint8List.fromList(authorPk.bytes),
      noisePubkey: Uint8List(32),
      serverKeyPair: serverKp,
    );

    final api = MemoryGatewayApi(
      serverPublicKey: Uint8List.fromList(serverPk.bytes),
      receiptSigner: (env) async {
        return ServerReceipt(
          version: 1,
          groupId: env.core.groupId,
          author: env.core.author,
          ranges: [SeqRange(env.core.seq, env.core.seq)],
          issuedAt: DateTime.now().millisecondsSinceEpoch,
          serverSig: Uint8List(64),
        );
      },
    );

    return GatewayApiContext(
      api: api,
      groupId: groupId,
      authorKeyPair: authorKp,
      groupKey: Uint8List(32),
      cert: cert,
    );
  });

  group('GatewayClient with MockHttpExecutor', () {
    late GroupId groupId;
    late SimpleKeyPair authorKp;
    late MembershipCert cert;
    final groupKey = Uint8List(32);

    setUp(() async {
      groupId = GroupId(Uint8List.fromList(List.generate(16, (i) => 0x55)));
      final ed25519 = Ed25519();
      authorKp = await ed25519.newKeyPair();
      final authorPk = await authorKp.extractPublicKey();
      final serverKp = await ed25519.newKeyPair();

      cert = await _createCert(
        groupId: groupId.bytes,
        userId: 'test_user',
        memberPubkey: Uint8List.fromList(authorPk.bytes),
        noisePubkey: Uint8List(32),
        serverKeyPair: serverKp,
      );
    });

    test('handles 401 Unauthorized throwing GatewayException', () async {
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

      expect(
        () => client.pull(groupId, VersionVector()),
        throwsA(isA<GatewayException>()
            .having((e) => e.statusCode, 'statusCode', 401)
            .having((e) => e.error, 'error', 'UNAUTHORIZED')),
      );
    });

    test('sync handles push, pull, receipts, and attachment upload/download',
        () async {
      final store = MemoryMessageStore();
      await store.saveCertificate(cert);

      final env = await Envelope.create(
        groupId: groupId.bytes,
        keyEpoch: 1,
        groupKey: groupKey,
        authorKeyPair: authorKp,
        certRef: cert.certRef,
        seq: 1,
        ttl: const Duration(hours: 1),
        priority: 1,
        payload: {'text': 'sync message'},
      );
      await store.saveEnvelope(env);

      final receipt = ServerReceipt(
        version: 1,
        groupId: groupId.bytes,
        author: env.core.author,
        ranges: [SeqRange(1, 1)],
        issuedAt: DateTime.now().millisecondsSinceEpoch,
        serverSig: Uint8List(64),
      );

      final client = GatewayClient(
        baseUrl: 'https://gateway.example.org',
        authToken: 'secret_token_123',
        httpExecutor: MockHttpExecutor((method, url, headers, body) async {
          expect(headers['authorization'], equals('Bearer secret_token_123'));

          if (url.path == '/sync/push') {
            return HttpReply(
              statusCode: 200,
              body: Uint8List.fromList(utf8.encode(jsonEncode({
                'accepted_ids': [env.messageIdHex],
                'rejected': [],
                'receipts': [
                  {
                    'raw_cbor_base64': base64Encode(receipt.toFullCbor()),
                  }
                ],
              }))),
            );
          } else if (url.path == '/sync/receipts') {
            return HttpReply(
              statusCode: 200,
              body: Uint8List.fromList(utf8.encode(jsonEncode({
                'receipts': [],
              }))),
            );
          } else if (url.path == '/sync/revocations') {
            return HttpReply(
              statusCode: 200,
              body: Uint8List.fromList(utf8.encode(jsonEncode({
                'revocations': [],
              }))),
            );
          } else if (url.path == '/sync/pull') {
            return HttpReply(
              statusCode: 200,
              body: Uint8List.fromList(utf8.encode(jsonEncode({
                'envelopes': [],
                'has_more': false,
              }))),
            );
          }
          return HttpReply(statusCode: 404, body: Uint8List(0));
        }),
      );

      final result = await client.sync(
        store: store,
        groupId: groupId,
        pendingEnvelopes: [env],
      );

      expect(result.pushedCount, 1);
      expect(result.acceptedCount, 1);
      expect(result.receiptsCount, 1);
      expect(await store.isConfirmed(env.core.author, 1), isTrue);
    });

    test('backwards-compatible named parameter aliases forward correctly',
        () async {
      var pushNamedCalled = false;
      var pullNamedCalled = false;
      var getReceiptsCalled = false;
      var getRevsCalled = false;

      final client = GatewayClient(
        baseUrl: 'https://gateway.example.org',
        httpExecutor: MockHttpExecutor((method, url, headers, body) async {
          if (url.path == '/sync/push') {
            pushNamedCalled = true;
            return HttpReply(
              statusCode: 200,
              body: Uint8List.fromList(utf8
                  .encode('{"accepted_ids":[],"rejected":[],"receipts":[]}')),
            );
          } else if (url.path == '/sync/pull') {
            pullNamedCalled = true;
            return HttpReply(
              statusCode: 200,
              body: Uint8List.fromList(
                  utf8.encode('{"envelopes":[],"has_more":false}')),
            );
          } else if (url.path == '/sync/receipts') {
            getReceiptsCalled = true;
            return HttpReply(
              statusCode: 200,
              body: Uint8List.fromList(utf8.encode('{"receipts":[]}')),
            );
          } else if (url.path == '/sync/revocations') {
            getRevsCalled = true;
            return HttpReply(
              statusCode: 200,
              body: Uint8List.fromList(utf8.encode('{"revocations":[]}')),
            );
          }
          return HttpReply(statusCode: 404, body: Uint8List(0));
        }),
      );

      await client.pushEnvelopes(groupId: groupId.hexString, envelopes: []);
      expect(pushNamedCalled, isTrue);

      await client.pullDelta(
          groupId: groupId.hexString, vector: VersionVector());
      expect(pullNamedCalled, isTrue);

      await client.getReceipts(groupId: groupId.hexString);
      expect(getReceiptsCalled, isTrue);

      await client.getRevocations(groupId: groupId.hexString);
      expect(getRevsCalled, isTrue);
    });
  });
}
