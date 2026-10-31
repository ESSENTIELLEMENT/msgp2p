import 'dart:convert';
import 'dart:typed_data';
import 'package:convert/convert.dart';
import 'package:meta/meta.dart';
import '../model/certificate.dart';
import '../model/envelope.dart';
import '../model/receipt.dart';
import '../model/revocation.dart';
import '../model/version_vector.dart';
import '../storage/message_store.dart';
import '../sync/clock_rules.dart';
import 'gateway_api.dart';
import 'io_http_executor_stub.dart'
    if (dart.library.io) 'io_http_executor.dart';

export 'gateway_api.dart'
    show GatewayException, RejectedItem, PushResult, PullResult, SyncResult;

/// Result of user registration.
@immutable
class RegisterResult {
  final String userId;
  final String status;

  const RegisterResult({required this.userId, required this.status});

  factory RegisterResult.fromJson(Map<String, dynamic> json) {
    return RegisterResult(
      userId: json['user_id'] as String,
      status: json['status'] as String,
    );
  }
}

/// Symmetrically shared group key epoch info.
@immutable
class GroupKeyDto {
  final int epoch;
  final String keyHex;
  final int validUntil;

  const GroupKeyDto({
    required this.epoch,
    required this.keyHex,
    required this.validUntil,
  });

  factory GroupKeyDto.fromJson(Map<String, dynamic> json) {
    return GroupKeyDto(
      epoch: json['epoch'] as int,
      keyHex: json['key_hex'] as String,
      validUntil: json['valid_until'] as int,
    );
  }
}

/// Result of user authentication.
@immutable
class LoginResult {
  final String accessToken;
  final int expiresIn;
  final Uint8List serverPubkey;
  final MembershipCert membershipCert;
  final Uint8List groupBeaconKey;
  final List<GroupKeyDto> groupKeys;

  const LoginResult({
    required this.accessToken,
    required this.expiresIn,
    required this.serverPubkey,
    required this.membershipCert,
    required this.groupBeaconKey,
    required this.groupKeys,
  });

  factory LoginResult.fromJson(Map<String, dynamic> json) {
    final certJson = json['membership_cert'] as Map<String, dynamic>;
    final rawCertCbor = base64Decode(certJson['raw_cbor_base64'] as String);
    final cert = MembershipCert.fromCbor(rawCertCbor);

    final rawKeys = json['group_keys'] as List? ?? [];
    final keys = rawKeys
        .map((k) => GroupKeyDto.fromJson(k as Map<String, dynamic>))
        .toList();

    return LoginResult(
      accessToken: json['access_token'] as String,
      expiresIn: json['expires_in'] as int,
      serverPubkey:
          Uint8List.fromList(hex.decode(json['server_pubkey'] as String)),
      membershipCert: cert,
      groupBeaconKey:
          Uint8List.fromList(hex.decode(json['group_beacon_key'] as String)),
      groupKeys: keys,
    );
  }
}

/// Result of revoking a group member and rotating the group key epoch (FR-SEC-02).
@immutable
class RevokeMemberResult {
  final RevocationNotice revocation;
  final GroupKeyDto newGroupKey;

  const RevokeMemberResult({
    required this.revocation,
    required this.newGroupKey,
  });

  factory RevokeMemberResult.fromJson(Map<String, dynamic> json) {
    final revMap = json['revocation'] as Map<String, dynamic>;
    final rawCbor = base64Decode(revMap['raw_cbor_base64'] as String);
    final rev = RevocationNotice.fromCbor(rawCbor);
    final newKey =
        GroupKeyDto.fromJson(json['new_group_key'] as Map<String, dynamic>);
    return RevokeMemberResult(revocation: rev, newGroupKey: newKey);
  }
}

/// Gateway HTTP client connecting a mobile mule node with the reference server (FR-SRV-02).
///
/// Implements [GatewayApi] using an injected [HttpExecutor] (defaulting to [IoHttpExecutor]).
class GatewayClient implements GatewayApi {
  final String baseUrl;
  String? authToken;
  final HttpExecutor httpExecutor;
  final bool _ownsExecutor;

  GatewayClient({
    required String baseUrl,
    this.authToken,
    HttpExecutor? httpExecutor,
    @Deprecated(
        'Pass httpExecutor: IoHttpExecutor(client: ...) instead (proposal 0001, step 3)')
    Object? httpClient,
  })  : assert(
          httpExecutor == null || httpClient == null,
          'Cannot specify both httpExecutor and httpClient',
        ),
        baseUrl = baseUrl.endsWith('/')
            ? baseUrl.substring(0, baseUrl.length - 1)
            : baseUrl,
        httpExecutor = httpExecutor ?? IoHttpExecutor(client: httpClient),
        _ownsExecutor = httpExecutor == null;

  /// Registers a new member account and obtains initial server-signed membership certificate (FR-SRV-02).
  @Deprecated(
      'Use MembershipSource / msgp2p_reference_auth instead (proposal 0001, step 4); removed in the next minor version')
  Future<RegisterResult> register({
    required String username,
    required String password,
    required String groupId,
    required Uint8List memberPubkey,
    Uint8List? noisePubkey,
  }) async {
    final payload = {
      'username': username,
      'password': password,
      'group_id': groupId,
      'member_pubkey': hex.encode(memberPubkey),
      if (noisePubkey != null) 'noise_pubkey': hex.encode(noisePubkey),
    };

    final json = await _post('/auth/register', payload, requiresAuth: false);
    return RegisterResult.fromJson(json);
  }

  /// Authenticates user and obtains access token, certificate, group key and beacon key (FR-SRV-03).
  @Deprecated(
      'Use MembershipSource / msgp2p_reference_auth instead (proposal 0001, step 4); removed in the next minor version')
  Future<LoginResult> login({
    required String username,
    required String password,
  }) async {
    final payload = {
      'username': username,
      'password': password,
    };

    final json = await _post('/auth/login', payload, requiresAuth: false);
    final result = LoginResult.fromJson(json);
    authToken = result.accessToken;
    return result;
  }

  /// Pushes a batch of message envelopes and optional author certificates to server (FR-SRV-04).
  @override
  Future<PushResult> push(
    GroupId group,
    List<Envelope> envelopes, {
    List<MembershipCert>? certificates,
  }) async {
    final payload = {
      'group_id': group.hexString,
      'envelopes':
          envelopes.map((e) => base64Encode(e.toCanonicalCbor())).toList(),
      if (certificates != null && certificates.isNotEmpty)
        'certificates':
            certificates.map((c) => base64Encode(c.toFullCbor())).toList(),
    };

    final json = await _post('/sync/push', payload, requiresAuth: true);
    return PushResult.fromJson(json);
  }

  /// Convenience named-parameter helper forwarding to [push].
  Future<PushResult> pushEnvelopes({
    required String groupId,
    required List<Envelope> envelopes,
    List<MembershipCert>? certificates,
  }) =>
      push(GroupId.from(groupId), envelopes, certificates: certificates);

  /// Pulls message delta missing from the client's [knownVector] from server (FR-SRV-05).
  @override
  Future<PullResult> pull(
    GroupId group,
    VersionVector knownVector, {
    int? limit,
  }) async {
    final effectiveLimit = limit ?? 100;
    final vectorCbor = knownVector.toCanonicalCbor();
    final vectorB64 = base64Encode(vectorCbor);
    final path =
        '/sync/pull?group_id=${group.hexString}&vector=${Uri.encodeComponent(vectorB64)}&limit=$effectiveLimit';

    final json = await _get(path, requiresAuth: true);
    return PullResult.fromJson(json);
  }

  /// Convenience named-parameter helper forwarding to [pull].
  Future<PullResult> pullDelta({
    required String groupId,
    required VersionVector vector,
    int limit = 100,
  }) =>
      pull(GroupId.from(groupId), vector, limit: limit);

  /// Retrieves server-signed delivery receipts issued strictly after [since] milliseconds (FR-SRV-05).
  @override
  Future<List<ServerReceipt>> receipts(
    GroupId group, {
    int? since,
  }) async {
    final effectiveSince = since ?? 0;
    final path =
        '/sync/receipts?group_id=${group.hexString}&since=$effectiveSince';
    final json = await _get(path, requiresAuth: true);

    final rawReceipts = json['receipts'] as List? ?? [];
    return rawReceipts.map((r) {
      final rMap = r as Map<String, dynamic>;
      final rawCbor = base64Decode(rMap['raw_cbor_base64'] as String);
      return ServerReceipt.fromCbor(rawCbor);
    }).toList();
  }

  /// Backwards-compatible named-parameter alias for [receipts].
  Future<List<ServerReceipt>> getReceipts({
    required String groupId,
    int since = 0,
  }) =>
      receipts(GroupId.from(groupId), since: since);

  /// Retrieves server-signed member revocations issued strictly after [since] milliseconds (FR-SRV-05).
  @override
  Future<List<RevocationNotice>> revocations(
    GroupId group, {
    int? since,
  }) async {
    final effectiveSince = since ?? 0;
    final path =
        '/sync/revocations?group_id=${group.hexString}&since=$effectiveSince';
    final json = await _get(path, requiresAuth: true);

    final rawRevs = json['revocations'] as List? ?? [];
    return rawRevs.map((r) {
      final rMap = r as Map<String, dynamic>;
      final rawCbor = base64Decode(rMap['raw_cbor_base64'] as String);
      return RevocationNotice.fromCbor(rawCbor);
    }).toList();
  }

  /// Backwards-compatible named-parameter alias for [revocations].
  Future<List<RevocationNotice>> getRevocations({
    required String groupId,
    int since = 0,
  }) =>
      revocations(GroupId.from(groupId), since: since);

  /// Issues a server-signed member revocation notice and rotates the group key epoch (FR-ID-05, FR-SEC-02).
  Future<RevokeMemberResult> revokeMember({
    required String groupId,
    required Uint8List memberPubkey,
    String reason = 'compromised_credential',
  }) async {
    final payload = {
      'group_id': groupId,
      'member_pubkey': hex.encode(memberPubkey),
      'reason': reason,
    };
    final json = await _post('/sync/revocations', payload, requiresAuth: true);
    return RevokeMemberResult.fromJson(json);
  }

  /// Uploads a hash-addressed attachment blob to the gateway server.
  @override
  Future<void> uploadAttachment(
    GroupId group,
    AttachmentRef ref,
    Uint8List bytes,
  ) async {
    if (!verifyAttachmentBytesHash(ref.hash, bytes)) {
      throw ArgumentError(
        'Attachment SHA-256 digest does not match AttachmentRef.hash',
      );
    }
    final payload = {
      'group_id': group.hexString,
      'hash': hex.encode(ref.hash),
      'mime': ref.mime,
      'data_base64': base64Encode(bytes),
    };
    await _post('/sync/attachments', payload, requiresAuth: true);
  }

  /// Convenience named-parameter helper forwarding to [uploadAttachment].
  Future<void> uploadAttachmentBlob({
    required String groupId,
    required Uint8List hash,
    required String mime,
    required Uint8List bytes,
  }) =>
      uploadAttachment(
        GroupId.from(groupId),
        AttachmentRef(hash: hash, size: bytes.length, mime: mime),
        bytes,
      );

  /// Downloads a hash-addressed attachment blob from the gateway server and verifies its SHA-256 hash.
  @override
  Future<StoredAttachmentBlob> downloadAttachment(
    GroupId group,
    AttachmentRef ref,
  ) async {
    if (ref.hash.length != 32) {
      throw ArgumentError.value(
        ref.hash.length,
        'ref.hash.length',
        'Attachment SHA-256 hash must be 32 bytes',
      );
    }
    final hashHex = hex.encode(ref.hash);
    final path = '/sync/attachments?group_id=${group.hexString}&hash=$hashHex';
    final json = await _get(path, requiresAuth: true);
    final rawDataB64 = json['data_base64'];
    if (rawDataB64 is! String) {
      throw const GatewayException(
        statusCode: 502,
        error: 'INVALID_RESPONSE',
        message: 'Missing data_base64 in attachment response',
      );
    }
    final Uint8List bytes;
    try {
      bytes = base64Decode(rawDataB64);
    } on FormatException catch (e) {
      throw GatewayException(
        statusCode: 502,
        error: 'INVALID_RESPONSE',
        message: 'Invalid base64 in attachment response: ${e.message}',
      );
    }
    if (!verifyAttachmentBytesHash(ref.hash, bytes)) {
      throw const GatewayException(
        statusCode: 502,
        error: 'ATTACHMENT_HASH_MISMATCH',
        message:
            'Downloaded attachment SHA-256 digest does not match expected hash',
      );
    }
    final mime = json['mime'] as String? ?? ref.mime;
    return StoredAttachmentBlob(
      hash: Uint8List.fromList(ref.hash),
      mime: mime,
      bytes: bytes,
      storedAt: DateTime.now().millisecondsSinceEpoch,
    );
  }

  /// Convenience named-parameter helper forwarding to [downloadAttachment].
  Future<StoredAttachmentBlob> downloadAttachmentBlob({
    required String groupId,
    required Uint8List hash,
  }) =>
      downloadAttachment(
        GroupId.from(groupId),
        AttachmentRef(hash: hash, size: 0, mime: 'application/octet-stream'),
      );

  /// High-level automated synchronization: delegates to [GatewayApiSync.syncStore] (`FR-SRV-02`).
  Future<SyncResult> sync({
    required MessageStore store,
    required Object groupId,
    required Uint8List pinnedServerKey,
    List<Envelope>? pendingEnvelopes,
    Clock? clock,
  }) =>
      syncStore(
        store: store,
        groupId: groupId,
        pinnedServerKey: pinnedServerKey,
        pendingEnvelopes: pendingEnvelopes,
        clock: clock,
      );

  Future<Map<String, dynamic>> _post(
    String endpoint,
    Map<String, dynamic> body, {
    required bool requiresAuth,
  }) async {
    final uri = _resolveUri(endpoint);
    final headers = <String, String>{
      'content-type': 'application/json',
      'accept': 'application/json',
      if (requiresAuth && authToken != null)
        'authorization': 'Bearer $authToken',
    };
    final bodyBytes = Uint8List.fromList(utf8.encode(jsonEncode(body)));

    final reply = await httpExecutor.send(
      'POST',
      uri,
      headers: headers,
      body: bodyBytes,
    );

    return _decodeJsonResponse(reply);
  }

  Future<Map<String, dynamic>> _get(
    String endpoint, {
    required bool requiresAuth,
  }) async {
    final uri = _resolveUri(endpoint);
    final headers = <String, String>{
      'accept': 'application/json',
      if (requiresAuth && authToken != null)
        'authorization': 'Bearer $authToken',
    };

    final reply = await httpExecutor.send(
      'GET',
      uri,
      headers: headers,
    );

    return _decodeJsonResponse(reply);
  }

  Map<String, dynamic> _decodeJsonResponse(HttpReply reply) {
    String bodyText;
    try {
      bodyText = reply.bodyAsString;
    } on FormatException {
      bodyText = utf8.decode(reply.body, allowMalformed: true);
    }

    Map<String, dynamic>? decodedMap;
    final trimmed = bodyText.trim();
    if (trimmed.isNotEmpty) {
      try {
        final decoded = jsonDecode(trimmed);
        if (decoded is Map<String, dynamic>) {
          decodedMap = decoded;
        } else if (decoded is Map) {
          decodedMap = decoded.map((k, v) => MapEntry(k.toString(), v));
        }
      } on FormatException {
        // Non-JSON body (e.g. HTML reverse-proxy 502/503 page or plain text)
      }
    }

    if (reply.statusCode >= 400) {
      throw GatewayException(
        statusCode: reply.statusCode,
        error: decodedMap?['error'] as String? ?? 'HTTP_${reply.statusCode}',
        message: decodedMap?['message'] as String? ??
            (trimmed.isNotEmpty ? trimmed : 'HTTP ${reply.statusCode} error'),
      );
    }

    if (decodedMap == null) {
      throw GatewayException(
        statusCode: reply.statusCode,
        error: 'INVALID_RESPONSE',
        message: 'Expected JSON object response from gateway, got: '
            '${trimmed.length > 200 ? '${trimmed.substring(0, 200)}...' : trimmed}',
      );
    }

    return decodedMap;
  }

  Uri _resolveUri(String endpoint) {
    final cleanEndpoint = endpoint.startsWith('/') ? endpoint : '/$endpoint';
    return Uri.parse('$baseUrl$cleanEndpoint');
  }

  void close() {
    if (_ownsExecutor && httpExecutor is IoHttpExecutor) {
      (httpExecutor as IoHttpExecutor).close();
    }
  }
}
