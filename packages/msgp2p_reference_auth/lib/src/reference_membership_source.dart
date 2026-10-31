import 'dart:convert';
import 'dart:typed_data';

import 'package:convert/convert.dart';
import 'package:msgp2p_core/msgp2p_core.dart';

bool _constantTimeBytesEqual(Uint8List a, Uint8List b) {
  if (a.length != b.length) return false;
  var diff = 0;
  for (var i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff == 0;
}

class _HttpApiError implements Exception {
  final int statusCode;
  final String error;
  final String message;

  const _HttpApiError({
    required this.statusCode,
    required this.error,
    required this.message,
  });

  MembershipException toMembershipException() {
    final lowerMsg = message.toLowerCase();
    final upperErr = error.toUpperCase();
    if (upperErr == 'REVOKED' || lowerMsg.contains('revoked')) {
      return MembershipException(
        MembershipErrorKind.revoked,
        message,
        cause: this,
      );
    }
    if (statusCode == 401 || statusCode == 403) {
      return MembershipException(
        MembershipErrorKind.unauthorized,
        message,
        cause: this,
      );
    }
    if (statusCode == 404) {
      return MembershipException(
        MembershipErrorKind.notFound,
        message,
        cause: this,
      );
    }
    if (statusCode >= 500) {
      return MembershipException(
        MembershipErrorKind.transport,
        'HTTP $statusCode ($error): $message',
        cause: this,
      );
    }
    return MembershipException(
      MembershipErrorKind.invalidGrant,
      'HTTP $statusCode ($error): $message',
      cause: this,
    );
  }
}

/// [MembershipSource] adapter for the `msgp2p` reference server (`/auth/register`, `/auth/login`,
/// and `/sync/revocations`) over [HttpExecutor] (Proposal 0001, Step 4; §3, §4, §7, §9.1–9.2).
class ReferenceMembershipSource implements MembershipSource {
  final String baseUrl;
  final String username;
  final String password;
  final HttpExecutor httpExecutor;
  final bool _ownsExecutor;
  final Uint8List? _pinnedServerKey;

  /// When `true` (default), a `401` on `/auth/login` triggers a one-time `/auth/register` attempt
  /// for `(group, keys)` before retrying `/auth/login` (preserving `401` if the username already exists).
  final bool autoRegister;

  /// When `true` (default) and `/auth/login` does not embed `revocations` inline, fetches active
  /// server-signed [RevocationNotice]s from `GET /sync/revocations` so [MembershipGrant.revocations]
  /// is always populated atomically with rotated keys (§9.1).
  final bool fetchRevocations;

  /// Safety margin subtracted from the earliest credential/key expiry when computing
  /// [MembershipGrant.refreshAfter].
  final Duration refreshMargin;

  final Clock clock;

  /// Optional [GatewayClient] whose `authToken` is automatically updated after a verified login.
  final GatewayClient? gatewayClient;

  /// Optional callback invoked with `(accessToken, expiresInSeconds)` after a verified login.
  final void Function(String accessToken, int expiresIn)? onAccessToken;

  String? _lastAccessToken;
  Uint8List? _lastServerPublicKey;

  ReferenceMembershipSource({
    required String baseUrl,
    required this.username,
    required this.password,
    HttpExecutor? httpExecutor,
    Uint8List? pinnedServerKey,
    this.autoRegister = true,
    this.fetchRevocations = true,
    this.refreshMargin = const Duration(minutes: 5),
    this.clock = const SystemClock(),
    this.gatewayClient,
    this.onAccessToken,
  })  : baseUrl = baseUrl.endsWith('/')
            ? baseUrl.substring(0, baseUrl.length - 1)
            : baseUrl,
        httpExecutor = httpExecutor ?? IoHttpExecutor(),
        _ownsExecutor = httpExecutor == null,
        _pinnedServerKey = pinnedServerKey == null
            ? null
            : Uint8List.fromList(pinnedServerKey) {
    if (_pinnedServerKey != null && _pinnedServerKey!.length != 32) {
      throw ArgumentError.value(
        _pinnedServerKey!.length,
        'pinnedServerKey.length',
        'Pinned server Ed25519 public key must be 32 bytes',
      );
    }
  }

  /// Defensive copy of the configured 32-byte pinned server Ed25519 public key, if set.
  Uint8List? get pinnedServerKey =>
      _pinnedServerKey == null ? null : Uint8List.fromList(_pinnedServerKey!);

  /// Bearer token obtained during the most recent verified [fetch], or `null` if none yet.
  String? get lastAccessToken => _lastAccessToken;

  /// Server Ed25519 public key returned during the most recent verified [fetch], or `null` if none yet.
  Uint8List? get lastServerPublicKey => _lastServerPublicKey == null
      ? null
      : Uint8List.fromList(_lastServerPublicKey!);

  /// Explicitly registers `(username, password)` with [keys] in [group] via `POST /auth/register`,
  /// returning the assigned `user_id`.
  Future<String> register(GroupId group, MemberPublicKeys keys) async {
    try {
      final json = await _postJson(
        '/auth/register',
        {
          'username': username,
          'password': password,
          'group_id': group.hexString,
          'member_pubkey': keys.signingHex,
          'noise_pubkey': keys.noiseHex,
        },
      );
      final userId = json['user_id'];
      if (userId is! String || userId.isEmpty) {
        throw const MembershipException(
          MembershipErrorKind.invalidGrant,
          'Missing user_id in /auth/register response',
        );
      }
      return userId;
    } on _HttpApiError catch (e) {
      throw e.toMembershipException();
    }
  }

  @override
  Future<MembershipGrant> fetch(GroupId group, MemberPublicKeys keys) async {
    Map<String, dynamic> loginJson;
    try {
      loginJson = await _postJson(
        '/auth/login',
        {
          'username': username,
          'password': password,
        },
      );
    } on _HttpApiError catch (loginErr) {
      if (autoRegister && loginErr.statusCode == 401) {
        try {
          await _postJson(
            '/auth/register',
            {
              'username': username,
              'password': password,
              'group_id': group.hexString,
              'member_pubkey': keys.signingHex,
              'noise_pubkey': keys.noiseHex,
            },
          );
        } on _HttpApiError catch (regErr) {
          final lowerMsg = regErr.message.toLowerCase();
          if (regErr.statusCode == 409 ||
              (regErr.statusCode == 400 &&
                  lowerMsg.contains('already exists'))) {
            throw loginErr.toMembershipException();
          }
          throw regErr.toMembershipException();
        }
        try {
          loginJson = await _postJson(
            '/auth/login',
            {
              'username': username,
              'password': password,
            },
          );
        } on _HttpApiError catch (retryErr) {
          throw retryErr.toMembershipException();
        }
      } else {
        throw loginErr.toMembershipException();
      }
    }

    final accessToken = loginJson['access_token'];
    if (accessToken is! String || accessToken.isEmpty) {
      throw const MembershipException(
        MembershipErrorKind.invalidGrant,
        'Missing or empty access_token in /auth/login response',
      );
    }

    final rawExpiresIn = loginJson['expires_in'];
    final expiresIn = rawExpiresIn is num ? rawExpiresIn.toInt() : 0;
    if (expiresIn <= 0) {
      throw const MembershipException(
        MembershipErrorKind.invalidGrant,
        'Invalid or non-positive expires_in in /auth/login response',
      );
    }

    final serverPubkey = _decodeHexBytes(
      loginJson['server_pubkey'],
      expectedBytes: 32,
      fieldName: 'server_pubkey',
    );
    if (_pinnedServerKey != null &&
        !_constantTimeBytesEqual(serverPubkey, _pinnedServerKey!)) {
      throw const MembershipException(
        MembershipErrorKind.invalidGrant,
        'Server public key in /auth/login does not match pinnedServerKey',
      );
    }

    final cert = _parseCertificate(loginJson['membership_cert']);
    final beaconKey = _decodeHexBytes(
      loginJson['group_beacon_key'],
      expectedBytes: 32,
      fieldName: 'group_beacon_key',
    );
    final grantedKeys = _parseGrantedKeys(loginJson['group_keys']);

    List<RevocationNotice> revocations;
    if (loginJson.containsKey('revocations') &&
        loginJson['revocations'] != null) {
      revocations = _parseRevocations(loginJson['revocations']);
    } else if (fetchRevocations) {
      try {
        final revJson = await _getJson(
          '/sync/revocations?group_id=${group.hexString}&since=0',
          bearerToken: accessToken,
        );
        revocations = _parseRevocations(revJson['revocations'] ?? const []);
      } on _HttpApiError catch (e) {
        throw e.toMembershipException();
      }
    } else {
      revocations = const [];
    }

    final refreshAfter = _computeRefreshAfter(
      expiresInSeconds: expiresIn,
      certExpiresAtMs: cert.expiresAt,
      grantedKeys: grantedKeys,
    );

    final MembershipGrant grant;
    try {
      grant = MembershipGrant(
        cert: cert,
        keys: grantedKeys,
        beaconKey: beaconKey,
        revocations: revocations,
        refreshAfter: refreshAfter,
      );
    } on ArgumentError catch (e) {
      throw MembershipException(
        MembershipErrorKind.invalidGrant,
        'Invalid MembershipGrant from reference server: ${e.message}',
        cause: e,
      );
    }

    final verificationKey = _pinnedServerKey ?? serverPubkey;
    await grant.verify(
      expectedGroup: group,
      expectedKeys: keys,
      pinnedServerKey: verificationKey,
      clock: clock,
    );

    _lastAccessToken = accessToken;
    _lastServerPublicKey = serverPubkey;
    gatewayClient?.authToken = accessToken;
    onAccessToken?.call(accessToken, expiresIn);
    return grant;
  }

  /// Releases the underlying [IoHttpExecutor] if created internally by this instance.
  void close() {
    if (_ownsExecutor && httpExecutor is IoHttpExecutor) {
      (httpExecutor as IoHttpExecutor).close();
    }
  }

  DateTime _computeRefreshAfter({
    required int expiresInSeconds,
    required int certExpiresAtMs,
    required List<GrantedKey> grantedKeys,
  }) {
    final nowMs = clock.now().millisecondsSinceEpoch;
    var earliestExpiryMs = nowMs + expiresInSeconds * 1000;
    if (certExpiresAtMs < earliestExpiryMs) {
      earliestExpiryMs = certExpiresAtMs;
    }

    var maxActiveValidUntil = 0;
    for (final k in grantedKeys) {
      final vu = k.validUntil;
      if (vu != null && vu > maxActiveValidUntil) {
        maxActiveValidUntil = vu;
      }
    }
    if (maxActiveValidUntil > nowMs && maxActiveValidUntil < earliestExpiryMs) {
      earliestExpiryMs = maxActiveValidUntil;
    }

    final lifetimeMs = earliestExpiryMs - nowMs;
    final quarterLifetimeMs = lifetimeMs > 0 ? lifetimeMs ~/ 4 : 0;
    final marginMs = refreshMargin.inMilliseconds < quarterLifetimeMs
        ? refreshMargin.inMilliseconds
        : quarterLifetimeMs;
    final targetMs = earliestExpiryMs - marginMs;
    return DateTime.fromMillisecondsSinceEpoch(
      targetMs > nowMs ? targetMs : earliestExpiryMs,
      isUtc: true,
    );
  }

  MembershipCert _parseCertificate(Object? rawCert) {
    try {
      Uint8List rawCbor;
      if (rawCert is Map) {
        final b64 = rawCert['raw_cbor_base64'];
        if (b64 is! String || b64.isEmpty) {
          throw const MembershipException(
            MembershipErrorKind.invalidGrant,
            'Missing membership_cert.raw_cbor_base64 in /auth/login response',
          );
        }
        rawCbor = base64Decode(b64);
      } else if (rawCert is String && rawCert.isNotEmpty) {
        rawCbor = base64Decode(rawCert);
      } else {
        throw const MembershipException(
          MembershipErrorKind.invalidGrant,
          'Missing or invalid membership_cert in /auth/login response',
        );
      }
      return MembershipCert.fromCbor(rawCbor);
    } on MembershipException {
      rethrow;
    } catch (e) {
      throw MembershipException(
        MembershipErrorKind.invalidGrant,
        'Failed to decode MembershipCert CBOR: $e',
        cause: e,
      );
    }
  }

  List<GrantedKey> _parseGrantedKeys(Object? rawKeys) {
    if (rawKeys is! List || rawKeys.isEmpty) {
      throw const MembershipException(
        MembershipErrorKind.invalidGrant,
        'Missing or empty group_keys in /auth/login response',
      );
    }
    final parsed = <GrantedKey>[];
    for (final item in rawKeys) {
      if (item is! Map) {
        throw const MembershipException(
          MembershipErrorKind.invalidGrant,
          'Malformed entry in group_keys',
        );
      }
      final rawEpoch = item['epoch'];
      final epoch = rawEpoch is num ? rawEpoch.toInt() : -1;
      if (epoch <= 0) {
        throw MembershipException(
          MembershipErrorKind.invalidGrant,
          'Invalid key epoch in group_keys: $rawEpoch',
        );
      }
      final keyBytes = _decodeHexBytes(
        item['key_hex'],
        expectedBytes: 32,
        fieldName: 'group_keys[$epoch].key_hex',
      );
      final rawValidUntil = item['valid_until'];
      final validUntil = rawValidUntil is num ? rawValidUntil.toInt() : null;
      final role = _parseKeyRole(item['role']);
      parsed.add(
        GrantedKey(
          epoch: epoch,
          role: role,
          key: keyBytes,
          validUntil: validUntil,
        ),
      );
    }
    return parsed;
  }

  KeyRole _parseKeyRole(Object? rawRole) {
    if (rawRole == null || rawRole == 'member' || rawRole == 0) {
      return KeyRole.member;
    }
    if (rawRole == 'tracker' || rawRole == 3) {
      return KeyRole.tracker;
    }
    throw MembershipException(
      MembershipErrorKind.invalidGrant,
      'Unsupported key role in group_keys: $rawRole',
    );
  }

  List<RevocationNotice> _parseRevocations(Object? rawRevs) {
    if (rawRevs is! List) {
      throw const MembershipException(
        MembershipErrorKind.invalidGrant,
        'Malformed revocations list in server response',
      );
    }
    final notices = <RevocationNotice>[];
    for (final item in rawRevs) {
      try {
        Uint8List rawCbor;
        if (item is Map) {
          final b64 = item['raw_cbor_base64'];
          if (b64 is! String || b64.isEmpty) {
            throw const MembershipException(
              MembershipErrorKind.invalidGrant,
              'Missing raw_cbor_base64 in revocation entry',
            );
          }
          rawCbor = base64Decode(b64);
        } else if (item is String && item.isNotEmpty) {
          rawCbor = base64Decode(item);
        } else {
          throw const MembershipException(
            MembershipErrorKind.invalidGrant,
            'Invalid revocation entry format',
          );
        }
        notices.add(RevocationNotice.fromCbor(rawCbor));
      } on MembershipException {
        rethrow;
      } catch (e) {
        throw MembershipException(
          MembershipErrorKind.invalidGrant,
          'Failed to decode RevocationNotice CBOR: $e',
          cause: e,
        );
      }
    }
    return notices;
  }

  Uint8List _decodeHexBytes(
    Object? raw, {
    required int expectedBytes,
    required String fieldName,
  }) {
    if (raw is! String) {
      throw MembershipException(
        MembershipErrorKind.invalidGrant,
        'Expected hex string for $fieldName',
      );
    }
    final clean =
        (raw.startsWith('0x') || raw.startsWith('0X')) ? raw.substring(2) : raw;
    if (clean.length != expectedBytes * 2) {
      throw MembershipException(
        MembershipErrorKind.invalidGrant,
        'Expected ${expectedBytes * 2} hex chars for $fieldName, got ${clean.length}',
      );
    }
    try {
      return Uint8List.fromList(hex.decode(clean));
    } on FormatException catch (e) {
      throw MembershipException(
        MembershipErrorKind.invalidGrant,
        'Invalid hex characters in $fieldName: ${e.message}',
        cause: e,
      );
    }
  }

  Future<Map<String, dynamic>> _postJson(
    String endpoint,
    Map<String, dynamic> payload, {
    String? bearerToken,
  }) async {
    final uri = _resolveUri(endpoint);
    final headers = <String, String>{
      'content-type': 'application/json',
      'accept': 'application/json',
      if (bearerToken != null) 'authorization': 'Bearer $bearerToken',
    };
    final bodyBytes = Uint8List.fromList(utf8.encode(jsonEncode(payload)));

    final HttpReply reply;
    try {
      reply = await httpExecutor.send(
        'POST',
        uri,
        headers: headers,
        body: bodyBytes,
      );
    } catch (e) {
      throw MembershipException(
        MembershipErrorKind.transport,
        'HTTP POST $endpoint failed: $e',
        cause: e,
      );
    }
    return _decodeJsonReply(reply);
  }

  Future<Map<String, dynamic>> _getJson(
    String endpoint, {
    String? bearerToken,
  }) async {
    final uri = _resolveUri(endpoint);
    final headers = <String, String>{
      'accept': 'application/json',
      if (bearerToken != null) 'authorization': 'Bearer $bearerToken',
    };

    final HttpReply reply;
    try {
      reply = await httpExecutor.send(
        'GET',
        uri,
        headers: headers,
      );
    } catch (e) {
      throw MembershipException(
        MembershipErrorKind.transport,
        'HTTP GET $endpoint failed: $e',
        cause: e,
      );
    }
    return _decodeJsonReply(reply);
  }

  Map<String, dynamic> _decodeJsonReply(HttpReply reply) {
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
        // Non-JSON response body (e.g. HTML reverse-proxy error page)
      }
    }

    if (reply.statusCode >= 400) {
      throw _HttpApiError(
        statusCode: reply.statusCode,
        error: decodedMap?['error'] as String? ?? 'HTTP_${reply.statusCode}',
        message: decodedMap?['message'] as String? ??
            (trimmed.isNotEmpty ? trimmed : 'HTTP ${reply.statusCode} error'),
      );
    }

    if (decodedMap == null) {
      throw MembershipException(
        MembershipErrorKind.invalidGrant,
        'Expected JSON object response from auth server, got: '
        '${trimmed.length > 200 ? '${trimmed.substring(0, 200)}...' : trimmed}',
      );
    }
    return decodedMap;
  }

  Uri _resolveUri(String endpoint) {
    final clean = endpoint.startsWith('/') ? endpoint : '/$endpoint';
    return Uri.parse('$baseUrl$clean');
  }
}
