import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';
import 'package:convert/convert.dart';
import 'package:meta/meta.dart';
import '../model/certificate.dart';
import '../model/envelope.dart';
import '../model/receipt.dart';
import '../model/revocation.dart';
import '../model/version_vector.dart';
import '../storage/message_store.dart';
import 'gateway_api.dart';
import 'io_http_executor.dart';

/// Exception thrown when the gateway server returns an error.
class GatewayException implements Exception {
  final int statusCode;
  final String error;
  final String message;

  const GatewayException({
    required this.statusCode,
    required this.error,
    required this.message,
  });

  @override
  String toString() => 'GatewayException($statusCode, $error): $message';
}

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

/// Rejected envelope item with specific failure reason.
@immutable
class RejectedItem {
  final String messageId;
  final String reason;

  const RejectedItem({required this.messageId, required this.reason});

  factory RejectedItem.fromJson(Map<String, dynamic> json) {
    return RejectedItem(
      messageId: json['message_id'] as String,
      reason: json['reason'] as String,
    );
  }
}

/// Result of envelope ingestion push.
@immutable
class PushResult {
  final List<String> acceptedIds;
  final List<RejectedItem> rejected;
  final List<ServerReceipt> receipts;

  const PushResult({
    required this.acceptedIds,
    required this.rejected,
    required this.receipts,
  });

  factory PushResult.fromJson(Map<String, dynamic> json) {
    final accepted = (json['accepted_ids'] as List? ?? []).cast<String>();
    final rawRejected = json['rejected'] as List? ?? [];
    final rejected = rawRejected
        .map((r) => RejectedItem.fromJson(r as Map<String, dynamic>))
        .toList();

    final rawReceipts = json['receipts'] as List? ?? [];
    final receipts = rawReceipts.map((r) {
      final rMap = r as Map<String, dynamic>;
      final rawCbor = base64Decode(rMap['raw_cbor_base64'] as String);
      return ServerReceipt.fromCbor(rawCbor);
    }).toList();

    return PushResult(
      acceptedIds: accepted,
      rejected: rejected,
      receipts: receipts,
    );
  }
}

/// Result of envelope delta pull.
@immutable
class PullResult {
  final List<Envelope> envelopes;
  final bool hasMore;
  final VersionVector? serverVector;

  const PullResult({
    required this.envelopes,
    required this.hasMore,
    this.serverVector,
  });

  factory PullResult.fromJson(Map<String, dynamic> json) {
    final rawEnvelopes = json['envelopes'] as List? ?? [];
    final envelopes = rawEnvelopes.map((e) {
      final rawCbor = base64Decode(e as String);
      return Envelope.fromCbor(rawCbor);
    }).toList();

    VersionVector? vec;
    final rawServerVec = json['server_vector'] as String?;
    if (rawServerVec != null && rawServerVec.isNotEmpty) {
      try {
        final vecBytes = base64Decode(rawServerVec);
        vec = VersionVector.fromCbor(vecBytes);
      } catch (_) {}
    }

    return PullResult(
      envelopes: envelopes,
      hasMore: json['has_more'] as bool? ?? false,
      serverVector: vec,
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

/// Summary of an automated bidirectional sync operation with gateway.
@immutable
class SyncResult {
  final int pushedCount;
  final int acceptedCount;
  final int pulledCount;
  final int receiptsCount;
  final int revocationsCount;
  final int attachmentsUploaded;
  final int attachmentsDownloaded;

  const SyncResult({
    required this.pushedCount,
    required this.acceptedCount,
    required this.pulledCount,
    required this.receiptsCount,
    required this.revocationsCount,
    this.attachmentsUploaded = 0,
    this.attachmentsDownloaded = 0,
  });

  @override
  String toString() =>
      'SyncResult(pushed: $pushedCount, accepted: $acceptedCount, pulled: $pulledCount, '
      'receipts: $receiptsCount, revocations: $revocationsCount, '
      'attUp: $attachmentsUploaded, attDown: $attachmentsDownloaded)';
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
    HttpClient? httpClient,
  })  : baseUrl = baseUrl.endsWith('/')
            ? baseUrl.substring(0, baseUrl.length - 1)
            : baseUrl,
        httpExecutor = httpExecutor ??
            IoHttpExecutor(
              client: httpClient,
              closeClientOnDispose: true,
            ),
        _ownsExecutor = httpExecutor == null;

  /// Registers a new member account and obtains initial server-signed membership certificate (FR-SRV-02).
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

  /// Backwards-compatible named-parameter overload for [push].
  Future<PushResult> pushEnvelopes({
    required String groupId,
    required List<Envelope> envelopes,
    List<MembershipCert>? certificates,
  }) =>
      push(GroupId.from(groupId), envelopes, certificates: certificates);

  /// Pulls message delta newer than client's version vector from server (FR-SRV-05).
  @override
  Future<PullResult> pull(
    GroupId group,
    VersionVector serverVector, {
    int? limit,
  }) async {
    final effectiveLimit = limit ?? 100;
    final vectorCbor = serverVector.toCanonicalCbor();
    final vectorB64 = base64Encode(vectorCbor);
    final path =
        '/sync/pull?group_id=${group.hexString}&vector=${Uri.encodeComponent(vectorB64)}&limit=$effectiveLimit';

    final json = await _get(path, requiresAuth: true);
    return PullResult.fromJson(json);
  }

  /// Backwards-compatible named-parameter overload for [pull].
  Future<PullResult> pullDelta({
    required String groupId,
    required VersionVector vector,
    int limit = 100,
  }) =>
      pull(GroupId.from(groupId), vector, limit: limit);

  /// Retrieves server-signed delivery receipts issued since [since] milliseconds (FR-SRV-05).
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

  /// Retrieves server-signed member revocations issued since [since] milliseconds (FR-SRV-05).
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
    final payload = {
      'group_id': group.hexString,
      'hash': hex.encode(ref.hash),
      'mime': ref.mime,
      'data_base64': base64Encode(bytes),
    };
    await _post('/sync/attachments', payload, requiresAuth: true);
  }

  /// Backwards-compatible named-parameter overload for [uploadAttachment].
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

  /// Downloads a hash-addressed attachment blob from the gateway server.
  @override
  Future<StoredAttachmentBlob> downloadAttachment(
    GroupId group,
    AttachmentRef ref,
  ) async {
    final hashHex = hex.encode(ref.hash);
    final path = '/sync/attachments?group_id=${group.hexString}&hash=$hashHex';
    final json = await _get(path, requiresAuth: true);
    final bytes = base64Decode(json['data_base64'] as String);
    final mime = json['mime'] as String? ?? ref.mime;
    return StoredAttachmentBlob(
      hash: Uint8List.fromList(ref.hash),
      mime: mime,
      bytes: bytes,
      storedAt: DateTime.now().millisecondsSinceEpoch,
    );
  }

  /// Backwards-compatible named-parameter overload for [downloadAttachment].
  Future<StoredAttachmentBlob> downloadAttachmentBlob({
    required String groupId,
    required Uint8List hash,
  }) =>
      downloadAttachment(
        GroupId.from(groupId),
        AttachmentRef(hash: hash, size: 0, mime: 'application/octet-stream'),
      );

  /// High-level automated synchronization: pushes local unconfirmed envelopes, stores receipts,
  /// pulls server delta envelopes, reconciles revocation notices, and syncs attachment blobs (FR-SRV-02).
  Future<SyncResult> sync({
    required MessageStore store,
    required dynamic groupId,
    List<Envelope>? pendingEnvelopes,
  }) async {
    final group = GroupId.from(groupId);

    // 1. Determine unconfirmed envelopes to push (`IT-AMP-04`: never re-upload confirmed seqs)
    final candidates = pendingEnvelopes ?? <Envelope>[];
    final toPush = <Envelope>[];
    for (final env in candidates) {
      final confirmed = await store.isConfirmed(env.core.author, env.core.seq);
      if (!confirmed) {
        toPush.add(env);
      }
    }

    // Gather certificates for authors of pushed envelopes
    final certsToPush = <MembershipCert>[];
    for (final env in toPush) {
      final cert = await store.getCertificate(env.certRef);
      if (cert != null) {
        certsToPush.add(cert);
      }
    }

    var acceptedCount = 0;
    var receiptsCount = 0;
    var attachmentsUploaded = 0;

    if (toPush.isNotEmpty) {
      final pushRes = await push(
        group,
        toPush,
        certificates: certsToPush,
      );
      acceptedCount = pushRes.acceptedIds.length;

      // Save returned receipts into store
      for (final receipt in pushRes.receipts) {
        await store.saveReceipt(receipt);
        receiptsCount++;
      }

      // Upload any attachment blobs referenced by pushed envelopes
      final uploadedHashes = <String>{};
      for (final env in toPush) {
        final atts = env.core.attachments;
        if (atts == null) continue;
        for (final att in atts) {
          final hHex = hex.encode(att.hash);
          if (uploadedHashes.contains(hHex)) continue;
          final blob = await store.getAttachmentBlob(att.hash);
          if (blob != null) {
            try {
              await uploadAttachment(
                group,
                att,
                blob.bytes,
              );
              uploadedHashes.add(hHex);
              attachmentsUploaded++;
            } catch (_) {
              // Ignore if server doesn't support attachments in legacy mock
            }
          }
        }
      }
    }

    // 2. Fetch any additional receipts
    final additionalReceipts = await receipts(group, since: 0);
    for (final receipt in additionalReceipts) {
      await store.saveReceipt(receipt);
      receiptsCount++;
    }

    // 3. Reconcile active revocations
    final revs = await revocations(group, since: 0);
    var revocationsCount = 0;
    for (final rev in revs) {
      await store.saveRevocation(rev);
      revocationsCount++;
    }

    // 4. Pull missing delta envelopes
    final localVector = await store.getVersionVector();
    final pullRes = await pull(
      group,
      localVector,
      limit: 200,
    );

    var pulledCount = 0;
    if (pullRes.envelopes.isNotEmpty) {
      pulledCount = await store.saveBatch(pullRes.envelopes);
    }

    // 5. Download any missing attachment blobs from server
    var attachmentsDownloaded = 0;
    final missingAtts = await store.getMissingAttachments();
    for (final att in missingAtts) {
      try {
        final blob = await downloadAttachment(
          group,
          att,
        );
        final saved = await store.saveAttachmentBlob(
          hash: blob.hash,
          mime: blob.mime,
          bytes: blob.bytes,
        );
        if (saved) {
          attachmentsDownloaded++;
        }
      } catch (_) {
        // Attachment may not be uploaded to server yet
      }
    }

    return SyncResult(
      pushedCount: toPush.length,
      acceptedCount: acceptedCount,
      pulledCount: pulledCount,
      receiptsCount: receiptsCount,
      revocationsCount: revocationsCount,
      attachmentsUploaded: attachmentsUploaded,
      attachmentsDownloaded: attachmentsDownloaded,
    );
  }

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

    final json = jsonDecode(reply.bodyAsString) as Map<String, dynamic>;
    if (reply.statusCode >= 400) {
      throw GatewayException(
        statusCode: reply.statusCode,
        error: json['error'] as String? ?? 'ERROR',
        message: json['message'] as String? ?? 'Unknown server error',
      );
    }

    return json;
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

    final json = jsonDecode(reply.bodyAsString) as Map<String, dynamic>;
    if (reply.statusCode >= 400) {
      throw GatewayException(
        statusCode: reply.statusCode,
        error: json['error'] as String? ?? 'ERROR',
        message: json['message'] as String? ?? 'Unknown server error',
      );
    }

    return json;
  }

  Uri _resolveUri(String endpoint) {
    final cleanEndpoint = endpoint.startsWith('/') ? endpoint : '/$endpoint';
    // If baseUrl already includes /api/v1, or server router handles both
    return Uri.parse('$baseUrl$cleanEndpoint');
  }

  void close() {
    if (_ownsExecutor && httpExecutor is IoHttpExecutor) {
      (httpExecutor as IoHttpExecutor).close();
    }
  }
}
