import 'dart:convert';
import 'dart:typed_data';
import 'package:convert/convert.dart';
import 'package:cryptography/cryptography.dart' as cg;
import 'package:meta/meta.dart';
import '../crypto/crypto.dart';
import '../model/certificate.dart';
import '../model/envelope.dart';
import '../model/receipt.dart';
import '../model/revocation.dart';
import '../model/version_vector.dart';
import '../storage/message_store.dart';
import '../sync/clock_rules.dart';

/// 16-byte unique identifier for a msgp2p group.
@immutable
class GroupId {
  final Uint8List _bytes;

  const GroupId._(this._bytes);

  /// A defensive 16-byte copy of this group ID's raw bytes.
  Uint8List get bytes => Uint8List.fromList(_bytes);

  /// Creates a validated, immutable [GroupId] from a 16-byte list.
  factory GroupId(List<int> bytes) => GroupId.fromBytes(bytes);

  /// Creates a validated, immutable [GroupId] from a 16-byte list.
  factory GroupId.fromBytes(List<int> bytes) {
    if (bytes.length != 16) {
      throw ArgumentError.value(
        bytes.length,
        'bytes.length',
        'GroupId must be exactly 16 bytes, got ${bytes.length}',
      );
    }
    return GroupId._(Uint8List.fromList(bytes));
  }

  /// Creates a [GroupId] from a 32-character hexadecimal string (with optional `0x`/`0X` prefix).
  factory GroupId.fromHex(String hexString) {
    final clean = (hexString.startsWith('0x') || hexString.startsWith('0X'))
        ? hexString.substring(2)
        : hexString;
    if (clean.length != 32) {
      throw ArgumentError.value(
        hexString,
        'hexString',
        'GroupId hex string must represent exactly 16 bytes (32 hex characters)',
      );
    }
    final List<int> decoded;
    try {
      decoded = hex.decode(clean);
    } on FormatException catch (e) {
      throw ArgumentError.value(
        hexString,
        'hexString',
        'GroupId contains invalid hex characters: ${e.message}',
      );
    }
    return GroupId._(Uint8List.fromList(decoded));
  }

  /// Converts a [GroupId], hex [String], or 16-byte [List<int>] to a [GroupId].
  factory GroupId.from(Object value) {
    if (value is GroupId) return value;
    if (value is String) return GroupId.fromHex(value);
    if (value is List<int>) return GroupId.fromBytes(value);
    throw ArgumentError(
        'Cannot convert ${value.runtimeType} to GroupId: $value');
  }

  /// Lowercase hexadecimal string representation of this group ID.
  String get hexString => hex.encode(_bytes);

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is GroupId && _constantTimeBytesEqual(_bytes, other._bytes);

  @override
  int get hashCode => Object.hashAll(_bytes);

  @override
  String toString() => hexString;
}

bool _constantTimeBytesEqual(Uint8List a, Uint8List b) {
  if (a.length != b.length) return false;
  var diff = 0;
  for (var i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff == 0;
}

/// Verifies in constant time that `SHA-256(bytes) == expectedHash` (32 bytes).
bool verifyAttachmentBytesHash(Uint8List expectedHash, Uint8List bytes) {
  if (expectedHash.length != 32) return false;
  final actualHash = MsgP2PCrypto.sha256(bytes);
  return _constantTimeBytesEqual(actualHash, expectedHash);
}

/// Exception thrown when a gateway operation returns an error.
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

/// Summary of an automated bidirectional sync operation with a [GatewayApi].
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

/// Represents an HTTP response returned by [HttpExecutor.send].
@immutable
class HttpReply {
  final int statusCode;
  final Map<String, String> headers;
  final Uint8List body;

  const HttpReply({
    required this.statusCode,
    required this.body,
    this.headers = const {},
  });

  /// Decodes [body] as a UTF-8 string.
  String get bodyAsString => utf8.decode(body);

  /// True if [statusCode] is between 200 and 299 inclusive.
  bool get isSuccess => statusCode >= 200 && statusCode < 300;

  /// Case-insensitive lookup of a response header by [name].
  String? header(String name) {
    final lower = name.toLowerCase();
    final direct = headers[lower] ?? headers[name];
    if (direct != null) return direct;
    for (final entry in headers.entries) {
      if (entry.key.toLowerCase() == lower) return entry.value;
    }
    return null;
  }
}

/// Abstract port for sending HTTP requests (Proposal 0001, Step 3).
///
/// Decouples gateway protocol operations from concrete HTTP I/O implementations
/// (`dart:io` `HttpClient`, `package:http`, browser `fetch`, or host custom network stack).
/// Outgoing request headers from `GatewayClient` use lowercase header names (RFC 9110).
abstract interface class HttpExecutor {
  /// Sends an HTTP request and returns the [HttpReply].
  Future<HttpReply> send(
    String method,
    Uri url, {
    Map<String, String>? headers,
    Uint8List? body,
  });
}

/// In-memory [HttpExecutor] for testing and mocking without network sockets.
class MockHttpExecutor implements HttpExecutor {
  final Future<HttpReply> Function(
    String method,
    Uri url,
    Map<String, String> headers,
    Uint8List? body,
  ) handler;

  const MockHttpExecutor(this.handler);

  @override
  Future<HttpReply> send(
    String method,
    Uri url, {
    Map<String, String>? headers,
    Uint8List? body,
  }) {
    return handler(method, url, headers ?? const {}, body);
  }
}

/// The gateway operations (FR-SRV-02..05), independent of how HTTP is done (Proposal 0001, Step 3).
abstract interface class GatewayApi {
  /// Pushes a batch of envelopes and optional certificates to the gateway server.
  Future<PushResult> push(
    GroupId group,
    List<Envelope> envelopes, {
    List<MembershipCert>? certificates,
  });

  /// Pulls delta envelopes missing from the caller's [knownVector].
  Future<PullResult> pull(
    GroupId group,
    VersionVector knownVector, {
    int? limit,
  });

  /// Retrieves server delivery receipts issued strictly after [since] milliseconds timestamp.
  Future<List<ServerReceipt>> receipts(
    GroupId group, {
    int? since,
  });

  /// Retrieves member revocation notices issued strictly after [since] milliseconds timestamp.
  Future<List<RevocationNotice>> revocations(
    GroupId group, {
    int? since,
  });

  /// Uploads a hash-addressed attachment blob to the gateway server.
  Future<void> uploadAttachment(
    GroupId group,
    AttachmentRef ref,
    Uint8List bytes,
  );

  /// Downloads a hash-addressed attachment blob from the gateway server.
  Future<StoredAttachmentBlob> downloadAttachment(
    GroupId group,
    AttachmentRef ref,
  );
}

/// High-level bidirectional [MessageStore] synchronization over any [GatewayApi] port.
extension GatewayApiSync on GatewayApi {
  /// Pushes local unconfirmed envelopes, verifies and stores server-signed receipts
  /// and revocation notices against [pinnedServerKey], verifies and pulls missing
  /// delta envelopes, and syncs attachment blobs (`FR-SRV-02`).
  Future<SyncResult> syncStore({
    required MessageStore store,
    required Object groupId,
    required Uint8List pinnedServerKey,
    List<Envelope>? pendingEnvelopes,
    Clock? clock,
  }) async {
    if (pinnedServerKey.length != 32) {
      throw ArgumentError.value(
        pinnedServerKey.length,
        'pinnedServerKey.length',
        'Pinned server Ed25519 public key must be 32 bytes',
      );
    }
    final group = GroupId.from(groupId);
    final nowMs = (clock ?? const SystemClock()).now().millisecondsSinceEpoch;

    // 1. Determine unconfirmed envelopes to push (`IT-AMP-04`: never re-upload confirmed seqs)
    final candidates = pendingEnvelopes ?? <Envelope>[];
    final toPush = <Envelope>[];
    for (final env in candidates) {
      final confirmed = await store.isConfirmed(env.core.author, env.core.seq);
      if (!confirmed) {
        toPush.add(env);
      }
    }

    // Gather unique certificates for authors of pushed envelopes
    final certsToPush = <MembershipCert>[];
    final seenCertRefs = <String>{};
    for (final env in toPush) {
      final certRefHex = hex.encode(env.certRef);
      if (!seenCertRefs.add(certRefHex)) continue;
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

      for (final receipt in pushRes.receipts) {
        if (_constantTimeBytesEqual(receipt.groupId, group.bytes) &&
            await receipt.verify(pinnedServerKey)) {
          await store.saveReceipt(receipt);
          receiptsCount++;
        }
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

    // 2. Fetch any additional receipts and verify against pinned server key
    final additionalReceipts = await receipts(group, since: 0);
    for (final receipt in additionalReceipts) {
      if (_constantTimeBytesEqual(receipt.groupId, group.bytes) &&
          await receipt.verify(pinnedServerKey)) {
        await store.saveReceipt(receipt);
        receiptsCount++;
      }
    }

    // 3. Reconcile active revocations after verifying server signature
    final revs = await revocations(group, since: 0);
    var revocationsCount = 0;
    for (final rev in revs) {
      if (_constantTimeBytesEqual(rev.groupId, group.bytes) &&
          await rev.verify(pinnedServerKey)) {
        await store.saveRevocation(rev);
        revocationsCount++;
      }
    }

    // 4. Pull missing delta envelopes and enforce group, revocation, clock, and signature checks
    final localVector = await store.getVersionVector(currentTimeMillis: nowMs);
    final pullRes = await pull(
      group,
      localVector,
      limit: 200,
    );

    var pulledCount = 0;
    if (pullRes.envelopes.isNotEmpty) {
      final validEnvelopes = <Envelope>[];
      for (final env in pullRes.envelopes) {
        if (!_constantTimeBytesEqual(env.core.groupId, group.bytes)) continue;
        if (await store.isRevoked(env.core.author)) continue;
        if (!ClockRules.isValidMessageTime(
          createdAt: env.core.createdAt,
          expiresAt: env.core.expiresAt,
          currentTimeMillis: nowMs,
        )) {
          continue;
        }
        if (await env.verifySignature()) {
          validEnvelopes.add(env);
        }
      }
      if (validEnvelopes.isNotEmpty) {
        pulledCount = await store.saveBatch(
          validEnvelopes,
          customStoredAt: nowMs,
        );
      }
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
          customStoredAt: nowMs,
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
}

/// In-memory implementation of [GatewayApi] for offline testing, contract suites, and simulations.
class MemoryGatewayApi implements GatewayApi {
  final Map<GroupId, List<Envelope>> _envelopes = {};
  final Map<GroupId, Set<String>> _envelopeIds = {};
  final Map<GroupId, Map<String, ServerReceipt>> _receiptsByMsgId = {};
  final Map<GroupId, List<ServerReceipt>> _receipts = {};
  final Map<GroupId, List<RevocationNotice>> _revocations = {};
  final Map<GroupId, Map<String, MembershipCert>> _certificates = {};
  final Map<GroupId, Map<String, StoredAttachmentBlob>> _attachments = {};

  Uint8List? serverPublicKey;
  final cg.SimpleKeyPair? serverSigningKeyPair;
  Future<ServerReceipt> Function(Envelope envelope)? receiptSigner;

  MemoryGatewayApi({
    this.serverPublicKey,
    this.serverSigningKeyPair,
    this.receiptSigner,
  });

  @override
  Future<PushResult> push(
    GroupId group,
    List<Envelope> envelopes, {
    List<MembershipCert>? certificates,
  }) async {
    final acceptedIds = <String>[];
    final rejected = <RejectedItem>[];
    final generatedReceipts = <ServerReceipt>[];

    if (certificates != null && certificates.isNotEmpty) {
      final groupCerts = _certificates.putIfAbsent(group, () => {});
      for (final cert in certificates) {
        if (_constantTimeBytesEqual(cert.groupId, group.bytes)) {
          groupCerts[hex.encode(cert.certRef)] = cert;
        }
      }
    }

    final groupEnvs = _envelopes.putIfAbsent(group, () => []);
    final groupIds = _envelopeIds.putIfAbsent(group, () => <String>{});
    final groupReceiptMap = _receiptsByMsgId.putIfAbsent(group, () => {});
    final groupReceipts = _receipts.putIfAbsent(group, () => []);

    for (final env in envelopes) {
      final msgIdHex = env.messageIdHex;

      if (!_constantTimeBytesEqual(env.core.groupId, group.bytes)) {
        rejected.add(
          RejectedItem(messageId: msgIdHex, reason: 'GROUP_MISMATCH'),
        );
        continue;
      }

      if (!await env.verifySignature()) {
        rejected.add(
          RejectedItem(messageId: msgIdHex, reason: 'INVALID_SIGNATURE'),
        );
        continue;
      }

      final isNew = groupIds.add(msgIdHex);
      if (isNew) {
        groupEnvs.add(env);
      }
      acceptedIds.add(msgIdHex);

      if (isNew) {
        final receipt = await _issueReceipt(env);
        if (receipt != null) {
          groupReceiptMap[msgIdHex] = receipt;
          groupReceipts.add(receipt);
          generatedReceipts.add(receipt);
        }
      } else {
        final existingReceipt = groupReceiptMap[msgIdHex];
        if (existingReceipt != null) {
          generatedReceipts.add(existingReceipt);
        }
      }
    }

    return PushResult(
      acceptedIds: acceptedIds,
      rejected: rejected,
      receipts: generatedReceipts,
    );
  }

  Future<ServerReceipt?> _issueReceipt(Envelope env) async {
    if (receiptSigner != null) {
      return receiptSigner!(env);
    }
    if (serverSigningKeyPair != null) {
      final issuedAt = DateTime.now().millisecondsSinceEpoch;
      final core = ServerReceipt(
        version: 1,
        groupId: Uint8List.fromList(env.core.groupId),
        author: Uint8List.fromList(env.core.author),
        ranges: [SeqRange(env.core.seq, env.core.seq)],
        issuedAt: issuedAt,
        serverSig: Uint8List(64),
      );
      final sig =
          await MsgP2PCrypto.sign(core.toCoreCbor(), serverSigningKeyPair!);
      return ServerReceipt(
        version: 1,
        groupId: core.groupId,
        author: core.author,
        ranges: core.ranges,
        issuedAt: issuedAt,
        serverSig: sig,
      );
    }
    return null;
  }

  @override
  Future<PullResult> pull(
    GroupId group,
    VersionVector knownVector, {
    int? limit,
  }) async {
    final groupEnvs = _envelopes[group] ?? const <Envelope>[];
    final effectiveLimit = (limit ?? 100).clamp(1, 500);

    final computedServerVector = VersionVector();
    final allMissing = <Envelope>[];
    for (final env in groupEnvs) {
      final authorHex = hex.encode(env.core.author);
      final seq = env.core.seq;
      computedServerVector.add(authorHex, seq);
      if (!knownVector.has(authorHex, seq)) {
        allMissing.add(env);
      }
    }

    // Priority-first ordering (`FR-SRV-05`: SOS priority 0 delivered first, then chronological).
    allMissing.sort((a, b) {
      final p = a.core.priority.compareTo(b.core.priority);
      if (p != 0) return p;
      final c = a.core.createdAt.compareTo(b.core.createdAt);
      if (c != 0) return c;
      return a.core.seq.compareTo(b.core.seq);
    });

    final hasMore = allMissing.length > effectiveLimit;
    final page = hasMore
        ? allMissing.sublist(0, effectiveLimit)
        : List<Envelope>.unmodifiable(allMissing);

    return PullResult(
      envelopes: page,
      hasMore: hasMore,
      serverVector: computedServerVector,
    );
  }

  @override
  Future<List<ServerReceipt>> receipts(
    GroupId group, {
    int? since,
  }) async {
    final groupReceipts = _receipts[group] ?? const <ServerReceipt>[];
    final threshold = since ?? 0;
    final filtered = groupReceipts.where((r) => r.issuedAt > threshold).toList()
      ..sort((a, b) => a.issuedAt.compareTo(b.issuedAt));
    return List<ServerReceipt>.unmodifiable(filtered);
  }

  @override
  Future<List<RevocationNotice>> revocations(
    GroupId group, {
    int? since,
  }) async {
    final groupRevs = _revocations[group] ?? const <RevocationNotice>[];
    final threshold = since ?? 0;
    final filtered = groupRevs.where((r) => r.revokedAt > threshold).toList()
      ..sort((a, b) => a.revokedAt.compareTo(b.revokedAt));
    return List<RevocationNotice>.unmodifiable(filtered);
  }

  @override
  Future<void> uploadAttachment(
    GroupId group,
    AttachmentRef ref,
    Uint8List bytes,
  ) async {
    if (!verifyAttachmentBytesHash(ref.hash, bytes)) {
      throw const GatewayException(
        statusCode: 400,
        error: 'ATTACHMENT_HASH_MISMATCH',
        message: 'Attachment SHA-256 hash mismatch',
      );
    }
    final hashHex = hex.encode(ref.hash);
    final groupAttachments = _attachments.putIfAbsent(group, () => {});
    groupAttachments.putIfAbsent(
      hashHex,
      () => StoredAttachmentBlob(
        hash: Uint8List.fromList(ref.hash),
        mime: ref.mime,
        bytes: Uint8List.fromList(bytes),
        storedAt: DateTime.now().millisecondsSinceEpoch,
      ),
    );
  }

  @override
  Future<StoredAttachmentBlob> downloadAttachment(
    GroupId group,
    AttachmentRef ref,
  ) async {
    final hashHex = hex.encode(ref.hash);
    final blob = _attachments[group]?[hashHex];
    if (blob == null) {
      throw GatewayException(
        statusCode: 404,
        error: 'ATTACHMENT_NOT_FOUND',
        message: 'Attachment not found for hash $hashHex',
      );
    }
    return StoredAttachmentBlob(
      hash: Uint8List.fromList(blob.hash),
      mime: blob.mime,
      bytes: Uint8List.fromList(blob.bytes),
      storedAt: blob.storedAt,
    );
  }

  /// Adds a revocation notice to this memory store.
  void addRevocation(GroupId group, RevocationNotice notice) {
    _revocations.putIfAbsent(group, () => []).add(notice);
  }

  /// Adds a server receipt to this memory store.
  void addReceipt(GroupId group, ServerReceipt receipt) {
    _receipts.putIfAbsent(group, () => []).add(receipt);
  }
}
