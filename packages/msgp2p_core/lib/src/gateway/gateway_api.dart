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
import 'gateway_client.dart';

/// 16-byte unique identifier for a msgp2p group.
@immutable
class GroupId {
  /// The 16 raw bytes of this group ID.
  final Uint8List bytes;

  const GroupId(this.bytes);

  /// Creates a [GroupId] from a 16-byte list.
  factory GroupId.fromBytes(List<int> bytes) {
    if (bytes.length != 16) {
      throw ArgumentError.value(
        bytes.length,
        'bytes.length',
        'GroupId must be exactly 16 bytes, got ${bytes.length}',
      );
    }
    return GroupId(bytes is Uint8List ? bytes : Uint8List.fromList(bytes));
  }

  /// Creates a [GroupId] from a 32-character hexadecimal string.
  factory GroupId.fromHex(String hexString) {
    final clean =
        hexString.startsWith('0x') ? hexString.substring(2) : hexString;
    final decoded = hex.decode(clean);
    if (decoded.length != 16) {
      throw ArgumentError.value(
        hexString,
        'hexString',
        'GroupId hex string must represent exactly 16 bytes (32 hex characters)',
      );
    }
    return GroupId(Uint8List.fromList(decoded));
  }

  /// Converts a [GroupId], hex [String], or 16-byte [List<int>] to a [GroupId].
  factory GroupId.from(dynamic value) {
    if (value is GroupId) return value;
    if (value is String) return GroupId.fromHex(value);
    if (value is List<int>) return GroupId.fromBytes(value);
    throw ArgumentError(
        'Cannot convert ${value.runtimeType} to GroupId: $value');
  }

  /// Hexadecimal string representation of this group ID.
  String get hexString => hex.encode(bytes).toLowerCase();

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is GroupId && _bytesEqual(bytes, other.bytes);

  @override
  int get hashCode => Object.hashAll(bytes);

  @override
  String toString() => hexString;

  static bool _bytesEqual(Uint8List a, Uint8List b) {
    if (a.length != b.length) return false;
    for (var i = 0; i < a.length; i++) {
      if (a[i] != b[i]) return false;
    }
    return true;
  }
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
}

/// Abstract port for sending HTTP requests (Proposal 0001, Step 3).
///
/// Decouples gateway protocol operations from concrete HTTP I/O implementations
/// (`dart:io` `HttpClient`, `package:http`, browser `fetch`, or host custom network stack).
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

  /// Pulls delta envelopes newer than [serverVector] from the gateway server.
  Future<PullResult> pull(
    GroupId group,
    VersionVector serverVector, {
    int? limit,
  });

  /// Retrieves server delivery receipts issued since [since] milliseconds timestamp.
  Future<List<ServerReceipt>> receipts(
    GroupId group, {
    int? since,
  });

  /// Retrieves member revocation notices issued since [since] milliseconds timestamp.
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

/// In-memory implementation of [GatewayApi] for offline testing, contract suites, and simulations.
class MemoryGatewayApi implements GatewayApi {
  final Map<GroupId, List<Envelope>> _envelopes = {};
  final Map<GroupId, List<ServerReceipt>> _receipts = {};
  final Map<GroupId, List<RevocationNotice>> _revocations = {};
  final Map<String, StoredAttachmentBlob> _attachments = {}; // hashHex -> blob

  Uint8List? serverPublicKey;
  Future<ServerReceipt> Function(Envelope envelope)? receiptSigner;

  MemoryGatewayApi({
    this.serverPublicKey,
    this.receiptSigner,
  });

  @override
  Future<PushResult> push(
    GroupId group,
    List<Envelope> envelopes, {
    List<MembershipCert>? certificates,
  }) async {
    final acceptedIds = <String>[];
    final generatedReceipts = <ServerReceipt>[];

    final groupEnvs = _envelopes.putIfAbsent(group, () => []);
    final groupReceipts = _receipts.putIfAbsent(group, () => []);

    for (final env in envelopes) {
      final msgIdHex = hex.encode(env.messageId);
      final alreadyExists =
          groupEnvs.any((e) => hex.encode(e.messageId) == msgIdHex);
      if (!alreadyExists) {
        groupEnvs.add(env);
      }
      acceptedIds.add(msgIdHex);

      if (receiptSigner != null) {
        final r = await receiptSigner!(env);
        generatedReceipts.add(r);
        groupReceipts.add(r);
      }
    }

    return PushResult(
      acceptedIds: acceptedIds,
      rejected: const [],
      receipts: generatedReceipts,
    );
  }

  @override
  Future<PullResult> pull(
    GroupId group,
    VersionVector serverVector, {
    int? limit,
  }) async {
    final groupEnvs = _envelopes[group] ?? [];
    final effectiveLimit = limit ?? 100;

    final missing = <Envelope>[];
    for (final env in groupEnvs) {
      final authorHex = hex.encode(env.core.author);
      final seq = env.core.seq;
      if (!serverVector.has(authorHex, seq)) {
        missing.add(env);
        if (missing.length >= effectiveLimit) break;
      }
    }

    return PullResult(
      envelopes: missing,
      hasMore:
          groupEnvs.length > missing.length && missing.length >= effectiveLimit,
      serverVector: serverVector,
    );
  }

  @override
  Future<List<ServerReceipt>> receipts(
    GroupId group, {
    int? since,
  }) async {
    final groupReceipts = _receipts[group] ?? [];
    if (since == null || since == 0) {
      return List.unmodifiable(groupReceipts);
    }
    return groupReceipts
        .where((r) => r.issuedAt >= since)
        .toList(growable: false);
  }

  @override
  Future<List<RevocationNotice>> revocations(
    GroupId group, {
    int? since,
  }) async {
    final groupRevs = _revocations[group] ?? [];
    if (since == null || since == 0) {
      return List.unmodifiable(groupRevs);
    }
    return groupRevs.where((r) => r.revokedAt >= since).toList(growable: false);
  }

  @override
  Future<void> uploadAttachment(
    GroupId group,
    AttachmentRef ref,
    Uint8List bytes,
  ) async {
    final hashHex = hex.encode(ref.hash);
    _attachments[hashHex] = StoredAttachmentBlob(
      hash: ref.hash,
      mime: ref.mime,
      bytes: bytes,
      storedAt: DateTime.now().millisecondsSinceEpoch,
    );
  }

  @override
  Future<StoredAttachmentBlob> downloadAttachment(
    GroupId group,
    AttachmentRef ref,
  ) async {
    final hashHex = hex.encode(ref.hash);
    final blob = _attachments[hashHex];
    if (blob == null) {
      throw GatewayException(
        statusCode: 404,
        error: 'ATTACHMENT_NOT_FOUND',
        message: 'Attachment not found for hash $hashHex',
      );
    }
    return blob;
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
