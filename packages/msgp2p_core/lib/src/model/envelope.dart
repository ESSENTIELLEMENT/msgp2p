import 'package:cbor/cbor.dart' as cbor;
import 'package:convert/convert.dart';
import '../crypto/random_source.dart';
import 'dart:typed_data';
import 'package:cryptography/cryptography.dart' as cg;
import 'package:meta/meta.dart';
import '../crypto/crypto.dart';
import '../encoding/canonical_cbor.dart';

/// Thrown when an envelope core exceeds the 4 KB (4096-byte) protocol hard limit (`requirements.md §3`).
class EnvelopeSizeLimitException implements Exception {
  final int actualBytes;
  final int maxBytes;

  const EnvelopeSizeLimitException({
    required this.actualBytes,
    this.maxBytes = Envelope.maxCoreSizeBytes,
  });

  @override
  String toString() =>
      'EnvelopeSizeLimitException: core size $actualBytes bytes exceeds hard limit of $maxBytes bytes';
}

/// Reference to an external bulk attachment (image, telemetry, etc.).
@immutable
class AttachmentRef {
  final Uint8List hash;
  final int size;
  final String mime;

  const AttachmentRef({
    required this.hash,
    required this.size,
    required this.mime,
  });

  /// Computes a SHA-256 content-addressed [AttachmentRef] directly from [bytes].
  factory AttachmentRef.fromBytes({
    required Uint8List bytes,
    required String mime,
  }) {
    return AttachmentRef(
      hash: MsgP2PCrypto.sha256(bytes),
      size: bytes.length,
      mime: mime,
    );
  }

  /// Verifies that [bytes] match this attachment reference's [hash] and [size].
  bool verifyBytes(Uint8List bytes) {
    if (bytes.length != size) return false;
    final actualHash = MsgP2PCrypto.sha256(bytes);
    if (actualHash.length != hash.length) return false;
    var diff = 0;
    for (var i = 0; i < hash.length; i++) {
      diff |= actualHash[i] ^ hash[i];
    }
    return diff == 0;
  }

  Map<String, dynamic> toMap() => {
        'hash': hash,
        'size': size,
        'mime': mime,
      };
}

/// Immutable core of a message envelope (hashed for messageId and signed by author).
@immutable
class EnvelopeCore {
  final int version;
  final Uint8List groupId;
  final int keyEpoch;
  final Uint8List author; // 32-byte Ed25519 public key
  final int seq; // Monotonic per-author sequence number (1, 2, 3...)
  final int createdAt; // Milliseconds Unix epoch
  final int expiresAt; // Milliseconds Unix epoch
  final int priority; // 0 = SOS, 1 = High, 2 = Normal, 3 = Low
  final Uint8List nonce; // 24-byte XChaCha20 nonce
  final Uint8List ciphertext; // Encrypted payload with 16-byte Poly1305 MAC
  final List<AttachmentRef>? attachments;

  const EnvelopeCore({
    this.version = 1,
    required this.groupId,
    required this.keyEpoch,
    required this.author,
    required this.seq,
    required this.createdAt,
    required this.expiresAt,
    this.priority = 2,
    required this.nonce,
    required this.ciphertext,
    this.attachments,
  });

  /// Map representation of the envelope core for Canonical CBOR encoding.
  Map<String, dynamic> toMap() {
    final map = <String, dynamic>{
      'v': version,
      'group_id': groupId,
      'key_epoch': keyEpoch,
      'author': author,
      'seq': seq,
      'created_at': createdAt,
      'expires_at': expiresAt,
      'priority': priority,
      'nonce': nonce,
      'ciphertext': ciphertext,
    };
    if (attachments != null && attachments!.isNotEmpty) {
      map['attachments'] = attachments!.map((a) => a.toMap()).toList();
    }
    return map;
  }

  /// Deterministic Canonical CBOR bytes of the envelope core.
  Uint8List toCanonicalCbor() => CanonicalCbor.encode(toMap());

  /// Deterministic content-addressed message ID: SHA-256(canonical_cbor(core)).
  Uint8List get messageId => MsgP2PCrypto.sha256(toCanonicalCbor());

  /// Hex-encoded message ID.
  String get messageIdHex => hex.encode(messageId);

  /// Associated Data (AAD) for XChaCha20-Poly1305 encryption/decryption:
  /// group_id (16 bytes) || epoch (4 bytes BE) || author (32 bytes) || seq (8 bytes BE)
  Uint8List computeAad() {
    final builder = BytesBuilder(copy: false)..add(groupId);

    final epochBytes = ByteData(4)..setUint32(0, keyEpoch, Endian.big);
    builder.add(epochBytes.buffer.asUint8List());

    builder.add(author);

    final seqBytes = ByteData(8)..setUint64(0, seq, Endian.big);
    builder.add(seqBytes.buffer.asUint8List());

    return builder.toBytes();
  }
}

/// Full envelope relayed across the P2P mesh and central server gateway.
@immutable
class Envelope {
  /// Hard protocol limit for `canonical_cbor(core)` per `requirements.md §3`.
  static const int maxCoreSizeBytes = 4096;

  final EnvelopeCore core;
  final Uint8List sig; // 64-byte Ed25519 signature over canonical_cbor(core)
  final Uint8List certRef; // 32-byte SHA-256 of author's membership certificate

  const Envelope({
    required this.core,
    required this.sig,
    required this.certRef,
  });

  /// The content-addressed deterministic ID of this message.
  Uint8List get messageId => core.messageId;

  /// Hex-encoded message ID.
  String get messageIdHex => core.messageIdHex;

  /// Map representation for Canonical CBOR encoding.
  Map<String, dynamic> toMap() => {
        'core': core.toMap(),
        'sig': sig,
        'cert_ref': certRef,
      };

  /// Deterministic Canonical CBOR bytes of the full envelope.
  Uint8List toCanonicalCbor() => CanonicalCbor.encode(toMap());

  /// Verifies the author's Ed25519 signature over the envelope core.
  Future<bool> verifySignature() async {
    return MsgP2PCrypto.verifySignature(
      message: core.toCanonicalCbor(),
      signature: sig,
      publicKeyBytes: core.author,
    );
  }

  /// Decrypts the message payload using the provided group key.
  Future<Uint8List> decryptPayloadCbor(Uint8List groupKey) async {
    return MsgP2PCrypto.decryptPayload(
      ciphertextWithMac: core.ciphertext,
      secretKey: groupKey,
      nonce: core.nonce,
      aad: core.computeAad(),
    );
  }

  /// Decrypts and CBOR-decodes the message payload map (`{type, body}`) using [groupKey].
  Future<Map<String, dynamic>> decryptPayload(Uint8List groupKey) async {
    final cborBytes = await decryptPayloadCbor(groupKey);
    final decoded = cbor.cbor.decode(cborBytes).toObject() as Map;
    return decoded.map((k, v) => MapEntry(k.toString(), v));
  }

  /// Factory to construct, encrypt, and sign a new Envelope in one step.
  static Future<Envelope> create({
    required Uint8List groupId,
    required int keyEpoch,
    required Uint8List groupKey,
    required cg.SimpleKeyPair authorKeyPair,
    required Uint8List certRef,
    required int seq,
    required Map<String, dynamic> payload,
    int priority = 2,
    Duration ttl = const Duration(hours: 24),
    List<AttachmentRef>? attachments,
    int? customCreatedAt,
    Uint8List? deterministicNonce,
    RandomSource? randomSource,
  }) async {
    final authorPk = await MsgP2PCrypto.getPublicKeyBytes(authorKeyPair);
    final now = customCreatedAt ?? DateTime.now().millisecondsSinceEpoch;
    final expiresAt = now + ttl.inMilliseconds;

    // 1. Generate or use 24-byte nonce
    final rng = randomSource ?? SystemRandomSource();
    final nonce = deterministicNonce ?? rng.nextBytes(24);

    // 2. Encode payload to Canonical CBOR
    final payloadCbor = CanonicalCbor.encode(payload);

    // 3. Compute AAD
    final corePlaceholder = EnvelopeCore(
      groupId: groupId,
      keyEpoch: keyEpoch,
      author: authorPk,
      seq: seq,
      createdAt: now,
      expiresAt: expiresAt,
      priority: priority,
      nonce: nonce,
      ciphertext: Uint8List(0),
    );
    final aad = corePlaceholder.computeAad();

    // 4. Encrypt with XChaCha20-Poly1305
    final ciphertext = await MsgP2PCrypto.encryptPayload(
      plaintext: payloadCbor,
      secretKey: groupKey,
      nonce: nonce,
      aad: aad,
    );

    // 5. Build envelope core
    final core = EnvelopeCore(
      groupId: groupId,
      keyEpoch: keyEpoch,
      author: authorPk,
      seq: seq,
      createdAt: now,
      expiresAt: expiresAt,
      priority: priority,
      nonce: nonce,
      ciphertext: ciphertext,
      attachments: attachments,
    );

    // 6. Sign core with author's Ed25519 key (after enforcing 4 KB core limit)
    final coreCbor = core.toCanonicalCbor();
    if (coreCbor.length > maxCoreSizeBytes) {
      throw EnvelopeSizeLimitException(actualBytes: coreCbor.length);
    }
    final sig = await MsgP2PCrypto.sign(coreCbor, authorKeyPair);

    return Envelope(
      core: core,
      sig: sig,
      certRef: certRef,
    );
  }

  factory Envelope.fromCbor(Uint8List bytes) {
    final decoded = cbor.cbor.decode(bytes).toObject() as Map;
    final coreMap = decoded['core'] as Map;

    final rawAttachments = coreMap['attachments'] as List?;
    final attachments = rawAttachments != null
        ? rawAttachments.map((a) {
            final aMap = a as Map;
            return AttachmentRef(
              hash: Uint8List.fromList((aMap['hash'] as List).cast<int>()),
              size: aMap['size'] as int,
              mime: aMap['mime'] as String,
            );
          }).toList()
        : null;

    final core = EnvelopeCore(
      version: coreMap['v'] as int? ?? 1,
      groupId: Uint8List.fromList((coreMap['group_id'] as List).cast<int>()),
      keyEpoch: coreMap['key_epoch'] as int,
      author: Uint8List.fromList((coreMap['author'] as List).cast<int>()),
      seq: coreMap['seq'] as int,
      createdAt: coreMap['created_at'] as int,
      expiresAt: coreMap['expires_at'] as int,
      priority: coreMap['priority'] as int? ?? 2,
      nonce: Uint8List.fromList((coreMap['nonce'] as List).cast<int>()),
      ciphertext:
          Uint8List.fromList((coreMap['ciphertext'] as List).cast<int>()),
      attachments: attachments,
    );
    final coreLen = core.toCanonicalCbor().length;
    if (coreLen > maxCoreSizeBytes) {
      throw EnvelopeSizeLimitException(actualBytes: coreLen);
    }

    return Envelope(
      core: core,
      sig: Uint8List.fromList((decoded['sig'] as List).cast<int>()),
      certRef: Uint8List.fromList((decoded['cert_ref'] as List).cast<int>()),
    );
  }
}
