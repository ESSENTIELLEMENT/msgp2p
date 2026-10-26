import 'dart:typed_data';
import 'package:cbor/cbor.dart' as cbor;
import 'package:meta/meta.dart';
import '../crypto/crypto.dart';
import '../encoding/canonical_cbor.dart';

/// Server-issued membership certificate granting access to a group.
@immutable
class MembershipCert {
  final int version;
  final Uint8List groupId;
  final String userId;
  final Uint8List memberPubkey;
  final Uint8List noisePubkey;
  final int role; // 0 = Member, 1 = Admin/Ranger
  final int issuedAt; // Milliseconds Unix epoch
  final int expiresAt; // Milliseconds Unix epoch
  final Uint8List serverSig;

  const MembershipCert({
    this.version = 1,
    required this.groupId,
    required this.userId,
    required this.memberPubkey,
    required this.noisePubkey,
    this.role = 0,
    required this.issuedAt,
    required this.expiresAt,
    required this.serverSig,
  });

  /// Map representation of the cert core (for signing & hashing).
  Map<String, dynamic> toCoreMap() => {
        'v': version,
        'group_id': groupId,
        'user_id': userId,
        'member_pubkey': memberPubkey,
        'noise_pubkey': noisePubkey,
        'role': role,
        'issued_at': issuedAt,
        'expires_at': expiresAt,
      };

  /// Deterministic Canonical CBOR bytes of the cert core.
  Uint8List toCoreCbor() => CanonicalCbor.encode(toCoreMap());

  /// Map representation of the full certificate (including server signature).
  Map<String, dynamic> toFullMap() => {
        ...toCoreMap(),
        'server_sig': serverSig,
      };

  /// Deterministic Canonical CBOR bytes of the full certificate.
  Uint8List toFullCbor() => CanonicalCbor.encode(toFullMap());

  /// Content-addressed certificate reference hash: SHA-256(canonical_cbor(full_cert)).
  Uint8List get certRef => MsgP2PCrypto.sha256(toFullCbor());

  /// Deserializes a [MembershipCert] from a full certificate map.
  factory MembershipCert.fromFullMap(Map<dynamic, dynamic> map) {
    return MembershipCert(
      version: map['v'] as int? ?? 1,
      groupId: Uint8List.fromList((map['group_id'] as List).cast<int>()),
      userId: map['user_id'] as String,
      memberPubkey:
          Uint8List.fromList((map['member_pubkey'] as List).cast<int>()),
      noisePubkey:
          Uint8List.fromList((map['noise_pubkey'] as List).cast<int>()),
      role: map['role'] as int? ?? 0,
      issuedAt: map['issued_at'] as int,
      expiresAt: map['expires_at'] as int,
      serverSig: Uint8List.fromList((map['server_sig'] as List).cast<int>()),
    );
  }

  /// Deserializes a [MembershipCert] from CBOR bytes.
  factory MembershipCert.fromCbor(Uint8List bytes) {
    final decoded = cbor.cbor.decode(bytes).toObject() as Map;
    return MembershipCert.fromFullMap(decoded);
  }

  /// Verifies the server's Ed25519 signature over this certificate.
  Future<bool> verify(Uint8List serverPublicKey) async {
    return MsgP2PCrypto.verifySignature(
      message: toCoreCbor(),
      signature: serverSig,
      publicKeyBytes: serverPublicKey,
    );
  }

  /// Checks if the certificate is expired at the given timestamp.
  bool isExpired([int? currentTimeMs]) {
    final now = currentTimeMs ?? DateTime.now().millisecondsSinceEpoch;
    return now >= expiresAt;
  }
}
