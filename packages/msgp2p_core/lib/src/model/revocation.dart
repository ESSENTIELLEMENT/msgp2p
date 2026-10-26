import 'package:cbor/cbor.dart' as cbor;
import 'dart:typed_data';
import 'package:meta/meta.dart';
import '../crypto/crypto.dart';
import '../encoding/canonical_cbor.dart';

/// Server-signed member revocation notice.
@immutable
class RevocationNotice {
  final int version;
  final Uint8List groupId;
  final Uint8List memberPubkey; // 32-byte Ed25519 public key
  final int revokedAt;
  final String reason;
  final Uint8List serverSig;

  const RevocationNotice({
    this.version = 1,
    required this.groupId,
    required this.memberPubkey,
    required this.revokedAt,
    required this.reason,
    required this.serverSig,
  });

  Map<String, dynamic> toCoreMap() => {
        'v': version,
        'group_id': groupId,
        'member_pubkey': memberPubkey,
        'revoked_at': revokedAt,
        'reason': reason,
      };

  Uint8List toCoreCbor() => CanonicalCbor.encode(toCoreMap());

  Map<String, dynamic> toFullMap() => {
        ...toCoreMap(),
        'server_sig': serverSig,
      };

  Uint8List toFullCbor() => CanonicalCbor.encode(toFullMap());

  Future<bool> verify(Uint8List serverPublicKey) async {
    return MsgP2PCrypto.verifySignature(
      message: toCoreCbor(),
      signature: serverSig,
      publicKeyBytes: serverPublicKey,
    );
  }

  factory RevocationNotice.fromCbor(Uint8List bytes) {
    final decoded = cbor.cbor.decode(bytes).toObject() as Map;
    return RevocationNotice(
      version: decoded['v'] as int? ?? 1,
      groupId: Uint8List.fromList((decoded['group_id'] as List).cast<int>()),
      memberPubkey:
          Uint8List.fromList((decoded['member_pubkey'] as List).cast<int>()),
      revokedAt: decoded['revoked_at'] as int,
      reason: decoded['reason'] as String,
      serverSig:
          Uint8List.fromList((decoded['server_sig'] as List).cast<int>()),
    );
  }
}
