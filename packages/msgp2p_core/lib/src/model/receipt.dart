import 'package:cbor/cbor.dart' as cbor;
import 'dart:typed_data';
import 'package:meta/meta.dart';
import '../crypto/crypto.dart';
import '../encoding/canonical_cbor.dart';
import 'version_vector.dart';

/// Server-signed batch receipt (anti-packet) confirming message sequence numbers stored on cloud.
@immutable
class ServerReceipt {
  final int version;
  final Uint8List groupId;
  final Uint8List author; // 32-byte Ed25519 public key
  final List<SeqRange> ranges;
  final int issuedAt;
  final Uint8List serverSig;

  const ServerReceipt({
    this.version = 1,
    required this.groupId,
    required this.author,
    required this.ranges,
    required this.issuedAt,
    required this.serverSig,
  });

  Map<String, dynamic> toCoreMap() => {
        'v': version,
        'group_id': groupId,
        'author': author,
        'ranges': ranges.map((r) => r.toList()).toList(),
        'issued_at': issuedAt,
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

  bool confirms(int seq) {
    for (final r in ranges) {
      if (r.contains(seq)) return true;
    }
    return false;
  }

  factory ServerReceipt.fromCbor(Uint8List bytes) {
    final decoded = cbor.cbor.decode(bytes).toObject() as Map;
    final rawRanges = decoded['ranges'] as List? ?? [];
    final ranges = <SeqRange>[];
    for (final r in rawRanges) {
      final pair = (r as List).cast<int>();
      ranges.add(SeqRange(pair[0], pair[1]));
    }
    return ServerReceipt(
      version: decoded['v'] as int? ?? 1,
      groupId: Uint8List.fromList((decoded['group_id'] as List).cast<int>()),
      author: Uint8List.fromList((decoded['author'] as List).cast<int>()),
      ranges: ranges,
      issuedAt: decoded['issued_at'] as int,
      serverSig:
          Uint8List.fromList((decoded['server_sig'] as List).cast<int>()),
    );
  }
}
