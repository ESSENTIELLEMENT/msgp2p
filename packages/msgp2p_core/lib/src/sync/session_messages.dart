import 'dart:typed_data';
import 'package:cbor/cbor.dart' as cbor;
import 'package:convert/convert.dart';
import 'package:meta/meta.dart';
import '../encoding/canonical_cbor.dart';
import '../model/version_vector.dart';

/// Protocol frame type codes per protocol/wire-format.md §7.
abstract final class SessionFrameType {
  static const int handshake1 = 0x01;
  static const int handshake2 = 0x02;
  static const int handshake3 = 0x03;

  static const int summary = 0x10;
  static const int want = 0x11;
  static const int data = 0x12;
  static const int receipts = 0x13;
  static const int revocations = 0x14;
  static const int certReq = 0x15;
  static const int certResp = 0x16;
  static const int blobWant = 0x17;
  static const int blobData = 0x18;
  static const int upgradeOffer = 0x19;
  static const int upgradeAccept = 0x1A;
  static const int bye = 0x1F;
}

/// Disconnect reasons for BYE frame (0x1F).
abstract final class ByeReason {
  static const int completed = 0;
  static const int error = 1;
  static const int timeout = 2;
  static const int tieBreakLowerPeer = 3;
}

/// Session SUMMARY payload (Type 0x10).
@immutable
class SessionSummary {
  final VersionVector vector;
  final int receiptWatermark;
  final int revocationVersion;

  const SessionSummary({
    required this.vector,
    required this.receiptWatermark,
    required this.revocationVersion,
  });

  Map<String, dynamic> toMap() => {
        'vector': vector.toMap(),
        'receipt_watermark': receiptWatermark,
        'revocation_version': revocationVersion,
      };

  Uint8List toCanonicalCbor() => CanonicalCbor.encode(toMap());

  factory SessionSummary.fromCbor(Uint8List bytes) {
    final decoded = cbor.cbor.decode(bytes).toObject() as Map;
    final vv = VersionVector();
    final vectorMap = decoded['vector'] as Map? ?? {};
    for (final entry in vectorMap.entries) {
      final key = entry.key;
      final authorHex = key is List<int> ? hex.encode(key) : key.toString();
      final stateMap = entry.value as Map;
      final contiguous = stateMap['contiguous'] as int? ?? 0;
      final gapsRaw = stateMap['gaps'] as List? ?? [];
      final gaps = gapsRaw.map((e) => e as int).toSet();
      vv.getOrCreate(authorHex)
        ..contiguous = contiguous
        ..gaps.addAll(gaps);
    }

    return SessionSummary(
      vector: vv,
      receiptWatermark: decoded['receipt_watermark'] as int? ?? 0,
      revocationVersion: decoded['revocation_version'] as int? ?? 0,
    );
  }
}

/// Session WANT payload (Type 0x11).
@immutable
class SessionWant {
  final List<AuthorWant> requests;

  const SessionWant({required this.requests});

  Map<String, dynamic> toMap() => {
        'requests': requests.map((r) => r.toMap()).toList(),
      };

  Uint8List toCanonicalCbor() => CanonicalCbor.encode(toMap());

  factory SessionWant.fromCbor(Uint8List bytes) {
    final decoded = cbor.cbor.decode(bytes).toObject() as Map;
    final rawRequests = decoded['requests'] as List? ?? [];
    final requests = <AuthorWant>[];

    for (final req in rawRequests) {
      final rMap = req as Map;
      final rawAuthor = rMap['author'];
      final authorHex =
          rawAuthor is List<int> ? hex.encode(rawAuthor) : rawAuthor.toString();
      final rawRanges = rMap['ranges'] as List? ?? [];
      final ranges = <SeqRange>[];
      for (final r in rawRanges) {
        final pair = (r as List).cast<int>();
        ranges.add(SeqRange(pair[0], pair[1]));
      }
      requests.add(AuthorWant(authorHex: authorHex, ranges: ranges));
    }

    return SessionWant(requests: requests);
  }
}

/// Session CERT_REQ payload (Type 0x15).
@immutable
class CertReq {
  final List<Uint8List> certRefs;

  const CertReq({required this.certRefs});

  Map<String, dynamic> toMap() => {
        'cert_refs': certRefs,
      };

  Uint8List toCanonicalCbor() => CanonicalCbor.encode(toMap());

  factory CertReq.fromCbor(Uint8List bytes) {
    final decoded = cbor.cbor.decode(bytes).toObject() as Map;
    final rawRefs = decoded['cert_refs'] as List? ?? [];
    return CertReq(
      certRefs: rawRefs
          .map((r) => Uint8List.fromList((r as List).cast<int>()))
          .toList(),
    );
  }
}

/// Session BLOB_WANT payload (Type 0x17) for requesting hash-addressed attachments over bulk links.
@immutable
class BlobWant {
  final List<Uint8List> hashes;

  const BlobWant({required this.hashes});

  Map<String, dynamic> toMap() => {
        'hashes': hashes,
      };

  Uint8List toCanonicalCbor() => CanonicalCbor.encode(toMap());

  factory BlobWant.fromCbor(Uint8List bytes) {
    final decoded = cbor.cbor.decode(bytes).toObject() as Map;
    final rawHashes = decoded['hashes'] as List? ?? [];
    return BlobWant(
      hashes: rawHashes
          .map((h) => Uint8List.fromList((h as List).cast<int>()))
          .toList(),
    );
  }
}

/// Session BLOB_DATA payload (Type 0x18) carrying a hash-addressed attachment blob.
@immutable
class BlobData {
  final Uint8List hash;
  final String mime;
  final Uint8List data;

  const BlobData({
    required this.hash,
    required this.mime,
    required this.data,
  });

  Map<String, dynamic> toMap() => {
        'hash': hash,
        'mime': mime,
        'data': data,
      };

  Uint8List toCanonicalCbor() => CanonicalCbor.encode(toMap());

  factory BlobData.fromCbor(Uint8List bytes) {
    final decoded = cbor.cbor.decode(bytes).toObject() as Map;
    return BlobData(
      hash: Uint8List.fromList((decoded['hash'] as List).cast<int>()),
      mime: decoded['mime'] as String? ?? 'application/octet-stream',
      data: Uint8List.fromList((decoded['data'] as List).cast<int>()),
    );
  }
}

/// Session UPGRADE_OFFER payload (Type 0x19) proposing BLE -> Wi-Fi Aware upgrade.
@immutable
class UpgradeOffer {
  final String serviceId;
  final Uint8List token;
  final int pendingBytes;

  const UpgradeOffer({
    required this.serviceId,
    required this.token,
    required this.pendingBytes,
  });

  Map<String, dynamic> toMap() => {
        'service_id': serviceId,
        'token': token,
        'pending_bytes': pendingBytes,
      };

  Uint8List toCanonicalCbor() => CanonicalCbor.encode(toMap());

  factory UpgradeOffer.fromCbor(Uint8List bytes) {
    final decoded = cbor.cbor.decode(bytes).toObject() as Map;
    return UpgradeOffer(
      serviceId: decoded['service_id'] as String? ?? 'msgp2p_bulk',
      token: Uint8List.fromList((decoded['token'] as List).cast<int>()),
      pendingBytes: decoded['pending_bytes'] as int? ?? 0,
    );
  }
}

/// Session UPGRADE_ACCEPT payload (Type 0x1A) responding to an upgrade offer.
@immutable
class UpgradeAccept {
  final bool accepted;
  final String peerHandle;

  const UpgradeAccept({
    required this.accepted,
    required this.peerHandle,
  });

  Map<String, dynamic> toMap() => {
        'accepted': accepted,
        'peer_handle': peerHandle,
      };

  Uint8List toCanonicalCbor() => CanonicalCbor.encode(toMap());

  factory UpgradeAccept.fromCbor(Uint8List bytes) {
    final decoded = cbor.cbor.decode(bytes).toObject() as Map;
    return UpgradeAccept(
      accepted: decoded['accepted'] as bool? ?? false,
      peerHandle: decoded['peer_handle'] as String? ?? '',
    );
  }
}

/// Session BYE payload (Type 0x1F).
@immutable
class ByeMessage {
  final int reason;

  const ByeMessage({this.reason = ByeReason.completed});

  Map<String, dynamic> toMap() => {
        'reason': reason,
      };

  Uint8List toCanonicalCbor() => CanonicalCbor.encode(toMap());

  factory ByeMessage.fromCbor(Uint8List bytes) {
    final decoded = cbor.cbor.decode(bytes).toObject() as Map;
    return ByeMessage(reason: decoded['reason'] as int? ?? ByeReason.completed);
  }
}
