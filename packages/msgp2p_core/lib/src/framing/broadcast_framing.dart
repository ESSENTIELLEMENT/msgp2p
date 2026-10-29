import 'dart:typed_data';
import 'package:cbor/cbor.dart' as cbor;
import 'package:meta/meta.dart';
import '../encoding/canonical_cbor.dart';
import '../model/certificate.dart';
import '../model/envelope.dart';
import 'crc16.dart';

/// Magic byte identifying a 0-RTT broadcast chunk packet.
const int broadcastMagicByte = 0xBD;

/// Self-contained asynchronous 0-RTT broadcast message wrapper for low-bandwidth packet radios.
@immutable
class BroadcastFrame {
  final int version;
  final Envelope envelope;
  final MembershipCert? cert;
  final int broadcastId;
  final int hopLimit;
  final int hopCount;

  const BroadcastFrame({
    this.version = 1,
    required this.envelope,
    this.cert,
    required this.broadcastId,
    this.hopLimit = 3,
    this.hopCount = 0,
  });

  /// Map representation for Canonical CBOR encoding.
  Map<String, dynamic> toMap() => {
        'v': version,
        'envelope': envelope.toCanonicalCbor(),
        if (cert != null) 'cert': cert!.toFullCbor(),
        'broadcast_id': broadcastId,
        'hop_limit': hopLimit,
        'hop_count': hopCount,
      };

  /// Deterministic Canonical CBOR bytes of this broadcast frame.
  Uint8List toCanonicalCbor() => CanonicalCbor.encode(toMap());

  /// Deserializes a [BroadcastFrame] from Canonical CBOR bytes.
  factory BroadcastFrame.fromCbor(Uint8List bytes) {
    final decoded = cbor.cbor.decode(bytes).toObject() as Map;
    final envBytes =
        Uint8List.fromList((decoded['envelope'] as List).cast<int>());
    final envelope = Envelope.fromCbor(envBytes);

    MembershipCert? cert;
    if (decoded.containsKey('cert') && decoded['cert'] != null) {
      final certBytes =
          Uint8List.fromList((decoded['cert'] as List).cast<int>());
      cert = MembershipCert.fromCbor(certBytes);
    }

    return BroadcastFrame(
      version: decoded['v'] as int? ?? 1,
      envelope: envelope,
      cert: cert,
      broadcastId: decoded['broadcast_id'] as int,
      hopLimit: decoded['hop_limit'] as int? ?? 3,
      hopCount: decoded['hop_count'] as int? ?? 0,
    );
  }

  /// Returns a copy of this frame with [hopCount] incremented for mesh forwarding.
  BroadcastFrame nextHop() => BroadcastFrame(
        version: version,
        envelope: envelope,
        cert: cert,
        broadcastId: broadcastId,
        hopLimit: hopLimit,
        hopCount: hopCount + 1,
      );

  /// Whether this frame can still be forwarded across another hop.
  bool get canForward => hopCount < hopLimit;
}

/// A discrete MTU-sized chunk packet formatted for broadcast transmissions (e.g. LoRa / Meshtastic).
///
/// Header (9 bytes):
/// - 1 byte Magic (`0xBD`)
/// - 4 bytes Broadcast ID (uint32 Big-Endian)
/// - 1 byte Chunk Index (uint8)
/// - 1 byte Total Chunks (uint8)
/// - 2 bytes CRC-16/IBM over data payload (uint16 Big-Endian)
/// Followed by data payload.
@immutable
class BroadcastChunkPacket {
  final int broadcastId;
  final int chunkIndex;
  final int totalChunks;
  final int crc16;
  final Uint8List data;

  const BroadcastChunkPacket({
    required this.broadcastId,
    required this.chunkIndex,
    required this.totalChunks,
    required this.crc16,
    required this.data,
  })  : assert(chunkIndex >= 0 && chunkIndex < totalChunks,
            'chunkIndex must be in [0, totalChunks - 1]'),
        assert(totalChunks >= 1 && totalChunks <= 255,
            'totalChunks must be in [1, 255]');

  /// Encodes this chunk into the 9-byte header + data wire format.
  Uint8List encode() {
    final bytes = Uint8List(9 + data.length);
    final bdata = ByteData.sublistView(bytes);
    bytes[0] = broadcastMagicByte;
    bdata.setUint32(1, broadcastId, Endian.big);
    bytes[5] = chunkIndex;
    bytes[6] = totalChunks;
    bdata.setUint16(7, crc16, Endian.big);
    bytes.setRange(9, bytes.length, data);
    return bytes;
  }

  /// Decodes and validates a broadcast chunk packet from raw [bytes].
  ///
  /// Throws [FormatException] if bytes is too short, magic does not match, or CRC-16 fails.
  static BroadcastChunkPacket decode(Uint8List bytes) {
    if (bytes.length < 9) {
      throw FormatException(
          'Insufficient bytes for broadcast chunk header: ${bytes.length} < 9');
    }
    if (bytes[0] != broadcastMagicByte) {
      throw FormatException(
          'Invalid broadcast magic byte: 0x${bytes[0].toRadixString(16)} (expected 0x${broadcastMagicByte.toRadixString(16)})');
    }

    final bdata = ByteData.sublistView(bytes);
    final broadcastId = bdata.getUint32(1, Endian.big);
    final chunkIndex = bytes[5];
    final totalChunks = bytes[6];
    final expectedCrc = bdata.getUint16(7, Endian.big);

    if (totalChunks < 1) {
      throw const FormatException('totalChunks must be >= 1');
    }
    if (chunkIndex >= totalChunks) {
      throw FormatException(
          'chunkIndex ($chunkIndex) >= totalChunks ($totalChunks)');
    }

    final data = Uint8List.sublistView(bytes, 9);
    final computedCrc = Crc16.compute(data);
    if (computedCrc != expectedCrc) {
      throw FormatException(
        'CRC-16 mismatch: expected 0x${expectedCrc.toRadixString(16)}, computed 0x${computedCrc.toRadixString(16)}',
      );
    }

    return BroadcastChunkPacket(
      broadcastId: broadcastId,
      chunkIndex: chunkIndex,
      totalChunks: totalChunks,
      crc16: expectedCrc,
      data: data,
    );
  }
}

/// Slices a [BroadcastFrame] into MTU-sized [BroadcastChunkPacket]s.
class BroadcastChunkSlicer {
  BroadcastChunkSlicer._();

  /// Slices [frame] into chunks that do not exceed [mtu] bytes when encoded.
  static List<BroadcastChunkPacket> slice(
    BroadcastFrame frame, {
    int mtu = 230,
  }) {
    if (mtu < 32) {
      throw ArgumentError.value(
          mtu, 'mtu', 'MTU must be at least 32 bytes for broadcast framing');
    }

    final payload = frame.toCanonicalCbor();
    final maxChunkDataSize = mtu - 9; // 9-byte header

    final totalChunks = (payload.length / maxChunkDataSize).ceil();
    if (totalChunks > 255) {
      throw ArgumentError(
          'Payload of ${payload.length} bytes requires $totalChunks chunks, exceeding max limit of 255');
    }

    final chunks = <BroadcastChunkPacket>[];
    for (var i = 0; i < totalChunks; i++) {
      final start = i * maxChunkDataSize;
      final end = (start + maxChunkDataSize < payload.length)
          ? start + maxChunkDataSize
          : payload.length;
      final chunkData = Uint8List.sublistView(payload, start, end);
      final crc = Crc16.compute(chunkData);

      chunks.add(BroadcastChunkPacket(
        broadcastId: frame.broadcastId,
        chunkIndex: i,
        totalChunks: totalChunks,
        crc16: crc,
        data: chunkData,
      ));
    }

    return chunks;
  }
}

/// In-progress buffer for a single broadcast message reassembly.
class _BroadcastReassemblyBuffer {
  final int broadcastId;
  final int totalChunks;
  final Map<int, Uint8List> chunks = {};
  final int createdAtMs;

  _BroadcastReassemblyBuffer({
    required this.broadcastId,
    required this.totalChunks,
    required this.createdAtMs,
  });

  bool get isComplete => chunks.length == totalChunks;

  Uint8List assemble() {
    var totalLen = 0;
    for (var i = 0; i < totalChunks; i++) {
      totalLen += chunks[i]!.length;
    }
    final combined = Uint8List(totalLen);
    var offset = 0;
    for (var i = 0; i < totalChunks; i++) {
      final chunk = chunks[i]!;
      combined.setRange(offset, offset + chunk.length, chunk);
      offset += chunk.length;
    }
    return combined;
  }
}

/// Reassembles broadcast chunks into complete [BroadcastFrame]s.
class BroadcastChunkReassembler {
  final Duration bufferTtl;
  final Map<int, _BroadcastReassemblyBuffer> _buffers = {};

  BroadcastChunkReassembler({
    this.bufferTtl = const Duration(seconds: 60),
  });

  /// Processes an incoming raw chunk packet.
  ///
  /// Returns a completed [BroadcastFrame] if all chunks for this broadcast ID
  /// have been received; otherwise returns `null`.
  BroadcastFrame? processRawChunk(Uint8List rawBytes, {int? nowMs}) {
    final now = nowMs ?? DateTime.now().millisecondsSinceEpoch;
    _pruneExpired(now);

    final BroadcastChunkPacket chunk;
    try {
      chunk = BroadcastChunkPacket.decode(rawBytes);
    } catch (_) {
      return null; // Ignore corrupted or invalid chunks
    }

    final buffer = _buffers.putIfAbsent(
      chunk.broadcastId,
      () => _BroadcastReassemblyBuffer(
        broadcastId: chunk.broadcastId,
        totalChunks: chunk.totalChunks,
        createdAtMs: now,
      ),
    );

    if (buffer.totalChunks != chunk.totalChunks) {
      // Inconsistent total chunks for same ID, discard corrupted buffer
      _buffers.remove(chunk.broadcastId);
      return null;
    }

    buffer.chunks[chunk.chunkIndex] = chunk.data;

    if (buffer.isComplete) {
      _buffers.remove(chunk.broadcastId);
      final combined = buffer.assemble();
      try {
        return BroadcastFrame.fromCbor(combined);
      } catch (_) {
        return null;
      }
    }

    return null;
  }

  void _pruneExpired(int now) {
    final ttlMs = bufferTtl.inMilliseconds;
    _buffers.removeWhere((_, b) => now - b.createdAtMs > ttlMs);
  }

  /// Clears all pending in-progress reassembly buffers.
  void reset() {
    _buffers.clear();
  }
}
