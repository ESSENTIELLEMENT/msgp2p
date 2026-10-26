import 'dart:typed_data';
import 'package:meta/meta.dart';
import 'crc16.dart';
import 'frame.dart';

/// Maximum allowable chunks per fragmented frame per protocol/wire-format.md ?8.
const int maxChunksPerFrame = 256;

/// A discrete radio-layer chunk packet as specified in protocol/wire-format.md ?6.2.
///
/// Header (6 bytes):
/// - 2 bytes Chunk Seq (uint16 Big-Endian)
/// - 2 bytes Total Chunks (uint16 Big-Endian)
/// - 2 bytes CRC-16 / IBM over Raw Data
/// Followed by Raw Data.
@immutable
class ChunkPacket {
  final int chunkSeq;
  final int totalChunks;
  final int crc16;
  final Uint8List data;

  const ChunkPacket({
    required this.chunkSeq,
    required this.totalChunks,
    required this.crc16,
    required this.data,
  })  : assert(chunkSeq >= 0 && chunkSeq < totalChunks,
            'chunkSeq must be in [0, totalChunks - 1]'),
        assert(totalChunks >= 1 && totalChunks <= maxChunksPerFrame,
            'totalChunks must be in [1, 256]');

  /// Encodes this chunk into wire format (6-byte header + data).
  Uint8List encode() {
    final bytes = Uint8List(6 + data.length);
    final bdata = ByteData.sublistView(bytes);
    bdata.setUint16(0, chunkSeq, Endian.big);
    bdata.setUint16(2, totalChunks, Endian.big);
    bdata.setUint16(4, crc16, Endian.big);
    bytes.setRange(6, bytes.length, data);
    return bytes;
  }

  /// Decodes and validates a chunk packet from [bytes].
  ///
  /// Throws [FormatException] if bytes is too short or if CRC-16 check fails.
  static ChunkPacket decode(Uint8List bytes) {
    if (bytes.length < 6) {
      throw FormatException(
          'Insufficient bytes for chunk header: ${bytes.length} < 6');
    }
    final bdata = ByteData.sublistView(bytes);
    final chunkSeq = bdata.getUint16(0, Endian.big);
    final totalChunks = bdata.getUint16(2, Endian.big);
    final expectedCrc = bdata.getUint16(4, Endian.big);

    if (totalChunks < 1 || totalChunks > maxChunksPerFrame) {
      throw FormatException(
          'Invalid totalChunks: $totalChunks (must be 1..$maxChunksPerFrame)');
    }
    if (chunkSeq >= totalChunks) {
      throw FormatException(
          'chunkSeq ($chunkSeq) >= totalChunks ($totalChunks)');
    }

    final data = Uint8List.sublistView(bytes, 6);
    final computedCrc = Crc16.compute(data);
    if (computedCrc != expectedCrc) {
      throw FormatException(
        'CRC-16 mismatch: expected 0x${expectedCrc.toRadixString(16)}, computed 0x${computedCrc.toRadixString(16)}',
      );
    }

    return ChunkPacket(
      chunkSeq: chunkSeq,
      totalChunks: totalChunks,
      crc16: expectedCrc,
      data: data,
    );
  }

  @override
  String toString() =>
      'ChunkPacket(seq: $chunkSeq/$totalChunks, len: ${data.length}, crc: 0x${crc16.toRadixString(16)})';

  @override
  bool operator ==(Object other) {
    if (identical(this, other)) return true;
    if (other is! ChunkPacket ||
        other.chunkSeq != chunkSeq ||
        other.totalChunks != totalChunks ||
        other.crc16 != crc16 ||
        other.data.length != data.length) {
      return false;
    }
    for (var i = 0; i < data.length; i++) {
      if (data[i] != other.data[i]) return false;
    }
    return true;
  }

  @override
  int get hashCode =>
      Object.hash(chunkSeq, totalChunks, crc16, Object.hashAll(data));
}

/// Slices frames into MTU-sized chunk packets.
class ChunkSlicer {
  ChunkSlicer._();

  /// Slices [rawFrameBytes] into chunks using the specified [mtu].
  ///
  /// The [mtu] represents the maximum packet size permitted by the transport
  /// (e.g. GATT MTU - 3 byte ATT header, or L2CAP MPS).
  /// Must be >= 7 bytes (6-byte chunk header + at least 1 byte payload).
  static List<ChunkPacket> slice(Uint8List rawFrameBytes, {required int mtu}) {
    if (mtu < 7) {
      throw ArgumentError.value(mtu, 'mtu', 'MTU must be at least 7 bytes');
    }

    final maxChunkPayload = mtu - 6;
    final totalBytes = rawFrameBytes.length;
    final totalChunks = totalBytes == 0
        ? 1
        : ((totalBytes + maxChunkPayload - 1) ~/ maxChunkPayload);

    if (totalChunks > maxChunksPerFrame) {
      throw ArgumentError(
        'Frame size (${rawFrameBytes.length} bytes) exceeds maximum allowable chunks ($maxChunksPerFrame) with MTU $mtu',
      );
    }

    final packets = <ChunkPacket>[];
    for (var i = 0; i < totalChunks; i++) {
      final start = i * maxChunkPayload;
      final end = (start + maxChunkPayload < totalBytes)
          ? (start + maxChunkPayload)
          : totalBytes;
      final sliceData = (totalBytes == 0)
          ? Uint8List(0)
          : Uint8List.sublistView(rawFrameBytes, start, end);
      final crc = Crc16.compute(sliceData);
      packets.add(ChunkPacket(
        chunkSeq: i,
        totalChunks: totalChunks,
        crc16: crc,
        data: sliceData,
      ));
    }

    return packets;
  }

  /// Convenience method to serialize [frame] and slice into MTU packets.
  static List<ChunkPacket> sliceFrame(Frame frame, {required int mtu}) =>
      slice(frame.encode(), mtu: mtu);
}

/// Collects chunk packets and reassembles complete protocol frames.
class ChunkReassembler {
  int? _expectedTotalChunks;
  final Map<int, Uint8List> _receivedChunks = {};

  /// Processes [chunk]. If this chunk completes a frame, reassembles and returns it.
  /// Otherwise returns `null`.
  Frame? addChunk(ChunkPacket chunk) {
    // If the chunk belongs to a new transmission with a different chunk count,
    // or if the previous reassembly had an unexpected total count, reset buffer.
    if (_expectedTotalChunks != null &&
        _expectedTotalChunks != chunk.totalChunks) {
      reset();
    }

    _expectedTotalChunks = chunk.totalChunks;
    _receivedChunks[chunk.chunkSeq] = chunk.data;

    if (_receivedChunks.length == _expectedTotalChunks) {
      final totalLen =
          _receivedChunks.values.fold<int>(0, (sum, data) => sum + data.length);
      final fullBytes = Uint8List(totalLen);
      var offset = 0;
      for (var i = 0; i < _expectedTotalChunks!; i++) {
        final chunkData = _receivedChunks[i]!;
        fullBytes.setRange(offset, offset + chunkData.length, chunkData);
        offset += chunkData.length;
      }

      reset();
      return Frame.decode(fullBytes);
    }

    return null;
  }

  /// Decodes raw [packetBytes] into a [ChunkPacket] and processes it.
  ///
  /// Corrupted packets (invalid CRC-16 or malformed header) are safely dropped
  /// returning `null`.
  Frame? addChunkBytes(Uint8List packetBytes) {
    try {
      final chunk = ChunkPacket.decode(packetBytes);
      return addChunk(chunk);
    } catch (_) {
      // Discard corrupted chunk packet immediately per specification.
      return null;
    }
  }

  /// Clears currently accumulated chunks.
  void reset() {
    _expectedTotalChunks = null;
    _receivedChunks.clear();
  }

  /// Returns the number of chunks accumulated for the current in-flight frame.
  int get accumulatedChunks => _receivedChunks.length;

  /// Returns the total expected chunks for the in-flight frame, or null if idle.
  int? get expectedTotalChunks => _expectedTotalChunks;
}
