import 'dart:typed_data';
import 'package:meta/meta.dart';

/// Discrete protocol frame as specified in protocol/wire-format.md ?6.1.
///
/// Prefix Header (3 bytes):
/// - 1 byte Frame Type
/// - 2 bytes Length (Big-Endian)
/// Followed by Payload (0 to 65,535 bytes).
@immutable
class Frame {
  // Handshake Frame Types
  static const int typeNoiseMsg1 = 0x01;
  static const int typeNoiseMsg2 = 0x02;
  static const int typeNoiseMsg3 = 0x03;

  // Session Control Frame Types
  static const int typeSummary = 0x10;
  static const int typeWant = 0x11;
  static const int typeData = 0x12;
  static const int typeReceipts = 0x13;
  static const int typeRevocations = 0x14;
  static const int typeCertReq = 0x15;
  static const int typeCertResp = 0x16;
  static const int typeBlobWant = 0x17;
  static const int typeBlobData = 0x18;
  static const int typeUpgradeOffer = 0x19;
  static const int typeUpgradeAccept = 0x1A;
  static const int typeBye = 0x1F;

  final int type;
  final Uint8List payload;

  const Frame({
    required this.type,
    required this.payload,
  })  : assert(type >= 0 && type <= 0xFF, 'Frame type must fit in 1 byte'),
        assert(payload.length <= 0xFFFF, 'Payload length must fit in uint16');

  /// Total wire size including 3-byte header.
  int get wireLength => 3 + payload.length;

  /// Serializes the frame into 3-byte header + payload.
  Uint8List encode() {
    if (payload.length > 0xFFFF) {
      throw FormatException(
          'Frame payload exceeds 65535-byte uint16 limit: ${payload.length}');
    }
    final bytes = Uint8List(wireLength);
    final bdata = ByteData.sublistView(bytes);
    bdata.setUint8(0, type);
    bdata.setUint16(1, payload.length, Endian.big);
    bytes.setRange(3, wireLength, payload);
    return bytes;
  }

  /// Decodes a single frame from [bytes] starting at [offset].
  /// Throws [FormatException] if bytes is too short for header or payload.
  static Frame decode(Uint8List bytes, [int offset = 0]) {
    final available = bytes.length - offset;
    if (available < 3) {
      throw FormatException(
          'Insufficient bytes for frame header: $available < 3');
    }
    final bdata = ByteData.sublistView(bytes, offset);
    final type = bdata.getUint8(0);
    final length = bdata.getUint16(1, Endian.big);
    if (available < 3 + length) {
      throw FormatException(
          'Insufficient bytes for frame payload: $available < ${3 + length}');
    }
    final payload =
        Uint8List.sublistView(bytes, offset + 3, offset + 3 + length);
    return Frame(type: type, payload: payload);
  }

  @override
  String toString() =>
      'Frame(type: 0x${type.toRadixString(16).padLeft(2, '0')}, len: ${payload.length})';

  @override
  bool operator ==(Object other) {
    if (identical(this, other)) return true;
    if (other is! Frame ||
        other.type != type ||
        other.payload.length != payload.length) {
      return false;
    }
    for (var i = 0; i < payload.length; i++) {
      if (payload[i] != other.payload[i]) return false;
    }
    return true;
  }

  @override
  int get hashCode => Object.hash(type, Object.hashAll(payload));
}

/// Accumulates streaming byte chunks and extracts complete [Frame]s.
class FrameParser {
  final BytesBuilder _buffer = BytesBuilder(copy: false);

  /// Appends [bytes] to the internal buffer and yields any fully-received [Frame]s.
  List<Frame> addBytes(Uint8List bytes) {
    _buffer.add(bytes);
    final frames = <Frame>[];
    var currentBytes = _buffer.toBytes();
    var offset = 0;

    while (currentBytes.length - offset >= 3) {
      final bdata = ByteData.sublistView(currentBytes, offset);
      final payloadLen = bdata.getUint16(1, Endian.big);
      final frameLen = 3 + payloadLen;

      if (currentBytes.length - offset >= frameLen) {
        final type = bdata.getUint8(0);
        final payload = Uint8List.fromList(
          currentBytes.sublist(offset + 3, offset + frameLen),
        );
        frames.add(Frame(type: type, payload: payload));
        offset += frameLen;
      } else {
        break;
      }
    }

    _buffer.clear();
    if (offset < currentBytes.length) {
      _buffer.add(currentBytes.sublist(offset));
    }

    return frames;
  }

  /// Clears any incomplete buffered bytes.
  void reset() {
    _buffer.clear();
  }

  /// Returns true if unparsed bytes remain in the buffer.
  bool get hasRemaining => _buffer.isNotEmpty;
}
