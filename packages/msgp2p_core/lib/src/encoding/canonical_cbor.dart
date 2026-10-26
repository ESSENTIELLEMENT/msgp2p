import 'package:cbor/cbor.dart' as cbor;
import 'dart:convert';
import 'dart:typed_data';

/// Deterministic Canonical CBOR encoder implementing RFC 8949 Section 4.2.
class CanonicalCbor {
  CanonicalCbor._();

  /// Decodes CBOR bytes into Dart objects.
  static dynamic decode(Uint8List bytes) => cbor.cbor.decode(bytes).toObject();

  /// Encodes any supported Dart object into canonical deterministic CBOR bytes.
  static Uint8List encode(dynamic value) {
    final builder = BytesBuilder(copy: false);
    _encodeValue(value, builder);
    return builder.toBytes();
  }

  static void _encodeValue(dynamic value, BytesBuilder builder) {
    if (value is int) {
      if (value < 0) {
        throw ArgumentError(
            'Negative integers are not used in msgp2p core ($value)');
      }
      _encodeUint(value, 0, builder);
    } else if (value is String) {
      final utf8Bytes = utf8.encode(value);
      _encodeUint(utf8Bytes.length, 3, builder);
      builder.add(utf8Bytes);
    } else if (value is Uint8List) {
      _encodeUint(value.length, 2, builder);
      builder.add(value);
    } else if (value is List<int> && value is! Uint8List) {
      // Treat as byte array if explicitly byte typed or check if array
      // In Dart, lists of dynamic or int should be handled based on context
      _encodeList(value, builder);
    } else if (value is List) {
      _encodeList(value, builder);
    } else if (value is Map) {
      _encodeMap(value, builder);
    } else if (value is bool) {
      builder.addByte(value ? 0xf5 : 0xf4);
    } else if (value == null) {
      builder.addByte(0xf6);
    } else if (value is double) {
      // 64-bit IEEE 754 float
      final bdata = ByteData(9);
      bdata.setUint8(0, 0xfb);
      bdata.setFloat64(1, value, Endian.big);
      builder.add(bdata.buffer.asUint8List());
    } else {
      throw ArgumentError('Unsupported CBOR type: ${value.runtimeType}');
    }
  }

  static void _encodeList(List value, BytesBuilder builder) {
    _encodeUint(value.length, 4, builder);
    for (final item in value) {
      _encodeValue(item, builder);
    }
  }

  static void _encodeMap(Map value, BytesBuilder builder) {
    // Canonical CBOR requires sorting keys by the byte representation of their encoded form!
    // RFC 8949 §4.2.1:
    // 1. Shorter byte string precedes longer byte string
    // 2. If equal length, lexicographical byte comparison
    final entries = <_CborMapEntry>[];
    for (final entry in value.entries) {
      final keyBytes = encode(entry.key);
      final valueBytes = encode(entry.value);
      entries.add(_CborMapEntry(keyBytes, valueBytes));
    }

    entries.sort((a, b) {
      if (a.keyBytes.length != b.keyBytes.length) {
        return a.keyBytes.length.compareTo(b.keyBytes.length);
      }
      for (var i = 0; i < a.keyBytes.length; i++) {
        final cmp = a.keyBytes[i].compareTo(b.keyBytes[i]);
        if (cmp != 0) return cmp;
      }
      return 0;
    });

    _encodeUint(entries.length, 5, builder);
    for (final e in entries) {
      builder.add(e.keyBytes);
      builder.add(e.valueBytes);
    }
  }

  static void _encodeUint(int val, int major, BytesBuilder builder) {
    final prefix = major << 5;
    if (val <= 23) {
      builder.addByte(prefix | val);
    } else if (val <= 0xff) {
      builder.addByte(prefix | 24);
      builder.addByte(val);
    } else if (val <= 0xffff) {
      builder.addByte(prefix | 25);
      final bdata = ByteData(2)..setUint16(0, val, Endian.big);
      builder.add(bdata.buffer.asUint8List());
    } else if (val <= 0xffffffff) {
      builder.addByte(prefix | 26);
      final bdata = ByteData(4)..setUint32(0, val, Endian.big);
      builder.add(bdata.buffer.asUint8List());
    } else {
      builder.addByte(prefix | 27);
      final bdata = ByteData(8)..setUint64(0, val, Endian.big);
      builder.add(bdata.buffer.asUint8List());
    }
  }
}

class _CborMapEntry {
  final Uint8List keyBytes;
  final Uint8List valueBytes;
  _CborMapEntry(this.keyBytes, this.valueBytes);
}
