import 'dart:typed_data';

/// CRC-16/IBM (also known as CRC-16/ARC or CRC-16/ANSI).
/// Polynomial: 0x8005 (reversed/reflected: 0xA001), Init: 0x0000, XorOut: 0x0000.
/// Check value for ASCII "123456789": 0xBB3D.
class Crc16 {
  Crc16._();

  static final List<int> _table = _generateTable();

  static List<int> _generateTable() {
    final table = List<int>.filled(256, 0);
    for (var i = 0; i < 256; i++) {
      var value = i;
      for (var j = 0; j < 8; j++) {
        if ((value & 1) != 0) {
          value = (value >> 1) ^ 0xA001;
        } else {
          value = value >> 1;
        }
      }
      table[i] = value & 0xffff;
    }
    return table;
  }

  /// Computes the 16-bit CRC-16/IBM checksum for [data].
  static int compute(Uint8List data) {
    var crc = 0x0000;
    for (var i = 0; i < data.length; i++) {
      final index = (crc ^ data[i]) & 0xff;
      crc = ((crc >> 8) & 0xff) ^ _table[index];
    }
    return crc & 0xffff;
  }
}
