import 'dart:convert';
import 'dart:typed_data';
import 'package:msgp2p_core/src/framing/crc16.dart';
import 'package:msgp2p_core/src/framing/frame.dart';
import 'package:msgp2p_core/src/framing/chunking.dart';
import 'package:test/test.dart';

void main() {
  group('CRC-16/IBM Checksum', () {
    test('Standard ASCII "123456789" vector matches 0xBB3D', () {
      final asciiBytes = Uint8List.fromList(utf8.encode('123456789'));
      final crc = Crc16.compute(asciiBytes);
      expect(crc, equals(0xBB3D));
    });

    test('Empty bytes yields 0x0000', () {
      final crc = Crc16.compute(Uint8List(0));
      expect(crc, equals(0x0000));
    });

    test('Single-byte change alters CRC', () {
      final data1 = Uint8List.fromList([1, 2, 3, 4, 5]);
      final data2 = Uint8List.fromList([1, 2, 3, 4, 6]);
      expect(Crc16.compute(data1), isNot(equals(Crc16.compute(data2))));
    });
  });

  group('Frame Serialization & Parsing', () {
    test('Encodes and decodes Frame correctly', () {
      final payload = Uint8List.fromList([10, 20, 30, 40, 50]);
      final frame = Frame(type: Frame.typeSummary, payload: payload);
      expect(frame.wireLength, equals(3 + 5));

      final encoded = frame.encode();
      expect(encoded.length, equals(8));
      expect(encoded[0], equals(Frame.typeSummary));
      expect(encoded[1], equals(0)); // Length high byte
      expect(encoded[2], equals(5)); // Length low byte

      final decoded = Frame.decode(encoded);
      expect(decoded.type, equals(Frame.typeSummary));
      expect(decoded.payload, equals(payload));
      expect(decoded, equals(frame));
    });

    test('FrameParser handles byte stream fragmentation', () {
      final frame1 = Frame(
        type: Frame.typeData,
        payload: Uint8List.fromList([1, 2, 3, 4]),
      );
      final frame2 = Frame(
        type: Frame.typeReceipts,
        payload: Uint8List.fromList([5, 6]),
      );

      final streamBytes = BytesBuilder(copy: false);
      streamBytes.add(frame1.encode());
      streamBytes.add(frame2.encode());
      final allBytes = streamBytes.toBytes();

      final parser = FrameParser();
      // Feed bytes 1 by 1 to test extreme fragmentation
      final collected = <Frame>[];
      for (var i = 0; i < allBytes.length; i++) {
        final chunk = Uint8List.fromList([allBytes[i]]);
        final parsed = parser.addBytes(chunk);
        collected.addAll(parsed);
      }

      expect(collected.length, equals(2));
      expect(collected[0], equals(frame1));
      expect(collected[1], equals(frame2));
      expect(parser.hasRemaining, isFalse);
    });
  });

  group('MTU Chunking & Reassembly', () {
    test('Single chunk frame fits in MTU', () {
      final payload = Uint8List.fromList([0xDE, 0xAD, 0xBE, 0xEF]);
      final frame = Frame(type: Frame.typeBye, payload: payload);

      // Frame length is 7 bytes (3 + 4). MTU 20 allows 20 - 6 = 14 bytes payload.
      final chunks = ChunkSlicer.sliceFrame(frame, mtu: 20);
      expect(chunks.length, equals(1));
      expect(chunks[0].chunkSeq, equals(0));
      expect(chunks[0].totalChunks, equals(1));
      expect(chunks[0].data, equals(frame.encode()));

      final reassembler = ChunkReassembler();
      final result = reassembler.addChunk(chunks[0]);
      expect(result, isNotNull);
      expect(result, equals(frame));
    });

    test('Multi-chunk frame slices and reassembles correctly', () {
      final payload = Uint8List(50);
      for (var i = 0; i < 50; i++) {
        payload[i] = i;
      }
      final frame = Frame(type: Frame.typeWant, payload: payload);

      // MTU = 16 bytes -> 16 - 6 = 10 bytes payload per chunk -> 6 chunks (10*5 + 3)
      final chunks = ChunkSlicer.sliceFrame(frame, mtu: 16);
      expect(chunks.length, equals(6));

      // Test wire encoding/decoding of each chunk packet
      final encodedPackets = chunks.map((c) => c.encode()).toList();

      final reassembler = ChunkReassembler();
      Frame? result;
      for (var i = 0; i < encodedPackets.length; i++) {
        result = reassembler.addChunkBytes(encodedPackets[i]);
        if (i < encodedPackets.length - 1) {
          expect(result, isNull);
          expect(reassembler.accumulatedChunks, equals(i + 1));
        }
      }

      expect(result, isNotNull);
      expect(result, equals(frame));
      expect(reassembler.accumulatedChunks, equals(0));
    });

    test('Reassembler handles out-of-order chunk arrivals', () {
      final payload = Uint8List.fromList(List.generate(30, (i) => i * 2));
      final frame = Frame(type: Frame.typeSummary, payload: payload);

      final chunks =
          ChunkSlicer.sliceFrame(frame, mtu: 15); // 9 bytes payload per chunk
      expect(chunks.length, equals(4));

      final reassembler = ChunkReassembler();
      // Feed chunks in order: 2, 0, 3, 1
      expect(reassembler.addChunk(chunks[2]), isNull);
      expect(reassembler.addChunk(chunks[0]), isNull);
      expect(reassembler.addChunk(chunks[3]), isNull);
      final completeFrame = reassembler.addChunk(chunks[1]);

      expect(completeFrame, isNotNull);
      expect(completeFrame, equals(frame));
    });

    test('Corrupted chunks are dropped by reassembler', () {
      final frame =
          Frame(type: Frame.typeBye, payload: Uint8List.fromList([1, 2, 3]));
      final chunks = ChunkSlicer.sliceFrame(frame, mtu: 20);
      final rawPacket = chunks[0].encode();

      // Corrupt 1 byte in payload
      rawPacket[rawPacket.length - 1] ^= 0xFF;

      final reassembler = ChunkReassembler();
      final result = reassembler.addChunkBytes(rawPacket);
      expect(result, isNull);
      expect(reassembler.accumulatedChunks, equals(0));
    });
  });
}
