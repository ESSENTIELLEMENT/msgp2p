import 'dart:io' show zlib;
import 'dart:typed_data';
import 'package:cbor/cbor.dart' as cbor;
import 'package:convert/convert.dart';
import 'package:meta/meta.dart';
import '../encoding/canonical_cbor.dart';

/// An inclusive range of message sequence numbers: [fromSeq, toSeq].
@immutable
class SeqRange {
  final int fromSeq;
  final int toSeq;

  const SeqRange(this.fromSeq, this.toSeq) : assert(fromSeq <= toSeq);

  bool contains(int seq) => seq >= fromSeq && seq <= toSeq;

  List<int> toList() => [fromSeq, toSeq];

  /// Consolidates overlapping, duplicate, or adjacent [SeqRange]s into canonical sorted disjoint ranges (`IT-DS-04`).
  static List<SeqRange> mergeRanges(List<SeqRange> ranges) {
    if (ranges.isEmpty) return const [];
    final sorted = List<SeqRange>.from(ranges)
      ..sort((a, b) {
        final cmp = a.fromSeq.compareTo(b.fromSeq);
        if (cmp != 0) return cmp;
        return a.toSeq.compareTo(b.toSeq);
      });

    final merged = <SeqRange>[sorted.first];
    for (var i = 1; i < sorted.length; i++) {
      final current = sorted[i];
      final last = merged.last;
      if (current.fromSeq <= last.toSeq + 1) {
        merged[merged.length - 1] = SeqRange(
          last.fromSeq,
          current.toSeq > last.toSeq ? current.toSeq : last.toSeq,
        );
      } else {
        merged.add(current);
      }
    }
    return merged;
  }

  @override
  String toString() => '[$fromSeq, $toSeq]';

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is SeqRange && fromSeq == other.fromSeq && toSeq == other.toSeq;

  @override
  int get hashCode => Object.hash(fromSeq, toSeq);
}

/// The held sequence state for a single author.
class AuthorState {
  int contiguous; // All sequences 1..contiguous are held
  final Set<int> gaps; // Sparse sequences held above contiguous

  AuthorState({
    this.contiguous = 0,
    Set<int>? gaps,
  }) : gaps = gaps ?? {};

  /// Checks if a sequence number is already held.
  bool has(int seq) {
    if (seq <= contiguous) return true;
    return gaps.contains(seq);
  }

  /// Records a new sequence number into the state, consolidating contiguous spans.
  void add(int seq) {
    if (seq <= contiguous) return;
    if (seq == contiguous + 1) {
      contiguous = seq;
      // Advance contiguous if adjacent gaps are now connected
      while (gaps.remove(contiguous + 1)) {
        contiguous++;
      }
    } else {
      gaps.add(seq);
    }
  }

  /// Calculates missing sequence ranges that this node lacks up to [remoteMaxSeq].
  List<SeqRange> findMissingRanges(int remoteContiguous, Set<int> remoteGaps) {
    final missing = <SeqRange>[];

    // Remote has all sequences 1..remoteContiguous
    if (remoteContiguous > contiguous) {
      var rangeStart = contiguous + 1;
      for (var s = contiguous + 1; s <= remoteContiguous; s++) {
        if (gaps.contains(s)) {
          // We have this gap item, so close the preceding missing range
          if (rangeStart < s) {
            missing.add(SeqRange(rangeStart, s - 1));
          }
          rangeStart = s + 1;
        }
      }
      if (rangeStart <= remoteContiguous) {
        missing.add(SeqRange(rangeStart, remoteContiguous));
      }
    }

    // Now check any remote sparse gaps that exceed remoteContiguous
    for (final rGap in remoteGaps) {
      if (!has(rGap)) {
        missing.add(SeqRange(rGap, rGap));
      }
    }

    // Consolidate adjacent ranges (e.g. [1, 2] and [3, 4] -> [1, 4])
    if (missing.isEmpty) return missing;
    missing.sort((a, b) => a.fromSeq.compareTo(b.fromSeq));

    final consolidated = <SeqRange>[missing.first];
    for (var i = 1; i < missing.length; i++) {
      final current = missing[i];
      final last = consolidated.last;
      if (current.fromSeq <= last.toSeq + 1) {
        consolidated[consolidated.length - 1] = SeqRange(
          last.fromSeq,
          current.toSeq > last.toSeq ? current.toSeq : last.toSeq,
        );
      } else {
        consolidated.add(current);
      }
    }
    return consolidated;
  }

  Map<String, dynamic> toMap() {
    final map = <String, dynamic>{'contiguous': contiguous};
    if (gaps.isNotEmpty) {
      final sortedGaps = gaps.toList()..sort();
      map['gaps'] = sortedGaps;
    }
    return map;
  }
}

/// Request for specific missing sequence ranges from an author.
@immutable
class AuthorWant {
  final String authorHex;
  final List<SeqRange> ranges;

  const AuthorWant({required this.authorHex, required this.ranges});

  Map<String, dynamic> toMap() => {
        'author': Uint8List.fromList(hex.decode(authorHex)),
        'ranges': ranges.map((r) => r.toList()).toList(),
      };
}

/// Version vector representing the state of all authors known to a node.
class VersionVector {
  final Map<String, AuthorState> _authors = {};

  VersionVector();

  Map<String, AuthorState> get authors => Map.unmodifiable(_authors);

  AuthorState getOrCreate(String authorHex) {
    return _authors.putIfAbsent(authorHex, () => AuthorState());
  }

  void add(String authorHex, int seq) {
    getOrCreate(authorHex).add(seq);
  }

  bool has(String authorHex, int seq) {
    final state = _authors[authorHex];
    if (state == null) return false;
    return state.has(seq);
  }

  /// Calculates missing sequence ranges that *this* vector lacks but [remote] possesses.
  /// (What *we* WANT from *remote*).
  List<AuthorWant> calculateWant(VersionVector remote) {
    final wants = <AuthorWant>[];

    for (final entry in remote.authors.entries) {
      final authorHex = entry.key;
      final remoteState = entry.value;
      final localState = _authors[authorHex] ?? AuthorState();

      final missing = localState.findMissingRanges(
        remoteState.contiguous,
        remoteState.gaps,
      );

      if (missing.isNotEmpty) {
        wants.add(AuthorWant(authorHex: authorHex, ranges: missing));
      }
    }

    return wants;
  }

  Map<String, dynamic> toMap() {
    final map = <String, dynamic>{};
    for (final entry in _authors.entries) {
      map[entry.key] = entry.value.toMap();
    }
    return map;
  }

  Uint8List toCanonicalCbor() => CanonicalCbor.encode(toMap());

  /// Deflate-compressed canonical CBOR representation (`architecture.md §3.1, §3.4`, `IT-DS-03`).
  Uint8List toDeflatedCbor() =>
      Uint8List.fromList(zlib.encode(toCanonicalCbor()));

  factory VersionVector.fromDeflatedCbor(Uint8List deflatedBytes) {
    return VersionVector.fromCbor(
        Uint8List.fromList(zlib.decode(deflatedBytes)));
  }

  factory VersionVector.fromMap(Map map) {
    final vec = VersionVector();
    for (final entry in map.entries) {
      final authorKey = entry.key;
      final authorHex =
          authorKey is List<int> ? hex.encode(authorKey) : authorKey.toString();
      final stateMap = entry.value as Map;
      final contiguous = stateMap['contiguous'] as int? ?? 0;
      final rawGaps = stateMap['gaps'] as List? ?? [];
      final gaps = rawGaps.cast<int>().toSet();
      vec._authors[authorHex] = AuthorState(contiguous: contiguous, gaps: gaps);
    }
    return vec;
  }

  factory VersionVector.fromCbor(Uint8List bytes) {
    final decoded = cbor.cbor.decode(bytes).toObject() as Map;
    return VersionVector.fromMap(decoded);
  }
}
