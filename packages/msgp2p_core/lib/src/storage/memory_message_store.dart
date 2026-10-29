import 'dart:typed_data';
import 'package:convert/convert.dart';
import '../crypto/crypto.dart';
import '../model/certificate.dart';
import '../model/envelope.dart';
import '../model/receipt.dart';
import '../model/revocation.dart';
import '../model/version_vector.dart';
import 'message_store.dart';

/// In-memory implementation of [MessageStore] designed for fast unit testing,
/// simulator runs, and memory-only mesh relay configurations.
class MemoryMessageStore implements MessageStore {
  @override
  final int maxStorageBytes;

  @override
  final int maxEvictionRefetches;

  /// Hard row cap for Tier 1 (`peer_sightings`, default 2,000 per `IT-DS-05a`).
  final int maxSightingsRows;

  /// Hard row cap for Tier 2 (`peer_daily_stats`, default 10,000 per `IT-DS-05b`).
  final int maxDailyStatsRows;

  int _storageBytes = 0;

  @override
  int get currentStorageBytes => _storageBytes;

  // Envelopes indexed by hex(messageId)
  final Map<String, StoredEnvelope> _envelopesById = {};

  // Envelopes indexed by hex(author) -> {seq -> StoredEnvelope}
  final Map<String, Map<int, StoredEnvelope>> _envelopesByAuthorSeq = {};

  // Eviction tracking for FR-SYNC-05 / IT-DS-01 (bounded re-fetch E_max)
  final Set<String> _evictedAuthorSeqs = {};
  final Map<String, int> _evictionRefetchesById = {};
  final Map<String, int> _evictionRefetchesByAuthorSeq = {};

  // Server receipts & canonical merged ranges per author
  final List<ServerReceipt> _receipts = [];
  final Map<String, List<SeqRange>> _confirmedRangesByAuthor = {};

  // Certificates indexed by hex(certRef)
  final Map<String, MembershipCert> _certsByRef = {};

  // Revocations indexed by hex(memberPubkey)
  final Map<String, RevocationNotice> _revocationsByMember = {};

  // Attachment blobs indexed by hex(hash)
  final Map<String, StoredAttachmentBlob> _attachmentsByHash = {};

  // Tier 1: Peer sightings indexed by "$tokenHex:$rotationWindow"
  final Map<String, PeerSighting> _sightingsByKey = {};

  // Tier 2: Peer daily stats indexed by "$memberPubkeyHex:$dayDate"
  final Map<String, PeerDailyStat> _dailyStatsByKey = {};

  // Highest observed timestamp for backward clock-jump protection (IT-DS-05d)
  int _maxObservedTimeMs = 0;

  // The identity this store belongs to and the highest sequence it authored (Discussion #10).
  Uint8List? _ownerPubkey;
  int _authorSeq = 0;

  MemoryMessageStore({
    this.maxStorageBytes = 100 * 1024 * 1024, // 100 MB default per FR-SYNC-05
    this.maxEvictionRefetches = 2, // E_max = 2 default per IT-DS-01
    this.maxSightingsRows = 2000,
    this.maxDailyStatsRows = 10000,
  });

  @override
  int getEvictionRefetchCount(Uint8List messageId) {
    return _evictionRefetchesById[hex.encode(messageId)] ?? 0;
  }

  /// Returns true if the last recepción of [messageId] was a re-fetch after prior eviction.
  bool wasRefetchedAfterEviction(Uint8List messageId) {
    return getEvictionRefetchCount(messageId) > 0;
  }

  @override
  Future<Uint8List?> getOwnerPubkey() async =>
      _ownerPubkey == null ? null : Uint8List.fromList(_ownerPubkey!);

  @override
  Future<void> setOwner(Uint8List ownerPubkey) async {
    final previous = _ownerPubkey;
    if (previous == null || !_bytesEqual(previous, ownerPubkey)) _authorSeq = 0;
    _ownerPubkey = Uint8List.fromList(ownerPubkey);
  }

  @override
  Future<int> getAuthorSeq() async => _authorSeq;

  @override
  Future<bool> saveOwnEnvelope(Envelope envelope, {int? customStoredAt}) async {
    final owner = _ownerPubkey;
    if (owner == null || !_bytesEqual(owner, envelope.core.author)) {
      throw StateError(
          'saveOwnEnvelope: the envelope author is not the store owner');
    }
    final bySeq = _envelopesByAuthorSeq[hex.encode(envelope.core.author)];
    if (bySeq != null && bySeq.containsKey(envelope.core.seq)) return false;
    final saved = await saveEnvelope(envelope, customStoredAt: customStoredAt);
    if (saved && envelope.core.seq > _authorSeq) _authorSeq = envelope.core.seq;
    return saved;
  }

  @override
  Future<bool> saveEnvelope(Envelope envelope, {int? customStoredAt}) async {
    final idHex = hex.encode(envelope.messageId);
    if (_envelopesById.containsKey(idHex)) {
      return false; // Deduplication
    }

    final authorHex = hex.encode(envelope.core.author);
    final authorSeqKey = '$authorHex:${envelope.core.seq}';

    // Check E_max eviction re-fetch bound (FR-SYNC-05, IT-DS-01)
    if (_evictedAuthorSeqs.contains(authorSeqKey)) {
      final prevRefetches = _evictionRefetchesByAuthorSeq[authorSeqKey] ?? 0;
      if (prevRefetches >= maxEvictionRefetches) {
        return false; // Suppressed: already re-fetched E_max times
      }
      final nextCount = prevRefetches + 1;
      _evictionRefetchesByAuthorSeq[authorSeqKey] = nextCount;
      _evictionRefetchesById[idHex] = nextCount;
    }

    final confirmed = _isAuthorSeqConfirmed(authorHex, envelope.core.seq);
    final byteSize = envelope.toCanonicalCbor().length;

    final stored = StoredEnvelope(
      envelope: envelope,
      storedAt: customStoredAt ?? DateTime.now().millisecondsSinceEpoch,
      byteSize: byteSize,
      isConfirmed: confirmed,
    );

    _envelopesById[idHex] = stored;
    _envelopesByAuthorSeq.putIfAbsent(authorHex, () => {})[envelope.core.seq] =
        stored;
    _storageBytes += byteSize;

    return true;
  }

  @override
  Future<int> saveBatch(List<Envelope> envelopes, {int? customStoredAt}) async {
    var savedCount = 0;
    for (final env in envelopes) {
      if (await saveEnvelope(env, customStoredAt: customStoredAt)) {
        savedCount++;
      }
    }
    return savedCount;
  }

  @override
  Future<Envelope?> getEnvelope(Uint8List messageId) async {
    final idHex = hex.encode(messageId);
    return _envelopesById[idHex]?.envelope;
  }

  @override
  Future<bool> containsEnvelope(Uint8List messageId) async {
    final idHex = hex.encode(messageId);
    return _envelopesById.containsKey(idHex);
  }

  @override
  Future<bool> isSequenceHeld(Uint8List author, int seq) async {
    final authorHex = hex.encode(author);
    return _envelopesByAuthorSeq[authorHex]?.containsKey(seq) ?? false;
  }

  @override
  Future<List<Envelope>> getEnvelopesByAuthorAndRanges(
    Uint8List author,
    List<SeqRange> ranges, {
    int? currentTimeMillis,
  }) async {
    final authorHex = hex.encode(author);
    final authorMap = _envelopesByAuthorSeq[authorHex];
    if (authorMap == null || authorMap.isEmpty) {
      return const [];
    }

    final results = <Envelope>[];
    for (final range in ranges) {
      for (var seq = range.fromSeq; seq <= range.toSeq; seq++) {
        final stored = authorMap[seq];
        if (stored != null) {
          if (currentTimeMillis != null &&
              stored.envelope.core.expiresAt <= currentTimeMillis) {
            continue; // IT-DS-02: never send expired envelopes in DATA
          }
          results.add(stored.envelope);
        }
      }
    }

    return results;
  }

  @override
  Future<VersionVector> getVersionVector({int? currentTimeMillis}) async {
    final vv = VersionVector();
    for (final entry in _envelopesByAuthorSeq.entries) {
      final authorHex = entry.key;
      final state = vv.getOrCreate(authorHex);
      final sortedSeqs = entry.value.keys.toList()..sort();
      for (final seq in sortedSeqs) {
        final stored = entry.value[seq]!;
        if (currentTimeMillis != null &&
            stored.envelope.core.expiresAt <= currentTimeMillis) {
          continue; // IT-DS-02: exclude expired envelopes from advertised vector
        }
        state.add(seq);
      }
    }

    // IT-DS-01: For evicted sequences that have exhausted their E_max re-fetch budget,
    // include them in the advertised vector so we stop requesting them in WANT.
    for (final entry in _evictionRefetchesByAuthorSeq.entries) {
      if (entry.value >= maxEvictionRefetches) {
        final parts = entry.key.split(':');
        if (parts.length == 2) {
          final authorHex = parts[0];
          final seq = int.tryParse(parts[1]);
          if (seq != null) {
            vv.getOrCreate(authorHex).add(seq);
          }
        }
      }
    }

    return vv;
  }

  @override
  Future<int> getEnvelopeCount() async => _envelopesById.length;

  @override
  Future<void> saveReceipt(ServerReceipt receipt) async {
    final authorHex = hex.encode(receipt.author);
    final currentRanges =
        _confirmedRangesByAuthor[authorHex] ?? const <SeqRange>[];
    final combined = <SeqRange>[...currentRanges, ...receipt.ranges];
    final merged = SeqRange.mergeRanges(combined);

    // IT-DS-04: If applying this receipt does not change the canonical merged ranges
    // and we already have an identical or newer receipt for this author, treat as no-op.
    final rangesUnchanged = _rangeListsEqual(currentRanges, merged);
    final rawDuplicate = _receipts.any(
      (r) => _bytesEqual(r.toFullCbor(), receipt.toFullCbor()),
    );
    if (!rawDuplicate && !rangesUnchanged) {
      _receipts.add(receipt);
    } else if (_receipts.isEmpty) {
      _receipts.add(receipt);
    }
    _confirmedRangesByAuthor[authorHex] = merged;

    // Update isConfirmed flag on existing stored envelopes
    final authorMap = _envelopesByAuthorSeq[authorHex];
    if (authorMap != null) {
      for (final entry in authorMap.entries) {
        final seq = entry.key;
        if (!entry.value.isConfirmed) {
          for (final range in merged) {
            if (range.contains(seq)) {
              authorMap[seq] = entry.value.copyWith(isConfirmed: true);
              _envelopesById[hex.encode(entry.value.envelope.messageId)] =
                  authorMap[seq]!;
              break;
            }
          }
        }
      }
    }
  }

  static bool _rangeListsEqual(List<SeqRange> a, List<SeqRange> b) {
    if (a.length != b.length) return false;
    for (var i = 0; i < a.length; i++) {
      if (a[i] != b[i]) return false;
    }
    return true;
  }

  static bool _bytesEqual(Uint8List a, Uint8List b) {
    if (a.length != b.length) return false;
    for (var i = 0; i < a.length; i++) {
      if (a[i] != b[i]) return false;
    }
    return true;
  }

  @override
  Future<List<SeqRange>> getConfirmedRanges(Uint8List author) async {
    final authorHex = hex.encode(author);
    return List.unmodifiable(
        _confirmedRangesByAuthor[authorHex] ?? const <SeqRange>[]);
  }

  @override
  Future<bool> isConfirmed(Uint8List author, int seq) async {
    final authorHex = hex.encode(author);
    return _isAuthorSeqConfirmed(authorHex, seq);
  }

  bool _isAuthorSeqConfirmed(String authorHex, int seq) {
    final ranges = _confirmedRangesByAuthor[authorHex];
    if (ranges == null) return false;
    for (final range in ranges) {
      if (range.contains(seq)) return true;
    }
    return false;
  }

  @override
  Future<List<ServerReceipt>> getReceipts({int? sinceTimestamp}) async {
    if (sinceTimestamp == null) {
      return List.unmodifiable(_receipts);
    }
    return _receipts.where((r) => r.issuedAt >= sinceTimestamp).toList();
  }

  @override
  Future<void> saveCertificate(MembershipCert cert) async {
    final refHex = hex.encode(cert.certRef);
    _certsByRef[refHex] = cert;
  }

  @override
  Future<MembershipCert?> getCertificate(Uint8List certRef) async {
    final refHex = hex.encode(certRef);
    return _certsByRef[refHex];
  }

  @override
  Future<void> saveRevocation(RevocationNotice revocation) async {
    final memberHex = hex.encode(revocation.memberPubkey);
    _revocationsByMember[memberHex] = revocation;
  }

  @override
  Future<bool> isRevoked(Uint8List memberPubkey) async {
    final memberHex = hex.encode(memberPubkey);
    return _revocationsByMember.containsKey(memberHex);
  }

  @override
  Future<List<RevocationNotice>> getRevocations() async {
    return List.unmodifiable(_revocationsByMember.values);
  }

  @override
  Future<bool> saveAttachmentBlob({
    required Uint8List hash,
    required String mime,
    required Uint8List bytes,
    int? customStoredAt,
  }) async {
    final actualHash = MsgP2PCrypto.sha256(bytes);
    if (actualHash.length != hash.length) {
      throw ArgumentError('Attachment hash length mismatch');
    }
    var diff = 0;
    for (var i = 0; i < hash.length; i++) {
      diff |= actualHash[i] ^ hash[i];
    }
    if (diff != 0) {
      throw ArgumentError(
          'Attachment SHA-256 digest does not match expected hash');
    }

    final hashHex = hex.encode(hash);
    if (_attachmentsByHash.containsKey(hashHex)) {
      return false;
    }

    final stored = StoredAttachmentBlob(
      hash: Uint8List.fromList(hash),
      mime: mime,
      bytes: Uint8List.fromList(bytes),
      storedAt: customStoredAt ?? DateTime.now().millisecondsSinceEpoch,
    );
    _attachmentsByHash[hashHex] = stored;
    _storageBytes += bytes.length;
    return true;
  }

  @override
  Future<StoredAttachmentBlob?> getAttachmentBlob(Uint8List hash) async {
    return _attachmentsByHash[hex.encode(hash)];
  }

  @override
  Future<bool> containsAttachmentBlob(Uint8List hash) async {
    return _attachmentsByHash.containsKey(hex.encode(hash));
  }

  @override
  Future<List<AttachmentRef>> getMissingAttachments() async {
    final missingByHex = <String, AttachmentRef>{};
    for (final stored in _envelopesById.values) {
      final attachments = stored.envelope.core.attachments;
      if (attachments == null) continue;
      for (final ref in attachments) {
        final hHex = hex.encode(ref.hash);
        if (!_attachmentsByHash.containsKey(hHex)) {
          missingByHex[hHex] = ref;
        }
      }
    }
    return missingByHex.values.toList();
  }

  @override
  Future<void> recordPeerSighting({
    required Uint8List token,
    required int seenAt,
    required String transport,
    required int rssi,
    int rotationWindowMs = 900000,
  }) async {
    // IT-DS-05d: Clamp timestamp if clock jumped backward relative to existing window,
    // and never create future-dated rows beyond seenAt.
    if (seenAt > _maxObservedTimeMs) {
      _maxObservedTimeMs = seenAt;
    }
    final rotationWindow = seenAt ~/ rotationWindowMs;
    final key = '${hex.encode(token)}:$rotationWindow';
    final existing = _sightingsByKey[key];
    final effectiveSeenAt = (existing != null && existing.seenAt > seenAt)
        ? existing.seenAt
        : seenAt;

    _sightingsByKey[key] = PeerSighting(
      token: Uint8List.fromList(token),
      rotationWindow: rotationWindow,
      seenAt: effectiveSeenAt,
      transport: transport,
      rssi: rssi,
    );

    if (_sightingsByKey.length > maxSightingsRows) {
      final sortedKeys = _sightingsByKey.entries.toList()
        ..sort((a, b) => a.value.seenAt.compareTo(b.value.seenAt));
      final excess = _sightingsByKey.length - maxSightingsRows;
      for (var i = 0; i < excess; i++) {
        _sightingsByKey.remove(sortedKeys[i].key);
      }
    }
  }

  @override
  Future<List<PeerSighting>> getRecentPeerSightings({
    required int currentTimeMillis,
    Duration maxAge = const Duration(hours: 24),
  }) async {
    final cutoff = currentTimeMillis - maxAge.inMilliseconds;
    final results = _sightingsByKey.values
        .where((s) => s.seenAt > cutoff && s.seenAt <= currentTimeMillis)
        .toList()
      ..sort((a, b) => b.seenAt.compareTo(a.seenAt));
    return results;
  }

  @override
  Future<void> recordPeerDailyStat({
    required Uint8List memberPubkey,
    required int timestampMs,
    int sessionsDelta = 0,
    int failedConnectsDelta = 0,
    int flapDelta = 0,
    int bytesSentDelta = 0,
    int bytesRecvDelta = 0,
  }) async {
    if (timestampMs > _maxObservedTimeMs) {
      _maxObservedTimeMs = timestampMs;
    }
    const dayMs = 86400000;
    final dayDate = (timestampMs ~/ dayMs) * dayMs;
    final key = '${hex.encode(memberPubkey)}:$dayDate';
    final existing = _dailyStatsByKey[key];

    if (existing == null) {
      _dailyStatsByKey[key] = PeerDailyStat(
        memberPubkey: Uint8List.fromList(memberPubkey),
        dayDate: dayDate,
        sessionsCount: sessionsDelta,
        failedConnects: failedConnectsDelta,
        flapCount: flapDelta,
        bytesSent: bytesSentDelta,
        bytesRecv: bytesRecvDelta,
      );
    } else {
      _dailyStatsByKey[key] = PeerDailyStat(
        memberPubkey: existing.memberPubkey,
        dayDate: dayDate,
        sessionsCount: existing.sessionsCount + sessionsDelta,
        failedConnects: existing.failedConnects + failedConnectsDelta,
        flapCount: existing.flapCount + flapDelta,
        bytesSent: existing.bytesSent + bytesSentDelta,
        bytesRecv: existing.bytesRecv + bytesRecvDelta,
      );
    }

    if (_dailyStatsByKey.length > maxDailyStatsRows) {
      final sortedKeys = _dailyStatsByKey.entries.toList()
        ..sort((a, b) => a.value.dayDate.compareTo(b.value.dayDate));
      final excess = _dailyStatsByKey.length - maxDailyStatsRows;
      for (var i = 0; i < excess; i++) {
        _dailyStatsByKey.remove(sortedKeys[i].key);
      }
    }
  }

  @override
  Future<List<PeerDailyStat>> getPeerDailyStats({
    Uint8List? memberPubkey,
    int? currentTimeMillis,
    Duration retention = const Duration(days: 90),
  }) async {
    final targetHex = memberPubkey != null ? hex.encode(memberPubkey) : null;
    final cutoff = currentTimeMillis != null
        ? currentTimeMillis - retention.inMilliseconds
        : null;

    final list = _dailyStatsByKey.values.where((stat) {
      if (targetHex != null && hex.encode(stat.memberPubkey) != targetHex) {
        return false;
      }
      if (cutoff != null && stat.dayDate <= cutoff) {
        return false;
      }
      return true;
    }).toList()
      ..sort((a, b) => a.dayDate.compareTo(b.dayDate));
    return list;
  }

  @override
  Future<({int sightingsPruned, int dailyStatsPruned})> prunePeerHistory({
    required int currentTimeMillis,
    Duration sightingsRetention = const Duration(hours: 24),
    Duration dailyStatsRetention = const Duration(days: 90),
  }) async {
    // IT-DS-05d: If the clock jumped backward relative to the highest observed timestamp,
    // do not delete rows based on the regressed clock (only enforce hard row caps).
    if (currentTimeMillis < _maxObservedTimeMs) {
      return (sightingsPruned: 0, dailyStatsPruned: 0);
    }
    _maxObservedTimeMs = currentTimeMillis;

    final sightingsCutoff =
        currentTimeMillis - sightingsRetention.inMilliseconds;
    final beforeSightings = _sightingsByKey.length;
    _sightingsByKey.removeWhere((_, s) => s.seenAt <= sightingsCutoff);
    final sightingsPruned = beforeSightings - _sightingsByKey.length;

    final statsCutoff = currentTimeMillis - dailyStatsRetention.inMilliseconds;
    final beforeStats = _dailyStatsByKey.length;
    _dailyStatsByKey.removeWhere((_, st) => st.dayDate <= statsCutoff);
    final dailyStatsPruned = beforeStats - _dailyStatsByKey.length;

    return (
      sightingsPruned: sightingsPruned,
      dailyStatsPruned: dailyStatsPruned,
    );
  }

  @override
  Future<int> prune({
    required int currentTimeMillis,
    Duration retentionWindow = const Duration(hours: 24),
  }) async {
    var evictedCount = 0;

    void removeEnvelope(StoredEnvelope stored,
        {required bool trackEvictionGap}) {
      final idHex = hex.encode(stored.envelope.messageId);
      final authorHex = hex.encode(stored.envelope.core.author);
      final seq = stored.envelope.core.seq;

      if (trackEvictionGap) {
        _evictedAuthorSeqs.add('$authorHex:$seq');
      }

      _envelopesById.remove(idHex);
      _envelopesByAuthorSeq[authorHex]?.remove(seq);
      if (_envelopesByAuthorSeq[authorHex]?.isEmpty ?? false) {
        _envelopesByAuthorSeq.remove(authorHex);
      }
      _storageBytes -= stored.byteSize;
      evictedCount++;
    }

    // Pass 1: Prune expired envelopes (expires_at <= currentTimeMillis)
    final expired = _envelopesById.values
        .where((s) => s.envelope.core.expiresAt <= currentTimeMillis)
        .toList();
    for (final item in expired) {
      removeEnvelope(item, trackEvictionGap: false);
    }

    // Pass 2: Prune server-confirmed envelopes older than retentionWindow
    final retentionThreshold =
        currentTimeMillis - retentionWindow.inMilliseconds;
    final confirmedOld = _envelopesById.values
        .where((s) => s.isConfirmed && s.storedAt <= retentionThreshold)
        .toList();
    for (final item in confirmedOld) {
      removeEnvelope(item, trackEvictionGap: true);
    }

    // Pass 3: If still over storage quota, evict by priority descending (3->2->1), then oldest
    if (_storageBytes > maxStorageBytes) {
      final candidates = _envelopesById.values.toList();

      // Separate non-SOS from SOS (Priority 0)
      final nonSos = candidates
          .where((s) => s.envelope.core.priority > 0)
          .toList()
        ..sort((a, b) {
          // Priority descending (3=Low evicted before 1=High)
          final pCmp =
              b.envelope.core.priority.compareTo(a.envelope.core.priority);
          if (pCmp != 0) return pCmp;
          // Oldest first
          return a.envelope.core.createdAt.compareTo(b.envelope.core.createdAt);
        });

      for (final item in nonSos) {
        if (_storageBytes <= maxStorageBytes) break;
        removeEnvelope(item, trackEvictionGap: true);
      }

      // If still over quota, evict SOS as last resort (oldest first)
      if (_storageBytes > maxStorageBytes) {
        final sos = _envelopesById.values
            .where((s) => s.envelope.core.priority == 0)
            .toList()
          ..sort((a, b) =>
              a.envelope.core.createdAt.compareTo(b.envelope.core.createdAt));

        for (final item in sos) {
          if (_storageBytes <= maxStorageBytes) break;
          removeEnvelope(item, trackEvictionGap: true);
        }
      }
    }

    return evictedCount;
  }
}
