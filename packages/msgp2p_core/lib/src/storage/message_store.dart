import 'dart:typed_data';
import 'package:meta/meta.dart';
import '../model/certificate.dart';
import '../model/envelope.dart';
import '../model/receipt.dart';
import '../model/revocation.dart';
import '../model/version_vector.dart';

/// Metadata wrapper for an envelope stored locally on this node.
@immutable
class StoredEnvelope {
  final Envelope envelope;
  final int storedAt;
  final int byteSize;
  final bool isConfirmed;

  const StoredEnvelope({
    required this.envelope,
    required this.storedAt,
    required this.byteSize,
    this.isConfirmed = false,
  });

  StoredEnvelope copyWith({
    Envelope? envelope,
    int? storedAt,
    int? byteSize,
    bool? isConfirmed,
  }) {
    return StoredEnvelope(
      envelope: envelope ?? this.envelope,
      storedAt: storedAt ?? this.storedAt,
      byteSize: byteSize ?? this.byteSize,
      isConfirmed: isConfirmed ?? this.isConfirmed,
    );
  }
}

/// Metadata wrapper for a hash-addressed attachment blob stored locally.
@immutable
class StoredAttachmentBlob {
  final Uint8List hash;
  final String mime;
  final Uint8List bytes;
  final int storedAt;

  const StoredAttachmentBlob({
    required this.hash,
    required this.mime,
    required this.bytes,
    required this.storedAt,
  });

  int get size => bytes.length;
}

/// Tier 1 anonymous rotating beacon sighting (`FR-SYNC-08`, `IT-DS-05a`, `architecture.md §6`).
/// Retained for <= 24 hours with at most one row per `(token, rotationWindow)`.
@immutable
class PeerSighting {
  final Uint8List token;
  final int rotationWindow;
  final int seenAt;
  final String transport;
  final int rssi;

  const PeerSighting({
    required this.token,
    required this.rotationWindow,
    required this.seenAt,
    required this.transport,
    required this.rssi,
  });
}

/// Tier 2 authenticated per-member daily summary (`FR-SYNC-08`, `IT-DS-05b`, `architecture.md §6`).
/// Keyed by `(memberPubkey, dayDate)` where `dayDate` is UTC midnight in milliseconds.
/// Retained for 90 days by default.
@immutable
class PeerDailyStat {
  final Uint8List memberPubkey;
  final int dayDate;
  final int sessionsCount;
  final int failedConnects;
  final int flapCount;
  final int bytesSent;
  final int bytesRecv;

  const PeerDailyStat({
    required this.memberPubkey,
    required this.dayDate,
    required this.sessionsCount,
    required this.failedConnects,
    required this.flapCount,
    required this.bytesSent,
    required this.bytesRecv,
  });
}

/// Abstract contract for local message storage, receipts, certs, peer history, and vector indexing.
abstract class MessageStore {
  /// Maximum storage quota in bytes (defaults to 100 MB per FR-SYNC-05).
  int get maxStorageBytes;

  /// Current total storage consumed by stored envelopes in bytes.
  int get currentStorageBytes;

  /// Maximum number of times (`E_max`) a quota-evicted message may be re-fetched from peers
  /// before its sequence is suppressed from future `WANT` requests (`FR-SYNC-05`, `IT-DS-01`).
  int get maxEvictionRefetches;

  /// Returns how many times [messageId] has been re-received after a prior eviction (`IT-DS-01`).
  int getEvictionRefetchCount(Uint8List messageId);

  /// Stores [envelope]. Returns true if stored, false if already present or suppressed by `E_max`.
  /// Optional [customStoredAt] allows simulating storage timestamps in tests & simulator.
  Future<bool> saveEnvelope(Envelope envelope, {int? customStoredAt});

  /// The identity this store belongs to (the author public key of its own envelopes), or null for a new
  /// store. Checked by `guardStoreIdentity` before the node authors (Discussion #10).
  Future<Uint8List?> getOwnerPubkey();

  /// Makes [ownerPubkey] the store's owner. A different owner than before resets the author sequence
  /// counter to 0 (a new identity is a new author).
  Future<void> setOwner(Uint8List ownerPubkey);

  /// The highest sequence number the owner has authored (0 for none). Never lowered by pruning or eviction:
  /// a reused sequence would conflict with copies peers hold and look already confirmed to the server.
  Future<int> getAuthorSeq();

  /// Stores an envelope the owner just authored (origin `LOCAL`) and raises the author sequence counter to
  /// its `seq`, in one transaction. Throws [StateError] if the store has no owner or the envelope's author
  /// is not the owner. Returns false (and leaves the counter unchanged) if an envelope with the same id or
  /// `(author, seq)` already exists.
  Future<bool> saveOwnEnvelope(Envelope envelope, {int? customStoredAt});

  /// Stores multiple [envelopes] atomically in a batch (NFR-REL-01).
  /// Returns the count of newly stored envelopes (excluding duplicates).
  Future<int> saveBatch(List<Envelope> envelopes, {int? customStoredAt});

  /// Retrieves an envelope by its 32-byte content-addressed [messageId].
  Future<Envelope?> getEnvelope(Uint8List messageId);

  /// Checks if [messageId] is already stored.
  Future<bool> containsEnvelope(Uint8List messageId);

  /// Checks if a specific sequence number for [author] is already held.
  Future<bool> isSequenceHeld(Uint8List author, int seq);

  /// Retrieves all envelopes for [author] that fall within any of the specified [ranges].
  /// If [currentTimeMillis] is provided, expired envelopes (`expiresAt <= currentTimeMillis`)
  /// are excluded (`IT-DS-02`).
  Future<List<Envelope>> getEnvelopesByAuthorAndRanges(
    Uint8List author,
    List<SeqRange> ranges, {
    int? currentTimeMillis,
  });

  /// Builds the exact [VersionVector] representing all held message sequences.
  /// - Evicted sequences with re-fetch count `< maxEvictionRefetches` are reported as gaps.
  /// - Evicted sequences that have reached `maxEvictionRefetches` (`E_max`) are marked as
  ///   known so this node stops requesting them (`IT-DS-01`).
  /// - If [currentTimeMillis] is provided, expired envelopes (`expiresAt <= currentTimeMillis`)
  ///   are excluded from the vector (`IT-DS-02`).
  Future<VersionVector> getVersionVector({int? currentTimeMillis});

  /// Total count of envelopes held in store.
  Future<int> getEnvelopeCount();

  /// Saves a server-signed batch [receipt] and canonically merges its ranges (`IT-DS-04`).
  Future<void> saveReceipt(ServerReceipt receipt);

  /// Returns the canonical merged list of confirmed [SeqRange]s for [author] (`IT-DS-04`).
  Future<List<SeqRange>> getConfirmedRanges(Uint8List author);

  /// Checks if a message by [author] at [seq] has been confirmed by a server receipt.
  Future<bool> isConfirmed(Uint8List author, int seq);

  /// Retrieves held server receipts, optionally filtered by [sinceTimestamp].
  Future<List<ServerReceipt>> getReceipts({int? sinceTimestamp});

  /// Saves a membership certificate.
  Future<void> saveCertificate(MembershipCert cert);

  /// Retrieves a membership certificate by its 32-byte [certRef] (SHA-256 of canonical cert).
  Future<MembershipCert?> getCertificate(Uint8List certRef);

  /// Saves a revocation notice.
  Future<void> saveRevocation(RevocationNotice revocation);

  /// Checks if a member's 32-byte public key [memberPubkey] has been revoked.
  Future<bool> isRevoked(Uint8List memberPubkey);

  /// Retrieves all known revocation notices.
  Future<List<RevocationNotice>> getRevocations();

  /// Saves a hash-addressed attachment blob after verifying `SHA-256(bytes) == hash`.
  /// Throws [ArgumentError] if the SHA-256 digest of [bytes] does not match [hash].
  /// Returns true if newly stored, false if already present.
  Future<bool> saveAttachmentBlob({
    required Uint8List hash,
    required String mime,
    required Uint8List bytes,
    int? customStoredAt,
  });

  /// Retrieves a stored attachment blob by its 32-byte SHA-256 [hash].
  Future<StoredAttachmentBlob?> getAttachmentBlob(Uint8List hash);

  /// Checks whether the attachment blob with 32-byte SHA-256 [hash] is stored locally.
  Future<bool> containsAttachmentBlob(Uint8List hash);

  /// Scans stored envelopes and returns all [AttachmentRef]s whose blobs are not yet stored locally.
  Future<List<AttachmentRef>> getMissingAttachments();

  /// Records a Tier 1 anonymous beacon token sighting (`FR-SYNC-08`, `IT-DS-05a`).
  /// Deduplicates by `(token, seenAt ~/ rotationWindowMs)` and enforces the hard row cap.
  Future<void> recordPeerSighting({
    required Uint8List token,
    required int seenAt,
    required String transport,
    required int rssi,
    int rotationWindowMs = 900000,
  });

  /// Returns Tier 1 sightings within `[currentTimeMillis - maxAge, currentTimeMillis]`.
  /// Never returns rows older than [maxAge] (`IT-DS-05a`).
  Future<List<PeerSighting>> getRecentPeerSightings({
    required int currentTimeMillis,
    Duration maxAge = const Duration(hours: 24),
  });

  /// Records or increments a Tier 2 per-member daily summary (`FR-SYNC-08`, `IT-DS-05b`).
  Future<void> recordPeerDailyStat({
    required Uint8List memberPubkey,
    required int timestampMs,
    int sessionsDelta = 0,
    int failedConnectsDelta = 0,
    int flapDelta = 0,
    int bytesSentDelta = 0,
    int bytesRecvDelta = 0,
  });

  /// Retrieves Tier 2 per-member daily summaries, optionally filtered by [memberPubkey] and [retention].
  Future<List<PeerDailyStat>> getPeerDailyStats({
    Uint8List? memberPubkey,
    int? currentTimeMillis,
    Duration retention = const Duration(days: 90),
  });

  /// Prunes Tier 1 (`peer_sightings`) and Tier 2 (`peer_daily_stats`) tables (`IT-DS-05a..e`).
  /// Safe under backward clock jumps (`IT-DS-05d`).
  Future<({int sightingsPruned, int dailyStatsPruned})> prunePeerHistory({
    required int currentTimeMillis,
    Duration sightingsRetention = const Duration(hours: 24),
    Duration dailyStatsRetention = const Duration(days: 90),
  });

  /// Prunes envelopes per FR-SYNC-05 eviction rules:
  /// 1. Expired envelopes (expiresAt <= currentTimeMillis)
  /// 2. Server-confirmed envelopes older than [retentionWindow]
  /// 3. If storage > maxStorageBytes: evict lowest priority first (3 -> 2 -> 1), oldest first.
  ///    Priority 0 (SOS) is only evicted as a last resort.
  ///
  /// Returns the number of evicted envelopes.
  Future<int> prune({
    required int currentTimeMillis,
    Duration retentionWindow = const Duration(hours: 24),
  });
}
