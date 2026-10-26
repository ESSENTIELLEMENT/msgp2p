import 'dart:convert';
import 'dart:ffi';
import 'dart:io';
import 'dart:typed_data';
import 'package:convert/convert.dart';
import 'package:sqlite3/open.dart';
import 'package:sqlite3/sqlite3.dart';
import '../crypto/crypto.dart';
import '../model/certificate.dart';
import '../model/envelope.dart';
import '../model/receipt.dart';
import '../model/revocation.dart';
import '../model/version_vector.dart';
import 'message_store.dart';

bool _sqliteLoaderConfigured = false;

void _ensureSqliteLibraryLoaded() {
  if (_sqliteLoaderConfigured) return;
  _sqliteLoaderConfigured = true;
  if (Platform.isLinux) {
    open.overrideFor(OperatingSystem.linux, () {
      try {
        return DynamicLibrary.open('libsqlite3.so');
      } catch (_) {
        return DynamicLibrary.open('libsqlite3.so.0');
      }
    });
  }
}

/// Persistent SQLite implementation of [MessageStore] using WAL mode and
/// atomic batch transactions (`NFR-REL-01`, `FR-SYNC-05`, `FR-SYNC-08`).
///
/// Pure Dart implementation backed by `package:sqlite3` FFI with zero Flutter dependencies.
class SqliteMessageStore implements MessageStore {
  @override
  final int maxStorageBytes;

  @override
  final int maxEvictionRefetches;

  /// Hard row cap for Tier 1 (`peer_sightings`, default 2,000 per `IT-DS-05a`).
  final int maxSightingsRows;

  /// Hard row cap for Tier 2 (`peer_daily_stats`, default 10,000 per `IT-DS-05b`).
  final int maxDailyStatsRows;

  final Database _db;
  bool _closed = false;

  /// Callback hook used in unit tests to simulate mid-batch failure/crash injection (NFR-REL-01).
  final void Function(int index, Envelope envelope)? onBatchItemBeforeCommit;

  /// Opens a persistent SQLite database at [filePath] with WAL mode enabled.
  factory SqliteMessageStore.open(
    String filePath, {
    int maxStorageBytes = 100 * 1024 * 1024,
    int maxEvictionRefetches = 2,
    int maxSightingsRows = 2000,
    int maxDailyStatsRows = 10000,
    void Function(int index, Envelope envelope)? onBatchItemBeforeCommit,
  }) {
    _ensureSqliteLibraryLoaded();
    final db = sqlite3.open(filePath);
    db.execute('PRAGMA journal_mode = WAL;');
    db.execute('PRAGMA synchronous = NORMAL;');
    db.execute('PRAGMA foreign_keys = ON;');
    return SqliteMessageStore._(
      db,
      maxStorageBytes: maxStorageBytes,
      maxEvictionRefetches: maxEvictionRefetches,
      maxSightingsRows: maxSightingsRows,
      maxDailyStatsRows: maxDailyStatsRows,
      onBatchItemBeforeCommit: onBatchItemBeforeCommit,
    );
  }

  /// Opens an in-memory SQLite database (useful for fast SQLite contract testing).
  factory SqliteMessageStore.inMemory({
    int maxStorageBytes = 100 * 1024 * 1024,
    int maxEvictionRefetches = 2,
    int maxSightingsRows = 2000,
    int maxDailyStatsRows = 10000,
    void Function(int index, Envelope envelope)? onBatchItemBeforeCommit,
  }) {
    _ensureSqliteLibraryLoaded();
    final db = sqlite3.openInMemory();
    return SqliteMessageStore._(
      db,
      maxStorageBytes: maxStorageBytes,
      maxEvictionRefetches: maxEvictionRefetches,
      maxSightingsRows: maxSightingsRows,
      maxDailyStatsRows: maxDailyStatsRows,
      onBatchItemBeforeCommit: onBatchItemBeforeCommit,
    );
  }

  SqliteMessageStore._(
    this._db, {
    required this.maxStorageBytes,
    required this.maxEvictionRefetches,
    required this.maxSightingsRows,
    required this.maxDailyStatsRows,
    this.onBatchItemBeforeCommit,
  }) {
    _initSchema();
  }

  void _initSchema() {
    _db.execute('''
      CREATE TABLE IF NOT EXISTS envelopes (
        id BLOB PRIMARY KEY,
        author BLOB NOT NULL,
        seq INTEGER NOT NULL,
        created_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL,
        priority INTEGER NOT NULL,
        key_epoch INTEGER NOT NULL,
        raw BLOB NOT NULL,
        byte_size INTEGER NOT NULL,
        stored_at INTEGER NOT NULL,
        origin TEXT NOT NULL DEFAULT 'PEER' CHECK (origin IN ('LOCAL','PEER','SERVER')),
        first_handed_at INTEGER,
        server_confirmed INTEGER NOT NULL DEFAULT 0,
        UNIQUE (author, seq)
      );
      CREATE INDEX IF NOT EXISTS idx_env_prio ON envelopes(priority, created_at ASC);
      CREATE INDEX IF NOT EXISTS idx_env_expiry ON envelopes(expires_at);

      CREATE TABLE IF NOT EXISTS eviction_tombstones (
        author BLOB NOT NULL,
        seq INTEGER NOT NULL,
        message_id BLOB NOT NULL,
        refetch_count INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY (author, seq)
      );
      CREATE INDEX IF NOT EXISTS idx_tombstone_msg ON eviction_tombstones(message_id);

      CREATE TABLE IF NOT EXISTS certs (
        hash BLOB PRIMARY KEY,
        raw BLOB NOT NULL,
        expires_at INTEGER NOT NULL
      );

      CREATE TABLE IF NOT EXISTS receipts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        author BLOB NOT NULL,
        issued_at INTEGER NOT NULL,
        ranges_json TEXT NOT NULL,
        raw BLOB NOT NULL
      );

      CREATE TABLE IF NOT EXISTS revocations (
        member_pubkey BLOB PRIMARY KEY,
        revoked_at INTEGER NOT NULL,
        raw BLOB NOT NULL
      );

      CREATE TABLE IF NOT EXISTS attachments (
        hash BLOB PRIMARY KEY,
        mime TEXT NOT NULL,
        bytes BLOB NOT NULL,
        byte_size INTEGER NOT NULL,
        stored_at INTEGER NOT NULL
      );

      -- Tier 1: Anonymous raw sightings (retained <= 24 h, at most 1 row per token + rotation_window)
      CREATE TABLE IF NOT EXISTS peer_sightings (
        token BLOB NOT NULL,
        rotation_window INTEGER NOT NULL,
        seen_at INTEGER NOT NULL,
        transport TEXT NOT NULL,
        rssi INTEGER NOT NULL,
        PRIMARY KEY (token, rotation_window)
      );
      CREATE INDEX IF NOT EXISTS idx_sightings_seen ON peer_sightings(seen_at);

      -- Tier 2: Authenticated member daily statistics (retained 90 days)
      CREATE TABLE IF NOT EXISTS peer_daily_stats (
        member_pubkey BLOB NOT NULL,
        day_date INTEGER NOT NULL,
        sessions_count INTEGER NOT NULL DEFAULT 0,
        failed_connects INTEGER NOT NULL DEFAULT 0,
        flap_count INTEGER NOT NULL DEFAULT 0,
        bytes_sent INTEGER NOT NULL DEFAULT 0,
        bytes_recv INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY (member_pubkey, day_date)
      );
      CREATE INDEX IF NOT EXISTS idx_daily_stats_date ON peer_daily_stats(day_date);

      CREATE TABLE IF NOT EXISTS local_state (
        k TEXT PRIMARY KEY,
        v INTEGER NOT NULL
      );
    ''');
  }

  int get _maxObservedTimeMs {
    final rows = _db.select(
        "SELECT v FROM local_state WHERE k = 'max_observed_time_ms' LIMIT 1;");
    if (rows.isEmpty) return 0;
    return (rows.first['v'] as int?) ?? 0;
  }

  void _updateMaxObservedTimeMs(int timestampMs) {
    final current = _maxObservedTimeMs;
    if (timestampMs > current) {
      _db.execute(
        "INSERT OR REPLACE INTO local_state (k, v) VALUES ('max_observed_time_ms', ?);",
        [timestampMs],
      );
    }
  }

  /// Returns the current SQLite journal mode (e.g. `wal` for file-backed stores).
  String get journalMode {
    final rows = _db.select('PRAGMA journal_mode;');
    if (rows.isEmpty) return '';
    return rows.first.values.first.toString().toLowerCase();
  }

  /// Lists table names in `sqlite_master` (useful for verifying Tier 3 ephemerality in `IT-DS-05c`).
  List<String> get tableNames {
    final rows = _db.select(
        "SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name ASC;");
    return rows.map((r) => r['name'].toString()).toList();
  }

  @override
  int get currentStorageBytes {
    final rows = _db
        .select('SELECT COALESCE(SUM(byte_size), 0) AS total FROM envelopes;');
    if (rows.isEmpty) return 0;
    return (rows.first['total'] as int?) ?? 0;
  }

  @override
  int getEvictionRefetchCount(Uint8List messageId) {
    final rows = _db.select(
      'SELECT refetch_count FROM eviction_tombstones WHERE message_id = ? LIMIT 1;',
      [messageId],
    );
    if (rows.isEmpty) return 0;
    return (rows.first['refetch_count'] as int?) ?? 0;
  }

  @override
  Future<bool> saveEnvelope(Envelope envelope, {int? customStoredAt}) async {
    return _insertSingleEnvelope(envelope, customStoredAt: customStoredAt);
  }

  bool _insertSingleEnvelope(Envelope envelope, {int? customStoredAt}) {
    final msgId = envelope.messageId;
    final existing = _db.select(
      'SELECT 1 FROM envelopes WHERE id = ? OR (author = ? AND seq = ?) LIMIT 1;',
      [msgId, envelope.core.author, envelope.core.seq],
    );
    if (existing.isNotEmpty) {
      return false;
    }

    // Check E_max eviction re-fetch bound (FR-SYNC-05, IT-DS-01)
    final tombstoneRows = _db.select(
      'SELECT refetch_count FROM eviction_tombstones WHERE author = ? AND seq = ? LIMIT 1;',
      [envelope.core.author, envelope.core.seq],
    );
    if (tombstoneRows.isNotEmpty) {
      final prevRefetches = (tombstoneRows.first['refetch_count'] as int?) ?? 0;
      if (prevRefetches >= maxEvictionRefetches) {
        return false; // Suppressed: already re-fetched E_max times
      }
      _db.execute(
        'UPDATE eviction_tombstones SET refetch_count = ?, message_id = ? WHERE author = ? AND seq = ?;',
        [prevRefetches + 1, msgId, envelope.core.author, envelope.core.seq],
      );
    }

    final raw = envelope.toCanonicalCbor();
    final storedAt = customStoredAt ?? DateTime.now().millisecondsSinceEpoch;
    final confirmed =
        _isAuthorSeqConfirmedSync(envelope.core.author, envelope.core.seq)
            ? 1
            : 0;

    _db.execute(
      '''
      INSERT INTO envelopes (
        id, author, seq, created_at, expires_at, priority, key_epoch,
        raw, byte_size, stored_at, origin, server_confirmed
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'PEER', ?);
      ''',
      [
        msgId,
        envelope.core.author,
        envelope.core.seq,
        envelope.core.createdAt,
        envelope.core.expiresAt,
        envelope.core.priority,
        envelope.core.keyEpoch,
        raw,
        raw.length,
        storedAt,
        confirmed,
      ],
    );
    return true;
  }

  @override
  Future<int> saveBatch(List<Envelope> envelopes, {int? customStoredAt}) async {
    if (envelopes.isEmpty) return 0;

    _db.execute('BEGIN IMMEDIATE TRANSACTION;');
    try {
      var savedCount = 0;
      for (var i = 0; i < envelopes.length; i++) {
        final env = envelopes[i];
        if (_insertSingleEnvelope(env, customStoredAt: customStoredAt)) {
          savedCount++;
        }
        onBatchItemBeforeCommit?.call(i, env);
      }
      _db.execute('COMMIT;');
      return savedCount;
    } catch (e) {
      _db.execute('ROLLBACK;');
      rethrow;
    }
  }

  @override
  Future<Envelope?> getEnvelope(Uint8List messageId) async {
    final rows = _db.select(
      'SELECT raw FROM envelopes WHERE id = ? LIMIT 1;',
      [messageId],
    );
    if (rows.isEmpty) return null;
    final raw = rows.first['raw'] as Uint8List;
    return Envelope.fromCbor(raw);
  }

  @override
  Future<bool> containsEnvelope(Uint8List messageId) async {
    final rows = _db.select(
      'SELECT 1 FROM envelopes WHERE id = ? LIMIT 1;',
      [messageId],
    );
    return rows.isNotEmpty;
  }

  @override
  Future<bool> isSequenceHeld(Uint8List author, int seq) async {
    final rows = _db.select(
      'SELECT 1 FROM envelopes WHERE author = ? AND seq = ? LIMIT 1;',
      [author, seq],
    );
    return rows.isNotEmpty;
  }

  @override
  Future<List<Envelope>> getEnvelopesByAuthorAndRanges(
    Uint8List author,
    List<SeqRange> ranges, {
    int? currentTimeMillis,
  }) async {
    if (ranges.isEmpty) return const [];

    final results = <Envelope>[];
    final stmt = _db.prepare(
      'SELECT raw, expires_at FROM envelopes WHERE author = ? AND seq >= ? AND seq <= ? ORDER BY seq ASC;',
    );
    try {
      for (final range in ranges) {
        final rows = stmt.select([author, range.fromSeq, range.toSeq]);
        for (final row in rows) {
          final expiresAt = row['expires_at'] as int;
          if (currentTimeMillis != null && expiresAt <= currentTimeMillis) {
            continue; // IT-DS-02: never send expired envelopes in DATA
          }
          results.add(Envelope.fromCbor(row['raw'] as Uint8List));
        }
      }
    } finally {
      stmt.dispose();
    }
    return results;
  }

  @override
  Future<VersionVector> getVersionVector({int? currentTimeMillis}) async {
    final vv = VersionVector();
    final rows = _db.select(
      'SELECT author, seq, expires_at FROM envelopes ORDER BY author ASC, seq ASC;',
    );
    for (final row in rows) {
      final expiresAt = row['expires_at'] as int;
      if (currentTimeMillis != null && expiresAt <= currentTimeMillis) {
        continue; // IT-DS-02: exclude expired envelopes
      }
      final authorHex = hex.encode(row['author'] as Uint8List);
      final seq = row['seq'] as int;
      vv.getOrCreate(authorHex).add(seq);
    }

    // IT-DS-01: Include evicted sequences that have reached E_max so we stop requesting them
    final exhaustedRows = _db.select(
      'SELECT author, seq FROM eviction_tombstones WHERE refetch_count >= ?;',
      [maxEvictionRefetches],
    );
    for (final row in exhaustedRows) {
      final authorHex = hex.encode(row['author'] as Uint8List);
      final seq = row['seq'] as int;
      vv.getOrCreate(authorHex).add(seq);
    }

    return vv;
  }

  @override
  Future<int> getEnvelopeCount() async {
    final rows = _db.select('SELECT COUNT(*) AS cnt FROM envelopes;');
    return (rows.first['cnt'] as int?) ?? 0;
  }

  @override
  Future<void> saveReceipt(ServerReceipt receipt) async {
    final raw = receipt.toFullCbor();

    _db.execute('BEGIN IMMEDIATE TRANSACTION;');
    try {
      final currentRanges = _getConfirmedRangesSync(receipt.author);
      final merged =
          SeqRange.mergeRanges([...currentRanges, ...receipt.ranges]);
      final rangesUnchanged = _rangeListsEqual(currentRanges, merged);

      final existing = _db.select(
        'SELECT 1 FROM receipts WHERE raw = ? LIMIT 1;',
        [raw],
      );
      if (existing.isEmpty && (!rangesUnchanged || currentRanges.isEmpty)) {
        final rangesJson = jsonEncode(
          merged.map((r) => [r.fromSeq, r.toSeq]).toList(),
        );
        _db.execute(
          'INSERT INTO receipts (author, issued_at, ranges_json, raw) VALUES (?, ?, ?, ?);',
          [receipt.author, receipt.issuedAt, rangesJson, raw],
        );
      }

      // Mark matching stored envelopes as server_confirmed = 1
      for (final range in merged) {
        _db.execute(
          'UPDATE envelopes SET server_confirmed = 1 WHERE author = ? AND seq >= ? AND seq <= ?;',
          [receipt.author, range.fromSeq, range.toSeq],
        );
      }
      _db.execute('COMMIT;');
    } catch (e) {
      _db.execute('ROLLBACK;');
      rethrow;
    }
  }

  static bool _rangeListsEqual(List<SeqRange> a, List<SeqRange> b) {
    if (a.length != b.length) return false;
    for (var i = 0; i < a.length; i++) {
      if (a[i] != b[i]) return false;
    }
    return true;
  }

  List<SeqRange> _getConfirmedRangesSync(Uint8List author) {
    final receiptRows = _db.select(
      'SELECT ranges_json FROM receipts WHERE author = ?;',
      [author],
    );
    final rawRanges = <SeqRange>[];
    for (final row in receiptRows) {
      final decoded = jsonDecode(row['ranges_json'] as String) as List;
      for (final r in decoded) {
        final pair = r as List;
        rawRanges.add(SeqRange(pair[0] as int, pair[1] as int));
      }
    }
    return SeqRange.mergeRanges(rawRanges);
  }

  @override
  Future<List<SeqRange>> getConfirmedRanges(Uint8List author) async {
    return _getConfirmedRangesSync(author);
  }

  @override
  Future<bool> isConfirmed(Uint8List author, int seq) async {
    return _isAuthorSeqConfirmedSync(author, seq);
  }

  bool _isAuthorSeqConfirmedSync(Uint8List author, int seq) {
    final envRow = _db.select(
      'SELECT server_confirmed FROM envelopes WHERE author = ? AND seq = ? LIMIT 1;',
      [author, seq],
    );
    if (envRow.isNotEmpty && (envRow.first['server_confirmed'] as int) == 1) {
      return true;
    }

    final merged = _getConfirmedRangesSync(author);
    for (final range in merged) {
      if (range.contains(seq)) {
        return true;
      }
    }
    return false;
  }

  @override
  Future<List<ServerReceipt>> getReceipts({int? sinceTimestamp}) async {
    final ResultSet rows;
    if (sinceTimestamp == null) {
      rows = _db
          .select('SELECT raw FROM receipts ORDER BY issued_at ASC, id ASC;');
    } else {
      rows = _db.select(
        'SELECT raw FROM receipts WHERE issued_at >= ? ORDER BY issued_at ASC, id ASC;',
        [sinceTimestamp],
      );
    }
    return rows
        .map((r) => ServerReceipt.fromCbor(r['raw'] as Uint8List))
        .toList();
  }

  @override
  Future<void> saveCertificate(MembershipCert cert) async {
    _db.execute(
      'INSERT OR REPLACE INTO certs (hash, raw, expires_at) VALUES (?, ?, ?);',
      [cert.certRef, cert.toFullCbor(), cert.expiresAt],
    );
  }

  @override
  Future<MembershipCert?> getCertificate(Uint8List certRef) async {
    final rows = _db.select(
      'SELECT raw FROM certs WHERE hash = ? LIMIT 1;',
      [certRef],
    );
    if (rows.isEmpty) return null;
    return MembershipCert.fromCbor(rows.first['raw'] as Uint8List);
  }

  @override
  Future<void> saveRevocation(RevocationNotice revocation) async {
    _db.execute(
      'INSERT OR REPLACE INTO revocations (member_pubkey, revoked_at, raw) VALUES (?, ?, ?);',
      [revocation.memberPubkey, revocation.revokedAt, revocation.toFullCbor()],
    );
  }

  @override
  Future<bool> isRevoked(Uint8List memberPubkey) async {
    final rows = _db.select(
      'SELECT 1 FROM revocations WHERE member_pubkey = ? LIMIT 1;',
      [memberPubkey],
    );
    return rows.isNotEmpty;
  }

  @override
  Future<List<RevocationNotice>> getRevocations() async {
    final rows =
        _db.select('SELECT raw FROM revocations ORDER BY revoked_at ASC;');
    return rows
        .map((r) => RevocationNotice.fromCbor(r['raw'] as Uint8List))
        .toList();
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

    final existing = _db.select(
      'SELECT 1 FROM attachments WHERE hash = ? LIMIT 1;',
      [hash],
    );
    if (existing.isNotEmpty) {
      return false;
    }

    final storedAt = customStoredAt ?? DateTime.now().millisecondsSinceEpoch;
    _db.execute(
      'INSERT INTO attachments (hash, mime, bytes, byte_size, stored_at) VALUES (?, ?, ?, ?, ?);',
      [hash, mime, bytes, bytes.length, storedAt],
    );
    return true;
  }

  @override
  Future<StoredAttachmentBlob?> getAttachmentBlob(Uint8List hash) async {
    final rows = _db.select(
      'SELECT hash, mime, bytes, stored_at FROM attachments WHERE hash = ? LIMIT 1;',
      [hash],
    );
    if (rows.isEmpty) return null;
    final row = rows.first;
    return StoredAttachmentBlob(
      hash: row['hash'] as Uint8List,
      mime: row['mime'] as String,
      bytes: row['bytes'] as Uint8List,
      storedAt: row['stored_at'] as int,
    );
  }

  @override
  Future<bool> containsAttachmentBlob(Uint8List hash) async {
    final rows = _db.select(
      'SELECT 1 FROM attachments WHERE hash = ? LIMIT 1;',
      [hash],
    );
    return rows.isNotEmpty;
  }

  @override
  Future<List<AttachmentRef>> getMissingAttachments() async {
    final envRows = _db.select('SELECT raw FROM envelopes;');
    final missingByHex = <String, AttachmentRef>{};
    for (final row in envRows) {
      final env = Envelope.fromCbor(row['raw'] as Uint8List);
      final attachments = env.core.attachments;
      if (attachments == null) continue;
      for (final ref in attachments) {
        final hHex = hex.encode(ref.hash);
        if (!missingByHex.containsKey(hHex)) {
          final present = await containsAttachmentBlob(ref.hash);
          if (!present) {
            missingByHex[hHex] = ref;
          }
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
    _updateMaxObservedTimeMs(seenAt);
    final rotationWindow = seenAt ~/ rotationWindowMs;
    _db.execute(
      '''
      INSERT INTO peer_sightings (token, rotation_window, seen_at, transport, rssi)
      VALUES (?, ?, ?, ?, ?)
      ON CONFLICT(token, rotation_window) DO UPDATE SET
        seen_at = MAX(peer_sightings.seen_at, excluded.seen_at),
        transport = excluded.transport,
        rssi = excluded.rssi;
      ''',
      [token, rotationWindow, seenAt, transport, rssi],
    );

    final countRow = _db.select('SELECT COUNT(*) AS cnt FROM peer_sightings;');
    final count = (countRow.first['cnt'] as int?) ?? 0;
    if (count > maxSightingsRows) {
      final excess = count - maxSightingsRows;
      _db.execute(
        '''
        DELETE FROM peer_sightings WHERE rowid IN (
          SELECT rowid FROM peer_sightings ORDER BY seen_at ASC LIMIT ?
        );
        ''',
        [excess],
      );
    }
  }

  @override
  Future<List<PeerSighting>> getRecentPeerSightings({
    required int currentTimeMillis,
    Duration maxAge = const Duration(hours: 24),
  }) async {
    final cutoff = currentTimeMillis - maxAge.inMilliseconds;
    final rows = _db.select(
      '''
      SELECT token, rotation_window, seen_at, transport, rssi
      FROM peer_sightings
      WHERE seen_at > ? AND seen_at <= ?
      ORDER BY seen_at DESC;
      ''',
      [cutoff, currentTimeMillis],
    );
    return rows
        .map(
          (r) => PeerSighting(
            token: r['token'] as Uint8List,
            rotationWindow: r['rotation_window'] as int,
            seenAt: r['seen_at'] as int,
            transport: r['transport'] as String,
            rssi: r['rssi'] as int,
          ),
        )
        .toList();
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
    _updateMaxObservedTimeMs(timestampMs);
    const dayMs = 86400000;
    final dayDate = (timestampMs ~/ dayMs) * dayMs;

    _db.execute(
      '''
      INSERT INTO peer_daily_stats (
        member_pubkey, day_date, sessions_count, failed_connects, flap_count, bytes_sent, bytes_recv
      ) VALUES (?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(member_pubkey, day_date) DO UPDATE SET
        sessions_count = peer_daily_stats.sessions_count + excluded.sessions_count,
        failed_connects = peer_daily_stats.failed_connects + excluded.failed_connects,
        flap_count = peer_daily_stats.flap_count + excluded.flap_count,
        bytes_sent = peer_daily_stats.bytes_sent + excluded.bytes_sent,
        bytes_recv = peer_daily_stats.bytes_recv + excluded.bytes_recv;
      ''',
      [
        memberPubkey,
        dayDate,
        sessionsDelta,
        failedConnectsDelta,
        flapDelta,
        bytesSentDelta,
        bytesRecvDelta,
      ],
    );

    final countRow =
        _db.select('SELECT COUNT(*) AS cnt FROM peer_daily_stats;');
    final count = (countRow.first['cnt'] as int?) ?? 0;
    if (count > maxDailyStatsRows) {
      final excess = count - maxDailyStatsRows;
      _db.execute(
        '''
        DELETE FROM peer_daily_stats WHERE rowid IN (
          SELECT rowid FROM peer_daily_stats ORDER BY day_date ASC LIMIT ?
        );
        ''',
        [excess],
      );
    }
  }

  @override
  Future<List<PeerDailyStat>> getPeerDailyStats({
    Uint8List? memberPubkey,
    int? currentTimeMillis,
    Duration retention = const Duration(days: 90),
  }) async {
    final conditions = <String>[];
    final args = <Object>[];

    if (memberPubkey != null) {
      conditions.add('member_pubkey = ?');
      args.add(memberPubkey);
    }
    if (currentTimeMillis != null) {
      conditions.add('day_date > ?');
      args.add(currentTimeMillis - retention.inMilliseconds);
    }

    final whereClause =
        conditions.isEmpty ? '' : 'WHERE ${conditions.join(' AND ')}';
    final rows = _db.select(
      'SELECT * FROM peer_daily_stats $whereClause ORDER BY day_date ASC;',
      args,
    );

    return rows
        .map(
          (r) => PeerDailyStat(
            memberPubkey: r['member_pubkey'] as Uint8List,
            dayDate: r['day_date'] as int,
            sessionsCount: r['sessions_count'] as int,
            failedConnects: r['failed_connects'] as int,
            flapCount: r['flap_count'] as int,
            bytesSent: r['bytes_sent'] as int,
            bytesRecv: r['bytes_recv'] as int,
          ),
        )
        .toList();
  }

  @override
  Future<({int sightingsPruned, int dailyStatsPruned})> prunePeerHistory({
    required int currentTimeMillis,
    Duration sightingsRetention = const Duration(hours: 24),
    Duration dailyStatsRetention = const Duration(days: 90),
  }) async {
    // IT-DS-05d: If clock jumped backward relative to the highest persisted timestamp,
    // skip age-based deletion so valid data is never wrongly deleted.
    if (currentTimeMillis < _maxObservedTimeMs) {
      return (sightingsPruned: 0, dailyStatsPruned: 0);
    }
    _updateMaxObservedTimeMs(currentTimeMillis);

    final sightingsCutoff =
        currentTimeMillis - sightingsRetention.inMilliseconds;
    _db.execute(
      'DELETE FROM peer_sightings WHERE seen_at <= ?;',
      [sightingsCutoff],
    );
    final sightingsPruned = _db.updatedRows;

    final statsCutoff = currentTimeMillis - dailyStatsRetention.inMilliseconds;
    _db.execute(
      'DELETE FROM peer_daily_stats WHERE day_date <= ?;',
      [statsCutoff],
    );
    final dailyStatsPruned = _db.updatedRows;

    return (
      sightingsPruned: sightingsPruned,
      dailyStatsPruned: dailyStatsPruned,
    );
  }

  void _recordEvictionTombstone(Uint8List author, int seq, Uint8List msgId) {
    _db.execute(
      '''
      INSERT INTO eviction_tombstones (author, seq, message_id, refetch_count)
      VALUES (?, ?, ?, 0)
      ON CONFLICT(author, seq) DO NOTHING;
      ''',
      [author, seq, msgId],
    );
  }

  @override
  Future<int> prune({
    required int currentTimeMillis,
    Duration retentionWindow = const Duration(hours: 24),
  }) async {
    var evictedCount = 0;

    _db.execute('BEGIN IMMEDIATE TRANSACTION;');
    try {
      // Pass 1: Prune expired envelopes (expires_at <= currentTimeMillis)
      _db.execute(
        'DELETE FROM envelopes WHERE expires_at <= ?;',
        [currentTimeMillis],
      );
      evictedCount += _db.updatedRows;

      // Pass 2: Prune server-confirmed envelopes older than retentionWindow
      final retentionThreshold =
          currentTimeMillis - retentionWindow.inMilliseconds;
      final confirmedRows = _db.select(
        'SELECT id, author, seq FROM envelopes WHERE server_confirmed = 1 AND stored_at <= ?;',
        [retentionThreshold],
      );
      for (final row in confirmedRows) {
        final id = row['id'] as Uint8List;
        _recordEvictionTombstone(
          row['author'] as Uint8List,
          row['seq'] as int,
          id,
        );
        _db.execute('DELETE FROM envelopes WHERE id = ?;', [id]);
        evictedCount++;
      }

      // Pass 3: If still over storage quota, evict by priority descending (3->2->1), oldest first
      var totalBytes = currentStorageBytes;
      if (totalBytes > maxStorageBytes) {
        final nonSosRows = _db.select('''
          SELECT id, author, seq, byte_size FROM envelopes
          WHERE priority > 0
          ORDER BY priority DESC, created_at ASC;
        ''');

        for (final row in nonSosRows) {
          if (totalBytes <= maxStorageBytes) break;
          final id = row['id'] as Uint8List;
          final size = row['byte_size'] as int;
          _recordEvictionTombstone(
            row['author'] as Uint8List,
            row['seq'] as int,
            id,
          );
          _db.execute('DELETE FROM envelopes WHERE id = ?;', [id]);
          totalBytes -= size;
          evictedCount++;
        }

        // Last resort: evict SOS (priority 0) oldest first
        if (totalBytes > maxStorageBytes) {
          final sosRows = _db.select('''
            SELECT id, author, seq, byte_size FROM envelopes
            WHERE priority = 0
            ORDER BY created_at ASC;
          ''');
          for (final row in sosRows) {
            if (totalBytes <= maxStorageBytes) break;
            final id = row['id'] as Uint8List;
            final size = row['byte_size'] as int;
            _recordEvictionTombstone(
              row['author'] as Uint8List,
              row['seq'] as int,
              id,
            );
            _db.execute('DELETE FROM envelopes WHERE id = ?;', [id]);
            totalBytes -= size;
            evictedCount++;
          }
        }
      }

      _db.execute('COMMIT;');
      return evictedCount;
    } catch (e) {
      _db.execute('ROLLBACK;');
      rethrow;
    }
  }

  /// Closes the underlying SQLite database connection.
  void close() {
    if (!_closed) {
      _closed = true;
      _db.dispose();
    }
  }
}
