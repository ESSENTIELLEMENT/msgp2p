import 'dart:async';
import 'dart:collection';
import 'dart:typed_data';
import 'package:cbor/cbor.dart' as cbor;
import 'package:convert/convert.dart';
import 'package:cryptography/cryptography.dart' as cg;
import '../crypto/noise.dart';
import '../crypto/noise_handshake.dart';
import '../encoding/canonical_cbor.dart';
import '../framing/chunking.dart';
import '../framing/frame.dart';
import '../model/certificate.dart';
import '../model/envelope.dart';
import '../model/receipt.dart';
import '../model/revocation.dart';
import '../storage/message_store.dart';
import '../transport/transport.dart';
import 'clock_rules.dart';
import 'session_messages.dart';

/// Phase states of an active synchronization session.
enum SessionPhase {
  handshaking,
  exchangingSummary,
  exchangingWant,
  exchangingMetadata,
  syncingData,
  completed,
  terminated,
}

/// Statistics and outcome of a completed or terminated session.
class SessionSyncResult {
  final int envelopesSent;
  final int envelopesReceived;
  final int duplicateEnvelopesReceived;
  final int receiptsSent;
  final int receiptsReceived;
  final int revocationsSent;
  final int revocationsReceived;
  final int attachmentsSent;
  final int attachmentsReceived;
  final int totalBytesSent;
  final int totalBytesReceived;
  final bool upgradeRecommended;
  final int pendingUpgradeBytes;
  final bool completedSuccessfully;
  final String? failureReason;
  final MembershipCert? peerCert;

  const SessionSyncResult({
    this.envelopesSent = 0,
    this.envelopesReceived = 0,
    this.duplicateEnvelopesReceived = 0,
    this.receiptsSent = 0,
    this.receiptsReceived = 0,
    this.revocationsSent = 0,
    this.revocationsReceived = 0,
    this.attachmentsSent = 0,
    this.attachmentsReceived = 0,
    this.totalBytesSent = 0,
    this.totalBytesReceived = 0,
    this.upgradeRecommended = false,
    this.pendingUpgradeBytes = 0,
    this.completedSuccessfully = false,
    this.failureReason,
    this.peerCert,
  });

  @override
  String toString() =>
      'SessionSyncResult(ok: $completedSuccessfully, sent: $envelopesSent, recv: $envelopesReceived, '
      'attSent: $attachmentsSent, attRecv: $attachmentsReceived, bytesSent: $totalBytesSent, '
      'upgrade: $upgradeRecommended, err: $failureReason)';
}

/// Orchestrates peer-to-peer session synchronization over [PeerLink].
class SessionStateMachine {
  final MessageStore store;
  final PeerLink link;
  final bool isInitiator;
  final cg.SimpleKeyPair staticKeyPair;
  final MembershipCert localCert;
  final Uint8List pinnedServerKey;
  final Uint8List expectedGroupId;
  final int Function()? getNowMs;
  final Clock? clock;

  /// Whether bulk attachment blobs (`BLOB_WANT` / `BLOB_DATA`) should be synced in this session.
  /// False on BLE links (attachments are never sent over BLE per requirements.md §3);
  /// true on Wi-Fi Aware / bulk links.
  final bool transferAttachments;

  /// Byte threshold above which a BLE session recommends upgrading to Wi-Fi Aware (default 16 KB).
  final int upgradeThresholdBytes;

  /// If true, immediately aborts the session after handshake if the peer's certificate
  /// is already listed in the local revocation store (`FR-ID-04`, `FR-ID-05`).
  /// Even when false, `DATA` envelopes authored by revoked members are always dropped.
  final bool rejectRevokedPeerHandshake;

  /// Timeout when awaiting the next protocol frame (`IT-FLAP-02` `T_reclaim`, default 10 s).
  final Duration frameTimeout;

  /// Fault-injection hook (`IT-FLAP-05`): if true, drops the link immediately after
  /// completing the Noise-XX handshake.
  final bool dropAfterHandshake;

  /// Fault-injection hook (`IT-RES-02`): if set, closes the link immediately after
  /// sending a frame matching this [SessionFrameType] code.
  final int? cutAfterSendingFrameType;

  /// Trace callback (`IT-OBS-01`) invoked whenever a frame is sliced and sent over the link.
  final void Function(int frameType, int wireBytes, int chunkCount)?
      onFrameSent;

  /// Trace callback (`IT-OBS-01`) invoked whenever a valid `DATA` envelope is received.
  final void Function(
          Envelope envelope, bool isDuplicate, int evictionRefetchCount)?
      onEnvelopeReceived;

  SessionPhase _phase = SessionPhase.handshaking;
  SessionPhase get phase => _phase;

  NoiseSession? _noiseSession;
  NoiseSession? get noiseSession => _noiseSession;

  final ChunkReassembler _reassembler = ChunkReassembler();
  final Queue<Frame> _frameQueue = Queue<Frame>();
  final Queue<Completer<Frame>> _frameWaiters = Queue<Completer<Frame>>();
  late final StreamSubscription<Uint8List> _linkRxSub;
  late final StreamSubscription<LinkEvent> _linkEventsSub;

  int _envelopesSent = 0;
  int _envelopesReceived = 0;
  int _duplicateEnvelopesReceived = 0;
  int _receiptsSent = 0;
  int _receiptsReceived = 0;
  int _revocationsSent = 0;
  int _revocationsReceived = 0;
  int _attachmentsSent = 0;
  int _attachmentsReceived = 0;
  int _totalBytesSent = 0;
  int _totalBytesReceived = 0;
  int _pendingUpgradeBytes = 0;

  SessionStateMachine({
    required this.store,
    required this.link,
    required this.isInitiator,
    required this.staticKeyPair,
    required this.localCert,
    required this.pinnedServerKey,
    required this.expectedGroupId,
    this.getNowMs,
    this.clock,
    this.transferAttachments = false,
    this.upgradeThresholdBytes = 16384,
    this.rejectRevokedPeerHandshake = false,
    this.frameTimeout = const Duration(seconds: 10),
    this.dropAfterHandshake = false,
    this.cutAfterSendingFrameType,
    this.onFrameSent,
    this.onEnvelopeReceived,
  }) {
    _linkRxSub = link.rx.listen(
      _onIncomingLinkBytes,
      onError: (err) => _terminate('Link error: $err'),
      onDone: () => _terminate('Link closed remotely'),
    );
    _linkEventsSub = link.events.listen((event) {
      if (event is LinkClosed) {
        _terminate('Link closed: ${event.reason}');
      }
    });
  }

  int _currentTimeMillis() {
    if (clock != null) return clock!.now().millisecondsSinceEpoch;
    if (getNowMs != null) return getNowMs!();
    return DateTime.now().millisecondsSinceEpoch;
  }

  void _onIncomingLinkBytes(Uint8List bytes) {
    if (_phase == SessionPhase.terminated) return;
    _totalBytesReceived += bytes.length;
    final frame = _reassembler.addChunkBytes(bytes);
    if (frame != null) {
      if (_frameWaiters.isNotEmpty) {
        final waiter = _frameWaiters.removeFirst();
        waiter.complete(frame);
      } else {
        _frameQueue.add(frame);
      }
    }
  }

  Future<void> _sendFrame(Frame frame) async {
    final packets = ChunkSlicer.sliceFrame(frame, mtu: link.mtu);
    var sentWireBytes = 0;
    for (final p in packets) {
      final encoded = p.encode();
      sentWireBytes += encoded.length;
      _totalBytesSent += encoded.length;
      await link.send(encoded);
    }
    onFrameSent?.call(frame.type, sentWireBytes, packets.length);
    if (cutAfterSendingFrameType != null &&
        frame.type == cutAfterSendingFrameType) {
      await link.close('simulated_phase_cut_0x${frame.type.toRadixString(16)}');
      throw StateError(
          'Simulated phase cut after frame 0x${frame.type.toRadixString(16)}');
    }
  }

  Future<Frame> _nextFrame({Duration? timeout}) async {
    final effectiveTimeout = timeout ?? frameTimeout;
    if (_frameQueue.isNotEmpty) {
      return _frameQueue.removeFirst();
    }
    if (_phase == SessionPhase.terminated || link.isClosed) {
      throw StateError('Link closed before next frame arrived');
    }
    final completer = Completer<Frame>();
    _frameWaiters.add(completer);
    return completer.future.timeout(
      effectiveTimeout,
      onTimeout: () {
        _frameWaiters.remove(completer);
        throw TimeoutException('Timed out awaiting protocol frame');
      },
    );
  }

  Future<void> _sendEncrypted(int typeCode, Uint8List plaintextBytes) async {
    if (_noiseSession == null) {
      throw StateError(
          'Cannot send encrypted frame before handshake completes');
    }
    final ciphertext = await _noiseSession!.encrypt(plaintextBytes);
    await _sendFrame(Frame(type: typeCode, payload: ciphertext));
  }

  Future<({int type, Uint8List payload})> _nextEncrypted({
    Duration? timeout,
  }) async {
    if (_noiseSession == null) {
      throw StateError(
          'Cannot receive encrypted frame before handshake completes');
    }
    final frame = await _nextFrame(timeout: timeout ?? frameTimeout);
    final decrypted = await _noiseSession!.decrypt(frame.payload);
    return (type: frame.type, payload: decrypted);
  }

  /// Lexicographical public key comparison for simultaneous connect tie-break (§7.4).
  static int comparePubkeys(Uint8List a, Uint8List b) {
    for (var i = 0; i < a.length && i < b.length; i++) {
      if (a[i] != b[i]) {
        return a[i].compareTo(b[i]);
      }
    }
    return a.length.compareTo(b.length);
  }

  /// Constant-time byte array comparison to prevent timing side channels.
  static bool _bytesEqual(Uint8List a, Uint8List b) {
    if (a.length != b.length) return false;
    var diff = 0;
    for (var i = 0; i < a.length; i++) {
      diff |= a[i] ^ b[i];
    }
    return diff == 0;
  }

  /// Runs the complete session protocol: Handshake -> Summary -> Want -> Data -> Bye.
  Future<SessionSyncResult> run() async {
    try {
      // --- PHASE 1: NOISE-XX HANDSHAKE ---
      _phase = SessionPhase.handshaking;
      final now = _currentTimeMillis();

      if (isInitiator) {
        final initiatorState = await NoiseHandshake.startInitiator(
          staticKeyPair: staticKeyPair,
          localCert: localCert,
          pinnedServerKey: pinnedServerKey,
          expectedGroupId: expectedGroupId,
        );

        // 1. Send Message 1
        final msg1 = await initiatorState.createMessage1();
        await _sendFrame(
            Frame(type: SessionFrameType.handshake1, payload: msg1));

        // 2. Await Message 2
        final frame2 = await _nextFrame();
        if (frame2.type != SessionFrameType.handshake2) {
          throw const SecurityException('Expected Noise handshake message 2');
        }

        // 3. Process Message 2 and create Message 3
        final stepResult =
            await initiatorState.processMessage2AndCreateMessage3(
          frame2.payload,
          currentTimeMillis: now,
        );
        _noiseSession = stepResult.session;

        // 4. Send Message 3
        await _sendFrame(
          Frame(
              type: SessionFrameType.handshake3,
              payload: stepResult.message3Bytes),
        );
      } else {
        // Responder side
        final responderState = await NoiseHandshake.startResponder(
          staticKeyPair: staticKeyPair,
          localCert: localCert,
          pinnedServerKey: pinnedServerKey,
          expectedGroupId: expectedGroupId,
        );

        // 1. Await Message 1
        final frame1 = await _nextFrame();
        if (frame1.type != SessionFrameType.handshake1) {
          throw const SecurityException('Expected Noise handshake message 1');
        }

        // 2. Process Message 1 and send Message 2
        final msg2 = await responderState
            .processMessage1AndCreateMessage2(frame1.payload);
        await _sendFrame(
            Frame(type: SessionFrameType.handshake2, payload: msg2));

        // 3. Await Message 3
        final frame3 = await _nextFrame();
        if (frame3.type != SessionFrameType.handshake3) {
          throw const SecurityException('Expected Noise handshake message 3');
        }

        // 4. Process Message 3
        _noiseSession = await responderState.processMessage3(
          frame3.payload,
          currentTimeMillis: now,
        );
      }

      if (_noiseSession != null) {
        if (rejectRevokedPeerHandshake &&
            await store.isRevoked(_noiseSession!.peerCert.memberPubkey)) {
          throw const SecurityException(
              'Peer membership certificate is revoked');
        }
        await store.saveCertificate(_noiseSession!.peerCert);
        if (dropAfterHandshake) {
          await link.close('malicious_post_handshake_drop');
          throw StateError('Simulated post-handshake drop (IT-FLAP-05)');
        }
      }

      // --- PHASE 2: EXCHANGE SUMMARY ---
      _phase = SessionPhase.exchangingSummary;
      final localVector =
          await store.getVersionVector(currentTimeMillis: _currentTimeMillis());
      final localReceipts = await store.getReceipts();
      final receiptWatermark = localReceipts.isEmpty
          ? 0
          : localReceipts
              .map((r) => r.issuedAt)
              .reduce((a, b) => a > b ? a : b);
      final localRevocations = await store.getRevocations();

      final localSummary = SessionSummary(
        vector: localVector,
        receiptWatermark: receiptWatermark,
        revocationVersion: localRevocations.length,
      );
      await _sendEncrypted(
          SessionFrameType.summary, localSummary.toCanonicalCbor());

      final peerSummaryFrame = await _nextEncrypted();
      if (peerSummaryFrame.type != SessionFrameType.summary) {
        throw StateError(
            'Expected SUMMARY frame, got ${peerSummaryFrame.type}');
      }
      final peerSummary = SessionSummary.fromCbor(peerSummaryFrame.payload);

      // --- PHASE 3: EXCHANGE WANT ---
      _phase = SessionPhase.exchangingWant;
      final localWantList = localVector.calculateWant(peerSummary.vector);
      final localWant = SessionWant(requests: localWantList);
      await _sendEncrypted(SessionFrameType.want, localWant.toCanonicalCbor());

      final peerWantFrame = await _nextEncrypted();
      if (peerWantFrame.type != SessionFrameType.want) {
        throw StateError('Expected WANT frame, got ${peerWantFrame.type}');
      }
      final peerWant = SessionWant.fromCbor(peerWantFrame.payload);

      // Optional bulk attachment reconciliation (Type 0x17 BLOB_WANT)
      var peerBlobWant = const BlobWant(hashes: []);
      if (transferAttachments) {
        final missingAtts = await store.getMissingAttachments();
        final localBlobWant = BlobWant(
          hashes: missingAtts.map((a) => a.hash).toList(),
        );
        await _sendEncrypted(
          SessionFrameType.blobWant,
          localBlobWant.toCanonicalCbor(),
        );

        final peerBlobWantFrame = await _nextEncrypted();
        if (peerBlobWantFrame.type != SessionFrameType.blobWant) {
          throw StateError(
              'Expected BLOB_WANT frame, got ${peerBlobWantFrame.type}');
        }
        peerBlobWant = BlobWant.fromCbor(peerBlobWantFrame.payload);
      }

      // --- PHASE 4: EXCHANGE METADATA (REVOCATIONS & RECEIPTS) ---
      // IT-AMP-03: Only send REVOCATIONS / RECEIPTS when peer's watermark is older.
      _phase = SessionPhase.exchangingMetadata;
      if (localRevocations.length > peerSummary.revocationVersion) {
        final revList = localRevocations.map((r) => r.toFullCbor()).toList();
        await _sendEncrypted(
          SessionFrameType.revocations,
          CanonicalCbor.encode(revList),
        );
        _revocationsSent += localRevocations.length;
      }

      if (receiptWatermark > peerSummary.receiptWatermark) {
        final newerReceipts = localReceipts
            .where((r) => r.issuedAt > peerSummary.receiptWatermark)
            .toList();
        if (newerReceipts.isNotEmpty) {
          final recList = newerReceipts.map((r) => r.toFullCbor()).toList();
          await _sendEncrypted(
            SessionFrameType.receipts,
            CanonicalCbor.encode(recList),
          );
          _receiptsSent += newerReceipts.length;
        }
      }

      // --- PHASE 5: EXCHANGE DATA ENVELOPES & BULK ATTACHMENTS (PRIORITY ORDER) ---
      _phase = SessionPhase.syncingData;

      // 1. Gather all non-expired envelopes requested by peer (IT-DS-02)
      final envelopesToSend = <Envelope>[];
      final sendTimeMs = _currentTimeMillis();
      for (final want in peerWant.requests) {
        final authorBytes = Uint8List.fromList(hex.decode(want.authorHex));
        final matching = await store.getEnvelopesByAuthorAndRanges(
          authorBytes,
          want.ranges,
          currentTimeMillis: sendTimeMs,
        );
        envelopesToSend.addAll(matching);
      }

      // 2. Sort by FR-SYNC-03 priority:
      // Priority 0 (SOS) first, then 1 (High), 2 (Normal), 3 (Low)
      // Within same priority: newest created_at first
      envelopesToSend.sort((a, b) {
        final pCmp = a.core.priority.compareTo(b.core.priority);
        if (pCmp != 0) return pCmp;
        return b.core.createdAt.compareTo(a.core.createdAt);
      });

      final sentBlobHashes = <String>{};
      var envelopeBytesTransferred = 0;

      // 3. Send requested envelopes (and attachment blobs if transferAttachments is true)
      for (final env in envelopesToSend) {
        final envCbor = env.toCanonicalCbor();
        envelopeBytesTransferred += envCbor.length;
        await _sendEncrypted(SessionFrameType.data, envCbor);
        _envelopesSent++;

        final atts = env.core.attachments;
        if (atts != null && atts.isNotEmpty) {
          for (final att in atts) {
            if (transferAttachments) {
              final hHex = hex.encode(att.hash);
              if (!sentBlobHashes.contains(hHex)) {
                final blob = await store.getAttachmentBlob(att.hash);
                if (blob != null) {
                  sentBlobHashes.add(hHex);
                  final blobMsg = BlobData(
                    hash: blob.hash,
                    mime: blob.mime,
                    data: blob.bytes,
                  );
                  await _sendEncrypted(
                    SessionFrameType.blobData,
                    blobMsg.toCanonicalCbor(),
                  );
                  _attachmentsSent++;
                }
              }
            } else {
              _pendingUpgradeBytes += att.size;
            }
          }
        }
      }

      // 3b. Send any explicitly requested attachment blobs from BLOB_WANT
      if (transferAttachments && peerBlobWant.hashes.isNotEmpty) {
        for (final reqHash in peerBlobWant.hashes) {
          final hHex = hex.encode(reqHash);
          if (!sentBlobHashes.contains(hHex)) {
            final blob = await store.getAttachmentBlob(reqHash);
            if (blob != null) {
              sentBlobHashes.add(hHex);
              final blobMsg = BlobData(
                hash: blob.hash,
                mime: blob.mime,
                data: blob.bytes,
              );
              await _sendEncrypted(
                SessionFrameType.blobData,
                blobMsg.toCanonicalCbor(),
              );
              _attachmentsSent++;
            }
          }
        }
      }

      // 4. Send BYE notification when our outbound queue is drained
      await _sendEncrypted(
          SessionFrameType.bye, const ByeMessage().toCanonicalCbor());

      // 5. Ingest in-flight peer frames until peer also sends BYE
      while (true) {
        final incoming = await _nextEncrypted();
        if (incoming.type == SessionFrameType.bye) {
          break; // Both peers agree synchronization is complete
        }

        if (incoming.type == SessionFrameType.revocations) {
          final decoded = cbor.cbor.decode(incoming.payload).toObject() as List;
          for (final item in decoded) {
            final rev = RevocationNotice.fromCbor(
                Uint8List.fromList((item as List).cast<int>()));
            if (!_bytesEqual(rev.groupId, expectedGroupId)) continue;
            final valid = await rev.verify(pinnedServerKey);
            if (valid) {
              await store.saveRevocation(rev);
              _revocationsReceived++;
            }
          }
        } else if (incoming.type == SessionFrameType.receipts) {
          final decoded = cbor.cbor.decode(incoming.payload).toObject() as List;
          for (final item in decoded) {
            final rec = ServerReceipt.fromCbor(
                Uint8List.fromList((item as List).cast<int>()));
            if (!_bytesEqual(rec.groupId, expectedGroupId)) continue;
            final valid = await rec.verify(pinnedServerKey);
            if (valid) {
              await store.saveReceipt(rec);
              _receiptsReceived++;
            }
          }
        } else if (incoming.type == SessionFrameType.data) {
          envelopeBytesTransferred += incoming.payload.length;
          final env = Envelope.fromCbor(incoming.payload);
          // Verify group isolation, author revocation status, envelope integrity & clock rules
          if (_bytesEqual(env.core.groupId, expectedGroupId) &&
              !(await store.isRevoked(env.core.author)) &&
              ClockRules.isValidMessageTime(
                createdAt: env.core.createdAt,
                expiresAt: env.core.expiresAt,
                currentTimeMillis: _currentTimeMillis(),
              )) {
            final validSig = await env.verifySignature();
            if (validSig) {
              final alreadyHeld = await store.containsEnvelope(env.messageId);
              final saved = await store.saveEnvelope(
                env,
                customStoredAt: _currentTimeMillis(),
              );
              final isDuplicate = alreadyHeld || !saved;
              if (saved) {
                _envelopesReceived++;
              } else if (alreadyHeld) {
                _duplicateEnvelopesReceived++;
              }
              onEnvelopeReceived?.call(
                env,
                isDuplicate,
                store.getEvictionRefetchCount(env.messageId),
              );
              if (!transferAttachments && env.core.attachments != null) {
                for (final att in env.core.attachments!) {
                  _pendingUpgradeBytes += att.size;
                }
              }
            }
          }
        } else if (incoming.type == SessionFrameType.blobData) {
          final blobMsg = BlobData.fromCbor(incoming.payload);
          try {
            final saved = await store.saveAttachmentBlob(
              hash: blobMsg.hash,
              mime: blobMsg.mime,
              bytes: blobMsg.data,
              customStoredAt: _currentTimeMillis(),
            );
            if (saved) {
              _attachmentsReceived++;
            }
          } catch (_) {
            // Drop corrupted or tampered attachment blob whose SHA-256 does not match hash
          }
        }
      }

      if (!transferAttachments) {
        final localMissing = await store.getMissingAttachments();
        for (final att in localMissing) {
          if (_pendingUpgradeBytes == 0) {
            _pendingUpgradeBytes += att.size;
          }
        }
      }

      if (_noiseSession != null) {
        await store.recordPeerDailyStat(
          memberPubkey: _noiseSession!.peerCert.memberPubkey,
          timestampMs: _currentTimeMillis(),
          sessionsDelta: 1,
          bytesSentDelta: _totalBytesSent,
          bytesRecvDelta: _totalBytesReceived,
        );
      }

      _phase = SessionPhase.completed;
      return SessionSyncResult(
        envelopesSent: _envelopesSent,
        envelopesReceived: _envelopesReceived,
        duplicateEnvelopesReceived: _duplicateEnvelopesReceived,
        receiptsSent: _receiptsSent,
        receiptsReceived: _receiptsReceived,
        revocationsSent: _revocationsSent,
        revocationsReceived: _revocationsReceived,
        attachmentsSent: _attachmentsSent,
        attachmentsReceived: _attachmentsReceived,
        totalBytesSent: _totalBytesSent,
        totalBytesReceived: _totalBytesReceived,
        upgradeRecommended: !transferAttachments &&
            (_pendingUpgradeBytes > 0 ||
                envelopeBytesTransferred >= upgradeThresholdBytes),
        pendingUpgradeBytes: _pendingUpgradeBytes + envelopeBytesTransferred,
        completedSuccessfully: true,
        peerCert: _noiseSession?.peerCert,
      );
    } catch (e) {
      if (_noiseSession != null) {
        try {
          await store.recordPeerDailyStat(
            memberPubkey: _noiseSession!.peerCert.memberPubkey,
            timestampMs: _currentTimeMillis(),
            failedConnectsDelta: 1,
            flapDelta: 1,
            bytesSentDelta: _totalBytesSent,
            bytesRecvDelta: _totalBytesReceived,
          );
        } catch (_) {}
      }
      _terminate(e.toString());
      return SessionSyncResult(
        envelopesSent: _envelopesSent,
        envelopesReceived: _envelopesReceived,
        duplicateEnvelopesReceived: _duplicateEnvelopesReceived,
        receiptsSent: _receiptsSent,
        receiptsReceived: _receiptsReceived,
        revocationsSent: _revocationsSent,
        revocationsReceived: _revocationsReceived,
        attachmentsSent: _attachmentsSent,
        attachmentsReceived: _attachmentsReceived,
        totalBytesSent: _totalBytesSent,
        totalBytesReceived: _totalBytesReceived,
        upgradeRecommended: false,
        pendingUpgradeBytes: _pendingUpgradeBytes,
        completedSuccessfully: false,
        failureReason: e.toString(),
        peerCert: _noiseSession?.peerCert,
      );
    } finally {
      await close();
    }
  }

  void _terminate(String reason) {
    if (_phase != SessionPhase.completed && _phase != SessionPhase.terminated) {
      _phase = SessionPhase.terminated;
      while (_frameWaiters.isNotEmpty) {
        final waiter = _frameWaiters.removeFirst();
        if (!waiter.isCompleted) {
          waiter.completeError(StateError(reason));
        }
      }
    }
  }

  Future<void> close() async {
    _phase = SessionPhase.terminated;
    await _linkRxSub.cancel();
    await _linkEventsSub.cancel();
    for (final waiter in _frameWaiters) {
      if (!waiter.isCompleted) {
        waiter.completeError(StateError('Session closed'));
      }
    }
    _frameWaiters.clear();
    _frameQueue.clear();
    if (!link.isClosed) {
      await link.close();
    }
  }
}
