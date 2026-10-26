import 'dart:async';
import 'dart:typed_data';
import 'package:cryptography/cryptography.dart' as cg;
import 'package:meta/meta.dart';
import 'package:msgp2p_core/msgp2p_core.dart';
import 'wifi_aware_transport.dart';

/// Combined outcome of a BLE session that optionally upgraded to Wi-Fi Aware (`v0.2`).
@immutable
class UpgradeSyncOutcome {
  final SessionSyncResult bleResult;
  final SessionSyncResult? wifiAwareResult;
  final bool upgradedToWifiAware;
  final bool wifiAwareTornDown;

  const UpgradeSyncOutcome({
    required this.bleResult,
    this.wifiAwareResult,
    required this.upgradedToWifiAware,
    required this.wifiAwareTornDown,
  });

  int get totalEnvelopesSent =>
      bleResult.envelopesSent + (wifiAwareResult?.envelopesSent ?? 0);

  int get totalEnvelopesReceived =>
      bleResult.envelopesReceived + (wifiAwareResult?.envelopesReceived ?? 0);

  int get totalAttachmentsSent =>
      bleResult.attachmentsSent + (wifiAwareResult?.attachmentsSent ?? 0);

  int get totalAttachmentsReceived =>
      bleResult.attachmentsReceived +
      (wifiAwareResult?.attachmentsReceived ?? 0);
}

/// Coordinates automatic session upgrade from BLE (`AndroidBleTransport` / `IosBleTransport`)
/// to `WifiAwareTransport` when pending transfer exceeds [upgradeThresholdBytes] or when
/// hash-addressed attachment blobs need to be synced, followed by immediate teardown (`v0.2`).
class SessionUpgradeCoordinator {
  final int upgradeThresholdBytes;

  const SessionUpgradeCoordinator({
    this.upgradeThresholdBytes = 16384,
  });

  /// Executes a two-stage peer synchronization between initiator (`A`) and responder (`B`):
  /// 1. Runs standard core-envelope reconciliation over BLE (`transferAttachments: false`).
  /// 2. If `upgradeRecommended` is true on either side (e.g. attachments referenced or backlog >= threshold)
  ///    and both nodes have a [WifiAwareTransport] available:
  ///    - Brings up the ephemeral Wi-Fi Aware session using the rotating beacon token.
  ///    - Runs bulk synchronization (`transferAttachments: true`, `MTU 1400`) over Wi-Fi Aware.
  ///    - Immediately tears down both Wi-Fi Aware transports (`teardownAfterTransfer()`) after transfer completes.
  Future<({UpgradeSyncOutcome initiator, UpgradeSyncOutcome responder})>
      runUpgradablePairSession({
    required PeerLink bleLinkInitiator,
    required PeerLink bleLinkResponder,
    required MessageStore storeInitiator,
    required MessageStore storeResponder,
    required cg.SimpleKeyPair noiseKeyPairInitiator,
    required cg.SimpleKeyPair noiseKeyPairResponder,
    required MembershipCert certInitiator,
    required MembershipCert certResponder,
    required Uint8List pinnedServerKey,
    required Uint8List expectedGroupId,
    required Uint8List sessionToken,
    WifiAwareTransport? wifiAwareInitiator,
    WifiAwareTransport? wifiAwareResponder,
    String? responderWifiAwareHandle,
    Clock? clock,
  }) async {
    // Stage 1: BLE session (core messages, receipts, revocations; no attachments over BLE)
    final bleSmA = SessionStateMachine(
      store: storeInitiator,
      link: bleLinkInitiator,
      isInitiator: true,
      staticKeyPair: noiseKeyPairInitiator,
      localCert: certInitiator,
      pinnedServerKey: pinnedServerKey,
      expectedGroupId: expectedGroupId,
      clock: clock,
      transferAttachments: false,
      upgradeThresholdBytes: upgradeThresholdBytes,
    );

    final bleSmB = SessionStateMachine(
      store: storeResponder,
      link: bleLinkResponder,
      isInitiator: false,
      staticKeyPair: noiseKeyPairResponder,
      localCert: certResponder,
      pinnedServerKey: pinnedServerKey,
      expectedGroupId: expectedGroupId,
      clock: clock,
      transferAttachments: false,
      upgradeThresholdBytes: upgradeThresholdBytes,
    );

    final bleResults = await Future.wait([bleSmA.run(), bleSmB.run()]);
    final bleResA = bleResults[0];
    final bleResB = bleResults[1];

    final shouldUpgrade =
        (bleResA.upgradeRecommended || bleResB.upgradeRecommended) &&
            wifiAwareInitiator != null &&
            wifiAwareResponder != null &&
            responderWifiAwareHandle != null;

    if (!shouldUpgrade) {
      return (
        initiator: UpgradeSyncOutcome(
          bleResult: bleResA,
          upgradedToWifiAware: false,
          wifiAwareTornDown: false,
        ),
        responder: UpgradeSyncOutcome(
          bleResult: bleResB,
          upgradedToWifiAware: false,
          wifiAwareTornDown: false,
        ),
      );
    }

    // Stage 2: Upgrade to Wi-Fi Aware bulk session
    try {
      await wifiAwareResponder.startAdvertising(sessionToken);
      await wifiAwareInitiator.startScanning();

      final incomingFuture = wifiAwareResponder.incoming.first;
      final awareLinkA = await wifiAwareInitiator.connect(
        PeerAdvert(
          peerAddress: responderWifiAwareHandle,
          token: sessionToken,
          rssi: -52,
        ),
      );
      final awareLinkB = await incomingFuture;

      final awareSmA = SessionStateMachine(
        store: storeInitiator,
        link: awareLinkA,
        isInitiator: true,
        staticKeyPair: noiseKeyPairInitiator,
        localCert: certInitiator,
        pinnedServerKey: pinnedServerKey,
        expectedGroupId: expectedGroupId,
        clock: clock,
        transferAttachments: true,
        upgradeThresholdBytes: upgradeThresholdBytes,
      );

      final awareSmB = SessionStateMachine(
        store: storeResponder,
        link: awareLinkB,
        isInitiator: false,
        staticKeyPair: noiseKeyPairResponder,
        localCert: certResponder,
        pinnedServerKey: pinnedServerKey,
        expectedGroupId: expectedGroupId,
        clock: clock,
        transferAttachments: true,
        upgradeThresholdBytes: upgradeThresholdBytes,
      );

      final awareResults = await Future.wait([awareSmA.run(), awareSmB.run()]);
      final awareResA = awareResults[0];
      final awareResB = awareResults[1];

      // Stage 3: Mandatory teardown after transfer completes
      await wifiAwareInitiator.teardownAfterTransfer();
      await wifiAwareResponder.teardownAfterTransfer();

      final tornDown = !wifiAwareInitiator.isPublishing &&
          !wifiAwareInitiator.isSubscribing &&
          wifiAwareInitiator.activeLinks.isEmpty &&
          !wifiAwareResponder.isPublishing &&
          !wifiAwareResponder.isSubscribing &&
          wifiAwareResponder.activeLinks.isEmpty;

      return (
        initiator: UpgradeSyncOutcome(
          bleResult: bleResA,
          wifiAwareResult: awareResA,
          upgradedToWifiAware: true,
          wifiAwareTornDown: tornDown,
        ),
        responder: UpgradeSyncOutcome(
          bleResult: bleResB,
          wifiAwareResult: awareResB,
          upgradedToWifiAware: true,
          wifiAwareTornDown: tornDown,
        ),
      );
    } finally {
      await wifiAwareInitiator.teardownAfterTransfer();
      await wifiAwareResponder.teardownAfterTransfer();
    }
  }
}
