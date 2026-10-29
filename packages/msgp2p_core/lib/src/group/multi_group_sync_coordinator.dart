import 'dart:typed_data';
import 'package:cryptography/cryptography.dart' as cg;
import '../sync/clock_rules.dart';
import '../sync/session_state_machine.dart';
import '../transport/transport.dart';
import 'group_membership.dart';

/// Orchestrates sequential group synchronization sessions over a persistent [PeerLink].
class MultiGroupSyncCoordinator {
  final cg.SimpleKeyPair staticKeyPair;
  final Uint8List pinnedServerKey;
  final Clock clock;

  MultiGroupSyncCoordinator({
    required this.staticKeyPair,
    required this.pinnedServerKey,
    this.clock = const SystemClock(),
  });

  /// Synchronizes multiple shared [groups] sequentially across a single open [link].
  ///
  /// Reuses the physical connection pipe for each group, avoiding radio teardown and setup overhead.
  /// Automatically closes [link] after all groups are synchronized or upon error.
  Future<List<SessionSyncResult>> syncAcrossSharedGroups({
    required PeerLink link,
    required bool isInitiator,
    required List<GroupMembership> groups,
    Duration? frameTimeout,
  }) async {
    final results = <SessionSyncResult>[];
    final effectiveTimeout = frameTimeout ??
        (link.mtu < 256
            ? const Duration(seconds: 45)
            : const Duration(seconds: 10));

    try {
      for (var i = 0; i < groups.length; i++) {
        if (link.isClosed) break;

        final group = groups[i];
        final isLast = i == groups.length - 1;

        final sm = SessionStateMachine(
          link: link,
          store: group.store,
          isInitiator: isInitiator,
          staticKeyPair: staticKeyPair,
          localCert: group.cert,
          pinnedServerKey: pinnedServerKey,
          expectedGroupId: group.groupId,
          clock: clock,
          frameTimeout: effectiveTimeout,
          closeLinkOnTermination: isLast,
        );

        final result = await sm.run();
        results.add(result);

        if (!result.completedSuccessfully || link.isClosed) {
          break;
        }
      }
    } finally {
      if (!link.isClosed) {
        await link.close('All groups synchronized');
      }
    }

    return results;
  }
}
