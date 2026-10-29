import 'dart:typed_data';
import 'package:convert/convert.dart';
import 'package:meta/meta.dart';
import '../model/certificate.dart';
import '../storage/message_store.dart';

/// Active group membership context on a multi-tenant device.
@immutable
class GroupMembership {
  /// 16-byte UUID of the group.
  final Uint8List groupId;

  /// Membership certificate signed by the server authority.
  final MembershipCert cert;

  /// 32-byte shared beacon key for generating rotating BLE advertising tokens.
  final Uint8List groupBeaconKey;

  /// Active encryption keys indexed by epoch.
  final Map<int, Uint8List> groupKeysByEpoch;

  /// The active key epoch used for new message authoring.
  final int activeEpoch;

  /// The dedicated [MessageStore] for this group.
  final MessageStore store;

  GroupMembership({
    required this.groupId,
    required this.cert,
    required this.groupBeaconKey,
    required this.store,
    Map<int, Uint8List>? groupKeysByEpoch,
    this.activeEpoch = 1,
  }) : groupKeysByEpoch = groupKeysByEpoch ?? {};

  /// Hex representation of [groupId].
  String get groupIdHex => hex.encode(groupId).toLowerCase();

  /// Retrieves the active group encryption key for [activeEpoch].
  Uint8List? get activeGroupKey => groupKeysByEpoch[activeEpoch];
}
