import 'dart:typed_data';

import '../storage/message_store.dart';

/// Why [guardStoreIdentity] refused to let this node author.
enum UnsynchronizedIdentityReason {
  /// The vault holds an existing identity but the store has no owner (the store was wiped or replaced).
  storeEmpty,

  /// The vault holds an existing identity and the store belongs to a different one.
  ownerMismatch,
}

/// The vault and the store disagree about who this node is. Authoring now could reuse `(author, seq)` pairs
/// that peers already hold with different content. The host either restores the store that belongs to this
/// identity, or calls `KeyVault.erase()` for a new identity (new certificate, `seq` from 1). Discussion #10.
class UnsynchronizedIdentityException implements Exception {
  final UnsynchronizedIdentityReason reason;

  const UnsynchronizedIdentityException(this.reason);

  @override
  String toString() => 'UnsynchronizedIdentityException: ${reason.name}';
}

/// Checks that [store] belongs to the identity [ownerPubkey] before the node authors, and returns the last
/// sequence number this identity used (0 for none). [created] says whether the vault created the identity
/// just now.
///
/// | vault       | store owner   | result                                                         |
/// | ----------- | ------------- | -------------------------------------------------------------- |
/// | created     | none          | the store records the owner; `seq` starts at 1                 |
/// | existing    | same key      | normal                                                         |
/// | existing    | none          | [UnsynchronizedIdentityException] (`storeEmpty`)               |
/// | existing    | another key   | [UnsynchronizedIdentityException] (`ownerMismatch`)            |
/// | created     | another key   | adopted: the owner becomes the new key and `seq` starts again; |
/// |             |               | the old author's envelopes stay as relayed copies              |
///
/// The store keeps the counter and raises it in the same transaction that stores an own envelope
/// (`MessageStore.saveOwnEnvelope`), so it is never lower than a sequence that left the device.
Future<int> guardStoreIdentity({
  required MessageStore store,
  required Uint8List ownerPubkey,
  required bool created,
}) async {
  final owner = await store.getOwnerPubkey();
  if (owner == null) {
    if (!created)
      throw const UnsynchronizedIdentityException(
          UnsynchronizedIdentityReason.storeEmpty);
    await store.setOwner(ownerPubkey);
    return 0;
  }
  if (!_bytesEqual(owner, ownerPubkey)) {
    if (!created)
      throw const UnsynchronizedIdentityException(
          UnsynchronizedIdentityReason.ownerMismatch);
    await store.setOwner(ownerPubkey);
    return 0;
  }
  return store.getAuthorSeq();
}

bool _bytesEqual(Uint8List a, Uint8List b) {
  if (a.length != b.length) return false;
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}
