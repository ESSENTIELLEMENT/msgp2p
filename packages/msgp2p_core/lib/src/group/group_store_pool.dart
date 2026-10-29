import 'dart:typed_data';
import 'package:convert/convert.dart';
import '../storage/memory_message_store.dart';
import '../storage/message_store.dart';
import '../storage/sqlite_message_store.dart';

/// Factory signature for initializing a [MessageStore] for a specific group.
typedef GroupStoreFactory = Future<MessageStore> Function(Uint8List groupId);

/// Manages a pool of isolated [MessageStore] instances implementing the Store-per-Group pattern.
class GroupStorePool {
  final GroupStoreFactory _factory;
  final Map<String, MessageStore> _stores = {};

  GroupStorePool({required GroupStoreFactory factory}) : _factory = factory;

  /// Creates an in-memory store pool (ideal for simulations and tests).
  factory GroupStorePool.inMemory() {
    return GroupStorePool(
      factory: (_) async => MemoryMessageStore(),
    );
  }

  /// Creates a pool backed by persistent SQLite databases in [baseDirectory].
  ///
  /// Stores are written to `$baseDirectory/messages_group_<groupIdHex>.db`.
  factory GroupStorePool.sqlite({
    required String baseDirectory,
    int maxStorageBytes = 100 * 1024 * 1024,
  }) {
    return GroupStorePool(
      factory: (groupId) async {
        final hexId = hex.encode(groupId).toLowerCase();
        final filePath = '$baseDirectory/messages_group_$hexId.db';
        return SqliteMessageStore.open(
          filePath,
          maxStorageBytes: maxStorageBytes,
        );
      },
    );
  }

  /// Retrieves or opens the [MessageStore] for [groupId].
  Future<MessageStore> getStore(Uint8List groupId) async {
    final hexId = hex.encode(groupId).toLowerCase();
    if (_stores.containsKey(hexId)) {
      return _stores[hexId]!;
    }
    final store = await _factory(groupId);
    _stores[hexId] = store;
    return store;
  }

  /// True if a store is currently open and cached in the pool for [groupId].
  bool hasStoreOpen(Uint8List groupId) {
    return _stores.containsKey(hex.encode(groupId).toLowerCase());
  }

  /// Closes and evicts the store for [groupId] from the pool.
  Future<void> closeStore(Uint8List groupId) async {
    final hexId = hex.encode(groupId).toLowerCase();
    final store = _stores.remove(hexId);
    if (store is SqliteMessageStore) {
      store.close();
    }
  }

  /// Closes all active stores in the pool.
  Future<void> closeAll() async {
    for (final store in _stores.values) {
      if (store is SqliteMessageStore) {
        store.close();
      }
    }
    _stores.clear();
  }
}
