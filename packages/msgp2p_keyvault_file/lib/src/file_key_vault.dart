import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:convert/convert.dart';
import 'package:msgp2p_core/msgp2p_core.dart';

/// A [KeyVault] in a file with mode 0600, for headless nodes (Linux CLI, gateways, on-board computers).
/// Proposal 0001, step 2 (Discussion #10).
///
/// - The file holds `{"v": 1, "signing": "<hex>", "noise": "<hex>"}`. It is created with mode 0600 before the
///   seeds are written, then moved into place with a rename, so a crash never leaves a half-written vault.
/// - One identity even with concurrent first calls: a lock per path inside the process, and an exclusive
///   lock on `<path>.lock` across processes (POSIX record locks do not exclude within one process).
/// - Unreadable or malformed contents throw [KeyVaultCorruptedError]; the file is left as it is.
/// - The seeds are protected by the file's permissions only (no keystore on such hosts). Keep the file on the
///   device: a copy on a second device would be the same identity there (see `KeyVault`).
/// - Windows has no POSIX modes; there the file gets the directory's default permissions.
class FileKeyVault implements KeyVault {
  final String path;
  final RandomSource _random;
  Future<KeyVaultLoad>? _loaded;

  FileKeyVault(this.path, {RandomSource? random})
      : _random = random ?? SystemRandomSource();

  static final Map<String, Future<void>> _pathLocks = {};

  @override
  Future<KeyVaultLoad> loadOrCreate() {
    final loaded = _loaded;
    if (loaded != null)
      return loaded.then((r) => (seeds: r.seeds, created: false));
    final future = _loaded = _locked(_loadOrCreateOnDisk);
    // A failed load (e.g. a corrupt file) is not cached, so the host can retry after fixing it.
    future.then((_) {}, onError: (Object _) {
      if (identical(_loaded, future)) _loaded = null;
    });
    return future;
  }

  @override
  Future<void> erase() async {
    _loaded = null;
    await _locked(() async {
      final file = File(path);
      if (!await file.exists()) return;
      // Best effort: overwrite before deleting (flash storage may keep old blocks).
      try {
        await file.writeAsBytes(Uint8List(await file.length()), flush: true);
      } on FileSystemException {
        // Deleting below is what counts.
      }
      await file.delete();
    });
  }

  Future<KeyVaultLoad> _loadOrCreateOnDisk() async {
    final file = File(path);
    if (await file.exists()) return (seeds: await _read(file), created: false);
    final seeds = IdentitySeeds.generate(_random);
    await _write(seeds);
    return (seeds: seeds, created: true);
  }

  static Future<IdentitySeeds> _read(File file) async {
    try {
      final json =
          jsonDecode(await file.readAsString()) as Map<String, dynamic>;
      final seeds = IdentitySeeds(
        version: json['v'] as int,
        signing: Uint8List.fromList(hex.decode(json['signing'] as String)),
        noise: Uint8List.fromList(hex.decode(json['noise'] as String)),
      );
      seeds.validate();
      return seeds;
    } on KeyVaultCorruptedError {
      rethrow;
    } catch (e) {
      throw KeyVaultCorruptedError(
          'cannot read ${file.path}: ${e.runtimeType}');
    }
  }

  Future<void> _write(IdentitySeeds seeds) async {
    final tmp = File('$path.tmp.$pid');
    await tmp.parent.create(recursive: true);
    await tmp.writeAsBytes(const [], flush: true);
    await _restrict(tmp.path); // before the seeds are in it
    await tmp.writeAsString(
      jsonEncode({
        'v': seeds.version,
        'signing': hex.encode(seeds.signing),
        'noise': hex.encode(seeds.noise)
      }),
      flush: true,
    );
    await tmp.rename(path);
  }

  /// chmod 600. Dart has no API for file modes, so the system's `chmod` does it.
  static Future<void> _restrict(String file) async {
    if (Platform.isWindows) return;
    final result = await Process.run('chmod', ['600', file]);
    if (result.exitCode != 0) {
      throw FileSystemException('chmod 600 failed (${result.exitCode})', file);
    }
  }

  /// Runs [action] alone for this path: after earlier calls in this process, holding `<path>.lock`.
  Future<T> _locked<T>(Future<T> Function() action) {
    final previous = _pathLocks[path] ?? Future<void>.value();
    final done = Completer<void>();
    _pathLocks[path] = done.future;
    return previous.then((_) async {
      final lockFile = File('$path.lock');
      await lockFile.parent.create(recursive: true);
      final raf = await lockFile.open(mode: FileMode.append);
      try {
        await raf.lock(FileLock.blockingExclusive);
        return await action();
      } finally {
        await raf.close(); // closing releases the lock
        done.complete();
        if (identical(_pathLocks[path], done.future)) _pathLocks.remove(path);
      }
    });
  }
}
