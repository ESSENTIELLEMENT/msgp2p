import 'dart:io';

import 'package:msgp2p_core/msgp2p_core.dart';
import 'package:msgp2p_keyvault_file/msgp2p_keyvault_file.dart';
import 'package:test/test.dart';

import '../../msgp2p_core/test/key_vault_contract.dart';

void main() {
  late Directory dir;
  var n = 0;

  setUp(
      () => dir = Directory.systemTemp.createTempSync('msgp2p_keyvault_file'));
  tearDown(() => dir.deleteSync(recursive: true));

  String nextPath() => '${dir.path}/vault${n++}/identity.json';

  runKeyVaultContractTests(
    'FileKeyVault',
    () => FileKeyVault(nextPath()),
    reopen: (vault) => FileKeyVault((vault as FileKeyVault).path),
  );

  test('the file has mode 0600 and no temporary file is left', () async {
    final path = nextPath();
    await FileKeyVault(path).loadOrCreate();
    expect(File(path).statSync().mode & 0x1FF, 0x180); // 0600
    expect(
        File(path)
            .parent
            .listSync()
            .map((e) => e.path)
            .where((p) => p.contains('.tmp.')),
        isEmpty);
  }, testOn: '!windows');

  test('a directory other users can write to is refused', () async {
    final path = nextPath();
    final vaultDir = File(path).parent..createSync(recursive: true);
    expect(Process.runSync('chmod', ['1777', vaultDir.path]).exitCode, 0);
    await expectLater(
        FileKeyVault(path).loadOrCreate(), throwsA(isA<FileSystemException>()));
    expect(vaultDir.listSync(), isEmpty, reason: 'nothing written');
  }, testOn: '!windows');

  test('a symlink in place of the vault is refused, not followed', () async {
    final path = nextPath();
    final planted = File('${dir.path}/planted.json')
      ..writeAsStringSync(
          '{"v": 1, "signing": "${'11' * 32}", "noise": "${'22' * 32}"}');
    File(path).parent.createSync(recursive: true);
    Link(path).createSync(planted.path);
    await expectLater(
        FileKeyVault(path).loadOrCreate(), throwsA(isA<FileSystemException>()));
  }, testOn: '!windows');

  test('a symlink in place of the lock file is refused', () async {
    final path = nextPath();
    final target = File('${dir.path}/elsewhere')..writeAsStringSync('');
    File(path).parent.createSync(recursive: true);
    Link('$path.lock').createSync(target.path);
    await expectLater(
        FileKeyVault(path).loadOrCreate(), throwsA(isA<FileSystemException>()));
    expect(File(path).existsSync(), isFalse);
  }, testOn: '!windows');

  test('two vault objects on one path create one identity', () async {
    final path = nextPath();
    final results = await Future.wait([
      for (var i = 0; i < 10; i++) FileKeyVault(path).loadOrCreate(),
    ]);
    expect(results.where((r) => r.created), hasLength(1));
    for (final r in results) {
      expect(r.seeds.signing, results.first.seeds.signing);
    }
  });

  for (final (name, contents) in [
    ('truncated', '{"v": 1, "signing": "00'),
    ('not JSON', 'garbage'),
    ('a short seed', '{"v": 1, "signing": "0011", "noise": "${'00' * 32}"}'),
    (
      'an unknown version',
      '{"v": 9, "signing": "${'00' * 32}", "noise": "${'00' * 32}"}'
    ),
  ]) {
    test('$name contents: KeyVaultCorruptedError, the file is kept', () async {
      final path = nextPath();
      File(path)
        ..parent.createSync(recursive: true)
        ..writeAsStringSync(contents);
      await expectLater(FileKeyVault(path).loadOrCreate(),
          throwsA(isA<KeyVaultCorruptedError>()));
      expect(File(path).readAsStringSync(), contents,
          reason: 'never silently replaced');
    });
  }

  test('after a corrupt read, erase gives a new identity', () async {
    final path = nextPath();
    File(path)
      ..parent.createSync(recursive: true)
      ..writeAsStringSync('garbage');
    final vault = FileKeyVault(path);
    await expectLater(
        vault.loadOrCreate(), throwsA(isA<KeyVaultCorruptedError>()));
    await vault.erase();
    expect((await vault.loadOrCreate()).created, isTrue);
  });
}
