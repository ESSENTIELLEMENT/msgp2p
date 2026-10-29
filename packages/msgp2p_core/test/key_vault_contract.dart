import 'package:msgp2p_core/msgp2p_core.dart';
import 'package:test/test.dart';

/// The `KeyVault` contract (Discussion #10). Every vault implementation runs it with a factory that returns a
/// new, empty vault; [reopen] returns another vault object over the same storage (null for in-memory vaults,
/// whose identity lasts only as long as the object).
void runKeyVaultContractTests(
  String name,
  KeyVault Function() create, {
  KeyVault Function(KeyVault original)? reopen,
}) {
  group('KeyVault contract ($name)', () {
    test(
        'the first call creates 32-byte seeds; later calls return the same ones',
        () async {
      final vault = create();
      final first = await vault.loadOrCreate();
      expect(first.created, isTrue);
      expect(first.seeds.version, 1);
      expect(first.seeds.signing, hasLength(32));
      expect(first.seeds.noise, hasLength(32));

      final second = await vault.loadOrCreate();
      expect(second.created, isFalse);
      expect(second.seeds.signing, first.seeds.signing);
      expect(second.seeds.noise, first.seeds.noise);
    });

    test('ten concurrent first calls create one identity', () async {
      final vault = create();
      final results =
          await Future.wait(List.generate(10, (_) => vault.loadOrCreate()));
      expect(results.where((r) => r.created), hasLength(1));
      for (final r in results) {
        expect(r.seeds.signing, results.first.seeds.signing);
        expect(r.seeds.noise, results.first.seeds.noise);
      }
    });

    test('erase, then a new identity', () async {
      final vault = create();
      final before = await vault.loadOrCreate();
      await vault.erase();
      final after = await vault.loadOrCreate();
      expect(after.created, isTrue);
      expect(after.seeds.signing, isNot(before.seeds.signing));
    });

    test('erasing an empty vault is harmless', () async {
      final vault = create();
      await vault.erase();
      expect((await vault.loadOrCreate()).created, isTrue);
    });

    if (reopen != null) {
      test('the identity survives reopening the storage', () async {
        final vault = create();
        final first = await vault.loadOrCreate();
        final again = await reopen(vault).loadOrCreate();
        expect(again.created, isFalse);
        expect(again.seeds.signing, first.seeds.signing);
        expect(again.seeds.noise, first.seeds.noise);
      });
    }
  });
}
