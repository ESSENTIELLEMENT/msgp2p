import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:msgp2p_flutter/msgp2p_flutter.dart';

/// The native side as the plugins implement it: keep the stored bytes, else store the candidate.
class FakeNativeVault {
  final Map<String, Uint8List> stored = {};
  final List<String> calls = [];
  PlatformException? failWith;

  Future<Object?> handle(MethodCall call) async {
    final args = call.arguments as Map<Object?, Object?>;
    final name = args['name']! as String;
    calls.add('${call.method} $name');
    if (failWith != null) throw failWith!;
    switch (call.method) {
      case 'loadOrCreate':
        final existing = stored[name];
        if (existing != null) return {'seeds': existing, 'created': false};
        final candidate = args['candidate']! as Uint8List;
        stored[name] = candidate;
        return {'seeds': candidate, 'created': true};
      case 'erase':
        stored.remove(name);
        return null;
    }
    throw MissingPluginException();
  }
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  late FakeNativeVault native;
  final messenger =
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger;

  setUp(() {
    native = FakeNativeVault();
    messenger.setMockMethodCallHandler(
        PlatformKeyVault.defaultChannel, native.handle);
  });
  tearDown(() => messenger.setMockMethodCallHandler(
      PlatformKeyVault.defaultChannel, null));

  // The KeyVault contract (msgp2p_core test/key_vault_contract.dart), over the channel.
  group('KeyVault contract (PlatformKeyVault)', () {
    test('the first call creates 32-byte seeds; later calls return the same',
        () async {
      final vault = PlatformKeyVault();
      final first = await vault.loadOrCreate();
      expect(first.created, isTrue);
      expect(first.seeds.signing, hasLength(32));
      expect(first.seeds.noise, hasLength(32));
      final second = await vault.loadOrCreate();
      expect(second.created, isFalse);
      expect(second.seeds.signing, first.seeds.signing);
      expect(second.seeds.noise, first.seeds.noise);
    });

    test('ten concurrent first calls create one identity', () async {
      final vault = PlatformKeyVault();
      final results =
          await Future.wait(List.generate(10, (_) => vault.loadOrCreate()));
      expect(results.where((r) => r.created), hasLength(1));
      for (final r in results) {
        expect(r.seeds.signing, results.first.seeds.signing);
      }
    });

    test('erase, then a new identity', () async {
      final vault = PlatformKeyVault();
      final before = await vault.loadOrCreate();
      await vault.erase();
      final after = await vault.loadOrCreate();
      expect(after.created, isTrue);
      expect(after.seeds.signing, isNot(before.seeds.signing));
    });

    test('the identity survives reopening the storage', () async {
      final first = await PlatformKeyVault().loadOrCreate();
      final again = await PlatformKeyVault().loadOrCreate();
      expect(again.created, isFalse);
      expect(again.seeds.signing, first.seeds.signing);
    });
  });

  test('names are separate identities and are validated', () async {
    final a = await PlatformKeyVault(name: 'a').loadOrCreate();
    final b = await PlatformKeyVault(name: 'b').loadOrCreate();
    expect(a.seeds.signing, isNot(b.seeds.signing));
    for (final bad in ['', '../x', 'a/b', 'x' * 65]) {
      expect(() => PlatformKeyVault(name: bad), throwsArgumentError);
    }
  });

  test('native error codes map to the KeyVault errors', () async {
    native.failWith = PlatformException(code: 'UNAVAILABLE');
    await expectLater(PlatformKeyVault().loadOrCreate(),
        throwsA(isA<KeyVaultUnavailableError>()));
    native.failWith = PlatformException(code: 'CORRUPTED');
    await expectLater(PlatformKeyVault().loadOrCreate(),
        throwsA(isA<KeyVaultCorruptedError>()));
    native.failWith = PlatformException(code: 'LOCKED');
    await expectLater(
        PlatformKeyVault().loadOrCreate(), throwsA(isA<PlatformException>()));
  });

  test('a failed load is not cached', () async {
    final vault = PlatformKeyVault();
    native.failWith = PlatformException(code: 'LOCKED');
    await expectLater(vault.loadOrCreate(), throwsA(isA<PlatformException>()));
    native.failWith = null;
    expect((await vault.loadOrCreate()).created, isTrue);
  });

  test('malformed stored bytes are KeyVaultCorruptedError', () async {
    for (final bytes in [
      Uint8List(64),
      Uint8List(65), // version 0
      Uint8List(65)..[0] = 2,
    ]) {
      native.stored['default'] = bytes;
      await expectLater(PlatformKeyVault().loadOrCreate(),
          throwsA(isA<KeyVaultCorruptedError>()));
    }
  });

  test('encodeSeeds and decodeSeeds round-trip', () {
    final seeds = IdentitySeeds(
        signing: Uint8List(32)..fillRange(0, 32, 1),
        noise: Uint8List(32)..fillRange(0, 32, 2));
    final back =
        PlatformKeyVault.decodeSeeds(PlatformKeyVault.encodeSeeds(seeds));
    expect(back.signing, seeds.signing);
    expect(back.noise, seeds.noise);
  });

  test('MsgP2PNode-ready: the stored seeds are the ones returned', () async {
    final loaded = await PlatformKeyVault().loadOrCreate();
    expect(
        PlatformKeyVault.encodeSeeds(loaded.seeds), native.stored['default']);
  });
}
