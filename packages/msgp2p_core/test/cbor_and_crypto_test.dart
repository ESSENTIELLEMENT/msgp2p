import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';
import 'package:convert/convert.dart';
import 'package:msgp2p_core/src/crypto/crypto.dart';
import 'package:msgp2p_core/src/encoding/canonical_cbor.dart';
import 'package:test/test.dart';

void main() {
  late Map<String, dynamic> cryptoKeys;
  late Map<String, dynamic> beaconTokens;
  late Map<String, dynamic> certs;
  late Map<String, dynamic> envelopes;

  setUpAll(() {
    // Locate protocol/test-vectors relative to package or project root
    var dir = Directory.current;
    while (!File('${dir.path}/protocol/test-vectors/crypto_keys.json')
        .existsSync()) {
      final parent = dir.parent;
      if (parent.path == dir.path) {
        throw StateError('Cannot find protocol/test-vectors/');
      }
      dir = parent;
    }
    final vDir = '${dir.path}/protocol/test-vectors';

    cryptoKeys = jsonDecode(File('$vDir/crypto_keys.json').readAsStringSync());
    beaconTokens =
        jsonDecode(File('$vDir/beacon_tokens.json').readAsStringSync());
    certs = jsonDecode(File('$vDir/membership_certs.json').readAsStringSync());
    envelopes = jsonDecode(File('$vDir/envelopes.json').readAsStringSync());
  });

  group('Cryptographic Keys & Derivation', () {
    test('Alice public key matches seed derivation', () async {
      final seed =
          Uint8List.fromList(hex.decode(cryptoKeys['alice']['seed_hex']));
      final kp = await MsgP2PCrypto.newKeyPairFromSeed(seed);
      final pk = await MsgP2PCrypto.getPublicKeyBytes(kp);
      expect(hex.encode(pk), equals(cryptoKeys['alice']['public_key_hex']));
    });

    test('Server public key matches seed derivation', () async {
      final seed =
          Uint8List.fromList(hex.decode(cryptoKeys['server']['seed_hex']));
      final kp = await MsgP2PCrypto.newKeyPairFromSeed(seed);
      final pk = await MsgP2PCrypto.getPublicKeyBytes(kp);
      expect(hex.encode(pk), equals(cryptoKeys['server']['public_key_hex']));
    });
  });

  group('BLE Beacon Tokens', () {
    test('Tokens match HMAC-SHA256 test fixtures across windows', () {
      final beaconKey =
          Uint8List.fromList(hex.decode(beaconTokens['group_beacon_key_hex']));
      final samples = beaconTokens['samples'] as List;

      for (final sample in samples) {
        final ts = sample['timestamp_seconds'] as int;
        final expectedHex = sample['token_16_bytes_hex'] as String;

        final token = MsgP2PCrypto.calculateBeaconToken(
          groupBeaconKey: beaconKey,
          timestampSeconds: ts,
        );

        expect(hex.encode(token), equals(expectedHex));
      }
    });
  });

  group('Membership Certificates & Canonical CBOR', () {
    test('Alice cert core CBOR and signature verify against server key',
        () async {
      final aliceCert = certs['alice'] as Map<String, dynamic>;
      final serverPk = Uint8List.fromList(
          hex.decode(cryptoKeys['server']['public_key_hex']));

      final certCoreMap = {
        'v': 1,
        'group_id': Uint8List.fromList(hex.decode(cryptoKeys['group_id_hex'])),
        'user_id': aliceCert['user_id'],
        'member_pubkey':
            Uint8List.fromList(hex.decode(aliceCert['member_pubkey_hex'])),
        'noise_pubkey':
            Uint8List.fromList(hex.decode(aliceCert['noise_pubkey_hex'])),
        'role': aliceCert['role'],
        'issued_at': aliceCert['issued_at'],
        'expires_at': aliceCert['expires_at'],
      };

      final encodedCore = CanonicalCbor.encode(certCoreMap);
      expect(hex.encode(encodedCore), equals(aliceCert['cert_core_cbor_hex']));

      final sig = Uint8List.fromList(hex.decode(aliceCert['server_sig_hex']));
      final valid = await MsgP2PCrypto.verifySignature(
        message: encodedCore,
        signature: sig,
        publicKeyBytes: serverPk,
      );
      expect(valid, isTrue);

      final fullCertMap = Map<String, dynamic>.from(certCoreMap)
        ..['server_sig'] = sig;
      final fullCertCbor = CanonicalCbor.encode(fullCertMap);
      expect(hex.encode(fullCertCbor), equals(aliceCert['full_cert_cbor_hex']));

      final certRef = MsgP2PCrypto.sha256(fullCertCbor);
      expect(hex.encode(certRef), equals(aliceCert['cert_ref_hex']));
    });
  });

  group('Encrypted Envelopes', () {
    test('Alice SOS envelope matches canonical CBOR, encryption, and signature',
        () async {
      final env = envelopes['envelope_sos_alice'] as Map<String, dynamic>;
      final groupKey =
          Uint8List.fromList(hex.decode(cryptoKeys['group_key_epoch_1_hex']));
      final authorPk = Uint8List.fromList(hex.decode(env['author']));

      // 1. Verify payload CBOR encoding
      final payload = env['payload'] as Map<String, dynamic>;
      final payloadCbor = CanonicalCbor.encode(payload);
      expect(hex.encode(payloadCbor), equals(env['payload_cbor_hex']));

      // 2. Decrypt ciphertext using XChaCha20-Poly1305
      final ciphertext = Uint8List.fromList(hex.decode(env['ciphertext_hex']));
      final nonce = Uint8List.fromList(hex.decode(env['nonce_hex']));
      final aad = Uint8List.fromList(hex.decode(env['aad_hex']));

      final decrypted = await MsgP2PCrypto.decryptPayload(
        ciphertextWithMac: ciphertext,
        secretKey: groupKey,
        nonce: nonce,
        aad: aad,
      );
      expect(hex.encode(decrypted), equals(env['payload_cbor_hex']));

      // 3. Verify envelope core CBOR
      final coreMap = {
        'v': 1,
        'group_id': Uint8List.fromList(hex.decode(cryptoKeys['group_id_hex'])),
        'key_epoch': 1,
        'author': authorPk,
        'seq': env['seq'],
        'created_at': 1773822001000,
        'expires_at': 1773822000000 + 86400000,
        'priority': env['priority'],
        'nonce': nonce,
        'ciphertext': ciphertext,
      };

      final coreCbor = CanonicalCbor.encode(coreMap);
      expect(hex.encode(coreCbor), equals(env['envelope_core_cbor_hex']));

      // 4. Verify message_id is SHA-256 of core
      final messageId = MsgP2PCrypto.sha256(coreCbor);
      expect(hex.encode(messageId), equals(env['message_id_hex']));

      // 5. Verify author's signature
      final sig = Uint8List.fromList(hex.decode(env['sig_hex']));
      final validSig = await MsgP2PCrypto.verifySignature(
        message: coreCbor,
        signature: sig,
        publicKeyBytes: authorPk,
      );
      expect(validSig, isTrue);

      // 6. Verify full envelope CBOR
      final certRef = Uint8List.fromList(hex.decode(env['cert_ref_hex']));
      final fullEnvMap = {
        'core': coreMap,
        'sig': sig,
        'cert_ref': certRef,
      };

      final fullEnvCbor = CanonicalCbor.encode(fullEnvMap);
      expect(hex.encode(fullEnvCbor), equals(env['full_envelope_cbor_hex']));
    });
  });
}
