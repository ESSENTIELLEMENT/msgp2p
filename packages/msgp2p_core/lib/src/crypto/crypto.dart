import 'dart:typed_data';
import 'package:crypto/crypto.dart' as standard_crypto;
import 'package:cryptography/cryptography.dart' as cg;

/// Cryptographic services for msgp2p.
class MsgP2PCrypto {
  MsgP2PCrypto._();

  static final cg.Ed25519 _ed25519 = cg.Ed25519();
  static final cg.Cipher _aead = cg.Xchacha20.poly1305Aead();

  /// Computes SHA-256 hash.
  static Uint8List sha256(Uint8List data) {
    final digest = standard_crypto.sha256.convert(data);
    return Uint8List.fromList(digest.bytes);
  }

  /// Derives an Ed25519 keypair from a 32-byte seed.
  static Future<cg.SimpleKeyPair> newKeyPairFromSeed(Uint8List seed) async {
    return _ed25519.newKeyPairFromSeed(seed);
  }

  /// Extracts the 32-byte public key from an Ed25519 keypair.
  static Future<Uint8List> getPublicKeyBytes(cg.SimpleKeyPair keyPair) async {
    final pk = await keyPair.extractPublicKey();
    return Uint8List.fromList(pk.bytes);
  }

  /// Signs [message] using an Ed25519 keypair.
  /// Returns a 64-byte detached signature.
  static Future<Uint8List> sign(
      Uint8List message, cg.SimpleKeyPair keyPair) async {
    final signature = await _ed25519.sign(message, keyPair: keyPair);
    return Uint8List.fromList(signature.bytes);
  }

  /// Verifies an Ed25519 [signature] against [message] and [publicKeyBytes].
  static Future<bool> verifySignature({
    required Uint8List message,
    required Uint8List signature,
    required Uint8List publicKeyBytes,
  }) async {
    try {
      final sigObj = cg.Signature(
        signature,
        publicKey:
            cg.SimplePublicKey(publicKeyBytes, type: cg.KeyPairType.ed25519),
      );
      return await _ed25519.verify(message, signature: sigObj);
    } catch (_) {
      return false;
    }
  }

  /// Encrypts [plaintext] using XChaCha20-Poly1305.
  ///
  /// Returns standard libsodium-compatible ciphertext with the 16-byte Poly1305 tag appended.
  static Future<Uint8List> encryptPayload({
    required Uint8List plaintext,
    required Uint8List secretKey,
    required Uint8List nonce, // 24 bytes
    required Uint8List aad,
  }) async {
    final secretKeyObj = cg.SecretKey(secretKey);
    final secretBox = await _aead.encrypt(
      plaintext,
      secretKey: secretKeyObj,
      nonce: nonce,
      aad: aad,
    );

    final result = BytesBuilder(copy: false)
      ..add(secretBox.cipherText)
      ..add(secretBox.mac.bytes);
    return result.toBytes();
  }

  /// Decrypts [ciphertextWithMac] (with 16-byte Poly1305 tag at the end).
  static Future<Uint8List> decryptPayload({
    required Uint8List ciphertextWithMac,
    required Uint8List secretKey,
    required Uint8List nonce, // 24 bytes
    required Uint8List aad,
  }) async {
    if (ciphertextWithMac.length < 16) {
      throw ArgumentError('Ciphertext is too short (must include 16-byte MAC)');
    }
    final cipherTextLen = ciphertextWithMac.length - 16;
    final cipherText = ciphertextWithMac.sublist(0, cipherTextLen);
    final macBytes = ciphertextWithMac.sublist(cipherTextLen);

    final secretBox = cg.SecretBox(
      cipherText,
      nonce: nonce,
      mac: cg.Mac(macBytes),
    );

    final decrypted = await _aead.decrypt(
      secretBox,
      secretKey: cg.SecretKey(secretKey),
      aad: aad,
    );
    return Uint8List.fromList(decrypted);
  }

  /// Computes the 16-byte anonymous rotating BLE beacon token.
  static Uint8List calculateBeaconToken({
    required Uint8List groupBeaconKey,
    required int timestampSeconds,
    int rotationIntervalSeconds = 900,
  }) {
    final window = timestampSeconds ~/ rotationIntervalSeconds;
    final bdata = ByteData(4)..setUint32(0, window, Endian.big);
    final windowBytes = bdata.buffer.asUint8List();

    final hmac = standard_crypto.Hmac(standard_crypto.sha256, groupBeaconKey);
    final digest = hmac.convert(windowBytes);
    return Uint8List.fromList(digest.bytes.sublist(0, 16));
  }
}
