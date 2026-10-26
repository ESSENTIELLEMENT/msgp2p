import 'dart:typed_data';
import 'package:crypto/crypto.dart' as standard_crypto;
import 'package:cryptography/cryptography.dart' as cg;
import '../model/certificate.dart';

/// RFC 5869 HKDF using SHA-256 for Noise protocol key derivation.
class NoiseHkdf {
  NoiseHkdf._();

  /// Extracts a pseudorandom key (PRK) from [salt] and [ikm].
  static Uint8List extract(Uint8List salt, Uint8List ikm) {
    final effectiveSalt = salt.isEmpty ? Uint8List(32) : salt;
    final hmac = standard_crypto.Hmac(standard_crypto.sha256, effectiveSalt);
    return Uint8List.fromList(hmac.convert(ikm).bytes);
  }

  /// Expands [prk] to produce two 32-byte keys [output1, output2].
  static List<Uint8List> expand2(Uint8List prk, [Uint8List? info]) {
    final infoBytes = info ?? Uint8List(0);
    final hmac = standard_crypto.Hmac(standard_crypto.sha256, prk);

    // T(1) = HMAC-Hash(PRK, info || 0x01)
    final bb1 = BytesBuilder(copy: false)
      ..add(infoBytes)
      ..addByte(0x01);
    final t1 = Uint8List.fromList(hmac.convert(bb1.toBytes()).bytes);

    // T(2) = HMAC-Hash(PRK, T(1) || info || 0x02)
    final bb2 = BytesBuilder(copy: false)
      ..add(t1)
      ..add(infoBytes)
      ..addByte(0x02);
    final t2 = Uint8List.fromList(hmac.convert(bb2.toBytes()).bytes);

    return [t1, t2];
  }
}

/// Cipher state using ChaCha20-Poly1305 with uint64 little-endian nonce.
class NoiseCipherState {
  static final cg.Cipher _cipher = cg.Chacha20.poly1305Aead();

  final Uint8List? key;
  int nonce = 0;

  NoiseCipherState([this.key]);

  bool get hasKey => key != null;

  Uint8List _formatNonce(int n) {
    final nBytes = Uint8List(12);
    ByteData.sublistView(nBytes).setUint64(4, n, Endian.little);
    return nBytes;
  }

  /// Encrypts [plaintext] with associated data [ad], incrementing nonce.
  Future<Uint8List> encryptWithAd(Uint8List ad, Uint8List plaintext) async {
    if (key == null) return plaintext;
    if (nonce > 0x7FFFFFFFFFFFFFFF) {
      throw StateError('Noise cipher nonce overflow');
    }

    final nonceBytes = _formatNonce(nonce++);
    final secretBox = await _cipher.encrypt(
      plaintext,
      secretKey: cg.SecretKey(key!),
      nonce: nonceBytes,
      aad: ad,
    );

    final bb = BytesBuilder(copy: false)
      ..add(secretBox.cipherText)
      ..add(secretBox.mac.bytes);
    return bb.toBytes();
  }

  /// Decrypts [ciphertext] with associated data [ad], incrementing nonce.
  Future<Uint8List> decryptWithAd(Uint8List ad, Uint8List ciphertext) async {
    if (key == null) return ciphertext;
    if (ciphertext.length < 16) {
      throw ArgumentError('Ciphertext too short (must include 16-byte MAC)');
    }
    if (nonce > 0x7FFFFFFFFFFFFFFF) {
      throw StateError('Noise cipher nonce overflow');
    }

    final nonceBytes = _formatNonce(nonce++);
    final cipherLen = ciphertext.length - 16;
    final cipherTextOnly = ciphertext.sublist(0, cipherLen);
    final macBytes = ciphertext.sublist(cipherLen);

    final secretBox = cg.SecretBox(
      cipherTextOnly,
      nonce: nonceBytes,
      mac: cg.Mac(macBytes),
    );

    final decrypted = await _cipher.decrypt(
      secretBox,
      secretKey: cg.SecretKey(key!),
      aad: ad,
    );

    return Uint8List.fromList(decrypted);
  }
}

/// Established authenticated Noise session holding symmetric transport ciphers.
class NoiseSession {
  final NoiseCipherState txCipher;
  final NoiseCipherState rxCipher;
  final MembershipCert peerCert;
  final Uint8List peerStaticPubkey;

  NoiseSession({
    required this.txCipher,
    required this.rxCipher,
    required this.peerCert,
    required this.peerStaticPubkey,
  });

  /// Encrypts an outgoing session payload frame.
  Future<Uint8List> encrypt(Uint8List plaintext) =>
      txCipher.encryptWithAd(Uint8List(0), plaintext);

  /// Decrypts an incoming session payload frame.
  Future<Uint8List> decrypt(Uint8List ciphertext) =>
      rxCipher.decryptWithAd(Uint8List(0), ciphertext);
}
