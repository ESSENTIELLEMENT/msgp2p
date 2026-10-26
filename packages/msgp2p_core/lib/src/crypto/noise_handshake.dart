import 'dart:convert';
import 'dart:typed_data';
import 'package:crypto/crypto.dart' as standard_crypto;
import 'package:cryptography/cryptography.dart' as cg;
import '../model/certificate.dart';
import 'noise.dart';

/// Exception thrown when cryptographic or certificate verification fails during handshake.
class SecurityException implements Exception {
  final String message;
  const SecurityException(this.message);

  @override
  String toString() => 'SecurityException: $message';
}

/// Constant protocol identifier for Noise_XX pattern over Curve25519, ChaCha20-Poly1305 and SHA-256.
const String noiseXxProtocolName = 'Noise_XX_25519_ChaChaPoly_SHA256';

/// Implements the Noise-XX mutually authenticated handshake bound to server-signed
/// membership certificates per protocol/wire-format.md §7.1 and FR-SEC-06.
class NoiseHandshake {
  static final cg.X25519 _x25519 = cg.X25519();

  NoiseHandshake._();

  static Future<Uint8List> _dh(
      cg.SimpleKeyPair keyPair, Uint8List remotePkBytes) async {
    final remotePk =
        cg.SimplePublicKey(remotePkBytes, type: cg.KeyPairType.x25519);
    final secret = await _x25519.sharedSecretKey(
        keyPair: keyPair, remotePublicKey: remotePk);
    final bytes = await secret.extractBytes();
    return Uint8List.fromList(bytes);
  }

  static Future<Uint8List> getPublicKeyBytes(cg.SimpleKeyPair kp) async {
    final pk = await kp.extractPublicKey();
    return Uint8List.fromList(pk.bytes);
  }

  static bool _constantTimeEquals(Uint8List a, Uint8List b) {
    if (a.length != b.length) return false;
    var result = 0;
    for (var i = 0; i < a.length; i++) {
      result |= a[i] ^ b[i];
    }
    return result == 0;
  }

  static Future<MembershipCert> _verifyPeerCert({
    required Uint8List payloadBytes,
    required Uint8List peerStaticPk,
    required Uint8List expectedGroupId,
    required Uint8List pinnedServerKey,
    int? currentTimeMillis,
  }) async {
    final cert = MembershipCert.fromCbor(payloadBytes);

    if (!_constantTimeEquals(cert.noisePubkey, peerStaticPk)) {
      throw const SecurityException(
          'Peer static public key does not match membership certificate noise_pubkey');
    }

    if (!_constantTimeEquals(cert.groupId, expectedGroupId)) {
      throw const SecurityException('Peer belongs to different group');
    }

    if (cert.isExpired(currentTimeMillis)) {
      throw const SecurityException('Peer membership certificate is expired');
    }

    final isValidSig = await cert.verify(pinnedServerKey);
    if (!isValidSig) {
      throw const SecurityException(
          'Peer membership certificate signature is invalid');
    }

    return cert;
  }

  /// Initiator handshake session state.
  static Future<NoiseInitiatorState> startInitiator({
    required cg.SimpleKeyPair staticKeyPair,
    required MembershipCert localCert,
    required Uint8List pinnedServerKey,
    required Uint8List expectedGroupId,
    cg.SimpleKeyPair? ephemeralKeyPair,
  }) async {
    final e = ephemeralKeyPair ?? await _x25519.newKeyPair();
    final state = NoiseInitiatorState._(
      staticKeyPair: staticKeyPair,
      ephemeralKeyPair: e,
      localCert: localCert,
      pinnedServerKey: pinnedServerKey,
      expectedGroupId: expectedGroupId,
    );
    await state._init();
    return state;
  }

  /// Responder handshake session state.
  static Future<NoiseResponderState> startResponder({
    required cg.SimpleKeyPair staticKeyPair,
    required MembershipCert localCert,
    required Uint8List pinnedServerKey,
    required Uint8List expectedGroupId,
    cg.SimpleKeyPair? ephemeralKeyPair,
  }) async {
    final e = ephemeralKeyPair ?? await _x25519.newKeyPair();
    final state = NoiseResponderState._(
      staticKeyPair: staticKeyPair,
      ephemeralKeyPair: e,
      localCert: localCert,
      pinnedServerKey: pinnedServerKey,
      expectedGroupId: expectedGroupId,
    );
    await state._init();
    return state;
  }
}

/// Initiator side of Noise-XX handshake.
class NoiseInitiatorState {
  final cg.SimpleKeyPair staticKeyPair;
  final cg.SimpleKeyPair ephemeralKeyPair;
  final MembershipCert localCert;
  final Uint8List pinnedServerKey;
  final Uint8List expectedGroupId;

  late Uint8List _h;
  late Uint8List _ck;
  NoiseCipherState _cipher = NoiseCipherState();

  NoiseInitiatorState._({
    required this.staticKeyPair,
    required this.ephemeralKeyPair,
    required this.localCert,
    required this.pinnedServerKey,
    required this.expectedGroupId,
  });

  Future<void> _init() async {
    final pNameBytes = utf8.encode(noiseXxProtocolName);
    _h = Uint8List.fromList(standard_crypto.sha256.convert(pNameBytes).bytes);
    _ck = Uint8List.fromList(_h);
  }

  void _mixHash(Uint8List data) {
    final bb = BytesBuilder(copy: false)
      ..add(_h)
      ..add(data);
    _h = Uint8List.fromList(standard_crypto.sha256.convert(bb.toBytes()).bytes);
  }

  void _mixKey(Uint8List dhOutput) {
    final keys = NoiseHkdf.expand2(NoiseHkdf.extract(_ck, dhOutput));
    _ck = keys[0];
    _cipher = NoiseCipherState(keys[1]);
  }

  /// Message 1: -> e
  Future<Uint8List> createMessage1() async {
    final ePk = await NoiseHandshake.getPublicKeyBytes(ephemeralKeyPair);
    _mixHash(ePk);
    final payload = await _cipher.encryptWithAd(_h, Uint8List(0));
    _mixHash(payload);

    final bb = BytesBuilder(copy: false)
      ..add(ePk)
      ..add(payload);
    return bb.toBytes();
  }

  /// Processes Message 2 (<- e, ee, s, es, payload) and creates Message 3 (-> s, se, payload).
  Future<NoiseInitiatorStepResult> processMessage2AndCreateMessage3(
    Uint8List msg2Bytes, {
    int? currentTimeMillis,
  }) async {
    if (msg2Bytes.length < 32 + 48 + 16) {
      throw const SecurityException('Message 2 payload is too short');
    }

    // 1. Read e
    final re = msg2Bytes.sublist(0, 32);
    _mixHash(re);

    // 2. ee
    final ee = await NoiseHandshake._dh(ephemeralKeyPair, re);
    _mixKey(ee);

    // 3. s
    final encryptedS = msg2Bytes.sublist(32, 80);
    final rs = await _cipher.decryptWithAd(_h, encryptedS);
    _mixHash(encryptedS);

    // 4. es
    final es = await NoiseHandshake._dh(ephemeralKeyPair, rs);
    _mixKey(es);

    // 5. payload (responder cert)
    final encryptedPayload = msg2Bytes.sublist(80);
    final payloadBytes = await _cipher.decryptWithAd(_h, encryptedPayload);
    _mixHash(encryptedPayload);

    // 6. Verify responder certificate
    final peerCert = await NoiseHandshake._verifyPeerCert(
      payloadBytes: payloadBytes,
      peerStaticPk: rs,
      expectedGroupId: expectedGroupId,
      pinnedServerKey: pinnedServerKey,
      currentTimeMillis: currentTimeMillis,
    );

    // Now construct Message 3: -> s, se, payload
    // 7. Encrypt static key
    final sPk = await NoiseHandshake.getPublicKeyBytes(staticKeyPair);
    final encS = await _cipher.encryptWithAd(_h, sPk);
    _mixHash(encS);

    // 8. se
    final se = await NoiseHandshake._dh(staticKeyPair, re);
    _mixKey(se);

    // 9. Encrypt payload (initiator cert)
    final encPayload = await _cipher.encryptWithAd(_h, localCert.toFullCbor());
    _mixHash(encPayload);

    // Message 3 wire bytes
    final msg3Builder = BytesBuilder(copy: false)
      ..add(encS)
      ..add(encPayload);
    final msg3Bytes = msg3Builder.toBytes();

    // 10. Split into transport ciphers
    final splitKeys = NoiseHkdf.expand2(NoiseHkdf.extract(_ck, Uint8List(0)));
    final session = NoiseSession(
      txCipher: NoiseCipherState(splitKeys[0]), // Initiator TX = k1
      rxCipher: NoiseCipherState(splitKeys[1]), // Initiator RX = k2
      peerCert: peerCert,
      peerStaticPubkey: rs,
    );

    return NoiseInitiatorStepResult(
      message3Bytes: msg3Bytes,
      session: session,
    );
  }
}

class NoiseInitiatorStepResult {
  final Uint8List message3Bytes;
  final NoiseSession session;

  NoiseInitiatorStepResult({
    required this.message3Bytes,
    required this.session,
  });
}

/// Responder side of Noise-XX handshake.
class NoiseResponderState {
  final cg.SimpleKeyPair staticKeyPair;
  final cg.SimpleKeyPair ephemeralKeyPair;
  final MembershipCert localCert;
  final Uint8List pinnedServerKey;
  final Uint8List expectedGroupId;

  late Uint8List _h;
  late Uint8List _ck;
  NoiseCipherState _cipher = NoiseCipherState();
  Uint8List? _initiatorEphemeralPk;

  NoiseResponderState._({
    required this.staticKeyPair,
    required this.ephemeralKeyPair,
    required this.localCert,
    required this.pinnedServerKey,
    required this.expectedGroupId,
  });

  Future<void> _init() async {
    final pNameBytes = utf8.encode(noiseXxProtocolName);
    _h = Uint8List.fromList(standard_crypto.sha256.convert(pNameBytes).bytes);
    _ck = Uint8List.fromList(_h);
  }

  void _mixHash(Uint8List data) {
    final bb = BytesBuilder(copy: false)
      ..add(_h)
      ..add(data);
    _h = Uint8List.fromList(standard_crypto.sha256.convert(bb.toBytes()).bytes);
  }

  void _mixKey(Uint8List dhOutput) {
    final keys = NoiseHkdf.expand2(NoiseHkdf.extract(_ck, dhOutput));
    _ck = keys[0];
    _cipher = NoiseCipherState(keys[1]);
  }

  /// Processes Message 1 (-> e, payload) and creates Message 2 (<- e, ee, s, es, payload).
  Future<Uint8List> processMessage1AndCreateMessage2(
      Uint8List msg1Bytes) async {
    if (msg1Bytes.length < 32) {
      throw const SecurityException('Message 1 payload is too short');
    }

    // 1. Read e
    _initiatorEphemeralPk = msg1Bytes.sublist(0, 32);
    _mixHash(_initiatorEphemeralPk!);

    // Payload (empty in msg1)
    final encryptedPayload = msg1Bytes.sublist(32);
    await _cipher.decryptWithAd(_h, encryptedPayload);
    _mixHash(encryptedPayload);

    // Construct Message 2: <- e, ee, s, es, payload
    // 2. Generate e
    final ePk = await NoiseHandshake.getPublicKeyBytes(ephemeralKeyPair);
    _mixHash(ePk);

    // 3. ee
    final ee =
        await NoiseHandshake._dh(ephemeralKeyPair, _initiatorEphemeralPk!);
    _mixKey(ee);

    // 4. s
    final sPk = await NoiseHandshake.getPublicKeyBytes(staticKeyPair);
    final encS = await _cipher.encryptWithAd(_h, sPk);
    _mixHash(encS);

    // 5. es
    final es = await NoiseHandshake._dh(staticKeyPair, _initiatorEphemeralPk!);
    _mixKey(es);

    // 6. payload (responder cert)
    final encPayload = await _cipher.encryptWithAd(_h, localCert.toFullCbor());
    _mixHash(encPayload);

    final bb = BytesBuilder(copy: false)
      ..add(ePk)
      ..add(encS)
      ..add(encPayload);
    return bb.toBytes();
  }

  /// Processes Message 3 (-> s, se, payload) and establishes [NoiseSession].
  Future<NoiseSession> processMessage3(
    Uint8List msg3Bytes, {
    int? currentTimeMillis,
  }) async {
    if (msg3Bytes.length < 48 + 16) {
      throw const SecurityException('Message 3 payload is too short');
    }
    if (_initiatorEphemeralPk == null) {
      throw StateError(
          'processMessage1AndCreateMessage2 must be called before processMessage3');
    }

    // 1. Decrypt s
    final encS = msg3Bytes.sublist(0, 48);
    final rs = await _cipher.decryptWithAd(_h, encS);
    _mixHash(encS);

    // 2. se
    final se = await NoiseHandshake._dh(ephemeralKeyPair, rs);
    _mixKey(se);

    // 3. payload (initiator cert)
    final encPayload = msg3Bytes.sublist(48);
    final payloadBytes = await _cipher.decryptWithAd(_h, encPayload);
    _mixHash(encPayload);

    // 4. Verify initiator certificate
    final peerCert = await NoiseHandshake._verifyPeerCert(
      payloadBytes: payloadBytes,
      peerStaticPk: rs,
      expectedGroupId: expectedGroupId,
      pinnedServerKey: pinnedServerKey,
      currentTimeMillis: currentTimeMillis,
    );

    // 5. Split into transport ciphers
    final splitKeys = NoiseHkdf.expand2(NoiseHkdf.extract(_ck, Uint8List(0)));
    return NoiseSession(
      txCipher: NoiseCipherState(splitKeys[1]), // Responder TX = k2
      rxCipher: NoiseCipherState(splitKeys[0]), // Responder RX = k1
      peerCert: peerCert,
      peerStaticPubkey: rs,
    );
  }
}
