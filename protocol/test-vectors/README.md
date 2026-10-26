# msgp2p Protocol Test Vectors

This directory contains deterministic test fixtures generated to guarantee cross-platform conformance between the pure-Dart engine (`msgp2p_core`), the reference server (`server/php`), and future backend adapters.

## Files Overview

| File | Description | Primitives Tested |
| :--- | :--- | :--- |
| [`crypto_keys.json`](crypto_keys.json) | Deterministic Ed25519 keypairs and symmetric secrets for Server, Alice, Bob, Charlie | Ed25519, SHA-256 |
| [`membership_certs.json`](membership_certs.json) | Server-signed membership certificates, raw CBOR, signature, and `cert_ref` hash | Canonical CBOR, Ed25519, SHA-256 |
| [`envelopes.json`](envelopes.json) | Encrypted message envelopes (SOS & BBS), AAD, nonces, ciphertexts, signatures, message IDs | XChaCha20-Poly1305, Ed25519, Canonical CBOR |
| [`server_receipts.json`](server_receipts.json) | Server receipts confirming delivered sequence number ranges | Canonical CBOR, Ed25519 |
| [`beacon_tokens.json`](beacon_tokens.json) | Rotating anonymous BLE beacon tokens across 15-minute windows | HMAC-SHA256 |
| [`version_vectors.json`](version_vectors.json) | Sample version vectors and expected missing range outputs for `WANT` frames | Version Vector sync logic |

## How Test Suites Use These Vectors

1. **Pure Dart Core (`packages/msgp2p_core/test/`)**:
   - Parses the JSON fixtures.
   - Decodes CBOR hex representations and verifies that `CborEncoder` produces byte-for-byte identical output.
   - Verifies Ed25519 signatures using `package:cryptography`.
   - Decrypts ciphertexts with XChaCha20-Poly1305 and asserts payload match.
   - Verifies `SHA-256(canonical_cbor(envelope_core)) == message_id`.

2. **Reference Server (`server/php/tests/`)**:
   - Ingests `full_envelope_cbor_base64` and verifies signature and certificate against server public key.
   - Generates receipts and asserts byte matching against `server_receipts.json`.

## Re-generating Test Vectors

The test fixtures are generated deterministically by [`tools/generate_test_vectors.php`](../../tools/generate_test_vectors.php) and validated by [`tools/verify_test_vectors.php`](../../tools/verify_test_vectors.php).