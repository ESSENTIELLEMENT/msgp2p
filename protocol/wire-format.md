# msgp2p Wire Format & Cryptographic Specification

> **Status:** Draft v1 (2026-10-18)  
> **Normative references:** RFC 8949 (CBOR), RFC 8032 (Ed25519), RFC 8439 / libsodium (XChaCha20-Poly1305), Noise Protocol Framework (Noise_XX_25519_ChaChaPoly_SHA256).

---

## 1. Encoding Rules: Canonical CBOR

All structured data objects that require cryptographic signing or content-addressed hashing **MUST** be serialized using **Deterministic Canonical CBOR** per RFC 8949 §4.2.

Key rules:
1. **Key Sorting:** Map keys must be sorted in lexicographical order of their encoded byte representation (not character collation).
2. **Definite Lengths Only:** Indefinite-length arrays, maps, strings, and byte arrays are forbidden.
3. **Smallest Integer Encoding:** Integers must use the shortest possible representation (e.g. `0`..`23` in 1 byte, `24`..`255` in 2 bytes, etc.).
4. **No Floating Point for Critical Fields:** Timestamps, sequences, priorities, and version numbers must be unsigned integers. Floating-point numbers are only permitted inside encrypted application payloads.
5. **No Optional Nulls:** Optional fields that are absent must be omitted from the map entirely, rather than encoded as `null`.

---

## 2. Cryptographic Primitives

| Purpose | Algorithm / Primitive | Key Length / Output | Notes |
| :--- | :--- | :--- | :--- |
| **Identity & Signatures** | Ed25519 (RFC 8032) | 32-byte public key, 64-byte signature | Used for message authors and server certificates. |
| **Payload Encryption** | XChaCha20-Poly1305 | 32-byte key, 24-byte nonce, 16-byte MAC tag | Group-level symmetric encryption. |
| **Content Addressing & Hashes** | SHA-256 | 32 bytes | Deterministic IDs (`message_id`, `cert_ref`). |
| **Beacon Anonymization** | HMAC-SHA256 truncated | 16 bytes | Rotating BLE discovery token. |
| **Session Encryption** | Noise_XX_25519_ChaChaPoly_SHA256 | Ephemeral X25519 keys, ChaCha20-Poly1305 | Mutually authenticated encrypted peer link. |

---

## 3. Data Structures (CDDL Specification)

Below is the formal CDDL (RFC 8610) definition for all data structures.

```cddl
; Top-level envelope carried across mesh and server
envelope = {
  core: envelope_core,
  sig: bstr .size 64,       ; Ed25519 signature by author over canonical_cbor(core)
  cert_ref: bstr .size 32    ; SHA-256(canonical_cbor(author_certificate))
}

; Immutable core of the envelope (hashed for message_id)
envelope_core = {
  v: 1,                      ; Protocol version (unsigned int)
  group_id: bstr .size 16,   ; 16-byte Group UUID
  key_epoch: uint,           ; Group encryption key epoch number
  author: bstr .size 32,     ; Author Ed25519 public key
  seq: uint,                 ; Monotonic sequence number per author (1, 2, 3...)
  created_at: uint,          ; Milliseconds since Unix epoch (UTC)
  expires_at: uint,          ; Milliseconds since Unix epoch (UTC)
  priority: uint .le 3,      ; 0 = SOS, 1 = High/Alert, 2 = Normal/BBS, 3 = Low/Backfill
  nonce: bstr .size 24,      ; XChaCha20 nonce
  ciphertext: bstr,          ; Encrypted payload
  ? attachments: [* attachment_ref] ; Optional attachment references
}

attachment_ref = {
  hash: bstr .size 32,       ; SHA-256 hash of attachment blob
  size: uint,                ; Size in bytes
  mime: tstr                 ; MIME type (e.g. "image/jpeg")
}

; Decrypted payload content (app-defined)
payload = {
  type: tstr,                ; e.g. "bbs_post", "location_fix", "sos"
  body: { * tstr => any }    ; Structured payload map
}

; Server-issued membership certificate
membership_cert = {
  v: 1,
  group_id: bstr .size 16,
  user_id: tstr,             ; Human-readable user handle or external ID
  member_pubkey: bstr .size 32, ; Member Ed25519 public signing key
  noise_pubkey: bstr .size 32,  ; Member X25519 static key agreement public key
  role: uint,                ; 0 = Member, 1 = Admin/Ranger
  issued_at: uint,           ; Milliseconds since Unix epoch
  expires_at: uint,          ; Milliseconds since Unix epoch
  server_sig: bstr .size 64  ; Ed25519 signature by pinned server key over cert_core
}

; Server-signed batch receipt (anti-packet)
server_receipt = {
  v: 1,
  group_id: bstr .size 16,
  author: bstr .size 32,     ; Author public key whose sequences are confirmed
  ranges: [* seq_range],     ; Confirmed contiguous sequence ranges
  issued_at: uint,           ; Milliseconds since Unix epoch
  server_sig: bstr .size 64  ; Ed25519 signature by pinned server key over receipt_core
}

seq_range = [
  from_seq: uint,            ; Inclusive start sequence
  to_seq: uint               ; Inclusive end sequence
]

; Revocation notice
revocation_notice = {
  v: 1,
  group_id: bstr .size 16,
  member_pubkey: bstr .size 32,
  revoked_at: uint,
  reason: tstr,
  server_sig: bstr .size 64
}
```

---

## 4. Cryptographic Envelope Construction & Verification

### 4.1 Message ID Formula
The `message_id` is content-addressed and deterministic across all nodes:
$$\text{message\_id} = \text{SHA-256}(\text{canonical\_cbor}(\text{envelope\_core}))$$

### 4.2 Payload Encryption (XChaCha20-Poly1305)
1. **Associated Data (AAD):**  
   $$\text{AAD} = \text{group\_id} \mathbin{\Vert} \text{key\_epoch (4 bytes BE)} \mathbin{\Vert} \text{author} \mathbin{\Vert} \text{seq (8 bytes BE)}$$
2. **Ciphertext:**  
   $$\text{ciphertext} = \text{XChaCha20-Poly1305}(\text{key} = \text{group\_key}[\text{key\_epoch}], \text{nonce} = \text{nonce}, \text{plaintext} = \text{canonical\_cbor}(\text{payload}), \text{aad} = \text{AAD})$$

### 4.3 Envelope Signing (Ed25519)
$$\text{sig} = \text{Ed25519\_Sign}(\text{author\_private\_key}, \text{canonical\_cbor}(\text{envelope\_core}))$$

### 4.4 Verification Pipeline (Relay & Server)
Upon receiving an envelope, a relay node or server **MUST** perform verification in the following strict order, dropping the packet immediately upon any failure:

1. **Size Check:** `length(raw_cbor) <= 4096 bytes`.
2. **Certificate Validation:** Look up certificate by `cert_ref`. Verify `expires_at > current_time`, check that `member_pubkey == author`, verify `server_sig` against pinned server key, and confirm `author` is not in the local revocation list. (If the certificate is not yet in the local store, hold envelope in quarantine and send `CERT_REQ`).
3. **Signature Verification:** Verify `sig` against `envelope_core.author` using Ed25519.
4. **Time & Expiry Check:**  
   - `created_at <= current_time + 600_000` (reject if more than 10 minutes in future).
   - `expires_at > current_time` (reject if already expired).
5. **Deduplication:** Check if `message_id` is already in SQLite `envelopes`. If present, discard.

---

## 5. BLE Discovery Token (Rotating Anonymous Beacon)

To prevent third-party eavesdroppers from tracking physical device locations, BLE advertisement packets carry an anonymous, rotating token instead of a static Peer ID.

### 5.1 Token Derivation
$$\text{time\_window} = \lfloor \text{UnixTimeSeconds} / 900 \rfloor \quad \text{(900 seconds = 15 minutes)}$$
$$\text{full\_mac} = \text{HMAC-SHA256}(\text{key} = \text{group\_beacon\_key}, \text{message} = \text{uint32\_be}(\text{time\_window}))$$
$$\text{beacon\_token} = \text{full\_mac}[0..15] \quad \text{(16 bytes)}$$

### 5.2 Verification
Receiving nodes compute tokens for `time_window` and `time_window - 1` (to account for clock drift). If `beacon_token` matches, the peer belongs to the group and connection proceeds.

---

## 6. Transport Framing & Chunking Protocol

The underlying transport (`P2PTransport`) transmits streams of discrete frames over BLE L2CAP, GATT characteristics, or Wi-Fi Aware sockets.

### 6.1 Session Framing

Every protocol message is prefixed by a 3-byte header:

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   Frame Type  |         Length (Big-Endian)   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                  Payload ...                  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

- **Frame Type (1 byte):** See Section 7.
- **Length (2 bytes unsigned, Big-Endian):** Payload size (0 to 65,535 bytes).

### 6.2 MTU Chunking Layer (for BLE links)
When transmitting over BLE links where the negotiated MTU is smaller than the frame (e.g. GATT MTU 23–517 bytes or L2CAP MPS), the Dart framing layer breaks frames into MTU-sized chunks:

```
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|       Chunk Seq (16 bits)     |      Total Chunks (16 bits)   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|        CRC-16 / IBM           |           Raw Data ...        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```
- `Chunk Seq`: 0-indexed chunk sequence.
- `Total Chunks`: Total number of chunks in this frame.
- `CRC-16`: Checksum over `Raw Data` to immediately discard corrupted radio packets before reassembly.

---

## 7. Peer Session Handshake & Message Types

### 7.1 Noise-XX Mutually Authenticated Handshake
Peer sessions begin with a Noise-XX handshake to establish a forward-secret, authenticated channel:

```
  Initiator                             Responder
    |                                       |
    |  Message 1 (0x01): -> e               |
    |-------------------------------------->|
    |                                       |
    |  Message 2 (0x02): <- e, ee, s, es    |
    |  Payload: responder_cert              |
    |<--------------------------------------|
    |                                       |
    |  Message 3 (0x03): -> s, se           |
    |  Payload: initiator_cert              |
    |-------------------------------------->|
    |                                       |
    |=== Handshake Complete: Secure Pipe ===|
```

Both nodes verify that the peer's static key matches the `member_pubkey` inside the provided membership certificate.

### 7.2 Session Control Message Types (Encrypted)

Once the Noise pipe is active, all subsequent frames are encrypted under the Noise session keys:

| Type Code | Name | Description | Payload Schema |
| :---: | :--- | :--- | :--- |
| `0x10` | **SUMMARY** | Exchange held version vectors & watermarks | `cbor(session_summary)` |
| `0x11` | **WANT** | Request missing author/sequence ranges | `cbor(session_want)` |
| `0x12` | **DATA** | Stream of signed message envelopes | `cbor([* envelope])` |
| `0x13` | **RECEIPTS** | Exchange server-confirmed receipts | `cbor([* server_receipt])` |
| `0x14` | **REVOCATIONS** | Exchange latest revocation notices | `cbor([* revocation_notice])` |
| `0x15` | **CERT_REQ** | Request full certificate by `cert_ref` | `cbor({ cert_refs: [* bstr .size 32] })` |
| `0x16` | **CERT_RESP** | Return requested full certificates | `cbor([* membership_cert])` |
| `0x17` | **BLOB_WANT** | Request missing attachment blobs over bulk links | `cbor({ hashes: [* bstr .size 32] })` |
| `0x18` | **BLOB_DATA** | Transfer hash-verified attachment blob | `cbor({ hash: bstr .size 32, mime: tstr, data: bstr })` |
| `0x19` | **UPGRADE_OFFER** | Propose BLE → Wi-Fi Aware session upgrade | `cbor({ service_id: tstr, token: bstr .size 16, pending_bytes: uint })` |
| `0x1A` | **UPGRADE_ACCEPT** | Accept or decline Wi-Fi Aware session upgrade | `cbor({ accepted: bool, peer_handle: tstr })` |
| `0x1F` | **BYE** | Clean disconnect notification | `cbor({ reason: uint })` |

### 7.3 Detailed Schemas for Session Messages

```cddl
; SUMMARY frame (Type 0x10)
session_summary = {
  vector: version_vector,
  receipt_watermark: uint,   ; Latest receipt timestamp held
  revocation_version: uint   ; Latest revocation sequence/count held
}

version_vector = {
  * bstr .size 32 => author_state  ; author pubkey => state
}

author_state = {
  contiguous: uint,          ; All sequences 1..contiguous are held
  ? gaps: [* uint]           ; Sparse sequence numbers held beyond contiguous
}

; WANT frame (Type 0x11)
session_want = {
  requests: [* author_want]
}

author_want = {
  author: bstr .size 32,
  ranges: [* seq_range]      ; Missing sequence ranges desired
}
```

---

### 7.4 Simultaneous Connect Tie-Break
When two peers discover each other simultaneously and initiate concurrent transport connections (A connects to B while B connects to A):
- The link initiated by the node with the lexicographically smaller static public key (`initiator_static_pubkey < responder_static_pubkey`) is retained as the authoritative session.
- The higher-keyed node cleanly cancels/closes its outgoing connection attempt and accepts the incoming link.

### 7.5 Maximum Encrypted Frame Payload
Because ChaCha20-Poly1305 appends a 16-byte authentication tag and the maximum transport frame length field is 16 bits (65,535 bytes), the unencrypted payload of any single protocol frame MUST NOT exceed 65,519 bytes (`65535 - 16`).

---

## 8. Summary of Constants & Limits

| Constant | Value | Description |
| :--- | :--- | :--- |
| `MAX_ENVELOPE_CORE_BYTES` | 4,096 bytes | Hard maximum size for `envelope_core` CBOR |
| `TARGET_ENVELOPE_CORE_BYTES` | 2,048 bytes | Recommended payload design limit |
| `BEACON_ROTATION_INTERVAL` | 900 seconds | 15 minutes window for rotating BLE advertisement token |
| `MAX_FUTURE_CLOCK_DRIFT` | 600,000 ms | 10 minutes tolerance for future timestamps |
| `DEFAULT_MESSAGE_TTL` | 86,400,000 ms | 24 hours default retention before pruning |
| `MAX_CHUNKS_PER_FRAME` | 256 | Maximum chunks when fragmenting large frames |