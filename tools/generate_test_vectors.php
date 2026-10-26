<?php
declare(strict_types=1);

class CborByteString {
    public function __construct(public string $bytes) {}
}

class CborEncoder {
    public static function encode(mixed $value): string {
        if (is_int($value)) {
            if ($value < 0) {
                throw new InvalidArgumentException("Negative integers not supported");
            }
            return self::encodeUint($value, 0);
        }
        if (is_float($value)) {
            return "\xfb" . pack('E', $value);
        }
        if (is_bool($value)) {
            return $value ? "\xf5" : "\xf4";
        }
        if ($value === null) {
            return "\xf6";
        }
        if (is_string($value)) {
            return self::encodeUint(strlen($value), 3) . $value;
        }
        if ($value instanceof CborByteString) {
            return self::encodeUint(strlen($value->bytes), 2) . $value->bytes;
        }
        if (is_array($value)) {
            if (array_is_list($value)) {
                $out = self::encodeUint(count($value), 4);
                foreach ($value as $item) {
                    $out .= self::encode($item);
                }
                return $out;
            } else {
                $pairs = [];
                foreach ($value as $k => $v) {
                    $kEncoded = self::encode($k);
                    $vEncoded = self::encode($v);
                    $pairs[] = ['k_raw' => $kEncoded, 'v_raw' => $vEncoded];
                }
                usort($pairs, function($a, $b) {
                    $la = strlen($a['k_raw']);
                    $lb = strlen($b['k_raw']);
                    if ($la !== $lb) {
                        return $la <=> $lb;
                    }
                    return strcmp($a['k_raw'], $b['k_raw']);
                });
                $out = self::encodeUint(count($pairs), 5);
                foreach ($pairs as $p) {
                    $out .= $p['k_raw'] . $p['v_raw'];
                }
                return $out;
            }
        }
        throw new InvalidArgumentException("Unsupported CBOR type: " . get_debug_type($value));
    }

    private static function encodeUint(int $val, int $major): string {
        $prefix = $major << 5;
        if ($val <= 23) {
            return chr($prefix | $val);
        }
        if ($val <= 0xFF) {
            return chr($prefix | 24) . chr($val);
        }
        if ($val <= 0xFFFF) {
            return chr($prefix | 25) . pack('n', $val);
        }
        if ($val <= 0xFFFFFFFF) {
            return chr($prefix | 26) . pack('N', $val);
        }
        return chr($prefix | 27) . pack('J', $val);
    }
}

$outDir = __DIR__ . '/../protocol/test-vectors';
if (!is_dir($outDir)) {
    mkdir($outDir, 0777, true);
}

// 1. Crypto Keys
$serverSeed = hash('sha256', 'msgp2p-test-seed-server-2026', true);
$serverKp = sodium_crypto_sign_seed_keypair($serverSeed);
$serverPk = sodium_crypto_sign_publickey($serverKp);
$serverSk = sodium_crypto_sign_secretkey($serverKp);

$aliceSeed = hash('sha256', 'msgp2p-test-seed-alice-2026', true);
$aliceKp = sodium_crypto_sign_seed_keypair($aliceSeed);
$alicePk = sodium_crypto_sign_publickey($aliceKp);
$aliceSk = sodium_crypto_sign_secretkey($aliceKp);

$bobSeed = hash('sha256', 'msgp2p-test-seed-bob-2026', true);
$bobKp = sodium_crypto_sign_seed_keypair($bobSeed);
$bobPk = sodium_crypto_sign_publickey($bobKp);
$bobSk = sodium_crypto_sign_secretkey($bobKp);

$charlieSeed = hash('sha256', 'msgp2p-test-seed-charlie-2026', true);
$charlieKp = sodium_crypto_sign_seed_keypair($charlieSeed);
$charliePk = sodium_crypto_sign_publickey($charlieKp);
$charlieSk = sodium_crypto_sign_secretkey($charlieKp);

// X25519 keys for Noise-XX key agreement
$aliceNoiseSeed = hash('sha256', 'msgp2p-test-noise-seed-alice-2026', true);
$aliceNoiseKp = sodium_crypto_box_seed_keypair($aliceNoiseSeed);
$aliceNoisePk = sodium_crypto_box_publickey($aliceNoiseKp);
$aliceNoiseSk = sodium_crypto_box_secretkey($aliceNoiseKp);

$bobNoiseSeed = hash('sha256', 'msgp2p-test-noise-seed-bob-2026', true);
$bobNoiseKp = sodium_crypto_box_seed_keypair($bobNoiseSeed);
$bobNoisePk = sodium_crypto_box_publickey($bobNoiseKp);
$bobNoiseSk = sodium_crypto_box_secretkey($bobNoiseKp);

$charlieNoiseSeed = hash('sha256', 'msgp2p-test-noise-seed-charlie-2026', true);
$charlieNoiseKp = sodium_crypto_box_seed_keypair($charlieNoiseSeed);
$charlieNoisePk = sodium_crypto_box_publickey($charlieNoiseKp);
$charlieNoiseSk = sodium_crypto_box_secretkey($charlieNoiseKp);

$groupId = hex2bin('a0b1c2d3e4f50123456789abcdef0123');
$groupBeaconKey = hash('sha256', 'msgp2p-test-group-beacon-key-2026', true);
$groupKeyEpoch1 = hash('sha256', 'msgp2p-test-group-key-epoch-1-2026', true);

$cryptoKeys = [
    'description' => 'Deterministic cryptographic keys for msgp2p test vectors',
    'group_id_hex' => bin2hex($groupId),
    'group_beacon_key_hex' => bin2hex($groupBeaconKey),
    'group_key_epoch_1_hex' => bin2hex($groupKeyEpoch1),
    'server' => [
        'seed_hex' => bin2hex($serverSeed),
        'public_key_hex' => bin2hex($serverPk),
        'secret_key_hex' => bin2hex($serverSk),
    ],
    'alice' => [
        'seed_hex' => bin2hex($aliceSeed),
        'public_key_hex' => bin2hex($alicePk),
        'secret_key_hex' => bin2hex($aliceSk),
        'noise_seed_hex' => bin2hex($aliceNoiseSeed),
        'noise_public_key_hex' => bin2hex($aliceNoisePk),
        'noise_secret_key_hex' => bin2hex($aliceNoiseSk),
    ],
    'bob' => [
        'seed_hex' => bin2hex($bobSeed),
        'public_key_hex' => bin2hex($bobPk),
        'secret_key_hex' => bin2hex($bobSk),
        'noise_seed_hex' => bin2hex($bobNoiseSeed),
        'noise_public_key_hex' => bin2hex($bobNoisePk),
        'noise_secret_key_hex' => bin2hex($bobNoiseSk),
    ],
    'charlie' => [
        'seed_hex' => bin2hex($charlieSeed),
        'public_key_hex' => bin2hex($charliePk),
        'secret_key_hex' => bin2hex($charlieSk),
        'noise_seed_hex' => bin2hex($charlieNoiseSeed),
        'noise_public_key_hex' => bin2hex($charlieNoisePk),
        'noise_secret_key_hex' => bin2hex($charlieNoiseSk),
    ],
];
file_put_contents("$outDir/crypto_keys.json", json_encode($cryptoKeys, JSON_PRETTY_PRINT));

// 2. Membership Certificates
function makeCert($groupId, $userId, $pk, $noisePk, $role, $issuedAt, $expiresAt, $serverSk) {
    $certCore = [
        'v' => 1,
        'group_id' => new CborByteString($groupId),
        'user_id' => $userId,
        'member_pubkey' => new CborByteString($pk),
        'noise_pubkey' => new CborByteString($noisePk),
        'role' => $role,
        'issued_at' => $issuedAt,
        'expires_at' => $expiresAt,
    ];
    $cborCore = CborEncoder::encode($certCore);
    $sig = sodium_crypto_sign_detached($cborCore, $serverSk);
    $fullCert = $certCore;
    $fullCert['server_sig'] = new CborByteString($sig);
    $fullCbor = CborEncoder::encode($fullCert);
    $certRef = hash('sha256', $fullCbor, true);

    return [
        'user_id' => $userId,
        'member_pubkey_hex' => bin2hex($pk),
        'noise_pubkey_hex' => bin2hex($noisePk),
        'role' => $role,
        'issued_at' => $issuedAt,
        'expires_at' => $expiresAt,
        'cert_core_cbor_hex' => bin2hex($cborCore),
        'server_sig_hex' => bin2hex($sig),
        'full_cert_cbor_hex' => bin2hex($fullCbor),
        'full_cert_cbor_base64' => base64_encode($fullCbor),
        'cert_ref_hex' => bin2hex($certRef),
    ];
}

$issuedAt = 1773822000000;
$expiresAt = $issuedAt + (7 * 86400 * 1000); // 7 days

$certs = [
    'description' => 'Server-signed membership certificates for test members',
    'alice' => makeCert($groupId, 'alice', $alicePk, $aliceNoisePk, 0, $issuedAt, $expiresAt, $serverSk),
    'bob' => makeCert($groupId, 'bob', $bobPk, $bobNoisePk, 0, $issuedAt, $expiresAt, $serverSk),
    'charlie' => makeCert($groupId, 'charlie', $charliePk, $charlieNoisePk, 1, $issuedAt, $expiresAt, $serverSk),
];
file_put_contents("$outDir/membership_certs.json", json_encode($certs, JSON_PRETTY_PRINT));

// 3. Envelopes
function makeEnvelope($groupId, $keyEpoch, $groupKey, $authorPk, $authorSk, $certRef, $seq, $createdAt, $expiresAt, $priority, $payload) {
    $nonce = substr(hash('sha256', "msgp2p-test-nonce-$seq-" . bin2hex($authorPk), true), 0, 24);
    
    // AAD = group_id (16) || epoch (4 BE) || author (32) || seq (8 BE)
    $aad = $groupId . pack('N', $keyEpoch) . $authorPk . pack('J', $seq);
    
    $payloadCbor = CborEncoder::encode($payload);
    $ciphertext = sodium_crypto_aead_xchacha20poly1305_ietf_encrypt($payloadCbor, $aad, $nonce, $groupKey);
    
    $core = [
        'v' => 1,
        'group_id' => new CborByteString($groupId),
        'key_epoch' => $keyEpoch,
        'author' => new CborByteString($authorPk),
        'seq' => $seq,
        'created_at' => $createdAt,
        'expires_at' => $expiresAt,
        'priority' => $priority,
        'nonce' => new CborByteString($nonce),
        'ciphertext' => new CborByteString($ciphertext),
    ];
    
    $coreCbor = CborEncoder::encode($core);
    $messageId = hash('sha256', $coreCbor, true);
    $sig = sodium_crypto_sign_detached($coreCbor, $authorSk);
    
    $envelope = [
        'core' => $core,
        'sig' => new CborByteString($sig),
        'cert_ref' => new CborByteString($certRef),
    ];
    $envelopeCbor = CborEncoder::encode($envelope);
    
    return [
        'author' => bin2hex($authorPk),
        'seq' => $seq,
        'priority' => $priority,
        'payload' => $payload,
        'payload_cbor_hex' => bin2hex($payloadCbor),
        'aad_hex' => bin2hex($aad),
        'nonce_hex' => bin2hex($nonce),
        'ciphertext_hex' => bin2hex($ciphertext),
        'envelope_core_cbor_hex' => bin2hex($coreCbor),
        'message_id_hex' => bin2hex($messageId),
        'sig_hex' => bin2hex($sig),
        'cert_ref_hex' => bin2hex($certRef),
        'full_envelope_cbor_hex' => bin2hex($envelopeCbor),
        'full_envelope_cbor_base64' => base64_encode($envelopeCbor),
    ];
}

$aliceCertRef = hex2bin($certs['alice']['cert_ref_hex']);
$bobCertRef = hex2bin($certs['bob']['cert_ref_hex']);

$env1 = makeEnvelope(
    $groupId, 1, $groupKeyEpoch1, $alicePk, $aliceSk, $aliceCertRef,
    1, $issuedAt + 1000, $issuedAt + 86400000, 0, // Priority 0 (SOS)
    [
        'type' => 'sos',
        'body' => [
            'text' => 'Injured hiker at waypoint 4. Sprained ankle, need assist.',
            'lat' => 35.3606,
            'lng' => 138.7274,
            'elevation' => 2400,
        ]
    ]
);

$env2 = makeEnvelope(
    $groupId, 1, $groupKeyEpoch1, $bobPk, $bobSk, $bobCertRef,
    1, $issuedAt + 2000, $issuedAt + 86400000, 2, // Priority 2 (Normal BBS)
    [
        'type' => 'bbs_post',
        'body' => [
            'title' => 'Trail water report',
            'text' => 'Spring at mile 14 is flowing cold and clean.',
        ]
    ]
);

$envelopes = [
    'description' => 'Canonical CBOR encrypted envelopes with valid Ed25519 signatures',
    'envelope_sos_alice' => $env1,
    'envelope_bbs_bob' => $env2,
];
file_put_contents("$outDir/envelopes.json", json_encode($envelopes, JSON_PRETTY_PRINT));

// 4. Server Receipts
function makeReceipt($groupId, $authorPk, $ranges, $issuedAt, $serverSk) {
    $core = [
        'v' => 1,
        'group_id' => new CborByteString($groupId),
        'author' => new CborByteString($authorPk),
        'ranges' => $ranges,
        'issued_at' => $issuedAt,
    ];
    $cborCore = CborEncoder::encode($core);
    $sig = sodium_crypto_sign_detached($cborCore, $serverSk);
    $full = $core;
    $full['server_sig'] = new CborByteString($sig);
    $fullCbor = CborEncoder::encode($full);
    
    return [
        'author_hex' => bin2hex($authorPk),
        'ranges' => $ranges,
        'issued_at' => $issuedAt,
        'receipt_core_cbor_hex' => bin2hex($cborCore),
        'server_sig_hex' => bin2hex($sig),
        'full_receipt_cbor_hex' => bin2hex($fullCbor),
        'full_receipt_cbor_base64' => base64_encode($fullCbor),
    ];
}

$receipts = [
    'description' => 'Server-signed batch receipts confirming delivered message sequence ranges',
    'receipt_alice_1_to_5' => makeReceipt($groupId, $alicePk, [[1, 5]], $issuedAt + 5000, $serverSk),
    'receipt_bob_multi_range' => makeReceipt($groupId, $bobPk, [[1, 4], [7, 10]], $issuedAt + 6000, $serverSk),
];
file_put_contents("$outDir/server_receipts.json", json_encode($receipts, JSON_PRETTY_PRINT));

// 5. Beacon Tokens
$baseTimestamp = 1773822000; // seconds
$beaconTokens = [
    'description' => 'Rotating anonymous BLE beacon tokens computed via HMAC-SHA256',
    'group_beacon_key_hex' => bin2hex($groupBeaconKey),
    'rotation_interval_seconds' => 900,
    'samples' => [],
];

for ($i = 0; $i < 3; $i++) {
    $ts = $baseTimestamp + ($i * 900);
    $window = (int)floor($ts / 900);
    $windowPacked = pack('N', $window);
    $hmac = hash_hmac('sha256', $windowPacked, $groupBeaconKey, true);
    $token = substr($hmac, 0, 16);
    
    $beaconTokens['samples'][] = [
        'timestamp_seconds' => $ts,
        'time_window' => $window,
        'window_uint32_hex' => bin2hex($windowPacked),
        'token_16_bytes_hex' => bin2hex($token),
    ];
}
file_put_contents("$outDir/beacon_tokens.json", json_encode($beaconTokens, JSON_PRETTY_PRINT));

// 6. Version Vectors & Want Calculation
$versionVectors = [
    'description' => 'Version vectors and expected delta WANT request outputs',
    'author_alice_hex' => bin2hex($alicePk),
    'author_bob_hex' => bin2hex($bobPk),
    'peer_a_vector' => [
        bin2hex($alicePk) => ['contiguous' => 5, 'gaps' => [8, 9]],
        bin2hex($bobPk) => ['contiguous' => 10, 'gaps' => []],
    ],
    'peer_b_vector' => [
        bin2hex($alicePk) => ['contiguous' => 10, 'gaps' => []],
        bin2hex($bobPk) => ['contiguous' => 6, 'gaps' => [8]],
    ],
    'expected_want_peer_a_requests_from_b' => [
        [
            'author_hex' => bin2hex($alicePk),
            'ranges' => [[6, 7], [10, 10]], // A misses 6, 7 and 10 from B
        ]
    ],
    'expected_want_peer_b_requests_from_a' => [
        [
            'author_hex' => bin2hex($bobPk),
            'ranges' => [[7, 7], [9, 10]], // B misses 7, 9, 10 from A
        ]
    ],
];
file_put_contents("$outDir/version_vectors.json", json_encode($versionVectors, JSON_PRETTY_PRINT));

echo "Generated all 6 test vector suites successfully in $outDir\n";