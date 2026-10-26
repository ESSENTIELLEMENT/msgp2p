<?php
declare(strict_types=1);

$dir = __DIR__ . '/../protocol/test-vectors';

// 1. Verify keys
$keys = json_decode(file_get_contents("$dir/crypto_keys.json"), true);
$serverPk = hex2bin($keys['server']['public_key_hex']);
$alicePk = hex2bin($keys['alice']['public_key_hex']);
$bobPk = hex2bin($keys['bob']['public_key_hex']);
$groupKey = hex2bin($keys['group_key_epoch_1_hex']);
$groupBeaconKey = hex2bin($keys['group_beacon_key_hex']);

echo "Loaded keys.\n";

// 2. Verify membership certificates
$certs = json_decode(file_get_contents("$dir/membership_certs.json"), true);
foreach (['alice', 'bob', 'charlie'] as $name) {
    $cert = $certs[$name];
    $core = hex2bin($cert['cert_core_cbor_hex']);
    $sig = hex2bin($cert['server_sig_hex']);
    $full = hex2bin($cert['full_cert_cbor_hex']);
    $certRef = hex2bin($cert['cert_ref_hex']);
    
    assert(sodium_crypto_sign_verify_detached($sig, $core, $serverPk), "Cert sig fail: $name");
    assert(hash('sha256', $full, true) === $certRef, "Cert ref fail: $name");
    echo "Cert $name OK.\n";
}

// 3. Verify envelopes
$envs = json_decode(file_get_contents("$dir/envelopes.json"), true);
foreach (['envelope_sos_alice', 'envelope_bbs_bob'] as $k) {
    $env = $envs[$k];
    $authorPk = hex2bin($env['author']);
    $core = hex2bin($env['envelope_core_cbor_hex']);
    $sig = hex2bin($env['sig_hex']);
    $msgId = hex2bin($env['message_id_hex']);
    
    assert(hash('sha256', $core, true) === $msgId, "Message ID mismatch: $k");
    assert(sodium_crypto_sign_verify_detached($sig, $core, $authorPk), "Envelope sig fail: $k");
    
    // Decrypt ciphertext
    $nonce = hex2bin($env['nonce_hex']);
    $aad = hex2bin($env['aad_hex']);
    $ciphertext = hex2bin($env['ciphertext_hex']);
    $decrypted = sodium_crypto_aead_xchacha20poly1305_ietf_decrypt($ciphertext, $aad, $nonce, $groupKey);
    assert(bin2hex($decrypted) === $env['payload_cbor_hex'], "Decryption mismatch: $k");
    echo "Envelope $k verified & decrypted OK.\n";
}

// 4. Verify receipts
$receipts = json_decode(file_get_contents("$dir/server_receipts.json"), true);
foreach (['receipt_alice_1_to_5', 'receipt_bob_multi_range'] as $k) {
    $r = $receipts[$k];
    $core = hex2bin($r['receipt_core_cbor_hex']);
    $sig = hex2bin($r['server_sig_hex']);
    assert(sodium_crypto_sign_verify_detached($sig, $core, $serverPk), "Receipt sig fail: $k");
    echo "Receipt $k OK.\n";
}

// 5. Verify beacon tokens
$beacons = json_decode(file_get_contents("$dir/beacon_tokens.json"), true);
foreach ($beacons['samples'] as $sample) {
    $windowPacked = hex2bin($sample['window_uint32_hex']);
    $expectedToken = hex2bin($sample['token_16_bytes_hex']);
    $calculated = substr(hash_hmac('sha256', $windowPacked, $groupBeaconKey, true), 0, 16);
    assert($calculated === $expectedToken, "Beacon token mismatch");
    echo "Beacon window {$sample['time_window']} OK.\n";
}

echo "ALL TEST VECTORS VERIFIED SUCCESSFULLY!\n";