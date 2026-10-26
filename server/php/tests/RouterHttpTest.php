<?php
declare(strict_types=1);

putenv('DB_NAME=msgp2p_test');

require_once __DIR__ . '/../vendor/autoload.php';

use MsgP2P\Server\Router;
use MsgP2P\Server\Database;
use MsgP2P\Server\Clock;

echo "\n=== Running Router & HTTP Dispatch Tests ===\n\n";

Database::resetDatabase('msgp2p_test');
Clock::setMockTime(1773822000000 + 5000);

function dispatchCapture(string $method, string $uri, ?string $body = null, array $headers = []): array {
    foreach ($headers as $k => $v) {
        $_SERVER['HTTP_' . strtoupper(str_replace('-', '_', $k))] = $v;
    }
    $_SERVER['REQUEST_METHOD'] = $method;
    $_SERVER['REQUEST_URI'] = $uri;
    
    $_GET = [];
    $parts = parse_url($uri);
    if (isset($parts['query'])) {
        parse_str($parts['query'], $_GET);
    }

    ob_start();
    Router::dispatch($method, $uri, $body);
    $output = ob_get_clean();

    foreach ($headers as $k => $v) {
        unset($_SERVER['HTTP_' . strtoupper(str_replace('-', '_', $k))]);
    }

    $decoded = json_decode($output, true);
    return [
        'body' => $decoded,
        'raw' => $output,
    ];
}

$cryptoKeys = json_decode(file_get_contents(__DIR__ . '/../../../protocol/test-vectors/crypto_keys.json'), true);
$groupId = $cryptoKeys['group_id_hex'];

// 1. Unauthenticated access
$res = dispatchCapture('GET', "/api/v1/sync/pull?group_id=$groupId&vector=");
if (isset($res['body']['error']) && $res['body']['error'] === 'UNAUTHORIZED') {
    echo " [PASS] Unauthenticated pull returns 401 UNAUTHORIZED\n";
} else {
    echo " [FAIL] Unauthenticated pull: {$res['raw']}\n";
}

// 2. Register alice
$regBody = json_encode([
    'username' => 'alice_http',
    'password' => 'securePassword123!',
    'group_id' => $groupId,
    'member_pubkey' => $cryptoKeys['alice']['public_key_hex'],
    'noise_pubkey' => $cryptoKeys['alice']['noise_public_key_hex'],
]);
$res = dispatchCapture('POST', '/api/v1/auth/register', $regBody);
if (($res['body']['status'] ?? '') === 'ACTIVE') {
    echo " [PASS] Registration via POST /api/v1/auth/register returns 200 ACTIVE\n";
} else {
    echo " [FAIL] Registration: {$res['raw']}\n";
}

// 3. Login
$loginBody = json_encode([
    'username' => 'alice_http',
    'password' => 'securePassword123!',
]);
$res = dispatchCapture('POST', '/api/v1/auth/login', $loginBody);
if (!empty($res['body']['access_token'])) {
    echo " [PASS] Login via POST /api/v1/auth/login returns 200 and access_token\n";
    $token = $res['body']['access_token'];
} else {
    echo " [FAIL] Login: {$res['raw']}\n";
    $token = '';
}

// 4. Authenticated Push
$envelopesTv = json_decode(file_get_contents(__DIR__ . '/../../../protocol/test-vectors/envelopes.json'), true);
$certsTv = json_decode(file_get_contents(__DIR__ . '/../../../protocol/test-vectors/membership_certs.json'), true);

$pushBody = json_encode([
    'group_id' => $groupId,
    'certificates' => [$certsTv['alice']['full_cert_cbor_base64']],
    'envelopes' => [$envelopesTv['envelope_sos_alice']['full_envelope_cbor_base64']],
]);
$res = dispatchCapture('POST', '/api/v1/sync/push', $pushBody, ['Authorization' => "Bearer $token"]);
if (count($res['body']['accepted_ids'] ?? []) === 1) {
    echo " [PASS] Push via POST /api/v1/sync/push returns 200 and accepted_ids\n";
} else {
    echo " [FAIL] Push: {$res['raw']}\n";
}

// 5. Authenticated Pull
$res = dispatchCapture('GET', "/api/v1/sync/pull?group_id=$groupId&vector=", null, ['Authorization' => "Bearer $token"]);
if (count($res['body']['envelopes'] ?? []) === 1) {
    echo " [PASS] Pull via GET /api/v1/sync/pull returns 200 and envelopes\n";
} else {
    echo " [FAIL] Pull: {$res['raw']}\n";
}

// 6. Authenticated Receipts
$res = dispatchCapture('GET', "/api/v1/sync/receipts?group_id=$groupId&since=0", null, ['Authorization' => "Bearer $token"]);
if (count($res['body']['receipts'] ?? []) >= 1) {
    echo " [PASS] Receipts via GET /api/v1/sync/receipts returns 200 and receipts\n";
} else {
    echo " [FAIL] Receipts: {$res['raw']}\n";
}

// 7. Authenticated Revoke & Group Key Rotation (POST /api/v1/sync/revocations)
$revokeBody = json_encode([
    'group_id' => $groupId,
    'member_pubkey' => 'fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210',
    'reason' => 'compromised_device',
]);
$res = dispatchCapture('POST', '/api/v1/sync/revocations', $revokeBody, ['Authorization' => "Bearer $token"]);
if (($res['body']['new_group_key']['epoch'] ?? 0) === 2) {
    echo " [PASS] Revoke via POST /api/v1/sync/revocations rotates group key to epoch 2\n";
} else {
    echo " [FAIL] Revoke POST: {$res['raw']}\n";
}

// 8. Authenticated Revocations Query
$res = dispatchCapture('GET', "/api/v1/sync/revocations?group_id=$groupId&since=0", null, ['Authorization' => "Bearer $token"]);
if (count($res['body']['revocations'] ?? []) === 1) {
    echo " [PASS] Revocations via GET /api/v1/sync/revocations returns 200 and signed revocation\n";
} else {
    echo " [FAIL] Revocations: {$res['raw']}\n";
}

echo "\nAll HTTP Router endpoint checks completed.\n";
