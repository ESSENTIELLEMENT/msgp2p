<?php
declare(strict_types=1);

require_once __DIR__ . '/../vendor/autoload.php';

use MsgP2P\Server\Config;
use MsgP2P\Server\Database;
use MsgP2P\Server\Crypto;
use MsgP2P\Server\Cbor;
use MsgP2P\Server\CborByteString;
use MsgP2P\Server\Auth;
use MsgP2P\Server\Clock;
use MsgP2P\Server\GatewayController;

echo "=== Running MsgP2P Reference Server Conformance Test Suite (FR-TEST-07) ===\n\n";

$passCount = 0;
$failCount = 0;

function assertTest(string $name, bool $condition, string $detail = ''): void {
    global $passCount, $failCount;
    if ($condition) {
        echo " [PASS] $name\n";
        $passCount++;
    } else {
        echo " [FAIL] $name: $detail\n";
        $failCount++;
    }
}

// Ensure testing against msgp2p_test
putenv('DB_NAME=msgp2p_test');

// 1. Crypto & Test Vector Conformance
echo "1. Cryptographic Primitives & Test Vectors\n";
$cryptoKeys = json_decode(file_get_contents(__DIR__ . '/../../../protocol/test-vectors/crypto_keys.json'), true);
$expectedServerPk = $cryptoKeys['server']['public_key_hex'];
$actualServerPk = bin2hex(Crypto::getServerPublicKey());
assertTest("Server public key matches test vector", $expectedServerPk === $actualServerPk, "Expected $expectedServerPk, got $actualServerPk");

$testMsg = "Test server signature verification 2026";
$sig = Crypto::signServer($testMsg);
assertTest("Server Ed25519 detached signature valid", Crypto::verifyServer($testMsg, $sig));

// 2. CBOR Canonical Encoding & Roundtrip
echo "\n2. Canonical CBOR Encoding & Decoding\n";
$envelopesTv = json_decode(file_get_contents(__DIR__ . '/../../../protocol/test-vectors/envelopes.json'), true);
$rawAliceEnvHex = $envelopesTv['envelope_sos_alice']['full_envelope_cbor_hex'];
$decodedEnv = Cbor::decode(hex2bin($rawAliceEnvHex));
assertTest("Decoded envelope has core, sig, cert_ref", isset($decodedEnv['core'], $decodedEnv['sig'], $decodedEnv['cert_ref']));
$reEncoded = Cbor::encode($decodedEnv);
assertTest("CBOR envelope encodes to exact canonical bytes", bin2hex($reEncoded) === $rawAliceEnvHex);

// 3. Database & Clean Slate
echo "\n3. Database Initialization & Clean Slate\n";
Database::resetDatabase('msgp2p_test');
$pdo = Database::getConnection('msgp2p_test');
$stmt = $pdo->query("SELECT COUNT(*) FROM envelopes");
assertTest("Database tables truncated cleanly", (int)$stmt->fetchColumn() === 0);

$controller = new GatewayController('msgp2p_test');

// Set virtual test clock to match test vectors creation window
$testVectorBaseTime = 1773822000000;
Clock::setMockTime($testVectorBaseTime + 5000);

// 4. Registration Flow (FR-SRV-02)
echo "\n4. User Registration (FR-SRV-02)\n";
$alicePkHex = $cryptoKeys['alice']['public_key_hex'];
$aliceNoisePkHex = $cryptoKeys['alice']['noise_public_key_hex'];
$groupIdHex = $cryptoKeys['group_id_hex'];

$regResult = $controller->register([
    'username' => 'alice',
    'password' => 'aliceSecurePass2026!',
    'group_id' => $groupIdHex,
    'member_pubkey' => $alicePkHex,
    'noise_pubkey' => $aliceNoisePkHex,
]);

assertTest("Registration returns user_id and ACTIVE", isset($regResult['user_id']) && $regResult['status'] === 'ACTIVE');

$stmt = $pdo->prepare("SELECT * FROM membership_certs WHERE user_id = ?");
$stmt->execute([$regResult['user_id']]);
$certRow = $stmt->fetch();
assertTest("Membership certificate issued and stored in DB", $certRow !== false);
assertTest("Membership certificate has valid server signature", Crypto::verifyServer(
    Cbor::encode([
        'v' => 1,
        'group_id' => new CborByteString(hex2bin($groupIdHex)),
        'user_id' => $regResult['user_id'],
        'member_pubkey' => new CborByteString(hex2bin($alicePkHex)),
        'noise_pubkey' => new CborByteString(hex2bin($aliceNoisePkHex)),
        'role' => 0,
        'issued_at' => (int)$certRow['issued_at'],
        'expires_at' => (int)$certRow['expires_at'],
    ]),
    hex2bin($certRow['server_sig'])
));

// 5. Login Flow (FR-SRV-03)
echo "\n5. User Login & Token Issuance (FR-SRV-03)\n";
$loginResult = $controller->login([
    'username' => 'alice',
    'password' => 'aliceSecurePass2026!',
]);

assertTest("Login returns access_token", !empty($loginResult['access_token']));
assertTest("Login returns server_pubkey", $loginResult['server_pubkey'] === $expectedServerPk);
assertTest("Login returns group_beacon_key", !empty($loginResult['group_beacon_key']));
assertTest("Login returns active group_keys", count($loginResult['group_keys']) >= 1);
$tokenPayload = Auth::verifyToken($loginResult['access_token']);
assertTest("JWT token validates and contains user ID", ($tokenPayload['sub'] ?? '') === $regResult['user_id']);

// Also register bob
$bobPkHex = $cryptoKeys['bob']['public_key_hex'];
$bobNoisePkHex = $cryptoKeys['bob']['noise_public_key_hex'];
$controller->register([
    'username' => 'bob',
    'password' => 'bobSecurePass2026!',
    'group_id' => $groupIdHex,
    'member_pubkey' => $bobPkHex,
    'noise_pubkey' => $bobNoisePkHex,
]);

// 6. Ingest Test Vector Envelopes (FR-SRV-04)
echo "\n6. Ingest Test Vector Envelopes (FR-SRV-04)\n";
$certsTv = json_decode(file_get_contents(__DIR__ . '/../../../protocol/test-vectors/membership_certs.json'), true);
$aliceCertBase64 = $certsTv['alice']['full_cert_cbor_base64'];
$bobCertBase64 = $certsTv['bob']['full_cert_cbor_base64'];

$pushPayload = [
    'group_id' => $groupIdHex,
    'certificates' => [$aliceCertBase64, $bobCertBase64],
    'envelopes' => [
        $envelopesTv['envelope_sos_alice']['full_envelope_cbor_base64'],
        $envelopesTv['envelope_bbs_bob']['full_envelope_cbor_base64'],
    ],
];

$pushResult = $controller->push($pushPayload);
$aliceMsgId = $envelopesTv['envelope_sos_alice']['message_id_hex'];
$bobMsgId = $envelopesTv['envelope_bbs_bob']['message_id_hex'];

assertTest("Accepted both test envelopes", in_array($aliceMsgId, $pushResult['accepted_ids']) && in_array($bobMsgId, $pushResult['accepted_ids']), "Rejected: " . json_encode($pushResult['rejected']));
assertTest("No envelopes rejected", count($pushResult['rejected']) === 0);
assertTest("Server receipts issued for authors", count($pushResult['receipts']) >= 2);

// Check receipt signature
foreach ($pushResult['receipts'] as $receipt) {
    $rawReceiptBytes = base64_decode($receipt['raw_cbor_base64']);
    $decodedReceipt = Cbor::decode($rawReceiptBytes);
    $receiptSig = $decodedReceipt['server_sig']->bytes;
    $receiptCore = $decodedReceipt;
    unset($receiptCore['server_sig']);
    assertTest("Server receipt has valid Ed25519 signature", Crypto::verifyServer(Cbor::encode($receiptCore), $receiptSig));
}

// 7. Deduplication Check
echo "\n7. Deduplication Check\n";
$pushDupResult = $controller->push($pushPayload);
assertTest("Duplicate envelopes accepted without duplicate insertion", in_array($aliceMsgId, $pushDupResult['accepted_ids']));
$stmt = $pdo->prepare("SELECT COUNT(*) FROM envelopes WHERE message_id = ?");
$stmt->execute([$aliceMsgId]);
assertTest("Envelope stored exactly once in DB", (int)$stmt->fetchColumn() === 1);

// 8. Rejection Scenarios (FR-SRV-04)
echo "\n8. Rejection Scenarios (FR-SRV-04)\n";

// A. Invalid signature
$badEnv = $decodedEnv;
$badEnv['sig'] = new CborByteString(str_repeat("\x00", 64)); // corrupted signature
$badPush = $controller->push([
    'group_id' => $groupIdHex,
    'envelopes' => [base64_encode(Cbor::encode($badEnv))],
]);
assertTest("Corrupted signature rejected as INVALID_SIGNATURE", ($badPush['rejected'][0]['reason'] ?? '') === 'INVALID_SIGNATURE');

// B. Size exceeded (> 4096 bytes)
$oversizedEnv = $decodedEnv;
$oversizedEnv['core']['ciphertext'] = new CborByteString(str_repeat('X', 4500));
$oversizedPush = $controller->push([
    'group_id' => $groupIdHex,
    'envelopes' => [base64_encode(Cbor::encode($oversizedEnv))],
]);
assertTest("Oversized payload rejected as SIZE_EXCEEDED", ($oversizedPush['rejected'][0]['reason'] ?? '') === 'SIZE_EXCEEDED');

// C. Expired TTL
$expiredEnv = $decodedEnv;
$expiredEnv['core']['expires_at'] = Clock::now() - 1000;
$expiredEnv['sig'] = new CborByteString(sodium_crypto_sign_detached(Cbor::encode($expiredEnv['core']), hex2bin($cryptoKeys['alice']['secret_key_hex'])));
$expiredPush = $controller->push([
    'group_id' => $groupIdHex,
    'envelopes' => [base64_encode(Cbor::encode($expiredEnv))],
]);
assertTest("Expired TTL rejected as EXPIRED_TTL", ($expiredPush['rejected'][0]['reason'] ?? '') === 'EXPIRED_TTL');

// D. Revoked certificate
$pdo->prepare("INSERT INTO revocations (group_id, member_pubkey, revoked_at, reason, raw_cbor, server_sig) VALUES (?, ?, ?, 'Stolen key', '', '')")
    ->execute([$groupIdHex, $alicePkHex, Clock::now()]);
$pdo->exec("DELETE FROM envelopes WHERE message_id = '$aliceMsgId'");
$revokedPush = $controller->push([
    'group_id' => $groupIdHex,
    'envelopes' => [$envelopesTv['envelope_sos_alice']['full_envelope_cbor_base64']],
]);
assertTest("Revoked member rejected as CERTIFICATE_REVOKED", ($revokedPush['rejected'][0]['reason'] ?? '') === 'CERTIFICATE_REVOKED');

// Restore alice envelope for pull test
$pdo->exec("DELETE FROM revocations WHERE member_pubkey = '$alicePkHex'");
$controller->push($pushPayload);

// 9. Delta Sync Pull (FR-SRV-05)
echo "\n9. Delta Sync Pull (FR-SRV-05)\n";
$pullAll = $controller->pull($groupIdHex, '', 100);
assertTest("Pull with empty vector returns 2 envelopes", count($pullAll['envelopes']) === 2);
$firstDecoded = Cbor::decode(base64_decode($pullAll['envelopes'][0]));
$secondDecoded = Cbor::decode(base64_decode($pullAll['envelopes'][1]));
assertTest("SOS (Priority 0) delivered before BBS (Priority 2)", (int)$firstDecoded['core']['priority'] === 0 && (int)$secondDecoded['core']['priority'] === 2);

// Pull with Alice already known
$knownAliceVec = [
    $alicePkHex => ['contiguous' => 1, 'gaps' => []],
];
$pullBobOnly = $controller->pull($groupIdHex, base64_encode(json_encode($knownAliceVec)), 100);
assertTest("Pull with Alice seq 1 known returns only Bob envelope", count($pullBobOnly['envelopes']) === 1);
$onlyEnv = Cbor::decode(base64_decode($pullBobOnly['envelopes'][0]));
assertTest("Returned envelope belongs to Bob", bin2hex($onlyEnv['core']['author']->bytes) === $bobPkHex);

// 10. Receipts, Revocations & Group Key Epoch Rotation (FR-SEC-02, FR-ID-05)
echo "\n10. Receipts, Revocations & Group Key Epoch Rotation (FR-SEC-02, FR-ID-05)\n";
$receiptsRes = $controller->receipts($groupIdHex, 0);
assertTest("Receipts retrieved for group", count($receiptsRes['receipts']) >= 1);

$compromisedMemberHex = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
$revokeRes = $controller->revokeMember([
    'group_id' => $groupIdHex,
    'member_pubkey' => $compromisedMemberHex,
    'reason' => 'Device lost on trail',
]);
assertTest("revokeMember rotates group key to epoch 2", ($revokeRes['new_group_key']['epoch'] ?? 0) === 2);
assertTest("New epoch 2 key is 64 hex chars (32 bytes)", strlen($revokeRes['new_group_key']['key_hex'] ?? '') === 64);

$rawRevCbor = base64_decode($revokeRes['revocation']['raw_cbor_base64']);
$decodedRev = Cbor::decode($rawRevCbor);
$revSig = $decodedRev['server_sig']->bytes;
$revCore = $decodedRev;
unset($revCore['server_sig']);
assertTest("RevocationNotice has valid Ed25519 server signature", Crypto::verifyServer(Cbor::encode($revCore), $revSig));

$revsRes = $controller->revocations($groupIdHex, 0);
assertTest("Revocations query returns active revocation notice", count($revsRes['revocations']) >= 1);

$loginAfterRotate = $controller->login([
    'username' => 'alice',
    'password' => 'aliceSecurePass2026!',
]);
assertTest("Login after revocation returns both epoch 1 (grace period) and epoch 2", count($loginAfterRotate['group_keys']) === 2);
$epoch1Grace = $loginAfterRotate['group_keys'][0]['valid_until'] - Clock::now();
assertTest("Previous epoch 1 has 24h grace period", $epoch1Grace === 24 * 3600 * 1000);

echo "\n=======================================================\n";
echo "Test Results: {$passCount} PASSED, {$failCount} FAILED.\n";
echo "=======================================================\n";

if ($failCount > 0) {
    exit(1);
}
