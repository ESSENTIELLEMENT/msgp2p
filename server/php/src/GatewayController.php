<?php
declare(strict_types=1);

namespace MsgP2P\Server;

use PDO;
use Exception;
use InvalidArgumentException;

class GatewayController {
    private PDO $pdo;

    public function __construct(?string $dbName = null) {
        $this->pdo = Database::getConnection($dbName);
    }

    public function register(array $data): array {
        $username = trim((string)($data['username'] ?? ''));
        $password = (string)($data['password'] ?? '');
        $groupIdHex = strtolower(trim((string)($data['group_id'] ?? '')));
        $memberPubkeyHex = strtolower(trim((string)($data['member_pubkey'] ?? '')));
        $noisePubkeyHex = strtolower(trim((string)($data['noise_pubkey'] ?? '')));

        if (strlen($username) < 3 || strlen($password) < 8 || strlen($groupIdHex) !== 32 || strlen($memberPubkeyHex) !== 64) {
            throw new InvalidArgumentException("Invalid registration parameters");
        }

        if (empty($noisePubkeyHex)) {
            $noiseKp = sodium_crypto_box_keypair();
            $noisePubkeyHex = bin2hex(sodium_crypto_box_publickey($noiseKp));
        }

        $stmt = $this->pdo->prepare("SELECT id FROM users WHERE username = ?");
        $stmt->execute([$username]);
        if ($stmt->fetch()) {
            throw new Exception("Username already exists", 400);
        }

        $userId = 'usr_' . bin2hex(random_bytes(6));
        $passHash = password_hash($password, PASSWORD_DEFAULT);
        $now = Clock::now();
        $expiresAt = $now + (7 * 86400 * 1000); // 7 days

        $this->pdo->beginTransaction();
        try {
            // 1. Insert user
            $stmt = $this->pdo->prepare("INSERT INTO users (id, username, password_hash, status, created_at) VALUES (?, ?, ?, 'ACTIVE', ?)");
            $stmt->execute([$userId, $username, $passHash, $now]);

            // 2. Issue membership certificate
            $certCore = [
                'v' => 1,
                'group_id' => new CborByteString(hex2bin($groupIdHex)),
                'user_id' => $userId,
                'member_pubkey' => new CborByteString(hex2bin($memberPubkeyHex)),
                'noise_pubkey' => new CborByteString(hex2bin($noisePubkeyHex)),
                'role' => 0,
                'issued_at' => $now,
                'expires_at' => $expiresAt,
            ];
            $coreCbor = Cbor::encode($certCore);
            $serverSig = Crypto::signServer($coreCbor);
            $fullCert = $certCore;
            $fullCert['server_sig'] = new CborByteString($serverSig);
            $fullCbor = Cbor::encode($fullCert);
            $certRefHex = hash('sha256', $fullCbor, false);

            $stmt = $this->pdo->prepare("
                INSERT INTO membership_certs 
                (cert_ref, group_id, user_id, member_pubkey, noise_pubkey, role, issued_at, expires_at, raw_cbor, server_sig)
                VALUES (?, ?, ?, ?, ?, 0, ?, ?, ?, ?)
            ");
            $stmt->execute([
                $certRefHex, $groupIdHex, $userId, $memberPubkeyHex, $noisePubkeyHex,
                $now, $expiresAt, $fullCbor, bin2hex($serverSig)
            ]);

            // 3. Ensure default group key exists
            $stmt = $this->pdo->prepare("SELECT epoch FROM group_keys WHERE group_id = ? AND epoch = 1");
            $stmt->execute([$groupIdHex]);
            if (!$stmt->fetch()) {
                $groupKeyHex = (string)Config::get('DEFAULT_GROUP_KEY_HEX');
                $beaconKeyHex = (string)Config::get('DEFAULT_BEACON_KEY_HEX');
                $validUntil = $now + (30 * 86400 * 1000);
                $stmt = $this->pdo->prepare("
                    INSERT INTO group_keys (group_id, epoch, key_hex, valid_until, beacon_key_hex)
                    VALUES (?, 1, ?, ?, ?)
                ");
                $stmt->execute([$groupIdHex, $groupKeyHex, $validUntil, $beaconKeyHex]);
            }

            $this->pdo->commit();

            return [
                'user_id' => $userId,
                'status' => 'ACTIVE',
            ];
        } catch (\Throwable $e) {
            $this->pdo->rollBack();
            throw $e;
        }
    }

    public function login(array $data): array {
        $username = trim((string)($data['username'] ?? ''));
        $password = (string)($data['password'] ?? '');

        $stmt = $this->pdo->prepare("SELECT * FROM users WHERE username = ?");
        $stmt->execute([$username]);
        $user = $stmt->fetch();

        if (!$user || !password_verify($password, $user['password_hash'])) {
            throw new Exception("Invalid username or password", 401);
        }

        $stmt = $this->pdo->prepare("SELECT * FROM membership_certs WHERE user_id = ? ORDER BY issued_at DESC LIMIT 1");
        $stmt->execute([$user['id']]);
        $cert = $stmt->fetch();
        if (!$cert) {
            throw new Exception("No membership certificate found for user", 403);
        }

        $groupId = $cert['group_id'];

        $stmt = $this->pdo->prepare("SELECT * FROM group_keys WHERE group_id = ? ORDER BY epoch ASC");
        $stmt->execute([$groupId]);
        $groupKeys = $stmt->fetchAll();

        $beaconKey = (string)Config::get('DEFAULT_BEACON_KEY_HEX');
        if (!empty($groupKeys)) {
            $beaconKey = $groupKeys[0]['beacon_key_hex'];
        }

        $tokenPayload = [
            'sub' => $user['id'],
            'username' => $user['username'],
            'group_id' => $groupId,
        ];
        $accessToken = Auth::createToken($tokenPayload, 86400);

        return [
            'access_token' => $accessToken,
            'expires_in' => 86400,
            'server_pubkey' => bin2hex(Crypto::getServerPublicKey()),
            'membership_cert' => [
                'raw_cbor_base64' => base64_encode($cert['raw_cbor']),
                'cert_ref' => $cert['cert_ref'],
                'group_id' => $cert['group_id'],
                'user_id' => $cert['user_id'],
                'member_pubkey' => $cert['member_pubkey'],
                'noise_pubkey' => $cert['noise_pubkey'],
                'role' => (int)$cert['role'],
                'issued_at' => (int)$cert['issued_at'],
                'expires_at' => (int)$cert['expires_at'],
            ],
            'group_beacon_key' => $beaconKey,
            'group_keys' => array_map(fn($k) => [
                'epoch' => (int)$k['epoch'],
                'key_hex' => $k['key_hex'],
                'valid_until' => (int)$k['valid_until'],
            ], $groupKeys),
        ];
    }

    public function push(array $data): array {
        $groupIdHex = strtolower(trim((string)($data['group_id'] ?? '')));
        $envelopes = $data['envelopes'] ?? [];
        $certificates = $data['certificates'] ?? [];

        if (strlen($groupIdHex) !== 32 || !is_array($envelopes)) {
            throw new InvalidArgumentException("Invalid push request payload");
        }

        $now = Clock::now();

        // 1. Ingest supplied certificates
        foreach ($certificates as $b64Cert) {
            $this->ingestCertificate($b64Cert);
        }

        $acceptedIds = [];
        $rejected = [];
        $authorNewSeqs = [];

        foreach ($envelopes as $b64Env) {
            $rawBytes = base64_decode($b64Env, true);
            if ($rawBytes === false) {
                $rejected[] = ['message_id' => 'unknown', 'reason' => 'MALFORMED_CBOR'];
                continue;
            }

            if (strlen($rawBytes) > 4096) {
                $rejected[] = ['message_id' => 'unknown', 'reason' => 'SIZE_EXCEEDED'];
                continue;
            }

            try {
                $decoded = Cbor::decode($rawBytes);
            } catch (\Throwable $e) {
                $rejected[] = ['message_id' => 'unknown', 'reason' => 'MALFORMED_CBOR'];
                continue;
            }

            if (!isset($decoded['core'], $decoded['sig'], $decoded['cert_ref'])) {
                $rejected[] = ['message_id' => 'unknown', 'reason' => 'MALFORMED_CBOR'];
                continue;
            }

            $core = $decoded['core'];
            $coreCbor = Cbor::encode($core);
            $messageIdHex = hash('sha256', $coreCbor, false);



            // Certificate check
            $certRefHex = bin2hex($decoded['cert_ref']->bytes);
            $stmt = $this->pdo->prepare("SELECT * FROM membership_certs WHERE cert_ref = ?");
            $stmt->execute([$certRefHex]);
            $cert = $stmt->fetch();

            if (!$cert) {
                $rejected[] = ['message_id' => $messageIdHex, 'reason' => 'CERTIFICATE_EXPIRED'];
                continue;
            }

            // Revocation check
            $authorHex = bin2hex($core['author']->bytes);
            $stmt = $this->pdo->prepare("SELECT id FROM revocations WHERE group_id = ? AND member_pubkey = ?");
            $stmt->execute([$groupIdHex, $authorHex]);
            if ($stmt->fetch()) {
                $rejected[] = ['message_id' => $messageIdHex, 'reason' => 'CERTIFICATE_REVOKED'];
                continue;
            }

            // Certificate expiry
            if ((int)$cert['expires_at'] <= $now) {
                $rejected[] = ['message_id' => $messageIdHex, 'reason' => 'CERTIFICATE_EXPIRED'];
                continue;
            }

            // Certificate member_pubkey matches author
            if (strtolower($cert['member_pubkey']) !== strtolower($authorHex)) {
                $rejected[] = ['message_id' => $messageIdHex, 'reason' => 'INVALID_SIGNATURE'];
                continue;
            }

            // Author signature verification
            $sigBytes = $decoded['sig']->bytes;
            $authorPkBytes = $core['author']->bytes;
            if (!Crypto::verifyEd25519($coreCbor, $sigBytes, $authorPkBytes)) {
                $rejected[] = ['message_id' => $messageIdHex, 'reason' => 'INVALID_SIGNATURE'];
                continue;
            }

            // Time & Expiry check
            $createdAt = (int)$core['created_at'];
            $expiresAt = (int)$core['expires_at'];

            if ($createdAt > $now + 600000) {
                $rejected[] = ['message_id' => $messageIdHex, 'reason' => 'FUTURE_TIMESTAMP'];
                continue;
            }

            if ($expiresAt <= $now) {
                $rejected[] = ['message_id' => $messageIdHex, 'reason' => 'EXPIRED_TTL'];
                continue;
            }

            // Deduplication check (Step 5 in wire-format.md §4.4)
            $stmt = $this->pdo->prepare("SELECT message_id FROM envelopes WHERE message_id = ?");
            $stmt->execute([$messageIdHex]);
            if ($stmt->fetch()) {
                $acceptedIds[] = $messageIdHex;
                continue;
            }

            // Accept and store envelope
            $seq = (int)$core['seq'];
            $keyEpoch = (int)$core['key_epoch'];
            $priority = (int)($core['priority'] ?? 2);

            $stmt = $this->pdo->prepare("
                INSERT INTO envelopes 
                (message_id, group_id, key_epoch, author, seq, created_at, expires_at, priority, raw_cbor, received_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ");
            $stmt->execute([
                $messageIdHex, $groupIdHex, $keyEpoch, $authorHex, $seq,
                $createdAt, $expiresAt, $priority, $rawBytes, $now
            ]);

            $acceptedIds[] = $messageIdHex;
            $authorNewSeqs[$authorHex][$seq] = true;
        }

        // Generate receipts for authors with accepted envelopes
        $receiptDtos = [];
        foreach (array_keys($authorNewSeqs) as $authorHex) {
            $receiptDto = $this->generateReceipt($groupIdHex, $authorHex, $now);
            if ($receiptDto !== null) {
                $receiptDtos[] = $receiptDto;
            }
        }

        return [
            'accepted_ids' => $acceptedIds,
            'rejected' => $rejected,
            'receipts' => $receiptDtos,
        ];
    }

    private function ingestCertificate(string $b64Cert): void {
        $rawBytes = base64_decode($b64Cert, true);
        if ($rawBytes === false) return;

        try {
            $decoded = Cbor::decode($rawBytes);
        } catch (\Throwable) {
            return;
        }

        if (!isset($decoded['server_sig'], $decoded['member_pubkey'], $decoded['group_id'])) {
            return;
        }

        $sigBytes = $decoded['server_sig']->bytes;
        $coreCert = $decoded;
        unset($coreCert['server_sig']);
        $coreCbor = Cbor::encode($coreCert);

        if (!Crypto::verifyServer($coreCbor, $sigBytes)) {
            return;
        }

        $fullCbor = Cbor::encode($decoded);
        $certRefHex = hash('sha256', $fullCbor, false);
        $groupIdHex = bin2hex($decoded['group_id']->bytes);
        $memberPubkeyHex = bin2hex($decoded['member_pubkey']->bytes);
        $noisePubkeyHex = isset($decoded['noise_pubkey']) ? bin2hex($decoded['noise_pubkey']->bytes) : '';
        $userId = (string)($decoded['user_id'] ?? 'unknown');
        $role = (int)($decoded['role'] ?? 0);
        $issuedAt = (int)($decoded['issued_at'] ?? 0);
        $expiresAt = (int)($decoded['expires_at'] ?? 0);

        $stmt = $this->pdo->prepare("
            INSERT IGNORE INTO membership_certs 
            (cert_ref, group_id, user_id, member_pubkey, noise_pubkey, role, issued_at, expires_at, raw_cbor, server_sig)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ");
        $stmt->execute([
            $certRefHex, $groupIdHex, $userId, $memberPubkeyHex, $noisePubkeyHex,
            $role, $issuedAt, $expiresAt, $fullCbor, bin2hex($sigBytes)
        ]);
    }

    private function generateReceipt(string $groupIdHex, string $authorHex, int $now): ?array {
        $stmt = $this->pdo->prepare("SELECT seq FROM envelopes WHERE group_id = ? AND author = ? ORDER BY seq ASC");
        $stmt->execute([$groupIdHex, $authorHex]);
        $rows = $stmt->fetchAll();
        if (empty($rows)) return null;

        $seqs = array_map(fn($r) => (int)$r['seq'], $rows);
        $ranges = $this->compactRanges($seqs);

        $receiptCore = [
            'v' => 1,
            'group_id' => new CborByteString(hex2bin($groupIdHex)),
            'author' => new CborByteString(hex2bin($authorHex)),
            'ranges' => $ranges,
            'issued_at' => $now,
        ];
        $coreCbor = Cbor::encode($receiptCore);
        $serverSig = Crypto::signServer($coreCbor);
        $fullReceipt = $receiptCore;
        $fullReceipt['server_sig'] = new CborByteString($serverSig);
        $fullCbor = Cbor::encode($fullReceipt);

        $stmt = $this->pdo->prepare("
            INSERT INTO receipts (group_id, author, ranges_json, issued_at, raw_cbor, server_sig)
            VALUES (?, ?, ?, ?, ?, ?)
        ");
        $stmt->execute([
            $groupIdHex, $authorHex, json_encode($ranges), $now, $fullCbor, bin2hex($serverSig)
        ]);

        return [
            'raw_cbor_base64' => base64_encode($fullCbor),
            'author' => $authorHex,
            'ranges' => $ranges,
            'issued_at' => $now,
        ];
    }

    private function compactRanges(array $seqs): array {
        if (empty($seqs)) return [];
        sort($seqs);
        $seqs = array_values(array_unique($seqs));

        $ranges = [];
        $start = $seqs[0];
        $prev = $seqs[0];

        for ($i = 1; $i < count($seqs); $i++) {
            $curr = $seqs[$i];
            if ($curr === $prev + 1) {
                $prev = $curr;
            } else {
                $ranges[] = [$start, $prev];
                $start = $curr;
                $prev = $curr;
            }
        }
        $ranges[] = [$start, $prev];
        return $ranges;
    }

    public function pull(string $groupIdHex, string $vectorStr, int $limit = 100): array {
        $limit = max(1, min(500, $limit));

        $clientVector = $this->parseVersionVector($vectorStr);

        $stmt = $this->pdo->prepare("SELECT * FROM envelopes WHERE group_id = ? ORDER BY priority ASC, created_at ASC");
        $stmt->execute([$groupIdHex]);
        $allEnvelopes = $stmt->fetchAll();

        $matching = [];
        foreach ($allEnvelopes as $env) {
            $author = $env['author'];
            $seq = (int)$env['seq'];

            $hasMessage = false;
            if (isset($clientVector[$author])) {
                $cInfo = $clientVector[$author];
                $contiguous = $cInfo['contiguous'];
                $gaps = $cInfo['gaps'];

                if ($seq <= $contiguous && !in_array($seq, $gaps, true)) {
                    $hasMessage = true;
                }
            }

            if (!$hasMessage) {
                $matching[] = $env;
            }
        }

        $hasMore = count($matching) > $limit;
        $page = array_slice($matching, 0, $limit);

        $serverVector = $this->computeGroupServerVector($groupIdHex);
        $serverVectorCbor = Cbor::encode($serverVector);

        return [
            'envelopes' => array_map(fn($e) => base64_encode($e['raw_cbor']), $page),
            'has_more' => $hasMore,
            'server_vector' => base64_encode($serverVectorCbor),
        ];
    }

    private function parseVersionVector(string $vectorStr): array {
        if (empty($vectorStr)) return [];

        $raw = base64_decode($vectorStr, true);
        if ($raw === false) {
            $raw = $vectorStr;
        }

        try {
            $decoded = Cbor::decode($raw);
            if (is_array($decoded)) {
                $vec = [];
                foreach ($decoded as $k => $v) {
                    $authorHex = ($k instanceof CborByteString) ? bin2hex($k->bytes) : (string)$k;
                    if (is_array($v)) {
                        $contiguous = (int)($v['contiguous'] ?? ($v[0] ?? 0));
                        $gaps = (array)($v['gaps'] ?? ($v[1] ?? []));
                        $vec[$authorHex] = ['contiguous' => $contiguous, 'gaps' => $gaps];
                    }
                }
                return $vec;
            }
        } catch (\Throwable) {}

        $json = json_decode($raw, true);
        if (is_array($json)) {
            $vec = [];
            foreach ($json as $k => $v) {
                if (is_array($v)) {
                    $contiguous = (int)($v['contiguous'] ?? ($v[0] ?? 0));
                    $gaps = (array)($v['gaps'] ?? ($v[1] ?? []));
                    $vec[(string)$k] = ['contiguous' => $contiguous, 'gaps' => $gaps];
                }
            }
            return $vec;
        }

        return [];
    }

    private function computeGroupServerVector(string $groupIdHex): array {
        $stmt = $this->pdo->prepare("SELECT author, seq FROM envelopes WHERE group_id = ? ORDER BY author, seq ASC");
        $stmt->execute([$groupIdHex]);
        $rows = $stmt->fetchAll();

        $authorSeqs = [];
        foreach ($rows as $r) {
            $authorSeqs[$r['author']][] = (int)$r['seq'];
        }

        $vectorMap = [];
        foreach ($authorSeqs as $authorHex => $seqs) {
            sort($seqs);
            $seqs = array_values(array_unique($seqs));
            $maxSeq = end($seqs);

            $authorKey = new CborByteString(hex2bin($authorHex));
            $vectorMap[$authorHex] = [
                'contiguous' => $maxSeq,
                'gaps' => [],
            ];
        }

        return $vectorMap;
    }

    public function receipts(string $groupIdHex, int $since = 0): array {
        $stmt = $this->pdo->prepare("SELECT * FROM receipts WHERE group_id = ? AND issued_at > ? ORDER BY issued_at ASC");
        $stmt->execute([$groupIdHex, $since]);
        $rows = $stmt->fetchAll();

        return [
            'receipts' => array_map(fn($r) => [
                'raw_cbor_base64' => base64_encode($r['raw_cbor']),
                'author' => $r['author'],
                'ranges' => json_decode($r['ranges_json'], true),
                'issued_at' => (int)$r['issued_at'],
            ], $rows),
        ];
    }

    public function revocations(string $groupIdHex, int $since = 0): array {
        $stmt = $this->pdo->prepare("SELECT * FROM revocations WHERE group_id = ? AND revoked_at > ? ORDER BY revoked_at ASC");
        $stmt->execute([$groupIdHex, $since]);
        $rows = $stmt->fetchAll();

        return [
            'revocations' => array_map(fn($r) => [
                'raw_cbor_base64' => base64_encode($r['raw_cbor']),
                'member_pubkey' => $r['member_pubkey'],
                'revoked_at' => (int)$r['revoked_at'],
                'reason' => $r['reason'],
            ], $rows),
        ];
    }

    /**
     * Issues a server-signed member revocation notice and rotates the group key epoch (FR-ID-05, FR-SEC-02).
     * Previous epoch retains a 24-hour grace period per FR-SEC-02.
     */
    public function revokeMember(array $data): array {
        $groupIdHex = strtolower(trim((string)($data['group_id'] ?? '')));
        $memberPubkeyHex = strtolower(trim((string)($data['member_pubkey'] ?? '')));
        $reason = trim((string)($data['reason'] ?? 'compromised_credential'));

        if (strlen($groupIdHex) !== 32 || strlen($memberPubkeyHex) !== 64 || empty($reason)) {
            throw new InvalidArgumentException("Invalid revocation parameters");
        }

        $now = Clock::now();
        $graceWindowMs = 24 * 3600 * 1000; // 24h grace period per FR-SEC-02
        $newKeyValidUntil = $now + (30 * 86400 * 1000);

        $revCore = [
            'v' => 1,
            'group_id' => new CborByteString(hex2bin($groupIdHex)),
            'member_pubkey' => new CborByteString(hex2bin($memberPubkeyHex)),
            'revoked_at' => $now,
            'reason' => $reason,
        ];
        $coreCbor = Cbor::encode($revCore);
        $serverSig = Crypto::signServer($coreCbor);
        $fullRev = $revCore;
        $fullRev['server_sig'] = new CborByteString($serverSig);
        $fullCbor = Cbor::encode($fullRev);

        $this->pdo->beginTransaction();
        try {
            // 1. Insert revocation notice
            $stmt = $this->pdo->prepare("
                INSERT INTO revocations (group_id, member_pubkey, revoked_at, reason, raw_cbor, server_sig)
                VALUES (?, ?, ?, ?, ?, ?)
            ");
            $stmt->execute([
                $groupIdHex,
                $memberPubkeyHex,
                $now,
                $reason,
                $fullCbor,
                bin2hex($serverSig),
            ]);

            // 2. Rotate group key epoch (FR-SEC-02)
            $stmt = $this->pdo->prepare("SELECT MAX(epoch) AS max_epoch, MAX(beacon_key_hex) AS beacon_key FROM group_keys WHERE group_id = ?");
            $stmt->execute([$groupIdHex]);
            $row = $stmt->fetch();
            $currentEpoch = (int)($row['max_epoch'] ?? 0);
            $beaconKeyHex = !empty($row['beacon_key'])
                ? (string)$row['beacon_key']
                : (string)Config::get('DEFAULT_BEACON_KEY_HEX');

            if ($currentEpoch > 0) {
                // Cap previous epoch validity to 24-hour grace period
                $graceUntil = $now + $graceWindowMs;
                $stmt = $this->pdo->prepare("
                    UPDATE group_keys
                    SET valid_until = CASE WHEN valid_until > ? THEN ? ELSE valid_until END
                    WHERE group_id = ? AND epoch = ?
                ");
                $stmt->execute([$graceUntil, $graceUntil, $groupIdHex, $currentEpoch]);
            }

            $newEpoch = $currentEpoch + 1;
            $newKeyHex = bin2hex(random_bytes(32));
            $stmt = $this->pdo->prepare("
                INSERT INTO group_keys (group_id, epoch, key_hex, valid_until, beacon_key_hex)
                VALUES (?, ?, ?, ?, ?)
            ");
            $stmt->execute([$groupIdHex, $newEpoch, $newKeyHex, $newKeyValidUntil, $beaconKeyHex]);

            $this->pdo->commit();

            return [
                'revocation' => [
                    'raw_cbor_base64' => base64_encode($fullCbor),
                    'member_pubkey' => $memberPubkeyHex,
                    'revoked_at' => $now,
                    'reason' => $reason,
                ],
                'new_group_key' => [
                    'epoch' => $newEpoch,
                    'key_hex' => $newKeyHex,
                    'valid_until' => $newKeyValidUntil,
                ],
            ];
        } catch (\Throwable $e) {
            $this->pdo->rollBack();
            throw $e;
        }
    }

    /**
     * Ensures the `attachments` table exists and stores a hash-addressed attachment blob.
     */
    public function uploadAttachment(array $data): array {
        $groupIdHex = strtolower(trim((string)($data['group_id'] ?? '')));
        $hashHex = strtolower(trim((string)($data['hash'] ?? '')));
        $mime = trim((string)($data['mime'] ?? 'application/octet-stream'));
        $blobB64 = (string)($data['data_base64'] ?? '');

        if (strlen($groupIdHex) !== 32 || strlen($hashHex) !== 64 || empty($blobB64)) {
            throw new InvalidArgumentException("Invalid attachment parameters");
        }

        $blobBytes = base64_decode($blobB64, true);
        if ($blobBytes === false) {
            throw new InvalidArgumentException("Invalid base64 attachment data");
        }

        $actualHashHex = hash('sha256', $blobBytes, false);
        if (!hash_equals($hashHex, $actualHashHex)) {
            throw new InvalidArgumentException("Attachment SHA-256 hash mismatch");
        }

        $this->ensureAttachmentsTable();
        $now = Clock::now();

        $stmt = $this->pdo->prepare("
            INSERT IGNORE INTO attachments (hash_hex, group_id, mime, byte_size, blob_data, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
        ");
        $stmt->execute([$hashHex, $groupIdHex, $mime, strlen($blobBytes), $blobBytes, $now]);

        return [
            'hash' => $hashHex,
            'size' => strlen($blobBytes),
            'stored' => true,
        ];
    }

    /**
     * Retrieves a hash-addressed attachment blob by group_id and hash.
     */
    public function getAttachment(string $groupId, string $hash): array {
        $groupIdHex = strtolower(trim($groupId));
        $hashHex = strtolower(trim($hash));
        if (strlen($groupIdHex) !== 32 || strlen($hashHex) !== 64) {
            throw new InvalidArgumentException("Invalid group_id or hash parameter");
        }

        $this->ensureAttachmentsTable();
        $stmt = $this->pdo->prepare("
            SELECT hash_hex, mime, byte_size, blob_data
            FROM attachments
            WHERE group_id = ? AND hash_hex = ?
            LIMIT 1
        ");
        $stmt->execute([$groupIdHex, $hashHex]);
        $row = $stmt->fetch();
        if (!$row) {
            throw new Exception("Attachment not found", 404);
        }

        return [
            'hash' => $row['hash_hex'],
            'mime' => $row['mime'],
            'size' => (int)$row['byte_size'],
            'data_base64' => base64_encode($row['blob_data']),
        ];
    }

    private function ensureAttachmentsTable(): void {
        $this->pdo->exec("
            CREATE TABLE IF NOT EXISTS attachments (
                hash_hex CHAR(64) PRIMARY KEY,
                group_id CHAR(32) NOT NULL,
                mime VARCHAR(128) NOT NULL,
                byte_size INT UNSIGNED NOT NULL,
                blob_data LONGBLOB NOT NULL,
                created_at BIGINT NOT NULL,
                INDEX idx_group_hash (group_id, hash_hex)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
        ");
    }
}
