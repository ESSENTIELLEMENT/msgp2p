-- msgp2p reference server MySQL schema (FR-SRV-01)

CREATE TABLE IF NOT EXISTS users (
    id VARCHAR(36) PRIMARY KEY,
    username VARCHAR(64) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'ACTIVE',
    created_at BIGINT NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS membership_certs (
    cert_ref CHAR(64) PRIMARY KEY,
    group_id CHAR(32) NOT NULL,
    user_id VARCHAR(36) NOT NULL,
    member_pubkey CHAR(64) NOT NULL,
    noise_pubkey CHAR(64) NOT NULL,
    role INT NOT NULL DEFAULT 0,
    issued_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL,
    raw_cbor LONGBLOB NOT NULL,
    server_sig CHAR(128) NOT NULL,
    INDEX idx_group_user (group_id, user_id),
    INDEX idx_member_pubkey (member_pubkey)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS group_keys (
    group_id CHAR(32) NOT NULL,
    epoch INT NOT NULL,
    key_hex CHAR(64) NOT NULL,
    valid_until BIGINT NOT NULL,
    beacon_key_hex CHAR(64) NOT NULL,
    PRIMARY KEY (group_id, epoch)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS envelopes (
    message_id CHAR(64) PRIMARY KEY,
    group_id CHAR(32) NOT NULL,
    key_epoch INT NOT NULL,
    author CHAR(64) NOT NULL,
    seq BIGINT NOT NULL,
    created_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL,
    priority INT NOT NULL DEFAULT 2,
    raw_cbor LONGBLOB NOT NULL,
    received_at BIGINT NOT NULL,
    INDEX idx_group_author_seq (group_id, author, seq),
    INDEX idx_group_received (group_id, received_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS receipts (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    group_id CHAR(32) NOT NULL,
    author CHAR(64) NOT NULL,
    ranges_json TEXT NOT NULL,
    issued_at BIGINT NOT NULL,
    raw_cbor LONGBLOB NOT NULL,
    server_sig CHAR(128) NOT NULL,
    INDEX idx_group_issued (group_id, issued_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS revocations (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    group_id CHAR(32) NOT NULL,
    member_pubkey CHAR(64) NOT NULL,
    revoked_at BIGINT NOT NULL,
    reason VARCHAR(255) NOT NULL,
    raw_cbor LONGBLOB NOT NULL,
    server_sig CHAR(128) NOT NULL,
    INDEX idx_group_member (group_id, member_pubkey)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS attachments (
    hash_hex CHAR(64) PRIMARY KEY,
    group_id CHAR(32) NOT NULL,
    mime VARCHAR(128) NOT NULL,
    byte_size INT UNSIGNED NOT NULL,
    blob_data LONGBLOB NOT NULL,
    created_at BIGINT NOT NULL,
    INDEX idx_group_hash (group_id, hash_hex)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
