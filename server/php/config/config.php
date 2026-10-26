<?php
declare(strict_types=1);

namespace MsgP2P\Server;

class Config {
    public static function get(string $key, mixed $default = null): mixed {
        $env = getenv($key);
        if ($env !== false && $env !== '') {
            return $env;
        }

        $defaults = [
            'DB_HOST' => '127.0.0.1',
            'DB_PORT' => 3306,
            'DB_NAME' => 'msgp2p_db',
            'DB_USER' => 'msgp2p_user',
            'DB_PASS' => 'your_password_here',
            'JWT_SECRET' => 'msgp2p_super_secret_jwt_key_1234567890',
            // Deterministic server seed matching protocol/test-vectors/crypto_keys.json
            'SERVER_KEY_SEED_HEX' => 'b0f7ab3ba4d1f2cdbd54861ab828f8930b3bffb538a51ea068dff247533bdd1a',
            'DEFAULT_GROUP_ID' => 'a0b1c2d3e4f50123456789abcdef0123',
            'DEFAULT_GROUP_KEY_HEX' => '6a6857b42afacd39bae57823e733fc9165583be6c3d46dfa4af174bdca658656',
            'DEFAULT_BEACON_KEY_HEX' => '771726326f8f952122f126098b68b616ac3630f9bd11dce587d6e62899da1327',
        ];

        return $defaults[$key] ?? $default;
    }
}
