<?php
declare(strict_types=1);

namespace MsgP2P\Server;

class Crypto {
    private static ?string $serverKp = null;

    public static function getServerKeypair(): string {
        if (self::$serverKp === null) {
            $seedHex = (string)Config::get('SERVER_KEY_SEED_HEX');
            $seed = hex2bin($seedHex);
            self::$serverKp = sodium_crypto_sign_seed_keypair($seed);
        }
        return self::$serverKp;
    }

    public static function getServerPublicKey(): string {
        return sodium_crypto_sign_publickey(self::getServerKeypair());
    }

    public static function getServerSecretKey(): string {
        return sodium_crypto_sign_secretkey(self::getServerKeypair());
    }

    public static function signServer(string $data): string {
        return sodium_crypto_sign_detached($data, self::getServerSecretKey());
    }

    public static function verifyServer(string $data, string $sig): bool {
        return sodium_crypto_sign_verify_detached($sig, $data, self::getServerPublicKey());
    }

    public static function verifyEd25519(string $data, string $sig, string $pubkey): bool {
        if (strlen($sig) !== SODIUM_CRYPTO_SIGN_BYTES || strlen($pubkey) !== SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES) {
            return false;
        }
        return sodium_crypto_sign_verify_detached($sig, $data, $pubkey);
    }

    public static function sha256(string $data): string {
        return hash('sha256', $data, true);
    }

    public static function sha256Hex(string $data): string {
        return hash('sha256', $data, false);
    }

    public static function xchacha20Encrypt(string $plaintext, string $aad, string $nonce, string $key): string {
        return sodium_crypto_aead_xchacha20poly1305_ietf_encrypt($plaintext, $aad, $nonce, $key);
    }

    public static function xchacha20Decrypt(string $ciphertext, string $aad, string $nonce, string $key): ?string {
        try {
            $res = sodium_crypto_aead_xchacha20poly1305_ietf_decrypt($ciphertext, $aad, $nonce, $key);
            return $res !== false ? $res : null;
        } catch (\Exception $e) {
            return null;
        }
    }
}
