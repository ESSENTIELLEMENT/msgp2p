<?php
declare(strict_types=1);

namespace MsgP2P\Server;

class Auth {
    public static function createToken(array $payload, int $ttl = 86400): string {
        $secret = (string)Config::get('JWT_SECRET');
        $header = ['alg' => 'HS256', 'typ' => 'JWT'];
        
        $payload['exp'] = time() + $ttl;
        $payload['iat'] = time();

        $b64Header = self::base64UrlEncode(json_encode($header));
        $b64Payload = self::base64UrlEncode(json_encode($payload));
        $signature = hash_hmac('sha256', "$b64Header.$b64Payload", $secret, true);
        $b64Sig = self::base64UrlEncode($signature);

        return "$b64Header.$b64Payload.$b64Sig";
    }

    public static function verifyToken(string $token): ?array {
        $parts = explode('.', $token);
        if (count($parts) !== 3) {
            return null;
        }

        [$b64Header, $b64Payload, $b64Sig] = $parts;
        $secret = (string)Config::get('JWT_SECRET');
        $expectedSig = self::base64UrlEncode(hash_hmac('sha256', "$b64Header.$b64Payload", $secret, true));

        if (!hash_equals($expectedSig, $b64Sig)) {
            return null;
        }

        $payload = json_decode(self::base64UrlDecode($b64Payload), true);
        if (!is_array($payload)) {
            return null;
        }

        if (isset($payload['exp']) && $payload['exp'] < time()) {
            return null; // Expired
        }

        return $payload;
    }

    private static function base64UrlEncode(string $data): string {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    private static function base64UrlDecode(string $data): string {
        return base64_decode(strtr($data, '-_', '+/') . str_repeat('=', (4 - strlen($data) % 4) % 4));
    }
}
