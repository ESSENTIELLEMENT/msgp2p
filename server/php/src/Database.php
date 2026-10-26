<?php
declare(strict_types=1);

namespace MsgP2P\Server;

use PDO;
use PDOException;

class Database {
    private static ?PDO $instance = null;
    private static ?string $currentDb = null;

    public static function getConnection(?string $dbName = null): PDO {
        $targetDb = $dbName ?? (string)Config::get('DB_NAME', 'msgp2p_db');
        if (self::$instance !== null && self::$currentDb === $targetDb) {
            return self::$instance;
        }

        $host = (string)Config::get('DB_HOST', '127.0.0.1');
        $port = (int)Config::get('DB_PORT', 3306);
        $user = (string)Config::get('DB_USER', 'msgp2p_user');
        $pass = (string)Config::get('DB_PASS', 'your_password_here');

        $dsn = "mysql:host={$host};port={$port};dbname={$targetDb};charset=utf8mb4";
        $pdo = new PDO($dsn, $user, $pass, [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES => false,
        ]);

        self::$instance = $pdo;
        self::$currentDb = $targetDb;
        return $pdo;
    }

    public static function resetDatabase(string $dbName): void {
        $pdo = self::getConnection($dbName);
        $pdo->exec("SET FOREIGN_KEY_CHECKS = 0;");
        $tables = ['envelopes', 'receipts', 'revocations', 'attachments', 'membership_certs', 'group_keys', 'users'];
        foreach ($tables as $t) {
            try {
                $pdo->exec("TRUNCATE TABLE `{$t}`;");
            } catch (PDOException $e) {
                // Table may not exist yet before migration
            }
        }
        $pdo->exec("SET FOREIGN_KEY_CHECKS = 1;");
    }
}
