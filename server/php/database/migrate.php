<?php
declare(strict_types=1);

$databases = ['msgp2p_db', 'msgp2p_test'];
$host = getenv('DB_HOST') ?: '127.0.0.1';
$port = (int)(getenv('DB_PORT') ?: 3306);
$user = getenv('DB_USER') ?: 'msgp2p_user';
$pass = getenv('DB_PASS') ?: 'your_password_here';

$schemaFile = __DIR__ . '/schema.sql';
if (!file_exists($schemaFile)) {
    fwrite(STDERR, "schema.sql not found at {$schemaFile}\n");
    exit(1);
}

$sql = file_get_contents($schemaFile);

foreach ($databases as $db) {
    echo "Migrating database: {$db}...\n";
    try {
        $pdo = new PDO("mysql:host={$host};port={$port};dbname={$db};charset=utf8mb4", $user, $pass, [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        ]);

        $pdo->exec($sql);
        echo "Successfully migrated {$db}.\n";
    } catch (PDOException $e) {
        fwrite(STDERR, "Error migrating {$db}: " . $e->getMessage() . "\n");
        exit(1);
    }
}

echo "All migrations completed successfully.\n";
