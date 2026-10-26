<?php
declare(strict_types=1);

namespace MsgP2P\Server;

class Clock {
    private static ?int $mockTime = null;

    public static function now(): int {
        if (self::$mockTime !== null) {
            return self::$mockTime;
        }
        $envMock = getenv('MOCK_TIME_MS');
        if ($envMock !== false && $envMock !== '') {
            return (int)$envMock;
        }
        return (int)(microtime(true) * 1000);
    }

    public static function setMockTime(?int $time): void {
        self::$mockTime = $time;
    }
}
