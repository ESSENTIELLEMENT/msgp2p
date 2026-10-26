<?php
declare(strict_types=1);

namespace MsgP2P\Server;

class CborByteString {
    public function __construct(public string $bytes) {}
}
