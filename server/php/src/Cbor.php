<?php
declare(strict_types=1);

namespace MsgP2P\Server;

use InvalidArgumentException;


class Cbor {
    public static function encode(mixed $value): string {
        if (is_int($value)) {
            if ($value >= 0) {
                return self::encodeUint($value, 0);
            } else {
                return self::encodeUint(-1 - $value, 1);
            }
        }
        if (is_float($value)) {
            return "\xfb" . pack('E', $value);
        }
        if (is_bool($value)) {
            return $value ? "\xf5" : "\xf4";
        }
        if ($value === null) {
            return "\xf6";
        }
        if (is_string($value)) {
            return self::encodeUint(strlen($value), 3) . $value;
        }
        if ($value instanceof CborByteString) {
            return self::encodeUint(strlen($value->bytes), 2) . $value->bytes;
        }
        if (is_array($value)) {
            if (array_is_list($value)) {
                $out = self::encodeUint(count($value), 4);
                foreach ($value as $item) {
                    $out .= self::encode($item);
                }
                return $out;
            } else {
                $pairs = [];
                foreach ($value as $k => $v) {
                    $kEncoded = self::encode($k);
                    $vEncoded = self::encode($v);
                    $pairs[] = ['k_raw' => $kEncoded, 'v_raw' => $vEncoded];
                }
                // Deterministic canonical sorting by byte length then strcmp
                usort($pairs, function($a, $b) {
                    $la = strlen($a['k_raw']);
                    $lb = strlen($b['k_raw']);
                    if ($la !== $lb) {
                        return $la <=> $lb;
                    }
                    return strcmp($a['k_raw'], $b['k_raw']);
                });
                $out = self::encodeUint(count($pairs), 5);
                foreach ($pairs as $p) {
                    $out .= $p['k_raw'] . $p['v_raw'];
                }
                return $out;
            }
        }
        throw new InvalidArgumentException("Unsupported CBOR type: " . get_debug_type($value));
    }

    private static function encodeUint(int $val, int $major): string {
        $prefix = $major << 5;
        if ($val <= 23) {
            return chr($prefix | $val);
        }
        if ($val <= 0xFF) {
            return chr($prefix | 24) . chr($val);
        }
        if ($val <= 0xFFFF) {
            return chr($prefix | 25) . pack('n', $val);
        }
        if ($val <= 0xFFFFFFFF) {
            return chr($prefix | 26) . pack('N', $val);
        }
        return chr($prefix | 27) . pack('J', $val);
    }

    public static function decode(string $data, int &$offset = 0): mixed {
        if ($offset >= strlen($data)) {
            throw new InvalidArgumentException("Unexpected end of CBOR data at offset $offset");
        }

        $first = ord($data[$offset++]);
        $major = $first >> 5;
        $info = $first & 0x1f;

        $val = self::readLength($info, $data, $offset);

        switch ($major) {
            case 0: // uint
                return $val;
            case 1: // nint
                return -1 - $val;
            case 2: // bstr
                $bytes = substr($data, $offset, $val);
                if (strlen($bytes) < $val) {
                    throw new InvalidArgumentException("Unexpected EOF reading bstr of length $val");
                }
                $offset += $val;
                return new CborByteString($bytes);
            case 3: // tstr
                $str = substr($data, $offset, $val);
                if (strlen($str) < $val) {
                    throw new InvalidArgumentException("Unexpected EOF reading tstr of length $val");
                }
                $offset += $val;
                return $str;
            case 4: // array
                $list = [];
                for ($i = 0; $i < $val; $i++) {
                    $list[] = self::decode($data, $offset);
                }
                return $list;
            case 5: // map
                $map = [];
                for ($i = 0; $i < $val; $i++) {
                    $key = self::decode($data, $offset);
                    $keyStr = ($key instanceof CborByteString) ? bin2hex($key->bytes) : (string)$key;
                    $valItem = self::decode($data, $offset);
                    $map[$keyStr] = $valItem;
                }
                return $map;
            case 7: // simple
                if ($info === 20) return false;
                if ($info === 21) return true;
                if ($info === 22) return null;
                if ($info === 27) { // 64-bit float
                    $fBytes = substr($data, $offset - 8, 8);
                    $unpacked = unpack('E', $fBytes);
                    return $unpacked[1];
                }
                return null;
            default:
                throw new InvalidArgumentException("Unsupported CBOR major type $major");
        }
    }

    private static function readLength(int $info, string $data, int &$offset): int {
        if ($info < 24) {
            return $info;
        }
        if ($info === 24) {
            if ($offset + 1 > strlen($data)) throw new InvalidArgumentException("EOF reading 1-byte length");
            return ord($data[$offset++]);
        }
        if ($info === 25) {
            if ($offset + 2 > strlen($data)) throw new InvalidArgumentException("EOF reading 2-byte length");
            $unpacked = unpack('n', substr($data, $offset, 2));
            $offset += 2;
            return $unpacked[1];
        }
        if ($info === 26) {
            if ($offset + 4 > strlen($data)) throw new InvalidArgumentException("EOF reading 4-byte length");
            $unpacked = unpack('N', substr($data, $offset, 4));
            $offset += 4;
            return $unpacked[1];
        }
        if ($info === 27) {
            if ($offset + 8 > strlen($data)) throw new InvalidArgumentException("EOF reading 8-byte length");
            $unpacked = unpack('J', substr($data, $offset, 8));
            $offset += 8;
            return $unpacked[1];
        }
        throw new InvalidArgumentException("Indefinite or reserved CBOR length info: $info");
    }
}
