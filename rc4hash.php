<?php
declare(strict_types=1);

use ParagonIE\ConstantTime\Binary;

require_once __DIR__ . '/vendor/autoload.php';

/**
 * @param string $input
 * @param bool $raw
 * @return string
 *
 * @throws SodiumException
 * @throws Exception
 */
function rc4hash(string $input, bool $raw = false): string
{
    $padded = sodium_pad($input, RC4HASH_BLOCK_SIZE);
    $c_len = Binary::safeStrlen($padded);

    $block = str_repeat("\0", RC4HASH_BLOCK_SIZE);
    $c0 = rc4_disc(RC4HASH_K0, $padded);
    $c1 = rc4_disc(RC4HASH_K1, $padded);
    $c2 = rc4_disc(RC4HASH_K2, $padded);
    $c3 = rc4_disc(RC4HASH_K3, $padded);

    for ($i = 0; $i < $c_len; $i += RC4HASH_BLOCK_SIZE) {
        $b0 = Binary::safeSubstr($c0, $i, RC4HASH_BLOCK_SIZE);
        $b1 = Binary::safeSubstr($c1, $i, RC4HASH_BLOCK_SIZE);
        $b2 = Binary::safeSubstr($c2, $i, RC4HASH_BLOCK_SIZE);
        $b3 = Binary::safeSubstr($c3, $i, RC4HASH_BLOCK_SIZE);
        for ($r = 0; $r < RC4HASH_ROUNDS; ++$r) {
            [$w, $z] = rc4hash_round($b0, $b1, $b2, $b3, $r);
            $block ^= rc4hash_word_rotl($z, $r);
            $b0 = rc4($b0, $w);
            $b1 = rc4($b1, $w);
            $b2 = rc4($b2, $w);
            $b3 = rc4($b3, $w);
        }
    }
    $block = rc4(RC4HASH_F, $block);

    // Finalization: XOR the two halves together
    $half = RC4HASH_BLOCK_SIZE >> 1;
    $final = Binary::safeSubstr($block, 0, $half) ^ Binary::safeSubstr($block, $half, $half);
    if (!$raw) {
        return sodium_bin2hex($final);
    }
    return $final;
}

/**
 * Encrypt with RC4, discarding the first N bytes of the keystream before encrypting.
 *
 * @param string $key
 * @param string $msg
 * @return string
 */
function rc4_disc(string $key, string $msg): string
{
    return Binary::safeSubstr(
        rc4($key, RC4HASH_PADDING . $msg),
        RC4HASH_PADDING_LENGTH,
        Binary::safeStrlen($msg)
    );
}

/**
 * Rotate every word in a value by a round-dependent amount
 *
 * @param string $block
 * @param int $round
 * @return string
 * @throws Exception
 */
function rc4hash_word_rotl(string $block, int $round): string
{
    needs(Binary::safeStrlen($block) === RC4HASH_BLOCK_SIZE, "Invalid input");
    $shift = rc4hash_shift($round);
    $out = '';
    for ($i = 0; $i < RC4HASH_BLOCK_SIZE; $i += 4) {
        $int = unpack('N', Binary::safeSubstr($block, $i, 4))[1];
        $rot = ($int << $shift) | ($int >> (32 - $shift));
        $out .= pack('N', $rot);
    }
    return $out;
}

/**
 * Round-dependent shift amount, for rotation.
 *
 * These numbers were derived from ChaCha.
 *
 * @param int $round
 * @return int
 */
function rc4hash_shift(int $round): int
{
    if (($round & 3) === 0) return 16;
    if (($round & 3) === 1) return 12;
    if (($round & 3) === 2) return 8;
    return 7;
}

/**
 * Round function
 *
 * 0 mod 4 rounds:
 *     X := A xor C
 *     Y := B + D
 *
 * 1 mod 4 rounds:
 *     X := A xor D
 *     Y := B + C
 *
 * 2 mod 4 rounds:
 *     X := B xor D
 *     Y := A + C
 *
 * 3 mod 4 rounds:
 *     X := B xor C
 *     Y := A + D
 *
 * returns RC4discard3072( key=X, message=Y)
 *
 * @param string $a
 * @param string $b
 * @param string $c
 * @param string $d
 * @param int $round
 * @return string
 *
 * @throws Exception
 */
function rc4hash_round(string $a, string $b, string $c, string $d, int $round): array
{
    needs(Binary::safeStrlen($a) === RC4HASH_BLOCK_SIZE, "Invalid input size for A");
    needs(Binary::safeStrlen($b) === RC4HASH_BLOCK_SIZE, "Invalid input size for B");
    needs(Binary::safeStrlen($c) === RC4HASH_BLOCK_SIZE, "Invalid input size for C");
    needs(Binary::safeStrlen($d) === RC4HASH_BLOCK_SIZE, "Invalid input size for D");

    // Convert to integer array
    $_a = array_values(unpack('C*', $a));
    $_b = array_values(unpack('C*', $b));
    $_c = array_values(unpack('C*', $c));
    $_d = array_values(unpack('C*', $d));

    if (($round & 3) === 0) {
        // X := A xor C
        // Y := B + D
        $x = pack('C*', ...array_xor($_a, $_c));
        $y = pack('C*', ...array_add($_b, $_d));
    } elseif (($round & 3) === 1) {
        // X := A xor D
        // Y := B + C
        $x = pack('C*', ...array_xor($_a, $_d));
        $y = pack('C*', ...array_add($_b, $_c));
    } elseif (($round & 3) === 2) {
        // X := B xor D
        // Y := A + C
        $x = pack('C*', ...array_xor($_b, $_d));
        $y = pack('C*', ...array_add($_a, $_c));
    } else {
        // X := B xor C
        // Y := A + D
        $x = pack('C*', ...array_xor($_b, $_c));
        $y = pack('C*', ...array_add($_a, $_d));
    }

    // W := RC4(y, x)
    // Z := RC4(x, y)
    return [
        rc4($y, $x),
        rc4($x, $y)
    ];
}

function array_add(array $a, array $b): array
{
    $x = array_values($a);
    $c = 0;
    for ($i = count($b) - 1; $i >= 0; --$i) {
        $c = $a[$i] + $b[$i] + $c;
        $x[$i] = $c & 0xff;
        $c >>= 8;
    }
    return $x;
}

function array_xor(array $a, array $b): array
{
    $c = array_values($a);
    for ($i = 0; $i < count($b); ++$i) {
        $c[$i] ^= $b[$i];
    }
    return $c;
}

/**
 * @param bool $condition
 * @param string $err_msg
 * @throws Exception
 */
function needs(bool $condition, string $err_msg = ''): void
{
    if (!$condition) {
        throw new Exception($err_msg);
    }
}

