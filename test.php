<?php
require_once __DIR__ . '/vendor/autoload.php';

// Test RC4
$key = sodium_hex2bin('0102030405');
$x = sodium_hex2bin('b2396305f03dc027ccc3524a0a1118a8');
needs($x === rc4($key, str_repeat("\0", 16)));

// Test RC4HASH_ROTATE
$in =     sodium_hex2bin('9caeac45d551873ffbea45a4e75ba6a1d2512164af6715a220866ad620705b24054cac68d817d46e70cd9d86acd9414cea564c5dcea9ed3ded3a3a4dfbe6166f');
$out =    rc4hash_word_rotl($in, 0);
$expect = sodium_hex2bin('ac459cae873fd55145a4fbeaa6a1e75b2164d25115a2af676ad620865b242070ac68054cd46ed8179d8670cd414cacd94c5dea56ed3dcea93a4ded3a166ffbe6');
needs($out === $expect, 'rotate 0 fail');

$out =    rc4hash_word_rotl($in, 1);
$expect = sodium_hex2bin('eac459ca1873fd55a45a4fbeba6a1e7512164d25715a2af666ad620805b24207cac680547d46ed81d9d8670c9414cacd64c5dea59ed3dceaa3a4ded36166ffbe');
needs($out === $expect, 'rotate 1 fail');

$out =    rc4hash_word_rotl($in, 2);
$expect = sodium_hex2bin('aeac459c51873fd5ea45a4fb5ba6a1e7512164d26715a2af866ad620705b24204cac680517d46ed8cd9d8670d9414cac564c5deaa9ed3dce3a3a4dede6166ffb');
needs($out === $expect, 'rotate 2 fail');

$out =    rc4hash_word_rotl($in, 3);
$expect = sodium_hex2bin('575622cea8c39feaf522d27dadd350f32890b269b38ad15743356b10382d9210a65634020bea376c66cec3386ca0a6562b262ef554f69ee79d1d26f6f30b37fd');
needs($out === $expect, 'rotate 3 fail');

// Test RC4Hash
needs(strlen(rc4hash('')) === RC4HASH_DIGEST_SIZE * 2); // Hex-encoded digest

$empty = "\x80" . str_repeat("\0", 63);
$tests = [
    ['', '06ac3bcdfe0590378a3f048d1e048a0c3e3dcbf704a5dd5b296036c7995166d7'],
    ['abc', 'e906d9e5951f7a88595b1a0161b0ab1c577919c7dd1f83a2108aaaaddcc6af14'],
    ['abd', '7ad119a996c2590a1c7755f6cb6513226cb364179fe676015c45cce9347506ad'],
    ['abcd', '5099c1dfe22e4442aa4e368a64a4bcfcd71e840cf62618f29af6a0e4a4d0177c'],
    ['soatok', '1c7b924520c7ed54aa5a58b5982d5a851222695309f9868ea38bc4e38dcebd5b'],
    ['The quick brown fox jumps over the lazy dog', '4b45493af90bec9c651dd05a00189bf677efa4d8bd5edf865c15fbfb14105a4d'],
    ['The quick brown fox jumps over the lazy dog.', 'a46d59edc1d8d14bbf0f5e6ff238221f0699bebaecdfe62c9a68712d12b1a509'],
    [str_repeat('a', 1000), 'bf01ac6cfaff090818bb2123ba89b3c5f31d64ca3f01b92cbe9aec00dc781d80'],
    [$empty, '6f5471cb9098384c670fde64618b739c78499ac0cd3678613c07b78beada8816'],
    [str_repeat($empty, 2), 'e75e0f4bb64370aa6b83accd76b000cfc18d550ba1b2238fb5fa2089364d0663'],
    [str_repeat($empty, 3), 'b1050aadf13614252215470703977287a338f0029c823ae2d160acc73acbf23b']
];
foreach ($tests as $row) {
    [$in, $out] = $row;
    $expect = rc4hash($in);
    if (!hash_equals($out, $expect)) {
        var_dump([
            '-' => $expect,
            '+' => $out,
            'in' => $in
        ]);
        exit(1);
    }
}
$random = random_bytes(32);
echo 'Random: ', sodium_bin2hex($random), PHP_EOL;
echo 'Hashed: ', rc4hash($random), PHP_EOL;

// Tests pass.
echo 'OK', PHP_EOL;
exit(0);
