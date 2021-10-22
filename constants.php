<?php
declare(strict_types=1);

const RC4HASH_PADDING_LENGTH = 3072;
const RC4HASH_BLOCK_SIZE = 64;
const RC4HASH_DIGEST_SIZE = 32;
const RC4HASH_ROUNDS = 24;

define('RC4HASH_PADDING', str_repeat("\0", RC4HASH_PADDING_LENGTH));
// From Tiaoxin-346
define('RC4HASH_K0', sodium_hex2bin('428a2f98d728ae227137449123ef65cdb5c0fbcfec4d3b2fe9b5dba58189dbbc'));
// SHA256(Soatok Dreamseeker)
define('RC4HASH_K1', sodium_hex2bin('9caeac45d551873ffbea45a4e75ba6a1d2512164af6715a220866ad620705b24'));
// SHA256(Furry Fandom)
define('RC4HASH_K2', sodium_hex2bin('054cac68d817d46e70cd9d86acd9414cea564c5dcea9ed3ded3a3a4dfbe6166f'));
// SHA256(2021-10-21)
define('RC4HASH_K3', sodium_hex2bin('c592e6caf906942772a15b1e20cd3f7105cd3b0f133e02ffb5f8932665d0b878'));
// SHA512(finalization)
define('RC4HASH_F', sodium_hex2bin('2b0eaa5bbabbfa53b93cad8df213547bdb5a82c9bd573cb89ae0a453c1244395173b6bc13f6e64880bc0b17d1327616cfee655f8ace140ff29976340fa5ff253'));
