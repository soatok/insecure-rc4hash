<?php

require_once __DIR__ . '/vendor/autoload.php';

/*
 * Copyright 2011 Michael Cutler <m@cotdp.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * A PHP implementation of RC4 based on the original C code from
 * the 1994 usenet post:
 *
 * http://groups.google.com/groups?selm=sternCvKL4B.Hyy@netcom.com
 *
 * @param string $key_str the key as a binary string
 * @param string $data_str the data to decrypt/encrypt as a binary string
 * @return string the result of the RC4 as a binary string
 * @author Michael Cutler <m@cotdp.com>
 */
function rc4(string $key_str, string $data_str): string
{
    // convert input string(s) to array(s)
    $key = array_values(unpack('C*', $key_str));
    $data = array_values(unpack('C*', $data_str));

    // prepare key
    $state = range(0, 255);

    $len = count($key);
    $index1 = $index2 = 0;
    for ($counter = 0; $counter < 256; ++$counter) {
        $index2   = ($key[$index1] + $state[$counter] + $index2) & 255;
        $tmp = $state[$counter];
        $state[$counter] = $state[$index2];
        $state[$index2] = $tmp;
        $index1 = ($index1 + 1) % $len;
    }

    // rc4
    $len = count($data);
    $x = $y = 0;
    for ($counter = 0; $counter < $len; $counter++) {
        $x = ($x + 1) & 255;
        $y = ($state[$x] + $y) & 255;
        $tmp = $state[$x];
        $state[$x] = $state[$y];
        $state[$y] = $tmp;
        $data[$counter] ^= $state[($state[$x] + $state[$y]) & 255];
    }

    // convert output back to a string
    return pack('C*', ...array_slice($data, 0, $len));
}
