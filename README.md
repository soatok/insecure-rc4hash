# RC4Hash - Really Crappy 4 Hash

[@dark_kirb said](https://twitter.com/dark_kirb/status/1450827935716417539):
> [@SoatokDhole said](https://twitter.com/SoatokDhole/status/1450826316077535237):
> > Everyone stand back, I'm going to encrypt with SHA256!
> > https://github.com/soatok/hash-crypt
> 
> next, create a cryptographic hash based on any stream cipher

Unfortunately, most stream ciphers I've studied are based on an iterated PRF (which
is basically a hash function) or block cipher in Counter Mode, so that would be 
redundant. If I tried to design a hash function based on, say, ChaCha, I'd probably
end up reinventing BLAKE but worse.

What the world really needed was something novel. Innovative.

Something absolutely **terrible**. Something that nobody should ever use.

## Introducing RC4Hash

> **It's literally just a crappy hash function made out of RC4.**

You know RC4. Everyone knows RC4. It's a stream cipher that is absolutely terrible.

How can we turn RC4 into a terrible hash function?

## RC4Hash Design Details

### Constants

* `DISCARD` = `3072`
* `BLOCK_SIZE` = `64`
* `DIGEST_SIZE` = `32`
* `ROUNDS` = `24`
* `K0` = `0x428a2f98d728ae227137449123ef65cdb5c0fbcfec4d3b2fe9b5dba58189dbbc`
  * Taken from Tiaoxin-346 
* `K1` = `0x9caeac45d551873ffbea45a4e75ba6a1d2512164af6715a220866ad620705b24`
  * The SHA256 hash of `Soatok Dreamseeker` 
* `K2` = `0x054cac68d817d46e70cd9d86acd9414cea564c5dcea9ed3ded3a3a4dfbe6166f`
  * The SHA256 hash of `Furry Fandom` 
* `K3` = `0xc592e6caf906942772a15b1e20cd3f7105cd3b0f133e02ffb5f8932665d0b878`
  * The SHA256 hash of `2021-10-21` 
* `F` = `0x2b0eaa5bbabbfa53b93cad8df213547bdb5a82c9bd573cb89ae0a453c1244395173b6bc13f6e64880bc0b17d1327616cfee655f8ace140ff29976340fa5ff253`
  * The SHA512 hash of `finalization` 

### Algorithms

#### RC4Hash(Msg)

First, the input is padded to a multiple of the block size (using ISO/IEC 7816-4 padding).

Then, it's encrypted with the four [constant](#constants) keys (K0-K3) with
[RC4_DISCARD](#rc4_discardkey-msg).

Note: This is the only time we use the discarding strategy. All further invocations use vanilla RC4.

```
State := ZERO_FILL(BLOCK_SIZE)
Padded := Pad(Msg, BLOCK_SIZE)
C0 := RC4_DISCARD(K0, Padded)
C1 := RC4_DISCARD(K1, Padded)
C2 := RC4_DISCARD(K2, Padded)
C3 := RC4_DISCARD(K3, Padded)
```

Next, for each BLOCK of the padded message, we perform the following loop:

```
// Get this block
B0 := C0.Slice(Start, BLOCK_SIZE)
B1 := C1.Slice(Start, BLOCK_SIZE)
B2 := C2.Slice(Start, BLOCK_SIZE)
B3 := C3.Slice(Start, BLOCK_SIZE)

// Process each round
for (R := 0, R < ROUNDS, R += 1):
    W, Z := RC4HASH_ROUND(B0, B1, B2, B3, R)
    State := State XOR RC4HASH_ROTATE(Z, R)
    B0 := RC4(B0, W)
    B1 := RC4(B1, W)
    B2 := RC4(B2, W)
    B3 := RC4(B3, W)
```

This processes [the round function](#rc4hash_rounda-b-c-d-r) to obtain `W` and `Z`.

`Z` is [rotated](#rc4hash_rotatex-r) by a round-dependent value, and XORed with
the State.

`W` is RC4-encrypted with each of the current block values (B0-B3) to produce new values
for the current block for the next round.

Once all rounds have concluded, we perform one final RC4 encryption using the finalization
key `F`. Next, we XOR the left half of `Block` with the right half to obtain the final hash.

```
Block := RC4(F, Block)
Left := Block.Slice(0, BLOCK_SIZE / 2)
Right := Block.Slice(BLOCK_SIZE / 2)

return (Left xor Right)
```

#### RC4_DISCARD(Key, Msg)

Encrypt `Msg` with RC4 using `Key`, skipping the first `DISCARD` bytes before encrypting.

#### RC4HASH_ROUND(A, B, C, D, r)

The RC4Hash Round Function. This produces some round-specific behavior.

First, we perform a round-dependent operation.

| Round (mod 4) | X | Y |
|---|---|---|
| 0 | `A xor C` | `B + D` |
| 1 | `A xor D` | `B + C` |
| 2 | `B xor D` | `A + C` |
| 3 | `B xor C` | `A + D` |

The main difference between xor and addition is the carry propagation.

We then return the following parameters:

```
W := RC4(Y, X)
Z := RC4(X, Y)
```

#### RC4HASH_ROTATE(X, R)

Rotate every word in `X` to the left a specific number of times, based on the round number `R`.

| Round (mod 4) | Rotation Amount |
|---|---|
| 0 | 16 |
| 1 | 12 |
| 2 | 8 |
| 3 | 7 |

These constants were taken from the design of ChaCha.
