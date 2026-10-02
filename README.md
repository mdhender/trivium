# trivium

Pure Go implementation of the Trivium stream cipher (80-bit key, 80-bit IV).
This README is written for coding agents: it states the contract, the rules,
and the commands. Prose for humans lives in the package documentation
(`doc.go`, or `go doc -all github.com/mdhender/trivium`).

- Module: `github.com/mdhender/trivium`
- Go: 1.26 or later (`go.mod`; the tests use `errors.AsType`)
- Dependencies: none (standard library only)
- Conformance: matches all 84 eSTREAM test vectors in `testdata/estream.txt`

## API

```go
const KeySize = 10 // bytes
const IVSize  = 10 // bytes

func New(key, iv []byte) (*Cipher, error)
func (c *Cipher) XORKeyStream(dst, src []byte) // implements crypto/cipher.Stream
func (c *Cipher) Reset()

type KeySizeError int // returned by New when len(key) != KeySize; value is len(key)
type IVSizeError  int // returned by New when len(iv) != IVSize; value is len(iv)
```

| Call | Behavior |
|---|---|
| `New` | Returns `nil` and a `KeySizeError` or `IVSizeError` on bad lengths. Otherwise allocates once; there are no further allocations. |
| `XORKeyStream` | `dst[i] = src[i] ^ keystream`. Encrypting and decrypting are the same operation. Successive calls continue the keystream, so chunk boundaries do not affect output. Writes only `dst[:len(src)]`. |
| `XORKeyStream` panics | if `len(dst) < len(src)`, if `dst` and `src` overlap without being identical, or after `Reset`. `dst` and `src` may be the same slice (in place). |
| `Reset` | Zeroes all key-dependent state. The `Cipher` cannot be used again. |

Check errors with `errors.As` / `errors.AsType[trivium.KeySizeError]`; do not
compare error strings.

## Usage

```go
key := make([]byte, trivium.KeySize) // secret, uniformly random
rand.Read(key)                       // crypto/rand

// Encrypt: fresh random IV per message, sent in the clear before the ciphertext.
out := make([]byte, trivium.IVSize+len(plaintext))
iv := out[:trivium.IVSize]
rand.Read(iv)
c, err := trivium.New(key, iv)
if err != nil {
	return err
}
c.XORKeyStream(out[trivium.IVSize:], plaintext)

// Decrypt: new Cipher with the same key and IV.
iv, body := out[:trivium.IVSize], out[trivium.IVSize:]
c, err = trivium.New(key, iv)
if err != nil {
	return err
}
c.XORKeyStream(body, body)
```

`*Cipher` works with `cipher.StreamReader` and `cipher.StreamWriter`. Runnable
examples are in `example_test.go`.

## Rules for code that uses this package

1. **Never reuse a key and IV pair.** Generate a new random IV with
   `crypto/rand` for every message. Reuse leaks the XOR of the plaintexts.
2. **Never copy a `Cipher` value.** A copy repeats the original's keystream.
   Pass `*Cipher`. `go vet` (copylocks) reports copies.
3. **Never share a `Cipher` between goroutines** without external locking.
4. **Add integrity separately.** Trivium does not authenticate: flipped
   ciphertext bits flip the same plaintext bits. Use encrypt-then-MAC (for
   example HMAC-SHA-256 over IV and ciphertext), or choose an AEAD such as
   `golang.org/x/crypto/chacha20poly1305` instead.
5. **Do not use passwords as keys.** Derive keys with `golang.org/x/crypto/argon2`
   (passwords) or `crypto/hkdf` (other key material).
6. **Do not pick Trivium for new general-purpose designs.** The 80-bit key is
   small. Use it for interoperability or constrained environments.
7. Call `Reset` when a `Cipher` is no longer needed if key material lingering
   in memory matters.

## Byte and bit ordering

Follows the eSTREAM reference implementation. Changing this breaks
compatibility with the test vectors and other implementations.

- Spec bit `K1` (and `IV1`) is the most significant bit of the **last** byte;
  `K80` is the least significant bit of the first byte.
- Keystream bytes are filled least significant bit first.

## Repository layout

| Path | Contents |
|---|---|
| `trivium.go` | Implementation. |
| `doc.go` | Package documentation. |
| `trivium_test.go` | eSTREAM vector test, bit-at-a-time `reference` implementation, fuzz test, benchmarks. |
| `example_test.go` | Runnable examples (checked by `go test`). |
| `testdata/estream.txt` | eSTREAM vectors; the header records their source. |

## Implementation notes for agents modifying this package

- State is three registers (`a`, `b`, `c`), each stored in 128 bits
  (`register{hi, lo}`). Position `p` is stored at bit `127-p`.
- `next()` computes 64 rounds at once. This works only because every tap is at
  0-based position 65 or deeper, and 64 rounds write only positions 0 through
  63. Any change to tap positions or batch width must preserve this.
- `register.taps(p)` requires `p` in `[64, 127)`.
- Initialization runs `4*288 = 1152` rounds (18 calls to `next`).
- `reference` in `trivium_test.go` is an independent bit-by-bit transcription
  of the spec, with its own key/IV bit decoding. Keep it independent of
  package internals; it is the oracle for `TestReference` and `FuzzReference`.
- Do not change output. Any change must pass all eSTREAM vectors unchanged.

## Commands

```sh
go vet ./...
go test -race ./...                                      # vectors, reference, examples
go test -run '^$' -fuzz FuzzReference -fuzztime 30s .    # fuzz against reference
go test -run '^$' -bench . .                             # benchmarks
```

All must pass before committing. `gofmt -l .` must print nothing.

## History

An earlier C implementation (in git history before the Go conversion) was not
Trivium: it used wrong tap positions, stored bytes instead of bits, read only 8
of the 10 key bytes, and hard-coded the IV. Its output cannot be reproduced by
this package, and its `Trivium_KeyHash` helper was removed in favor of
standard KDFs.

## License

MIT. See `LICENSE`.
