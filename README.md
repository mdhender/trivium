# trivium

[![Go Reference](https://pkg.go.dev/badge/github.com/mdhender/trivium.svg)](https://pkg.go.dev/github.com/mdhender/trivium)

A pure Go implementation of the [Trivium](https://www.ecrypt.eu.org/stream/e2-trivium.html)
stream cipher (80-bit key, 80-bit IV). It has no dependencies, implements
`crypto/cipher.Stream`, and matches all 84 published eSTREAM test vectors.

```sh
go get github.com/mdhender/trivium
```

Requires Go 1.26 or later.

## Usage

```go
key := make([]byte, trivium.KeySize) // 10 bytes of secret random data
iv := make([]byte, trivium.IVSize)   // 10 bytes, unique per message
rand.Read(key)
rand.Read(iv)

c, err := trivium.New(key, iv)
if err != nil {
	return err
}
ciphertext := make([]byte, len(plaintext))
c.XORKeyStream(ciphertext, plaintext)
```

Decrypt by building a new `Cipher` with the same key and IV and calling
`XORKeyStream` on the ciphertext. Because a `Cipher` is a `cipher.Stream`, you
can also wrap it in `cipher.StreamReader` or `cipher.StreamWriter`. The
[package documentation](https://pkg.go.dev/github.com/mdhender/trivium) has
runnable examples.

## Security notes

- **Never reuse a key and IV pair.** Two messages encrypted with the same pair
  share a keystream, and XORing the ciphertexts reveals the XOR of the
  plaintexts. Use a fresh random IV for each message and send it alongside the
  ciphertext.
- **Trivium does not authenticate.** An attacker can flip ciphertext bits and
  the same plaintext bits flip on decryption. Add a MAC such as HMAC-SHA-256,
  or use an AEAD like ChaCha20-Poly1305 for new designs.
- **Keys must be uniformly random.** Derive keys from passwords with Argon2 or
  from other key material with HKDF rather than using them directly.
- An 80-bit key is small by modern standards. Trivium suits constrained or
  interoperability settings, not new general-purpose designs.

## Bit ordering

The Trivium specification numbers key, IV and keystream bits but does not
define how bytes map to them. This package uses the eSTREAM reference
convention, so its output matches the eSTREAM test vectors and other
implementations that follow them:

- Spec bit `K1` (and `IV1`) is the most significant bit of the **last** byte,
  and `K80` is the least significant bit of the first byte.
- Keystream bytes are filled least significant bit first.

## Implementation

Every tap in Trivium's three shift registers sits at least 65 positions deep,
so the next 64 rounds never read a bit that one of those rounds wrote. The
cipher therefore computes 64 rounds at once with plain `uint64` operations,
running at about 1.6 GB/s on an Apple M-series core with no allocations after
`New`. The tests cross-check this against a bit-at-a-time transcription of the
specification.

## Testing

```sh
go test ./...                                  # unit tests, eSTREAM vectors, examples
go test -run '^$' -fuzz FuzzReference -fuzztime 30s   # fuzz against the reference
go test -run '^$' -bench .                     # benchmarks
```

The eSTREAM vectors live in [`testdata/estream.txt`](testdata/estream.txt),
with their source recorded at the top of the file.

## History

This package replaces an earlier C implementation (still in the git history
before the Go conversion). That code had bugs and departed from the
specification: it stored whole bytes where the spec calls for single bits,
used three wrong tap positions (`s142` for `s242`, `s171` for `s170`, and
`s174·s174` for `s174·s175` in 0-based indexing), copied only 8 of the 10 key
bytes, and hard-coded the IV. Its output is not Trivium and cannot be
reproduced by this package. The C version's ISAAC-derived `Trivium_KeyHash`
helper was also dropped in favor of standard key derivation functions.
