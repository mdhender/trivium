// Package trivium implements the Trivium stream cipher, as specified by
// Christophe De Cannière and Bart Preneel and selected for the eSTREAM
// hardware portfolio.
//
// Trivium takes an 80-bit key and an 80-bit initialization vector (IV) and
// produces a keystream that is XORed with data to encrypt or decrypt it.
// A [Cipher] implements [crypto/cipher.Stream], so it can be used anywhere a
// stream is expected, such as [crypto/cipher.StreamReader] and
// [crypto/cipher.StreamWriter].
//
// The output matches the published eSTREAM test vectors.
//
// # Security
//
// Trivium is an unauthenticated cipher: it hides data but does not detect
// tampering. Flipping a bit of the ciphertext flips the same bit of the
// decrypted plaintext. Pair it with a MAC (for example [crypto/hmac]) if
// integrity matters, or prefer an AEAD such as
// [golang.org/x/crypto/chacha20poly1305] for new designs.
//
// Never encrypt two messages with the same key and IV. Doing so reuses the
// keystream, and XORing the two ciphertexts reveals the XOR of the two
// plaintexts.
//
// The key must be 80 bits of secret, uniformly random data. To derive one
// from a password or other low-entropy input, use a key derivation function
// such as [crypto/hkdf] or [golang.org/x/crypto/argon2] rather than using
// the input directly.
package trivium
