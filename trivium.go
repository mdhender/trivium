package trivium

import (
	"crypto/cipher"
	"encoding/binary"
	"strconv"
	"unsafe"
)

const (
	// KeySize is the size of a Trivium key in bytes (80 bits).
	KeySize = 10

	// IVSize is the size of a Trivium initialization vector in bytes (80 bits).
	IVSize = 10
)

// KeySizeError is returned by New when the key is not KeySize bytes long.
type KeySizeError int

func (k KeySizeError) Error() string {
	return "trivium: invalid key size " + strconv.Itoa(int(k))
}

// IVSizeError is returned by New when the IV is not IVSize bytes long.
type IVSizeError int

func (k IVSizeError) Error() string {
	return "trivium: invalid IV size " + strconv.Itoa(int(k))
}

// Cipher is an instance of the Trivium stream cipher. It implements
// cipher.Stream.
//
// A Cipher is not safe for concurrent use by multiple goroutines.
type Cipher struct {
	// The three shift registers, A (s1..s93), B (s94..s177) and
	// C (s178..s288). See register for the bit layout.
	a, b, c register

	// buf holds keystream bytes generated but not yet consumed;
	// buf[off:] is still available.
	buf [8]byte
	off int
}

var _ cipher.Stream = (*Cipher)(nil)

// New returns a Cipher keyed with the 10-byte key and 10-byte iv.
//
// Bit ordering follows the eSTREAM reference implementation, so output
// matches the published eSTREAM test vectors: key and iv are read as
// big-endian 80-bit values with K1 (and IV1) the most significant bit of the
// last byte, and keystream bytes are filled least significant bit first.
//
// Never use the same key and iv pair to encrypt two different messages.
func New(key, iv []byte) (*Cipher, error) {
	if len(key) != KeySize {
		return nil, KeySizeError(len(key))
	}
	if len(iv) != IVSize {
		return nil, IVSizeError(len(iv))
	}

	c := &Cipher{off: len(Cipher{}.buf)}

	// (s1, ..., s93)    <- (K1, ..., K80, 0, ..., 0)
	// (s94, ..., s177)  <- (IV1, ..., IV80, 0, ..., 0)
	// (s178, ..., s288) <- (0, ..., 0, 1, 1, 1)
	for i := range 8 * KeySize {
		c.a.set(i, specBit(key, i))
	}
	for i := range 8 * IVSize {
		c.b.set(i, specBit(iv, i))
	}
	c.c.set(108, 1)
	c.c.set(109, 1)
	c.c.set(110, 1)

	// Rotate the state over four full cycles (4 * 288 = 1152 rounds)
	// without producing output.
	for range 4 * 288 / 64 {
		c.next()
	}
	return c, nil
}

// specBit returns bit i+1 of the spec's numbering (K1..K80 or IV1..IV80)
// from a 10-byte key or IV in eSTREAM byte order.
func specBit(b []byte, i int) byte {
	return b[len(b)-1-i/8] >> (7 - i%8) & 1
}

// XORKeyStream XORs each byte in src with a byte from the keystream and
// writes the result to dst. Because XOR is its own inverse, the same call
// both encrypts and decrypts.
//
// dst and src must overlap entirely or not at all, and len(dst) must be at
// least len(src). Successive calls continue the keystream where the previous
// call stopped.
func (c *Cipher) XORKeyStream(dst, src []byte) {
	if len(dst) < len(src) {
		panic("trivium: output smaller than input")
	}
	dst = dst[:len(src)]
	if inexactOverlap(dst, src) {
		panic("trivium: invalid buffer overlap")
	}

	// Drain any keystream left over from a previous call.
	if c.off < len(c.buf) {
		n := min(len(src), len(c.buf)-c.off)
		for i := range n {
			dst[i] = src[i] ^ c.buf[c.off+i]
		}
		c.off += n
		dst, src = dst[n:], src[n:]
	}

	// Whole 64-bit words.
	for len(src) >= 8 {
		z := c.next()
		binary.LittleEndian.PutUint64(dst, binary.LittleEndian.Uint64(src)^z)
		dst, src = dst[8:], src[8:]
	}

	// Trailing partial word; keep the unused keystream for the next call.
	if len(src) > 0 {
		binary.LittleEndian.PutUint64(c.buf[:], c.next())
		for i := range src {
			dst[i] = src[i] ^ c.buf[i]
		}
		c.off = len(src)
	}
}

// next advances the cipher by 64 rounds and returns the 64 keystream bits
// produced, the first round in the least significant bit.
//
// The spec defines one round as (1-indexed state bits):
//
//	t1 <- s66 + s93
//	t2 <- s162 + s177
//	t3 <- s243 + s288
//	z  <- t1 + t2 + t3
//	t1 <- t1 + s91.s92 + s171
//	t2 <- t2 + s175.s176 + s264
//	t3 <- t3 + s286.s287 + s69
//	(s1, s2, ..., s93)    <- (t3, s1, ..., s92)
//	(s94, s95, ..., s177) <- (t1, s94, ..., s176)
//	(s178, s179, ..., s288) <- (t2, s178, ..., s287)
//
// Every tap sits at least 65 bits into its register, so none of the next 64
// rounds reads a bit written by an earlier one of those rounds. That lets
// all 64 rounds be computed at once, one round per bit of a uint64.
func (c *Cipher) next() uint64 {
	a, b, cc := &c.a, &c.b, &c.c

	t1 := a.taps(65) ^ a.taps(92)
	t2 := b.taps(68) ^ b.taps(83)
	t3 := cc.taps(65) ^ cc.taps(110)
	z := t1 ^ t2 ^ t3

	t1 ^= a.taps(90)&a.taps(91) ^ b.taps(77)
	t2 ^= b.taps(81)&b.taps(82) ^ cc.taps(86)
	t3 ^= cc.taps(108)&cc.taps(109) ^ a.taps(68)

	a.push(t3)
	b.push(t1)
	cc.push(t2)
	return z
}

// register is a shift register of up to 128 bits. Position 0 is the most
// recently shifted-in bit (s1, s94 or s178 in the spec), and position p is
// stored at bit 127-p of the 128-bit value hi:lo. Positions past the
// register's length hold stale bits that are never read.
type register struct {
	hi, lo uint64
}

// set sets the bit at position p to v, which must be 0 or 1.
func (r *register) set(p int, v byte) {
	i := 127 - p
	if i >= 64 {
		r.hi |= uint64(v) << (i - 64)
	} else {
		r.lo |= uint64(v) << i
	}
}

// taps returns a word whose bit j is the bit at position p as seen by round
// j of the next 64 rounds, that is, the bit currently at position p-j.
// p must be in [64, 127).
func (r *register) taps(p int) uint64 {
	s := uint(127 - p)
	return r.lo>>s | r.hi<<(64-s)
}

// push shifts the register forward by 64 rounds, where bit j of w is the
// bit shifted in by round j.
func (r *register) push(w uint64) {
	r.hi, r.lo = w, r.hi
}

// inexactOverlap reports whether x and y share memory at any non-corresponding
// index. It mirrors crypto/internal/alias.InexactOverlap.
func inexactOverlap(x, y []byte) bool {
	if len(x) == 0 || len(y) == 0 || &x[0] == &y[0] {
		return false
	}
	return anyOverlap(x, y)
}

func anyOverlap(x, y []byte) bool {
	return len(x) > 0 && len(y) > 0 &&
		uintptr(unsafe.Pointer(&x[0])) <= uintptr(unsafe.Pointer(&y[len(y)-1])) &&
		uintptr(unsafe.Pointer(&y[0])) <= uintptr(unsafe.Pointer(&x[len(x)-1]))
}
