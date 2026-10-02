package trivium

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"errors"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// vector is one eSTREAM test case: the keystream for key and iv, sampled at
// several offsets, plus the XOR of every 64-byte block of the full stream.
type vector struct {
	name      string
	key, iv   []byte
	samples   []sample
	xorDigest []byte
}

type sample struct {
	offset int
	want   []byte
}

var (
	vectorRE = regexp.MustCompile(`^Set (\d+), vector#\s*(\d+):$`)
	fieldRE  = regexp.MustCompile(`^(key|IV|stream\[(\d+)\.\.(\d+)\]|xor-digest) = ([0-9A-F]+)$`)
	hexRE    = regexp.MustCompile(`^[0-9A-F]+$`)
)

// loadVectors parses the eSTREAM test vector file in testdata.
func loadVectors(t *testing.T) []*vector {
	t.Helper()
	f, err := os.Open("testdata/estream.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	var (
		vectors []*vector
		cur     *vector
		// appendTo extends the field that hex continuation lines belong
		// to, or is nil when the previous line started no such field.
		appendTo func([]byte)
	)
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if m := vectorRE.FindStringSubmatch(line); m != nil {
			cur = &vector{name: "set" + m[1] + "/vector" + m[2]}
			vectors = append(vectors, cur)
			appendTo = nil
			continue
		}
		if cur == nil {
			continue
		}
		if m := fieldRE.FindStringSubmatch(line); m != nil {
			b := mustHex(t, m[4])
			v := cur
			switch {
			case m[1] == "key":
				v.key, appendTo = b, nil
			case m[1] == "IV":
				v.iv, appendTo = b, nil
			case m[1] == "xor-digest":
				v.xorDigest = b
				appendTo = func(more []byte) { v.xorDigest = append(v.xorDigest, more...) }
			default:
				off, _ := strconv.Atoi(m[2])
				v.samples = append(v.samples, sample{offset: off, want: b})
				i := len(v.samples) - 1
				appendTo = func(more []byte) { v.samples[i].want = append(v.samples[i].want, more...) }
			}
			continue
		}
		if appendTo != nil && hexRE.MatchString(line) {
			appendTo(mustHex(t, line))
			continue
		}
		appendTo = nil
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	return vectors
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// keystream returns the first n bytes of keystream for key and iv.
func keystream(t testing.TB, key, iv []byte, n int) []byte {
	t.Helper()
	c, err := New(key, iv)
	if err != nil {
		t.Fatal(err)
	}
	b := make([]byte, n)
	c.XORKeyStream(b, b)
	return b
}

func TestVectors(t *testing.T) {
	vectors := loadVectors(t)
	if len(vectors) != 84 {
		t.Fatalf("parsed %d vectors, want 84", len(vectors))
	}
	for _, v := range vectors {
		t.Run(v.name, func(t *testing.T) {
			if len(v.key) != KeySize || len(v.iv) != IVSize || len(v.samples) == 0 {
				t.Fatalf("malformed vector: key %x, iv %x, %d samples", v.key, v.iv, len(v.samples))
			}
			n := 0
			for _, s := range v.samples {
				n = max(n, s.offset+len(s.want))
			}
			stream := keystream(t, v.key, v.iv, n)

			for _, s := range v.samples {
				got := stream[s.offset : s.offset+len(s.want)]
				if !bytes.Equal(got, s.want) {
					t.Errorf("stream[%d..%d]:\n got %X\nwant %X", s.offset, s.offset+len(s.want)-1, got, s.want)
				}
			}

			digest := make([]byte, 64)
			for block := range slices.Chunk(stream, 64) {
				for i, b := range block {
					digest[i] ^= b
				}
			}
			if !bytes.Equal(digest, v.xorDigest) {
				t.Errorf("xor-digest:\n got %X\nwant %X", digest, v.xorDigest)
			}
		})
	}
}

// reference is a direct, bit-at-a-time transcription of the Trivium
// specification, used to cross-check the 64-rounds-at-a-time implementation.
// It decodes key and iv itself rather than calling specBit, so that a bit
// ordering mistake in the package is not shared with the reference.
func reference(key, iv []byte, n int) []byte {
	// bits returns the 80 spec bits X1..X80 of a 10-byte key or IV, where X1
	// is the most significant bit of the last byte.
	bits := func(b []byte) []byte {
		var out []byte
		for _, x := range slices.Backward(b) {
			for shift := 7; shift >= 0; shift-- {
				out = append(out, x>>shift&1)
			}
		}
		return out
	}

	var s [289]byte // s[1] through s[288]; s[0] is unused
	copy(s[1:], bits(key))
	copy(s[94:], bits(iv))
	s[286], s[287], s[288] = 1, 1, 1

	round := func() byte {
		t1 := s[66] ^ s[93]
		t2 := s[162] ^ s[177]
		t3 := s[243] ^ s[288]
		z := t1 ^ t2 ^ t3
		t1 ^= s[91]&s[92] ^ s[171]
		t2 ^= s[175]&s[176] ^ s[264]
		t3 ^= s[286]&s[287] ^ s[69]
		copy(s[2:], s[1:288])
		s[1], s[94], s[178] = t3, t1, t2
		return z
	}
	for range 4 * 288 {
		round()
	}
	out := make([]byte, n)
	for i := range 8 * n {
		out[i/8] |= round() << (i % 8)
	}
	return out
}

func TestReference(t *testing.T) {
	for _, tc := range []struct{ key, iv string }{
		{"00000000000000000000", "00000000000000000000"},
		{"FFFFFFFFFFFFFFFFFFFF", "FFFFFFFFFFFFFFFFFFFF"},
		{"0123456789ABCDEF0123", "FEDCBA9876543210FEDC"},
		{"DEADBEEFCAFEF00DBAAD", "0102030405060708090A"},
	} {
		key, iv := mustHex(t, tc.key), mustHex(t, tc.iv)
		got := keystream(t, key, iv, 1000)
		if want := reference(key, iv, 1000); !bytes.Equal(got, want) {
			t.Errorf("key %s iv %s: keystream differs from reference", tc.key, tc.iv)
		}
	}
}

func TestRoundTrip(t *testing.T) {
	key := mustHex(t, "0123456789ABCDEF0123")
	iv := mustHex(t, "FEDCBA9876543210FEDC")
	plaintext := []byte("A very good day to you, Mr. Doogles.")

	enc, _ := New(key, iv)
	ciphertext := make([]byte, len(plaintext))
	enc.XORKeyStream(ciphertext, plaintext)
	if bytes.Equal(ciphertext, plaintext) {
		t.Fatal("ciphertext equals plaintext")
	}

	dec, _ := New(key, iv)
	got := make([]byte, len(ciphertext))
	dec.XORKeyStream(got, ciphertext)
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("round trip: got %q, want %q", got, plaintext)
	}
}

func TestInPlace(t *testing.T) {
	key := make([]byte, KeySize)
	iv := make([]byte, IVSize)
	src := bytes.Repeat([]byte{0x5a}, 100)

	want := make([]byte, len(src))
	c, _ := New(key, iv)
	c.XORKeyStream(want, src)

	buf := bytes.Clone(src)
	c, _ = New(key, iv)
	c.XORKeyStream(buf, buf)
	if !bytes.Equal(buf, want) {
		t.Fatal("in-place output differs from out-of-place output")
	}
}

// TestChunking checks that splitting input across calls of every size from
// 1 to 17 bytes produces the same output as a single call.
func TestChunking(t *testing.T) {
	key := mustHex(t, "0558ABFE51A4F74A9DF0")
	iv := mustHex(t, "167DE44BB21980E74EB5")
	want := keystream(t, key, iv, 500)

	for size := 1; size <= 17; size++ {
		c, _ := New(key, iv)
		got := make([]byte, len(want))
		for i := 0; i < len(got); i += size {
			end := min(i+size, len(got))
			c.XORKeyStream(got[i:end], got[i:end])
		}
		if !bytes.Equal(got, want) {
			t.Errorf("chunk size %d: output differs from single call", size)
		}
	}
}

func TestEmptyInput(t *testing.T) {
	c, _ := New(make([]byte, KeySize), make([]byte, IVSize))
	c.XORKeyStream(nil, nil)
	c.XORKeyStream(make([]byte, 4), nil)

	want := keystream(t, make([]byte, KeySize), make([]byte, IVSize), 8)
	got := make([]byte, 8)
	c.XORKeyStream(got, got)
	if !bytes.Equal(got, want) {
		t.Fatal("empty calls advanced the keystream")
	}
}

func TestDstLongerThanSrc(t *testing.T) {
	c, _ := New(make([]byte, KeySize), make([]byte, IVSize))
	dst := bytes.Repeat([]byte{0xff}, 16)
	c.XORKeyStream(dst, make([]byte, 8))
	if !bytes.Equal(dst[8:], bytes.Repeat([]byte{0xff}, 8)) {
		t.Fatal("bytes past len(src) were modified")
	}
}

func TestNewErrors(t *testing.T) {
	good := make([]byte, 10)
	for _, tc := range []struct {
		name    string
		key, iv []byte
		check   func(error) bool
	}{
		{"short key", make([]byte, 9), good, isErr[KeySizeError](9)},
		{"long key", make([]byte, 16), good, isErr[KeySizeError](16)},
		{"nil key", nil, good, isErr[KeySizeError](0)},
		{"short iv", good, make([]byte, 8), isErr[IVSizeError](8)},
		{"nil iv", good, nil, isErr[IVSizeError](0)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, err := New(tc.key, tc.iv)
			if c != nil || !tc.check(err) {
				t.Fatalf("New() = %v, %v", c, err)
			}
		})
	}
}

func isErr[E interface {
	~int
	error
}](n int) func(error) bool {
	return func(err error) bool {
		e, ok := errors.AsType[E](err)
		return ok && int(e) == n
	}
}

func TestErrorStrings(t *testing.T) {
	if got := KeySizeError(3).Error(); got != "trivium: invalid key size 3" {
		t.Errorf("KeySizeError: %q", got)
	}
	if got := IVSizeError(4).Error(); got != "trivium: invalid IV size 4" {
		t.Errorf("IVSizeError: %q", got)
	}
}

func TestReset(t *testing.T) {
	c, _ := New(mustHex(t, "0123456789ABCDEF0123"), mustHex(t, "FEDCBA9876543210FEDC"))
	c.XORKeyStream(make([]byte, 3), make([]byte, 3)) // leave buffered keystream
	c.Reset()
	if c.a != (register{}) || c.b != (register{}) || c.c != (register{}) || c.buf != [bufSize]byte{} {
		t.Fatal("Reset left state behind")
	}
	defer func() {
		if recover() == nil {
			t.Fatal("XORKeyStream after Reset did not panic")
		}
	}()
	c.XORKeyStream(make([]byte, 1), make([]byte, 1))
}

func TestPanics(t *testing.T) {
	buf := make([]byte, 32)
	for _, tc := range []struct {
		name     string
		dst, src []byte
	}{
		{"short dst", make([]byte, 4), make([]byte, 8)},
		{"inexact overlap", buf[1:17], buf[0:16]},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Fatal("XORKeyStream did not panic")
				}
			}()
			c, _ := New(make([]byte, KeySize), make([]byte, IVSize))
			c.XORKeyStream(tc.dst, tc.src)
		})
	}
}

func FuzzReference(f *testing.F) {
	f.Add(make([]byte, KeySize), make([]byte, IVSize), uint16(64))
	f.Add(bytes.Repeat([]byte{0xff}, KeySize), bytes.Repeat([]byte{0x80}, IVSize), uint16(13))
	f.Fuzz(func(t *testing.T, key, iv []byte, n uint16) {
		if len(key) != KeySize || len(iv) != IVSize {
			if _, err := New(key, iv); err == nil {
				t.Fatal("New accepted bad sizes")
			}
			return
		}
		if got, want := keystream(t, key, iv, int(n)), reference(key, iv, int(n)); !bytes.Equal(got, want) {
			t.Fatal("keystream differs from reference")
		}
	})
}

func BenchmarkNew(b *testing.B) {
	key, iv := make([]byte, KeySize), make([]byte, IVSize)
	for b.Loop() {
		New(key, iv)
	}
}

func BenchmarkXORKeyStream(b *testing.B) {
	for _, size := range []int{64, 1024, 64 * 1024} {
		b.Run(strconv.Itoa(size), func(b *testing.B) {
			c, _ := New(make([]byte, KeySize), make([]byte, IVSize))
			buf := make([]byte, size)
			b.SetBytes(int64(size))
			for b.Loop() {
				c.XORKeyStream(buf, buf)
			}
		})
	}
}
