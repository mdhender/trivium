package trivium_test

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"os"

	"github.com/mdhender/trivium"
)

func Example() {
	key, _ := hex.DecodeString("0123456789abcdef0123")
	iv, _ := hex.DecodeString("fedcba9876543210fedc")
	plaintext := []byte("A very good day to you, Mr. Doogles.")

	enc, err := trivium.New(key, iv)
	if err != nil {
		panic(err)
	}
	ciphertext := make([]byte, len(plaintext))
	enc.XORKeyStream(ciphertext, plaintext)

	// Decrypting is the same operation with a fresh Cipher built from the
	// same key and IV.
	dec, err := trivium.New(key, iv)
	if err != nil {
		panic(err)
	}
	decrypted := make([]byte, len(ciphertext))
	dec.XORKeyStream(decrypted, ciphertext)

	fmt.Printf("%s\n", decrypted)
	// Output: A very good day to you, Mr. Doogles.
}

// This example uses a random IV for each message and sends it in the clear
// ahead of the ciphertext, so that a key can safely encrypt many messages.
func Example_randomIV() {
	key := make([]byte, trivium.KeySize)
	rand.Read(key)

	// Sender: prefix the ciphertext with a fresh random IV.
	message := []byte("attack at dawn")
	packet := make([]byte, trivium.IVSize+len(message))
	iv := packet[:trivium.IVSize]
	rand.Read(iv)
	c, _ := trivium.New(key, iv)
	c.XORKeyStream(packet[trivium.IVSize:], message)

	// Receiver: split off the IV and decrypt the rest in place.
	iv, body := packet[:trivium.IVSize], packet[trivium.IVSize:]
	c, _ = trivium.New(key, iv)
	c.XORKeyStream(body, body)

	fmt.Printf("%s\n", body)
	// Output: attack at dawn
}

// This example encrypts a stream of data with crypto/cipher.StreamWriter.
func Example_streamWriter() {
	key, _ := hex.DecodeString("0123456789abcdef0123")
	iv, _ := hex.DecodeString("fedcba9876543210fedc")

	c, _ := trivium.New(key, iv)
	var ciphertext bytes.Buffer
	w := cipher.StreamWriter{S: c, W: &ciphertext}
	io.WriteString(w, "streamed ")
	io.WriteString(w, "plaintext\n")

	c, _ = trivium.New(key, iv)
	r := cipher.StreamReader{S: c, R: &ciphertext}
	io.Copy(os.Stdout, r)
	// Output: streamed plaintext
}

func ExampleCipher_XORKeyStream() {
	// Encrypting zeros yields the raw keystream. This is eSTREAM test
	// vector set 1, vector 0.
	key, _ := hex.DecodeString("80000000000000000000")
	iv := make([]byte, trivium.IVSize)

	c, _ := trivium.New(key, iv)
	keystream := make([]byte, 16)
	c.XORKeyStream(keystream, keystream)

	fmt.Printf("%X\n", keystream)
	// Output: 38EB86FF730D7A9CAF8DF13A4420540D
}
