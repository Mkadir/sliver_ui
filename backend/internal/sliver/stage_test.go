package sliver

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"io"
	"strings"
	"testing"
)

func TestPreludeEncryptDecryptRoundTrip(t *testing.T) {
	key := []byte("0123456789abcdef") // 16
	iv := []byte("abcdefghijklmnop")  // 16
	plain := []byte("sliver-stage-payload-for-lab-test")

	ct := preludeEncrypt(plain, key, iv)
	if len(ct) < aes.BlockSize+aes.BlockSize {
		t.Fatalf("cipher too short: %d", len(ct))
	}
	if !bytes.Equal(ct[:aes.BlockSize], iv) {
		t.Fatalf("IV not prepended")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	body := append([]byte(nil), ct[aes.BlockSize:]...)
	mode := cipher.NewCBCDecrypter(block, ct[:aes.BlockSize])
	mode.CryptBlocks(body, body)
	pad := int(body[len(body)-1])
	got := body[:len(body)-pad]
	if !bytes.Equal(got, plain) {
		t.Fatalf("round-trip mismatch: got %q want %q", got, plain)
	}
}

func TestPrepareStagePayloadPrependSize(t *testing.T) {
	raw := []byte{0x90, 0x90, 0x90, 0xc3}
	out, enc, err := prepareStagePayload(raw, "", "", "", "", true)
	if err != nil {
		t.Fatal(err)
	}
	if enc {
		t.Fatal("expected not encrypted")
	}
	if len(out) != 8 {
		t.Fatalf("len=%d want 8", len(out))
	}
	n := binary.LittleEndian.Uint32(out[:4])
	if n != 4 {
		t.Fatalf("size prefix=%d want 4", n)
	}
	if !bytes.Equal(out[4:], raw) {
		t.Fatalf("payload mismatch")
	}
}

func TestNormalizeAES(t *testing.T) {
	k, iv, err := normalizeAES("0123456789abcdef", "")
	if err != nil {
		t.Fatal(err)
	}
	if iv != "0000000000000000" {
		t.Fatalf("default iv = %q", iv)
	}
	if k != "0123456789abcdef" {
		t.Fatalf("key = %q", k)
	}
	if _, _, err := normalizeAES("short", ""); err == nil {
		t.Fatal("expected short key error")
	}
	if _, _, err := normalizeAES("0123456789abcdef", "tooshort"); err == nil {
		t.Fatal("expected short IV error")
	}
	// 32-char hex IV must be rejected — CBC needs exactly 16-byte IV (Sliver panic otherwise).
	if _, _, err := normalizeAES("0123456789abcdef", "0123456789abcdef0123456789abcdef"); err == nil {
		t.Fatal("expected oversized IV error")
	}
}

func TestRC4Length(t *testing.T) {
	a := rc4Encrypt([]byte("hello"), []byte("key"))
	b := rc4Encrypt([]byte("hello"), []byte("key"))
	if !bytes.Equal(a, b) {
		t.Fatal("RC4 not deterministic")
	}
	if bytes.Equal(a, []byte("hello")) {
		t.Fatal("RC4 did not change data")
	}
}

func TestRC4Roundtrip(t *testing.T) {
	plain := []byte("sliver-stage-rc4-test-payload")
	key := []byte("rc4testkey")
	ct := rc4Encrypt(plain, key)
	got := rc4Encrypt(ct, key) // RC4 is symmetric: apply twice to recover plaintext
	if !bytes.Equal(got, plain) {
		t.Fatalf("RC4 roundtrip mismatch: got %x want %x", got, plain)
	}
}

func TestPrepareStagePayloadRC4(t *testing.T) {
	raw := []byte{0x90, 0xc3, 0x48, 0x31, 0xc0, 0xc3}
	out, enc, err := prepareStagePayload(raw, "", "", "", "secretkey", false)
	if err != nil {
		t.Fatal(err)
	}
	if !enc {
		t.Fatal("expected encrypted=true with RC4 key")
	}
	if bytes.Equal(out, raw) {
		t.Fatal("RC4 did not change payload")
	}
	// Verify roundtrip via RC4 symmetry.
	decrypted := rc4Encrypt(out, []byte("secretkey"))
	if !bytes.Equal(decrypted, raw) {
		t.Fatalf("RC4 prepareStagePayload roundtrip failed")
	}
}

func TestPrepareStagePayloadZlib(t *testing.T) {
	raw := bytes.Repeat([]byte("SLIVER"), 100) // highly compressible
	out, enc, err := prepareStagePayload(raw, "zlib", "", "", "", false)
	if err != nil {
		t.Fatal(err)
	}
	if enc {
		t.Fatal("expected encrypted=false with no key")
	}
	if len(out) >= len(raw) {
		t.Errorf("zlib output %d >= input %d (no compression)", len(out), len(raw))
	}
	r, err := zlib.NewReader(bytes.NewReader(out))
	if err != nil {
		t.Fatalf("zlib.NewReader: %v", err)
	}
	decompressed, err := io.ReadAll(r)
	_ = r.Close()
	if err != nil {
		t.Fatalf("zlib ReadAll: %v", err)
	}
	if !bytes.Equal(decompressed, raw) {
		t.Fatal("zlib roundtrip mismatch")
	}
}

func TestPrepareStagePayloadGzip(t *testing.T) {
	raw := bytes.Repeat([]byte("GZIP"), 50)
	out, _, err := prepareStagePayload(raw, "gzip", "", "", "", false)
	if err != nil {
		t.Fatal(err)
	}
	r, err := gzip.NewReader(bytes.NewReader(out))
	if err != nil {
		t.Fatalf("gzip.NewReader: %v", err)
	}
	decompressed, err := io.ReadAll(r)
	_ = r.Close()
	if err != nil {
		t.Fatalf("gzip ReadAll: %v", err)
	}
	if !bytes.Equal(decompressed, raw) {
		t.Fatal("gzip roundtrip mismatch")
	}
}

func TestPrepareStagePayloadCombined(t *testing.T) {
	raw := bytes.Repeat([]byte("AES-ZLIB"), 50)
	aesKey := "0123456789abcdef" // 16-byte AES-128 key
	aesIV := "abcdefghijklmnop"  // 16-byte IV
	out, enc, err := prepareStagePayload(raw, "zlib", aesKey, aesIV, "", false)
	if err != nil {
		t.Fatal(err)
	}
	if !enc {
		t.Fatal("expected encrypted=true with AES key")
	}
	// Output must start with the IV prefix.
	if len(out) < aes.BlockSize {
		t.Fatalf("output too short (%d bytes), expected ≥%d", len(out), aes.BlockSize)
	}
	if !bytes.Equal(out[:aes.BlockSize], []byte(aesIV)) {
		t.Fatal("AES IV not prepended to combined output")
	}
}

func TestPrepareStagePayloadBadCompress(t *testing.T) {
	_, _, err := prepareStagePayload([]byte("data"), "bogus", "", "", "", false)
	if err == nil {
		t.Fatal("expected error for unknown compress algorithm")
	}
	if !strings.Contains(err.Error(), "unsupported compress") {
		t.Fatalf("unexpected error message: %v", err)
	}
}

func TestValidateRC4(t *testing.T) {
	if err := validateRC4(""); err != nil {
		t.Fatalf("empty key should be allowed: %v", err)
	}
	if err := validateRC4("validkey"); err != nil {
		t.Fatalf("normal key should be allowed: %v", err)
	}
	oversized := strings.Repeat("k", 257)
	if err := validateRC4(oversized); err == nil {
		t.Fatal("expected error for 257-byte key (exceeds RC4 max of 256)")
	}
}
