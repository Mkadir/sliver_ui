package loader

import (
	"bytes"
	"strings"
	"testing"
)

func TestCleanImplantBranding(t *testing.T) {
	blob := []byte("pre github.com/bishopfox/sliver/protobuf/sliverpb post GetJitter end bishopfox X")
	out, rep := CleanImplant(blob, CleanOpts{Seed: []byte("seed-key-1")})
	if len(out) != len(blob) {
		t.Fatalf("length changed %d -> %d", len(blob), len(out))
	}
	if bytes.Contains(out, []byte("bishopfox")) {
		t.Fatalf("bishopfox still present: %q", out)
	}
	if bytes.Contains(out, []byte("github.com/bishopfox/sliver")) {
		t.Fatal("import path still present")
	}
	if !bytes.Contains(out, []byte("GetJitter")) {
		t.Fatal("protobuf RPC names must stay for stock teamserver")
	}
	if !contains(rep.Replaced, "github.com/bishopfox/sliver/protobuf/sliverpb") && !contains(rep.Replaced, "bishopfox") {
		t.Fatalf("replaced = %v", rep.Replaced)
	}
	if !contains(rep.Remaining, "GetJitter") {
		t.Fatalf("remaining = %v", rep.Remaining)
	}
	if !strings.Contains(rep.Note, "not a Defender bypass") {
		t.Fatal("missing honest note")
	}
}

func TestCleanImplantUTF16AndStartW(t *testing.T) {
	ascii := []byte("github.com/bishopfox/sliver")
	u16 := asciiToUTF16(ascii)
	buf := append([]byte("StartW\x00"), u16...)
	out, rep := CleanImplant(buf, CleanOpts{Seed: []byte{9, 8, 7, 6}, RenameStartW: true})
	if bytes.Contains(out, []byte("StartW")) {
		t.Fatal("StartW export should be rewritten when RenameStartW")
	}
	if bytes.Contains(out, asciiToUTF16([]byte("bishopfox"))) {
		t.Fatal("utf16 bishopfox still present")
	}
	if rep.Export == "" || rep.Export == "StartW" {
		t.Fatalf("export = %q", rep.Export)
	}
	if len(rep.Export) != len("StartW") {
		t.Fatal("export length must match StartW")
	}
}

func TestCleanImplantLeavesProto(t *testing.T) {
	blob := []byte("HTTPSessionInit ScreenshotReq sliverpb GetJitter")
	out, rep := CleanImplant(blob, CleanOpts{Seed: []byte("x")})
	for _, s := range []string{"HTTPSessionInit", "ScreenshotReq", "sliverpb", "GetJitter"} {
		if !bytes.Contains(out, []byte(s)) {
			t.Fatalf("rewrote protocol string %s", s)
		}
		if !contains(rep.Remaining, s) {
			t.Fatalf("%s not in remaining", s)
		}
	}
}

func contains(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}
