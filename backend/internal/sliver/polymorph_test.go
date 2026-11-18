package sliver

import (
	"strings"
	"testing"
)

func TestPolymorphName(t *testing.T) {
	a := polymorphName("OneDriveUpdater")
	b := polymorphName("OneDriveUpdater")
	if a == b {
		t.Fatal("expected unique suffix")
	}
	if !strings.HasPrefix(a, "OneDriveUpdater_") || len(a) != len("OneDriveUpdater_")+4 {
		t.Fatalf("a = %q", a)
	}
}

func TestApplyGeneratePolymorph(t *testing.T) {
	req := &GenerateRequest{Name: "foo", Format: "shellcode", Polymorph: true}
	applyGeneratePolymorph(req)
	if !req.Obfuscate {
		t.Fatal("obfuscate")
	}
	if req.ShellcodeEntropy != 3 {
		t.Fatalf("entropy = %d", req.ShellcodeEntropy)
	}
	if req.Name == "foo" {
		t.Fatal("name should gain a unique suffix")
	}
}
