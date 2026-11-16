package sliver

import "testing"

func TestPsExecServiceMeta(t *testing.T) {
	name, desc := psExecServiceMeta("", "")
	if name != defaultPsExecServiceName || desc != defaultPsExecServiceDesc {
		t.Fatalf("empty → %q / %q", name, desc)
	}
	name, desc = psExecServiceMeta("  ", "  ")
	if name != defaultPsExecServiceName || desc != defaultPsExecServiceDesc {
		t.Fatalf("blank → %q / %q", name, desc)
	}
	name, desc = psExecServiceMeta("Svc", "Does things")
	if name != "Svc" || desc != "Does things" {
		t.Fatalf("explicit → %q / %q", name, desc)
	}
	if defaultPsExecServiceName == "Sliver" || defaultPsExecServiceDesc == "Sliver implant" {
		t.Fatal("stock Sliver service metadata")
	}
}
