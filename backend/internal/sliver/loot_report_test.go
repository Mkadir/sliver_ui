package sliver

import "testing"

func TestLootReportMarkdownEmpty(t *testing.T) {
	r := &LootReport{GeneratedAt: "2026-11-16T00:00:00Z"}
	md := r.Markdown()
	if md == "" {
		t.Fatal("empty markdown")
	}
	if want := "Generated 2026-11-16T00:00:00Z"; !contains(md, want) {
		t.Fatalf("missing %q in %s", want, md)
	}
}

func TestLootReportMarkdownEscapesPipes(t *testing.T) {
	r := &LootReport{
		GeneratedAt: "now",
		Loot: []LootReportItem{
			{Name: "a|b", LootType: "LOOT_FILE", File: "x", Size: 3, HasCred: true},
		},
		Canaries: []CanaryView{{Domain: "ex.com", ImplantName: "imp", Triggered: true, Count: 2}},
		Hosts:    []HostView{{Hostname: "h1", HostUUID: "u", OSVersion: "win", IOCs: []IOCView{{}}}},
		Implants: []LootReportImplant{{Name: "n", OS: "linux", Arch: "amd64", SHA256: "abc"}},
	}
	md := r.Markdown()
	if !contains(md, "a\\|b") {
		t.Fatalf("pipe not escaped: %s", md)
	}
	if !contains(md, "burned") || !contains(md, "credential present") {
		t.Fatalf("status missing: %s", md)
	}
	js, err := r.JSON()
	if err != nil || !contains(string(js), `"name": "a|b"`) {
		t.Fatalf("json: %s %v", js, err)
	}
}

func TestMdCell(t *testing.T) {
	if mdCell("") != "—" {
		t.Fatal("empty")
	}
	if mdCell("a|b\nc") != "a\\|b c" {
		t.Fatalf("got %q", mdCell("a|b\nc"))
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(sub) == 0 || (len(s) > 0 && (func() bool {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	})()))
}
