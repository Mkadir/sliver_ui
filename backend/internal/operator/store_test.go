package operator

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func testStore(t *testing.T) *Store {
	t.Helper()
	dir := t.TempDir()
	return Open(dir, filepath.Join(dir, "reactions.json"))
}

func TestNotesRoundTrip(t *testing.T) {
	s := testStore(t)
	n, err := s.PutNote("uuid-1", "session", []string{"lab", "linux", "lab"}, "box in lab", "op-alpha")
	if err != nil {
		t.Fatal(err)
	}
	if n.UUID != "uuid-1" || n.Campaign != "op-alpha" || len(n.Tags) != 2 {
		t.Fatalf("note = %+v", n)
	}
	got := s.Note("uuid-1")
	if got.Comment != "box in lab" || got.Tags[0] != "lab" {
		t.Fatalf("got = %+v", got)
	}
	all := s.Notes()
	if len(all) != 1 {
		t.Fatalf("len(notes) = %d", len(all))
	}
}

func TestAdvisoryLockOverwrite(t *testing.T) {
	s := testStore(t)
	first, prev, err := s.AcquireLock("sess-1", "cup", "cup")
	if err != nil {
		t.Fatal(err)
	}
	if prev != nil {
		t.Fatalf("first acquire should have no previous holder")
	}
	if first.User != "cup" {
		t.Fatalf("user = %q", first.User)
	}
	second, prev, err := s.AcquireLock("sess-1", "other", "other-op")
	if err != nil {
		t.Fatal(err)
	}
	if prev == nil || prev.User != "cup" {
		t.Fatalf("previous = %+v", prev)
	}
	if second.User != "other" {
		t.Fatalf("second user = %q", second.User)
	}
	if err := s.ReleaseLock("sess-1", "cup"); err == nil {
		t.Fatal("expected release by previous holder to fail")
	}
	if err := s.ReleaseLock("sess-1", "other"); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.LockFor("sess-1"); ok {
		t.Fatal("lock still present")
	}
}

func TestAuditCap(t *testing.T) {
	s := testStore(t)
	for i := 0; i < maxAudit+10; i++ {
		s.AppendAudit(AuditEntry{User: "cup", Method: "POST", Path: "/api/x", Action: "mutate", Status: 200})
	}
	got := s.Audit()
	if len(got) != maxAudit {
		t.Fatalf("len(audit) = %d, want %d", len(got), maxAudit)
	}
}

func TestReactionsCLIFormat(t *testing.T) {
	s := testStore(t)
	r, err := s.AddReaction("session-connected", []string{"whoami", "ps"})
	if err != nil {
		t.Fatal(err)
	}
	if r.ID == 0 {
		t.Fatal("id not assigned")
	}
	raw, err := os.ReadFile(s.reactionsPath)
	if err != nil {
		t.Fatal(err)
	}
	var cli []cliReaction
	if err := json.Unmarshal(raw, &cli); err != nil {
		t.Fatal(err)
	}
	if len(cli) != 1 || cli[0].EventType != "session-connected" || len(cli[0].Commands) != 2 {
		t.Fatalf("cli = %+v", cli)
	}
	if _, ok := any(cli[0]).(interface{ ID() int }); ok {
		t.Fatal("cli reaction should not expose ID")
	}

	dir2 := t.TempDir()
	s2 := Open(dir2, s.reactionsPath)
	imported := s2.Reactions()
	if len(imported) != 1 || imported[0].EventType != "session-connected" {
		t.Fatalf("imported = %+v", imported)
	}

	if _, err := s.AddReaction("not-an-event", []string{"whoami"}); err == nil {
		t.Fatal("expected non-reactable error")
	}
	if !s.RemoveReaction(r.ID) {
		t.Fatal("remove failed")
	}
	if len(s.Reactions()) != 0 {
		t.Fatal("reactions still present")
	}
}

func TestNormalizeCommand(t *testing.T) {
	if NormalizeCommand("whoami") != "whoami" {
		t.Fatal("whoami")
	}
	if NormalizeCommand("  PS -foo") != "ps" {
		t.Fatal("ps")
	}
	if NormalizeCommand("execute /bin/sh") != "" {
		t.Fatal("execute should be skipped")
	}
}
