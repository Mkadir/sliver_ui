package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestForkRewriteRequiresRoot(t *testing.T) {
	body, _ := json.Marshal(map[string]any{"branding": true})
	rec := newRecorder(httptest.NewRequest(http.MethodPost, "/api/fork/rewrite", bytes.NewReader(body)))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestForkRewriteDryRun(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte("module github.com/bishopfox/sliver\n\ngo 1.22\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "implant"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "implant", "a.go"), []byte("package implant\nimport \"github.com/bishopfox/sliver/protobuf/cpmfczjv\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]any{
		"root":       root,
		"branding":   true,
		"new_module": "github.com/labhost/implant",
		"dry_run":    true,
	})
	rec := newRecorder(httptest.NewRequest(http.MethodPost, "/api/fork/rewrite", bytes.NewReader(body)))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out["dry_run"] != true {
		t.Fatalf("dry_run = %v", out["dry_run"])
	}
	if out["needs_ui_build"] == true {
		t.Fatal("branding dry-run must not need UI rebuild")
	}
}
