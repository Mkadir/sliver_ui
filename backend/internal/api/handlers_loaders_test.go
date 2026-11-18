package api

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestLoaderBuildRequiresPayload(t *testing.T) {
	body, _ := json.Marshal(map[string]any{"os": "linux", "arch": "amd64"})
	rec := newRecorder(httptest.NewRequest(http.MethodPost, "/api/loaders/build", bytes.NewReader(body)))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
}

func TestLoaderBuildRejectsBadPersist(t *testing.T) {
	payload := base64.StdEncoding.EncodeToString([]byte{0x90, 0xC3})
	body, _ := json.Marshal(map[string]any{
		"data_b64":    payload,
		"os":          "linux",
		"arch":        "amd64",
		"persistence": "runkey_hkcu",
	})
	rec := newRecorder(httptest.NewRequest(http.MethodPost, "/api/loaders/build", bytes.NewReader(body)))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
}

func TestLoaderBuildRDIRequiresClient(t *testing.T) {
	pe := make([]byte, 0x80)
	pe[0], pe[1] = 'M', 'Z'
	pe[0x3c] = 0x40
	pe[0x40], pe[0x41] = 'P', 'E'
	payload := base64.StdEncoding.EncodeToString(pe)
	body, _ := json.Marshal(map[string]any{
		"data_b64": payload,
		"os":       "windows",
		"arch":     "amd64",
		"rdi":      true,
	})
	rec := newRecorder(httptest.NewRequest(http.MethodPost, "/api/loaders/build", bytes.NewReader(body)))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503; body=%s", rec.Code, rec.Body.String())
	}
}

func TestLoaderBuildRejectsTruncatedPE(t *testing.T) {
	payload := base64.StdEncoding.EncodeToString([]byte{'M', 'Z', 0, 0})
	body, _ := json.Marshal(map[string]any{
		"data_b64": payload,
		"os":       "windows",
		"arch":     "amd64",
	})
	rec := newRecorder(httptest.NewRequest(http.MethodPost, "/api/loaders/build", bytes.NewReader(body)))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
}

func TestLoaderBuildCompilesLinux(t *testing.T) {
	payload := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x90}, 32))
	hide := false
	body, _ := json.Marshal(map[string]any{
		"data_b64":     payload,
		"os":           "linux",
		"arch":         "amd64",
		"name":         "lab",
		"hide_console": hide,
		"persistence":  "off",
	})
	rec := newRecorder(httptest.NewRequest(http.MethodPost, "/api/loaders/build", bytes.NewReader(body)))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d; body=%s", rec.Code, rec.Body.String())
	}
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	raw, err := base64.StdEncoding.DecodeString(out["data_b64"].(string))
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) < 4 || raw[0] != 0x7f || raw[1] != 'E' {
		t.Fatalf("expected ELF, got %d bytes", len(raw))
	}
	if out["filename"] != "lab_loader" {
		t.Fatalf("filename = %v", out["filename"])
	}
}
