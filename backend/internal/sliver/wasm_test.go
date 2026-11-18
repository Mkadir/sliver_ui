package sliver

import (
	"bytes"
	"compress/gzip"
	"io"
	"testing"
)

func TestGzipWasmRoundTrip(t *testing.T) {
	src := bytes.Repeat([]byte("wasm-module-bytes"), 64)
	gz, err := gzipWasm(src)
	if err != nil {
		t.Fatal(err)
	}
	if len(gz) == 0 {
		t.Fatal("empty gzip")
	}
	r, err := gzip.NewReader(bytes.NewReader(gz))
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, src) {
		t.Fatalf("round trip mismatch: %d vs %d", len(got), len(src))
	}
}

func TestWasmExecArgs(t *testing.T) {
	r := WasmExecRequest{Args: []string{"--foo", "bar"}}
	if got := r.argList(); len(got) != 2 || got[0] != "--foo" {
		t.Fatalf("args = %v", got)
	}
	r = WasmExecRequest{ArgsLine: "  --a  b  "}
	if got := r.argList(); len(got) != 2 || got[1] != "b" {
		t.Fatalf("args_line = %v", got)
	}
}

func TestDecodeMemFS(t *testing.T) {
	fs, err := decodeMemFS(map[string]string{
		"input.txt": encodeBase64([]byte("hello")),
	})
	if err != nil {
		t.Fatal(err)
	}
	if string(fs["input.txt"]) != "hello" {
		t.Fatalf("memfs = %q", fs["input.txt"])
	}
	if _, err := decodeMemFS(map[string]string{"": "YQ=="}); err == nil {
		t.Fatal("expected missing name error")
	}
}
