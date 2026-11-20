package sliver

import (
	"bytes"
	"compress/gzip"
	"testing"

	"github.com/bishopfox/sliver/protobuf/cpmfczjv"
)

func TestDirToView_SortsDirsFirst(t *testing.T) {
	d := dirToView(&cpmfczjv.Ls{
		Path:   "/tmp",
		Exists: true,
		Files: []*cpmfczjv.FileInfo{
			{Name: "zeta.txt", IsDir: false, Size: 10},
			{Name: "alpha", IsDir: true},
			{Name: "beta.txt", IsDir: false},
			{Name: "gamma", IsDir: true},
		},
	})
	if d == nil || !d.Exists || d.Path != "/tmp" {
		t.Fatalf("unexpected view: %+v", d)
	}
	want := []string{"alpha", "gamma", "beta.txt", "zeta.txt"}
	for i, name := range want {
		if d.Files[i].Name != name {
			t.Fatalf("files[%d] = %q, want %q (order: %v)", i, d.Files[i].Name, name, d.Files)
		}
	}
}

func TestDirToView_HandlesNil(t *testing.T) {
	if dirToView(nil) != nil {
		t.Fatal("nil input should produce nil view")
	}
}

func TestDirToView_SkipsNilFiles(t *testing.T) {
	d := dirToView(&cpmfczjv.Ls{
		Files: []*cpmfczjv.FileInfo{nil, {Name: "ok.txt", IsDir: false}},
	})
	if len(d.Files) != 1 || d.Files[0].Name != "ok.txt" {
		t.Fatalf("unexpected files: %+v", d.Files)
	}
}

func TestEncodeBase64(t *testing.T) {
	got := encodeBase64([]byte("hello world"))
	if got != "aGVsbG8gd29ybGQ=" {
		t.Fatalf("encodeBase64 = %q", got)
	}
	if encodeBase64(nil) != "" {
		t.Fatal("nil should produce empty string")
	}
}

func TestDecodeDownloadPayload_Gzip(t *testing.T) {
	plain := []byte("DATABASE_URL=postgres://local\n")
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(plain); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	got, err := decodeDownloadPayload("gzip", buf.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("got %q want %q", got, plain)
	}
	raw, err := decodeDownloadPayload("", plain)
	if err != nil || !bytes.Equal(raw, plain) {
		t.Fatalf("raw passthrough: %v %q", err, raw)
	}
}
