package sliver

import (
	"testing"
)

func TestSha256HexEmpty(t *testing.T) {
	if sha256Hex(nil) != "" {
		t.Fatal("empty input should yield empty hash")
	}
}

func TestNoteArtifactHashCollision(t *testing.T) {
	resetArtifactHashesForTest()
	h := sha256Hex([]byte("same-bytes"))
	if other := noteArtifactHash("alpha", h); other != "" {
		t.Fatalf("first insert collided with %q", other)
	}
	if other := noteArtifactHash("alpha", h); other != "" {
		t.Fatalf("same name should not collide, got %q", other)
	}
	if other := noteArtifactHash("beta", h); other != "alpha" {
		t.Fatalf("collision_with = %q, want alpha", other)
	}
}

func TestAttachArtifactHash(t *testing.T) {
	resetArtifactHashesForTest()
	out := map[string]any{}
	attachArtifactHash(out, "one", []byte("payload"))
	hash, _ := out["sha256"].(string)
	if len(hash) != 64 {
		t.Fatalf("sha256 length = %d, want 64", len(hash))
	}
	out2 := map[string]any{}
	attachArtifactHash(out2, "two", []byte("payload"))
	if out2["collision_with"] != "one" {
		t.Fatalf("collision_with = %v, want one", out2["collision_with"])
	}
}
