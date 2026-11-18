package sliver

import (
	"crypto/sha256"
	"encoding/hex"
	"sync"
)

// artifactHashes remembers SHA-256 of generate/regenerate blobs in this
// process so a later build can warn when two different names collide.
var (
	artifactMu     sync.Mutex
	artifactHashes = map[string]string{} // hash -> implant name
)

func sha256Hex(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// noteArtifactHash records hash→name. It returns the other implant name when
// this digest was already produced under a different name.
func noteArtifactHash(name, hash string) string {
	if hash == "" || name == "" {
		return ""
	}
	artifactMu.Lock()
	defer artifactMu.Unlock()
	if existing, ok := artifactHashes[hash]; ok && existing != name {
		return existing
	}
	artifactHashes[hash] = name
	return ""
}

func attachArtifactHash(out map[string]any, name string, raw []byte) {
	hash := sha256Hex(raw)
	if hash == "" {
		return
	}
	out["sha256"] = hash
	if other := noteArtifactHash(name, hash); other != "" {
		out["collision_with"] = other
	}
}

func resetArtifactHashesForTest() {
	artifactMu.Lock()
	artifactHashes = map[string]string{}
	artifactMu.Unlock()
}
