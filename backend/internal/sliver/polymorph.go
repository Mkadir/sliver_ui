package sliver

import (
	"crypto/rand"
	"encoding/hex"
	"strings"

	"sliverui/internal/loader"
)

func randHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "a1b2"
	}
	return hex.EncodeToString(b)
}

func polymorphName(name string) string {
	base := strings.TrimSpace(name)
	if base == "" {
		base = "payload"
	}
	base = strings.TrimSuffix(base, ".exe")
	base = strings.TrimSuffix(base, ".dll")
	base = strings.TrimSuffix(base, ".bin")
	return base + "_" + randHex(2)
}

func applyGeneratePolymorph(req *GenerateRequest) {
	if req == nil || !req.Polymorph {
		return
	}
	req.Obfuscate = true
	req.Name = polymorphName(req.Name)
	if strings.EqualFold(req.Format, "shellcode") && req.ShellcodeEntropy == 0 {
		req.ShellcodeEntropy = 3
	}
}

func polymorphArtifact(raw []byte, format string) ([]byte, any) {
	if len(raw) < 2 {
		return raw, nil
	}
	seed := make([]byte, 16)
	_, _ = rand.Read(seed)
	fmtLower := strings.ToLower(format)
	pe := loader.LooksLikePE(raw)
	out, rep := loader.CleanImplant(raw, loader.CleanOpts{
		Seed:          seed,
		RenameStartW:  pe && strings.Contains(fmtLower, "shared"),
		RenameExports: pe,
	})
	return out, &rep
}
