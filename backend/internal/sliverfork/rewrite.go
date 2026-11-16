package sliverfork

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"unicode"
)

const stockModule = "github.com/bishopfox/sliver"

var skipDirs = map[string]bool{
	".git": true, "vendor": true, "node_modules": true, "dist": true,
}

var textExt = map[string]bool{
	".go": true, ".proto": true, ".mod": true, ".md": true,
	".yml": true, ".yaml": true, ".json": true, ".txt": true,
}

// ProtoNeedles are Elastic/Fortbridge family strings that live in .proto/.go.
// Same-length rewrite keeps call sites in sync without regenerating pb.go.
var ProtoNeedles = []string{
	"GetReconnectIntervalSeconds",
	"name=ReconnectIntervalSeconds",
	"ReconnectIntervalSeconds",
	"InvokeSpawnDllReq",
	"HTTPSessionInit",
	"RegistryReadReq",
	"ScreenshotReq",
	").RequestResend",
	").GetPrivInfo",
	").GetPivotID",
	"name=PrivInfo",
	"name=PivotID",
	"RequestResend",
	"GetPrivInfo",
	"GetPivotID",
	"NetstatReq",
	"GetJitter",
	"AddTunnel",
	"GetIsIOC",
	"VoidFunc",
	"GetKill",
	"PrivInfo",
	"PivotID",
	"sliverpb",
}

// Stock protobuf package path identifiers. Always these names (never collected
// from a morphed tree) so re-apply is idempotent.
var protoPkgNeedles = []string{"sliverpb", "dnspb"}

var brandingLeft = []string{"BishopFox", "bishopfox"}

var moduleRE = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._/-]{0,127}$`)

// Options for a source-tree rewrite.
type Options struct {
	Root      string
	NewModule string
	Branding  bool
	Proto     bool
	Generator bool
	ProtoPkg  bool
	DryRun    bool
	Seed      []byte
	// ProtoSrc is the Sliver checkout used to collect .proto identifiers.
	// Empty means opts.Root.
	ProtoSrc string
	// Needles, when set, is the identifier list (stable across sliver + UI).
	Needles []string
}

// Report is the honest result of a fork rewrite.
type Report struct {
	Root         string            `json:"root"`
	Module       string            `json:"module"`
	NewModule    string            `json:"new_module,omitempty"`
	DryRun       bool              `json:"dry_run"`
	Files        int               `json:"files"`
	Hits         map[string]int    `json:"hits"`
	Changed      []string          `json:"changed"`
	Skipped      []string          `json:"skipped,omitempty"`
	Next         []string          `json:"next"`
	Note         string            `json:"note"`
	NeedsUIBuild bool              `json:"needs_ui_build"`
	Mapping      map[string]string `json:"mapping,omitempty"`
}

// Apply rewrites a local Sliver checkout. dry-run counts without writing.
func Apply(opts Options) (*Report, error) {
	root, err := validateRoot(opts.Root)
	if err != nil {
		return nil, err
	}
	mod, err := readModule(root)
	if err != nil {
		return nil, err
	}
	if !opts.Branding && !opts.Proto && !opts.Generator && !opts.ProtoPkg {
		return nil, fmt.Errorf("select branding, proto, proto-pkg, and/or generator")
	}
	if mod == "sliverui" && (opts.Branding || opts.Generator) {
		return nil, fmt.Errorf("refusing branding/generator rewrite of sliver-ui; proto/proto-pkg is allowed")
	}
	newMod := strings.TrimSpace(opts.NewModule)
	if opts.Branding {
		if newMod == "" {
			newMod = "github.com/labhost/implant"
		}
		if !moduleRE.MatchString(newMod) || strings.Contains(newMod, "..") {
			return nil, fmt.Errorf("invalid module path %q", newMod)
		}
		if newMod == stockModule || newMod == mod {
			return nil, fmt.Errorf("new module path must differ from %s", mod)
		}
	}
	seed := opts.Seed
	if len(seed) == 0 {
		seed = make([]byte, 16)
		if _, err := rand.Read(seed); err != nil {
			seed = []byte{0x51, 0xA3, 0x7E, 0x09, 0xC2}
		}
	}

	rep := &Report{
		Root:      root,
		Module:    mod,
		NewModule: newMod,
		DryRun:    opts.DryRun,
		Hits:      map[string]int{},
		Mapping:   map[string]string{},
		Note:      noteFor(opts.Branding, opts.Proto, opts.Generator, opts.ProtoPkg),
	}

	pneedles := ProtoNeedles
	if opts.Proto {
		if len(opts.Needles) > 0 {
			pneedles = append([]string{}, opts.Needles...)
		} else {
			src := opts.ProtoSrc
			if src == "" {
				src = root
			}
			pneedles = protoNeedlesFor(src)
		}
		for _, n := range pneedles {
			neu := string(morphIdent([]byte(n), seed))
			if neu != n {
				rep.Mapping[n] = neu
			}
		}
	}
	if opts.ProtoPkg {
		for _, n := range protoPkgNeedles {
			neu := string(morphIdent([]byte(n), seed))
			if neu != n {
				rep.Mapping[n] = neu
			}
		}
	}

	var changed []string
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == "vendor" {
				rel, _ := filepath.Rel(root, path)
				if (opts.Proto || opts.ProtoPkg) && strings.HasPrefix(filepath.ToSlash(rel), "implant/") {
					return nil
				}
				return filepath.SkipDir
			}
			if skipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if d.Type()&os.ModeSymlink != 0 {
			return nil
		}
		if !textExt[strings.ToLower(filepath.Ext(path))] && d.Name() != "go.mod" {
			return nil
		}
		st, err := d.Info()
		if err != nil || st.Size() > 2<<20 {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		if bytes.ContainsRune(raw[:min(len(raw), 256)], 0) {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		if (opts.Proto || opts.ProtoPkg) && skipProtoRel(rel) {
			return nil
		}
		next := raw
		fileHits := map[string]int{}
		if opts.Proto {
			var h map[string]int
			next, h = rewriteNeedles(next, pneedles, seed, true)
			for k, v := range h {
				fileHits[k] += v
			}
		}
		if opts.ProtoPkg {
			var h map[string]int
			// Substring replace: generated pb.go uses file_sliverpb_sliver_proto_*
			// identifiers. ident-boundary replace misses those, and YARA still
			// matches the sliverpb infix.
			next, h = rewriteNeedles(next, protoPkgNeedles, seed, false)
			for k, v := range h {
				fileHits[k] += v
			}
			for _, n := range protoPkgNeedles {
				neu := morphIdent([]byte(n), seed)
				if bytes.Equal([]byte(n), neu) {
					continue
				}
				var c int
				next, c = rewriteHexIdent(next, []byte(n), neu)
				if c > 0 {
					fileHits[n+"_hex"] += c
				}
			}
		}
		if opts.Branding {
			if mod == stockModule || strings.HasPrefix(mod, stockModule) {
				if n := bytes.Count(next, []byte(stockModule)); n > 0 {
					next = bytes.ReplaceAll(next, []byte(stockModule), []byte(newMod))
					fileHits[stockModule] += n
				}
			} else if n := bytes.Count(next, []byte(mod)); n > 0 && newMod != "" {
				next = bytes.ReplaceAll(next, []byte(mod), []byte(newMod))
				fileHits[mod] += n
			}
			var more map[string]int
			next, more = rewriteNeedles(next, brandingLeft, seed, false)
			for k, v := range more {
				fileHits[k] += v
			}
		}
		if bytes.Equal(next, raw) {
			return nil
		}
		changed = append(changed, rel)
		for k, v := range fileHits {
			rep.Hits[k] += v
		}
		if !opts.DryRun {
			if err := os.WriteFile(path, next, st.Mode().Perm()); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if opts.Generator {
		gfiles, err := applyGeneratorPatches(root, opts.DryRun, rep.Hits)
		if err != nil {
			return nil, err
		}
		changed = append(changed, gfiles...)
	}
	if opts.ProtoPkg {
		dfiles, err := renameProtoPkgDirs(root, rep.Mapping, opts.DryRun, rep.Hits)
		if err != nil {
			return nil, err
		}
		changed = append(changed, dfiles...)
	}
	sort.Strings(changed)
	rep.Files = len(changed)
	if len(changed) > 40 {
		rep.Changed = append([]string{}, changed[:40]...)
		rep.Skipped = []string{fmt.Sprintf("… %d more files", len(changed)-40)}
	} else {
		rep.Changed = changed
	}
	rep.NeedsUIBuild = opts.Proto || opts.ProtoPkg
	rep.Next = nextSteps(root, newMod, opts.Branding, opts.Proto, opts.Generator, opts.ProtoPkg)
	if rep.Files == 0 {
		rep.Note += " No matching strings in text files (already rewritten, or not a full checkout)."
	}
	return rep, nil
}

func noteFor(branding, proto, generator, protoPkg bool) string {
	switch {
	case generator && !branding && !proto && !protoPkg:
		return "Patches sliver-server's implant generator (Donut bypass none, drop COM/VoidFunc exports, inline max-errors). Rebuild sliver-server from this tree. This UI stays a client. Garble -seed=random already unique-hashes obfuscated builds. Protobuf RPC names stay unless proto mode. Not a Defender guarantee."
	case proto || protoPkg:
		return "Protobuf family rename, sliverpb/dnspb package-path morph, and/or generator patches. Rebuild sliver-server and this UI against the tree if proto or proto-pkg is on. Stock teamserver will not interoperate after proto. Package-path needles are always the stock names (re-apply is idempotent). Not a Defender guarantee."
	default:
		return "Go module path / bishopfox branding and/or generator patches. Protobuf RPC names unchanged unless proto is on, so this UI can still speak to the rebuilt server. Not a Defender guarantee."
	}
}

func nextSteps(root, newMod string, branding, proto, generator, protoPkg bool) []string {
	out := []string{
		"Rebuild sliver-server from this checkout (the implant compiler lives there, not in sliver-ui).",
		"Point this UI at that server (same client config). Generate SHARED, wrap with disk LoadLibrary.",
	}
	if generator {
		out = append([]string{"Generator patches: Donut default bypass=none, exports=StartW only, inline MaxConnectionErrors."}, out...)
	}
	if branding && newMod != "" {
		out = append([]string{"go mod tidy && go mod vendor (in the checkout) after the module path change."}, out...)
	}
	if proto || protoPkg {
		out = append(out,
			"In sliver-ui/backend: go mod edit -replace github.com/bishopfox/sliver="+root,
			"Then: go mod tidy && go build, restart sliver-ui, reconnect.",
		)
	} else {
		out = append(out, "Do not rebuild sliver-ui unless proto or proto-pkg was applied.")
	}
	return out
}

func validateRoot(root string) (string, error) {
	root = strings.TrimSpace(root)
	if root == "" {
		return "", fmt.Errorf("root path is required")
	}
	if !filepath.IsAbs(root) {
		return "", fmt.Errorf("root path must be absolute")
	}
	clean, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	st, err := os.Stat(clean)
	if err != nil {
		return "", fmt.Errorf("root: %w", err)
	}
	if !st.IsDir() {
		return "", fmt.Errorf("root is not a directory")
	}
	return clean, nil
}

func readModule(root string) (string, error) {
	b, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		return "", fmt.Errorf("go.mod: %w (need a Sliver checkout)", err)
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "module ") {
			mod := strings.TrimSpace(strings.TrimPrefix(line, "module "))
			if mod == "sliverui" {
				return mod, nil
			}
			if !looksLikeSliver(root, mod) {
				return "", fmt.Errorf("go.mod module %q does not look like Sliver", mod)
			}
			return mod, nil
		}
	}
	return "", fmt.Errorf("go.mod has no module line")
}

func looksLikeSliver(root, mod string) bool {
	if mod == stockModule || strings.Contains(mod, "sliver") {
		return true
	}
	for _, p := range []string{"protobuf", "implant", "server"} {
		if st, err := os.Stat(filepath.Join(root, p)); err == nil && st.IsDir() {
			return true
		}
	}
	return false
}

func rewriteNeedles(src []byte, needles []string, seed []byte, ident bool) ([]byte, map[string]int) {
	hits := map[string]int{}
	ns := append([]string{}, needles...)
	sort.Slice(ns, func(i, j int) bool { return len(ns[i]) > len(ns[j]) })
	out := src
	for _, n := range ns {
		old := []byte(n)
		var neu []byte
		if ident {
			neu = morphIdent(old, seed)
			if bytes.Equal(old, neu) {
				continue
			}
			var c int
			out, c = replaceIdent(out, old, neu)
			if c > 0 {
				hits[n] = c
			}
			continue
		}
		neu = morphKeep(old, seed)
		if bytes.Equal(old, neu) {
			continue
		}
		c := bytes.Count(out, old)
		if c == 0 {
			continue
		}
		out = bytes.ReplaceAll(out, old, neu)
		hits[n] = c
	}
	return out, hits
}

func replaceIdent(buf, old, neu []byte) ([]byte, int) {
	if len(old) == 0 || len(old) != len(neu) {
		return buf, 0
	}
	out := append([]byte(nil), buf...)
	n := 0
	for i := 0; i+len(old) <= len(out); {
		if !bytes.Equal(out[i:i+len(old)], old) {
			i++
			continue
		}
		if i > 0 && isIdent(out[i-1]) {
			i++
			continue
		}
		if i+len(old) < len(out) && isIdent(out[i+len(old)]) {
			i++
			continue
		}
		copy(out[i:i+len(old)], neu)
		n++
		i += len(old)
	}
	return out, n
}

func isIdent(c byte) bool {
	return unicode.IsLetter(rune(c)) || unicode.IsDigit(rune(c)) || c == '_'
}

func hexLit(b []byte) string {
	parts := make([]string, len(b))
	for i, x := range b {
		parts[i] = fmt.Sprintf("0x%02x", x)
	}
	return strings.Join(parts, ", ")
}

// rewriteHexIdent replaces 0xHH, 0xHH, ... encodings of old (FileDescriptor
// rawDesc in generated pb.go) with neu. Whitespace/newlines between bytes allowed.
func rewriteHexIdent(src, old, neu []byte) ([]byte, int) {
	if len(old) == 0 || len(old) != len(neu) {
		return src, 0
	}
	var b strings.Builder
	for i, x := range old {
		if i > 0 {
			b.WriteString(`,\s*`)
		}
		b.WriteString(fmt.Sprintf("0x%02x", x))
	}
	re, err := regexp.Compile(`(?i)` + b.String())
	if err != nil {
		return src, 0
	}
	n := len(re.FindAll(src, -1))
	if n == 0 {
		return src, 0
	}
	return re.ReplaceAll(src, []byte(hexLit(neu))), n
}

func skipProtoRel(rel string) bool {
	rel = filepath.ToSlash(rel)
	if strings.Contains(rel, "internal/sliverfork/") || strings.HasPrefix(rel, "internal/sliverfork") {
		return true
	}
	return strings.Contains(rel, "implant_clean")
}

// renameProtoPkgDirs renames directories whose basename is a stock proto package
// (sliverpb, dnspb). Deepest path first. Skips .git and the checkout's top-level
// vendor/; walks implant/vendor so vendored protobuf copies move too.
func renameProtoPkgDirs(root string, mapping map[string]string, dry bool, hits map[string]int) ([]string, error) {
	var dirs []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			return nil
		}
		name := d.Name()
		if skipDirs[name] {
			if name == "vendor" {
				rel, relErr := filepath.Rel(root, path)
				if relErr == nil && filepath.ToSlash(rel) != "vendor" {
					return nil
				}
			}
			return filepath.SkipDir
		}
		if name != "sliverpb" && name != "dnspb" {
			return nil
		}
		neu := mapping[name]
		if neu == "" || neu == name {
			return nil
		}
		dirs = append(dirs, path)
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(dirs, func(i, j int) bool {
		si := strings.Count(dirs[i], string(os.PathSeparator))
		sj := strings.Count(dirs[j], string(os.PathSeparator))
		if si != sj {
			return si > sj
		}
		return dirs[i] > dirs[j]
	})
	var changed []string
	for _, path := range dirs {
		base := filepath.Base(path)
		dest := filepath.Join(filepath.Dir(path), mapping[base])
		rel, _ := filepath.Rel(root, path)
		hits[base]++
		changed = append(changed, rel)
		if dry {
			continue
		}
		if err := os.Rename(path, dest); err != nil {
			return changed, err
		}
	}
	return changed, nil
}

var protoDecl = regexp.MustCompile(`(?m)^[ \t]*(message|enum|rpc)\s+([A-Za-z_][A-Za-z0-9_]{7,})`)

var protoDeny = map[string]bool{
	"Session": true, "Beacon": true, "Execute": true, "Download": true, "Upload": true,
	"Process": true, "Tunnel": true, "Envelope": true, "Register": true, "Windows": true,
	"Request": true, "Response": true, "Message": true, "Client": true, "Server": true,
	"Header": true, "Status": true, "Config": true, "Empty": true, "Screenshot": true,
	"Services": true, "Listener": true, "Builders": true, "Implant": true, "Operator": true,
	"FileInfo": true, "Credential": true, "Version": true, "Context": true, "Duration": true,
	"Metadata": true, "Progress": true, "Encoding": true, "Compress": true, "Builder": true,
	"Profile": true, "Website": true, "Resource": true, "Extension": true, "Manifest": true,
	"Reaction": true, "Monitor": true, "Integrity": true, "Hostname": true, "Username": true,
	"Password": true, "Content": true, "Option": true, "Result": true, "Output": true,
}

// ProtoNeedlesFor lists distinctive protobuf identifiers from a clean checkout.
func ProtoNeedlesFor(root string) []string {
	return protoNeedlesFor(root)
}

func protoNeedlesFor(root string) []string {
	seen := map[string]bool{}
	for _, n := range ProtoNeedles {
		if n == "sliverpb" {
			continue
		}
		if len(n) >= 6 {
			seen[n] = true
		}
	}
	for _, sub := range []string{"protobuf/sliverpb", "protobuf/dnspb"} {
		protoDir := filepath.Join(root, filepath.FromSlash(sub))
		_ = filepath.WalkDir(protoDir, func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(path, ".proto") {
				return nil
			}
			b, err := os.ReadFile(path)
			if err != nil {
				return nil
			}
			for _, m := range protoDecl.FindAllSubmatch(b, -1) {
				name := string(m[2])
				if protoDeny[name] {
					continue
				}
				seen[name] = true
			}
			return nil
		})
	}
	out := make([]string, 0, len(seen))
	for n := range seen {
		out = append(out, n)
	}
	return out
}

func isWord(c byte) bool {
	return unicode.IsLetter(rune(c)) || unicode.IsDigit(rune(c))
}

func morphKeep(old, seed []byte) []byte {
	out := make([]byte, len(old))
	j := 0
	for i, c := range old {
		if isWord(c) {
			b := seed[j%len(seed)] ^ byte(j) ^ c
			letter := byte('a' + (b % 26))
			if c >= 'A' && c <= 'Z' {
				letter -= 32
			}
			out[i] = letter
			j++
		} else {
			out[i] = c
		}
	}
	return out
}

func morphIdent(old, seed []byte) []byte {
	out := morphKeep(old, seed)
	if len(out) == 0 {
		return out
	}
	if out[0] >= '0' && out[0] <= '9' {
		out[0] = 'A'
	}
	return out
}
