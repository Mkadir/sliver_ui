package sliverfork

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestApplyBrandingDryRun(t *testing.T) {
	root := writeTree(t, map[string]string{
		"go.mod":       "module github.com/bishopfox/sliver\n\ngo 1.22\n",
		"implant/a.go": "package implant\nimport \"github.com/bishopfox/sliver/protobuf/sliverpb\"\nconst s = \"bishopfox\"\n",
	})
	rep, err := Apply(Options{Root: root, NewModule: "github.com/labhost/implant", Branding: true, DryRun: true})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Files == 0 || rep.Hits["github.com/bishopfox/sliver"] == 0 {
		t.Fatalf("expected branding hits: %+v", rep)
	}
	raw, _ := os.ReadFile(filepath.Join(root, "implant/a.go"))
	if !strings.Contains(string(raw), "bishopfox") {
		t.Fatal("dry-run must not write")
	}
}

func TestApplyBrandingWrites(t *testing.T) {
	root := writeTree(t, map[string]string{
		"go.mod":       "module github.com/bishopfox/sliver\n\ngo 1.22\n",
		"implant/a.go": "package implant\nimport \"github.com/bishopfox/sliver/protobuf/sliverpb\"\n",
	})
	rep, err := Apply(Options{Root: root, NewModule: "github.com/labhost/implant", Branding: true, DryRun: false})
	if err != nil {
		t.Fatal(err)
	}
	if rep.NeedsUIBuild {
		t.Fatal("branding-only must not require UI rebuild")
	}
	mod, _ := os.ReadFile(filepath.Join(root, "go.mod"))
	if !strings.Contains(string(mod), "github.com/labhost/implant") {
		t.Fatalf("go.mod = %s", mod)
	}
	if strings.Contains(string(mod), "bishopfox") {
		t.Fatal("stock module still in go.mod")
	}
}

func TestApplyProtoSameLength(t *testing.T) {
	root := writeTree(t, map[string]string{
		"go.mod":        "module github.com/bishopfox/sliver\n\ngo 1.22\n",
		"protobuf/x.go": "package sliverpb\nfunc GetJitter() {}\nconst ScreenshotReq = 1\n",
	})
	rep, err := Apply(Options{Root: root, Proto: true, DryRun: false, Seed: []byte("seed")})
	if err != nil {
		t.Fatal(err)
	}
	if !rep.NeedsUIBuild {
		t.Fatal("proto rewrite requires UI rebuild")
	}
	raw, _ := os.ReadFile(filepath.Join(root, "protobuf/x.go"))
	s := string(raw)
	if strings.Contains(s, "GetJitter") || strings.Contains(s, "ScreenshotReq") {
		t.Fatalf("proto names still present: %s", s)
	}
	if !strings.Contains(s, "package sliverpb") {
		t.Fatal("package sliverpb must stay (import path)")
	}
	if !strings.Contains(s, "package ") {
		t.Fatal("package line missing")
	}
}

func TestApplyGeneratorPatches(t *testing.T) {
	root := writeTree(t, map[string]string{
		"go.mod":                              "module github.com/bishopfox/sliver\n\ngo 1.22\n",
		"server/generate/donut.go":            "\tdefaultDonutBypass   = wasmdonut.DonutBypassContinue\n",
		"client/command/generate/commands.go": `f.StringP("exports", "v", "StartW,VoidFunc,DllInstall,DllRegisterServer,DllUnregisterServer", "x")` + "\n",
		"implant/sliver/runner/runner.go":     "if transports.GetMaxConnectionErrors() < connectionErrors {\n",
		"server/rpc/rpc-generate.go":          "\tif len(config.Exports) == 0 {\n\t\tconfig.Exports = []string{\"StartW\"}\n\t}\n\tif len(profile.Config.Exports) == 0 {\n\t\tprofile.Config.Exports = []string{\"StartW\"}\n\t}\n",
		"server/generate/binaries.go":         "\t\tnewImportPrefix := path.Join(modResult.NewModule, \"runc\", \"cgroup\")\n",
		"server/certs/ca.go":                  `GenerateCertificateAuthority(OperatorCA, "operators")` + "\n",
		"server/transport/mtls.go":            `tlsConfig := getOperatorServerTLSConfig("multiplayer")` + "\n",
		"server/transport/tailscale.go":       `tlsConfig := getOperatorServerTLSConfig("multiplayer")` + "\n",
		"client/command/exec/commands.go": "f.StringP(\"process\", \"p\", \"notepad.exe\", \"hosting process to inject into\")\n" +
			"f.StringP(\"process\", \"n\", `c:\\windows\\system32\\notepad.exe`, \"Process to inject into when running in interactive mode\")\n" +
			"f.StringP(\"process\", \"p\", `c:\\windows\\system32\\notepad.exe`, \"Path to process to host the shellcode\")\n",
		"client/command/alias/load.go": "windowsDefaultHostProc = `c:\\windows\\system32\\notepad.exe`\n",
	})
	rep, err := Apply(Options{Root: root, Generator: true, DryRun: false})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Hits["donut-bypass-none"] < 1 || rep.Hits["exports-startw-only"] < 1 || rep.Hits["inline-max-errors"] < 1 {
		t.Fatalf("hits = %+v", rep.Hits)
	}
	if rep.Hits["rpc-polymorph-generate"] < 1 || rep.Hits["random-import-disguise"] < 1 || rep.Hits["polymorph.go"] < 1 {
		t.Fatalf("polymorph hits = %+v", rep.Hits)
	}
	if rep.Hits["ca-cn-workgroup"] < 1 || rep.Hits["mtls-cn-application"] < 1 || rep.Hits["tailscale-cn-application"] < 1 {
		t.Fatalf("tls ioc hits = %+v", rep.Hits)
	}
	if rep.Hits["exec-host-notepad"] < 1 || rep.Hits["exec-host-notepad-path"] < 1 || rep.Hits["alias-windows-host"] < 1 {
		t.Fatalf("post-ex host hits = %+v", rep.Hits)
	}
	donut, _ := os.ReadFile(filepath.Join(root, "server/generate/donut.go"))
	if !strings.Contains(string(donut), "defaultDonutBypass   = 1") {
		t.Fatalf("donut.go = %s", donut)
	}
	run, _ := os.ReadFile(filepath.Join(root, "implant/sliver/runner/runner.go"))
	if strings.Contains(string(run), "GetMaxConnectionErrors()") {
		t.Fatal("call site still present")
	}
	if !strings.Contains(string(run), "{{.Config.MaxConnectionErrors}}") {
		t.Fatalf("runner.go = %s", run)
	}
	execCmd, _ := os.ReadFile(filepath.Join(root, "client/command/exec/commands.go"))
	if strings.Contains(string(execCmd), "notepad.exe") {
		t.Fatalf("exec commands still default notepad: %s", execCmd)
	}
	if !strings.Contains(string(execCmd), "RuntimeBroker.exe") {
		t.Fatalf("exec commands.go = %s", execCmd)
	}
	aliasLoad, _ := os.ReadFile(filepath.Join(root, "client/command/alias/load.go"))
	if strings.Contains(string(aliasLoad), "notepad.exe") {
		t.Fatalf("alias load still default notepad: %s", aliasLoad)
	}
}

func TestRefuseSliverUI(t *testing.T) {
	root := writeTree(t, map[string]string{"go.mod": "module sliverui\n"})
	if _, err := Apply(Options{Root: root, Branding: true, NewModule: "github.com/labhost/implant"}); err == nil {
		t.Fatal("expected refuse")
	}
	if _, err := Apply(Options{Root: root, ProtoPkg: true, Seed: []byte("seed")}); err != nil {
		t.Fatalf("proto-pkg on sliver-ui must be allowed: %v", err)
	}
}

func TestApplyProtoPkgRenamesPackageAndDir(t *testing.T) {
	root := writeTree(t, map[string]string{
		"go.mod":                      "module github.com/bishopfox/sliver\n\ngo 1.22\n",
		"protobuf/sliverpb/sliver.go": "package sliverpb\nvar file_sliverpb_sliver_proto_init = 1\nvar raw = []byte{0x73, 0x6c, 0x69, 0x76, 0x65, 0x72, 0x70,\n\t0x62, 0x1a}\nfunc GetJitter() {}\n",
		"implant/a.go":                "package implant\nimport \"github.com/bishopfox/sliver/protobuf/sliverpb\"\n",
		"implant/vendor/github.com/bishopfox/sliver/protobuf/sliverpb/sliver.go": "package sliverpb\n",
		"internal/loader/implant_clean.go":                                       "package loader\nconst needle = \"sliverpb\"\n",
	})
	seed := []byte("seed")
	mapped := string(morphIdent([]byte("sliverpb"), seed))
	if len(mapped) != 8 {
		t.Fatalf("mapped sliverpb len = %d (%q)", len(mapped), mapped)
	}
	rep, err := Apply(Options{Root: root, Proto: true, ProtoPkg: true, Seed: seed})
	if err != nil {
		t.Fatal(err)
	}
	if !rep.NeedsUIBuild {
		t.Fatal("proto-pkg requires UI rebuild")
	}
	if got := rep.Mapping["sliverpb"]; got != mapped {
		t.Fatalf("mapping sliverpb = %q want %q", got, mapped)
	}
	if got := rep.Mapping["dnspb"]; got == "" || len(got) != 5 {
		t.Fatalf("mapping dnspb = %q", got)
	}
	if _, err := os.Stat(filepath.Join(root, "protobuf", "sliverpb")); !os.IsNotExist(err) {
		t.Fatal("stock protobuf/sliverpb dir must be gone")
	}
	newDir := filepath.Join(root, "protobuf", mapped)
	if st, err := os.Stat(newDir); err != nil || !st.IsDir() {
		t.Fatalf("mapped dir missing: %s err=%v", newDir, err)
	}
	vendored := filepath.Join(root, "implant/vendor/github.com/bishopfox/sliver/protobuf", mapped)
	if st, err := os.Stat(vendored); err != nil || !st.IsDir() {
		t.Fatalf("vendored mapped dir missing: %s err=%v", vendored, err)
	}
	if _, err := os.Stat(filepath.Join(root, "implant/vendor/github.com/bishopfox/sliver/protobuf/sliverpb")); !os.IsNotExist(err) {
		t.Fatal("stock implant/vendor sliverpb dir must be gone")
	}
	raw, err := os.ReadFile(filepath.Join(newDir, "sliver.go"))
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	if strings.Contains(s, "sliverpb") {
		t.Fatalf("sliverpb still present: %s", s)
	}
	if !strings.Contains(s, "package "+mapped) {
		t.Fatalf("package clause: %s", s)
	}
	if !strings.Contains(s, "file_"+mapped+"_sliver_proto_init") {
		t.Fatalf("generated infix not rewritten: %s", s)
	}
	wantHex := hexLit([]byte(mapped))
	if !strings.Contains(s, wantHex) {
		t.Fatalf("rawDesc hex not rewritten, want %s in %s", wantHex, s)
	}
	if strings.Contains(s, "GetJitter") {
		t.Fatalf("GetJitter still present: %s", s)
	}
	imp, _ := os.ReadFile(filepath.Join(root, "implant/a.go"))
	if !strings.Contains(string(imp), "github.com/bishopfox/sliver/protobuf/"+mapped) {
		t.Fatalf("import = %s", imp)
	}
	if strings.Contains(string(imp), "sliverpb") {
		t.Fatalf("importer still has sliverpb: %s", imp)
	}
	clean, _ := os.ReadFile(filepath.Join(root, "internal/loader/implant_clean.go"))
	if !strings.Contains(string(clean), "sliverpb") {
		t.Fatal("implant_clean must keep stock sliverpb")
	}

	if _, err := Apply(Options{Root: root, Proto: true, ProtoPkg: true, Seed: seed}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "protobuf", "sliverpb")); !os.IsNotExist(err) {
		t.Fatal("stock sliverpb dir reappeared")
	}
}

func TestApplyProtoPkgIdempotentNeedles(t *testing.T) {
	seed := []byte("seed")
	mapped := string(morphIdent([]byte("sliverpb"), seed))
	root := writeTree(t, map[string]string{
		"go.mod":                            "module github.com/bishopfox/sliver\n\ngo 1.22\n",
		"protobuf/" + mapped + "/sliver.go": "package " + mapped + "\n",
	})
	rep, err := Apply(Options{Root: root, ProtoPkg: true, Seed: seed})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Hits["sliverpb"] != 0 {
		t.Fatalf("hits sliverpb = %d, want 0", rep.Hits["sliverpb"])
	}
}

func TestRelativePathRejected(t *testing.T) {
	if _, err := Apply(Options{Root: "tmp/sliver", Branding: true}); err == nil {
		t.Fatal("expected abs path error")
	}
}

func writeTree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for name, body := range files {
		p := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}
