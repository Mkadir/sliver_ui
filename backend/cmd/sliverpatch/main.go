package main

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"sliverui/internal/sliverfork"
)

func main() {
	root := flag.String("root", "", "path to a Sliver checkout")
	module := flag.String("module", "github.com/labhost/implant", "new Go module path (branding only)")
	branding := flag.Bool("branding", false, "rewrite github.com/bishopfox/sliver module path")
	proto := flag.Bool("proto", false, "same-length protobuf family rename (breaks stock clients)")
	protoPkg := flag.Bool("proto-pkg", false, "same-length cpmfczjv/pnwlb package path rename")
	generator := flag.Bool("generator", true, "patch implant compiler (Donut none, StartW-only exports, inline max-errors)")
	dry := flag.Bool("dry-run", false, "count hits without writing")
	seedHex := flag.String("seed", "", "hex seed so sliver-server and sliver-ui share the same name map")
	protoSrc := flag.String("proto-src", "", "Sliver checkout to read .proto identifiers from")
	needlesFile := flag.String("needles", "", "JSON array of identifiers (from a clean checkout)")
	dumpNeedles := flag.Bool("dump-needles", false, "print proto identifiers from -proto-src or -root and exit")
	flag.Parse()
	if *dumpNeedles {
		src := *protoSrc
		if src == "" {
			src = *root
		}
		if src == "" {
			fatal(fmt.Errorf("-dump-needles needs -root or -proto-src"))
		}
		abs, err := filepath.Abs(src)
		if err != nil {
			fatal(err)
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(sliverfork.ProtoNeedlesFor(abs))
		return
	}
	if *root == "" {
		fmt.Fprintln(os.Stderr, "usage: sliverpatch -root /path/to/sliver [-generator] [-branding] [-proto] [-proto-pkg] [-dry-run]")
		os.Exit(2)
	}
	abs, err := filepath.Abs(*root)
	if err != nil {
		fatal(err)
	}
	var needles []string
	if *needlesFile != "" {
		raw, err := os.ReadFile(*needlesFile)
		if err != nil {
			fatal(err)
		}
		if err := json.Unmarshal(raw, &needles); err != nil {
			fatal(fmt.Errorf("needles: %w", err))
		}
	}
	var seed []byte
	if *seedHex != "" {
		seed, err = hex.DecodeString(*seedHex)
		if err != nil {
			fatal(fmt.Errorf("seed: %w", err))
		}
	}
	rep, err := sliverfork.Apply(sliverfork.Options{
		Root:      abs,
		NewModule: *module,
		Branding:  *branding,
		Proto:     *proto,
		Generator: *generator,
		ProtoPkg:  *protoPkg,
		DryRun:    *dry,
		Seed:      seed,
		ProtoSrc:  *protoSrc,
		Needles:   needles,
	})
	if err != nil {
		fatal(err)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(rep)
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
