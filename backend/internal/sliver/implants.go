package sliver

import (
	"context"
	"encoding/base64"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/bishopfox/sliver/protobuf/clientpb"
	"github.com/bishopfox/sliver/protobuf/commonpb"
	"github.com/bishopfox/sliver/protobuf/cpmfczjv"
)

// GenerateRequest is the JSON body for implant generation.
type GenerateRequest struct {
	Name   string `json:"name"`
	OS     string `json:"os"`
	Arch   string `json:"arch"`
	Format string `json:"format"`
	C2     []struct {
		Address  string `json:"address"`
		Protocol string `json:"protocol"`
	} `json:"c2"`
	Interval  int64 `json:"interval"`
	Jitter    int64 `json:"jitter"`
	MaxErrors int32 `json:"maxConnectionErrors"`
	IsBeacon  bool  `json:"is_beacon"`
	Debug     bool  `json:"debug"`
	Evasion   bool  `json:"evasion"`
	Obfuscate bool  `json:"obfuscate"`

	// OPSEC / camouflage
	HTTPC2Profile          string   `json:"http_c2_profile"`
	TrafficEncodersEnabled bool     `json:"traffic_encoders_enabled"`
	TrafficEncoders        []string `json:"traffic_encoders"`
	LimitDomainJoined      bool     `json:"limitDomainJoined"`
	LimitHostname          string   `json:"limit_hostname"`
	LimitUsername          string   `json:"limit_username"`
	LimitDatetime          string   `json:"limit_datetime"`
	LimitFileExists        string   `json:"limit_file_exists"`
	LimitLocale            string   `json:"limit_locale"`
	ConnectionStrategy     string   `json:"connection_strategy"`

	// Shellcode packaging (honest naming — not a PE crypter)
	SGNEnabled       bool   `json:"sgn_enabled"`
	ShellcodeEntropy uint32 `json:"shellcode_entropy"` // Donut: 1=none 2=names 3=names+encrypt
	ShellcodeEncoder string `json:"shellcode_encoder"` // NONE|SHIKATA_GA_NAI|XOR|XOR_DYNAMIC

	// If true and a build with the same name already exists, delete it first then generate.
	ReplaceExisting bool `json:"replace_existing"`

	// DNS canary domains (FQDNs). Implant DNS lookups here mean the binary ran.
	CanaryDomains []string `json:"canary_domains"`

	// ExternalBuilderName, when set, uses GenerateExternal + BuilderTrigger
	// (CLI `generate --external-builder`). ImplantConfig has no such field.
	ExternalBuilderName string `json:"external_builder_name"`
	Polymorph           bool   `json:"polymorph"`
}

// ImplantConfigView mirrors the relevant fields of clientpb.ImplantConfig.
type ImplantConfigView struct {
	Name                   string `json:"Name"`
	OS                     string `json:"OS"`
	Arch                   string `json:"Arch"`
	Format                 string `json:"Format"`
	Interval               int64  `json:"Interval"`
	Jitter                 int64  `json:"Jitter"`
	Obfuscate              bool   `json:"Obfuscate"`
	Debug                  bool   `json:"Debug"`
	Evasion                bool   `json:"Evasion"`
	MaxErrors              uint32 `json:"MaxConnectionErrors"`
	IsBeacon               bool   `json:"IsBeacon"`
	BeaconInt              int64  `json:"BeaconInterval"`
	BeaconJit              int64  `json:"BeaconJitter"`
	HTTPC2Profile          string `json:"HTTPC2ConfigName"`
	TrafficEncodersEnabled bool   `json:"TrafficEncodersEnabled"`
	LimitDomainJoined      bool   `json:"LimitDomainJoined"`
	LimitHostname          string `json:"LimitHostname,omitempty"`
	LimitUsername          string `json:"LimitUsername,omitempty"`
	LimitDatetime          string `json:"LimitDatetime,omitempty"`
	LimitFileExists        string `json:"LimitFileExists,omitempty"`
	LimitLocale            string `json:"LimitLocale,omitempty"`
	C2                     []struct {
		URL string `json:"URL"`
	} `json:"C2"`
	CanaryDomains []string `json:"CanaryDomains,omitempty"`
	Exports       []string `json:"Exports,omitempty"`
}

// ImplantBuildView is the JSON shape for a stored implant build.
type ImplantBuildView struct {
	Name          string             `json:"Name"`
	ImplantConfig *ImplantConfigView `json:"ImplantConfig"`
	OS            string             `json:"OS"`
	Arch          string             `json:"Arch"`
}

func configToView(c *clientpb.ImplantConfig, name string) *ImplantConfigView {
	if c == nil {
		return nil
	}
	// C2 list — start from nil, append actual URLs only
	var c2 []struct {
		URL string `json:"URL"`
	}
	for _, u := range c.C2 {
		if u == nil {
			continue
		}
		c2 = append(c2, struct {
			URL string `json:"URL"`
		}{URL: u.URL})
	}
	return &ImplantConfigView{
		Name:                   name,
		OS:                     c.GOOS,
		Arch:                   c.GOARCH,
		Format:                 c.Format.String(),
		Interval:               durationToSeconds(c.BeaconInterval),
		Jitter:                 durationToSeconds(c.BeaconJitter),
		Obfuscate:              c.ObfuscateSymbols,
		Debug:                  c.Debug,
		Evasion:                c.Evasion,
		MaxErrors:              c.MaxConnectionErrors,
		IsBeacon:               c.IsBeacon,
		BeaconInt:              durationToSeconds(c.BeaconInterval),
		BeaconJit:              durationToSeconds(c.BeaconJitter),
		HTTPC2Profile:          c.HTTPC2ConfigName,
		TrafficEncodersEnabled: c.TrafficEncodersEnabled,
		LimitDomainJoined:      c.LimitDomainJoined,
		LimitHostname:          c.LimitHostname,
		LimitUsername:          c.LimitUsername,
		LimitDatetime:          c.LimitDatetime,
		LimitFileExists:        c.LimitFileExists,
		LimitLocale:            c.LimitLocale,
		C2:                     c2,
		CanaryDomains:          append([]string{}, c.CanaryDomains...),
		Exports:                append([]string{}, c.Exports...),
	}
}

// ImplantBuilds lists stored implant builds.
func (c *Client) ImplantBuilds() ([]ImplantBuildView, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	resp, err := c.RPC.ImplantBuilds(ctx, &commonpb.Empty{})
	if err != nil {
		return nil, err
	}
	out := make([]ImplantBuildView, 0, len(resp.Configs))
	for name, cfg := range resp.Configs {
		if cfg == nil {
			continue
		}
		out = append(out, ImplantBuildView{
			Name:          name,
			ImplantConfig: configToView(cfg, name),
			OS:            cfg.GOOS,
			Arch:          cfg.GOARCH,
		})
	}
	return out, nil
}

func buildC2URL(address, protocol string) string {
	url := address
	if !strings.Contains(url, "://") {
		if protocol == "" {
			protocol = "mtls"
		}
		switch protocol {
		case "mtls":
			url = "mtls://" + url
		case "http":
			url = "http://" + url
		case "https":
			url = "https://" + url
		case "dns":
			url = "dns://" + url
		case "wireguard":
			url = "wg://" + url
		default:
			url = "mtls://" + url
		}
	}
	return url
}

// ImplantProfileView is the JSON shape of an implant profile.
type ImplantProfileView struct {
	Name   string             `json:"Name"`
	Config *ImplantConfigView `json:"Config"`
}

// ImplantProfiles lists saved implant profiles.
func (c *Client) ImplantProfiles() ([]ImplantProfileView, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	resp, err := c.RPC.ImplantProfiles(ctx, &commonpb.Empty{})
	if err != nil {
		return nil, err
	}
	out := make([]ImplantProfileView, 0, len(resp.Profiles))
	for _, p := range resp.Profiles {
		if p == nil {
			continue
		}
		out = append(out, ImplantProfileView{Name: p.Name, Config: configToView(p.Config, p.Name)})
	}
	return out, nil
}

// SaveImplantProfile saves (or updates) an implant profile.
func (c *Client) SaveImplantProfile(name string, req *GenerateRequest, isBeacon bool) error {
	if name == "" {
		return fmt.Errorf("profile name is required")
	}
	cfg := buildImplantConfig(req, isBeacon)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_, err := c.RPC.SaveImplantProfile(ctx, &clientpb.ImplantProfile{Name: name, Config: cfg})
	return err
}

// DeleteImplantProfile removes a saved implant profile.
//
// Guard: sliver-server v1.15.16's DeleteImplantProfile RPC panics (nil
// dereference in db.ProfileByName) when the named profile does not exist,
// taking the whole server down. Verify the profile exists first and never
// forward the delete RPC for an unknown name.
func (c *Client) DeleteImplantProfile(name string) error {
	profiles, err := c.ImplantProfiles()
	if err != nil {
		return err
	}
	found := false
	for _, p := range profiles {
		if p.Name == name {
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("implant profile %q not found", name)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_, err = c.RPC.DeleteImplantProfile(ctx, &clientpb.DeleteReq{Name: name})
	return err
}

// buildImplantConfig converts a GenerateRequest into a clientpb.ImplantConfig.
func buildImplantConfig(req *GenerateRequest, isBeacon bool) *clientpb.ImplantConfig {
	if req.OS == "" {
		req.OS = "windows"
	}
	if req.Arch == "" {
		req.Arch = "amd64"
	}
	if req.Interval == 0 {
		req.Interval = 60
	}

	format := clientpb.OutputFormat_EXECUTABLE
	switch strings.ToLower(req.Format) {
	case "service":
		format = clientpb.OutputFormat_SERVICE
	case "shellcode":
		format = clientpb.OutputFormat_SHELLCODE
	case "shared":
		format = clientpb.OutputFormat_SHARED_LIB
	}
	isShared := format == clientpb.OutputFormat_SHARED_LIB
	isShell := format == clientpb.OutputFormat_SHELLCODE

	httpProfile := strings.TrimSpace(req.HTTPC2Profile)
	if httpProfile == "" {
		httpProfile = "default"
	}
	strategy := strings.TrimSpace(req.ConnectionStrategy)
	if strategy == "" {
		strategy = "sequential"
	}

	cfg := &clientpb.ImplantConfig{
		GOOS:                   req.OS,
		GOARCH:                 req.Arch,
		Format:                 format,
		IsSharedLib:            isShared,
		IsShellcode:            isShell,
		Debug:                  req.Debug,
		Evasion:                req.Evasion,
		ObfuscateSymbols:       req.Obfuscate,
		IsBeacon:               isBeacon,
		BeaconInterval:         durationSeconds(req.Interval),
		BeaconJitter:           durationSeconds(req.Jitter),
		HTTPC2ConfigName:       httpProfile,
		ConnectionStrategy:     strategy,
		TrafficEncodersEnabled: req.TrafficEncodersEnabled,
		TrafficEncoders:        req.TrafficEncoders,
		LimitDomainJoined:      req.LimitDomainJoined,
		LimitHostname:          req.LimitHostname,
		LimitUsername:          req.LimitUsername,
		LimitDatetime:          req.LimitDatetime,
		LimitFileExists:        req.LimitFileExists,
		LimitLocale:            req.LimitLocale,
		SGNEnabled:             req.SGNEnabled,
		CanaryDomains:          normalizeCanaryDomains(req.CanaryDomains),
	}
	if format == clientpb.OutputFormat_SHELLCODE {
		entropy := req.ShellcodeEntropy
		if entropy == 0 {
			entropy = 2 // Donut default: random names
		}
		cfg.ShellcodeConfig = &clientpb.ShellcodeConfig{Entropy: entropy}
		if enc, err := parseShellcodeEncoder(req.ShellcodeEncoder); err == nil {
			cfg.ShellcodeEncoder = enc
			if enc == clientpb.ShellcodeEncoder_SHIKATA_GA_NAI {
				cfg.SGNEnabled = true
			}
		}
	}
	if isBeacon {
		cfg.BeaconInterval = durationSeconds(req.Interval)
		cfg.BeaconJitter = durationSeconds(req.Jitter)
	} else {
		cfg.ReconnectInterval = durationSeconds(req.Interval)
	}
	if req.MaxErrors != 0 {
		cfg.MaxConnectionErrors = uint32(req.MaxErrors)
	} else {
		cfg.MaxConnectionErrors = 1000
	}

	for _, c2 := range req.C2 {
		if c2.Address == "" {
			continue
		}
		url := buildC2URL(c2.Address, c2.Protocol)
		cfg.C2 = append(cfg.C2, &clientpb.ImplantC2{URL: url})
		switch {
		case strings.HasPrefix(url, "mtls://"):
			cfg.IncludeMTLS = true
		case strings.HasPrefix(url, "http://"), strings.HasPrefix(url, "https://"):
			cfg.IncludeHTTP = true
		case strings.HasPrefix(url, "dns://"):
			cfg.IncludeDNS = true
		case strings.HasPrefix(url, "wg://"):
			cfg.IncludeWG = true
		}
	}
	if len(cfg.C2) == 0 {
		cfg.C2 = append(cfg.C2, &clientpb.ImplantC2{URL: "mtls://127.0.0.1:8888"})
		cfg.IncludeMTLS = true
	}
	return cfg
}

// implantFileExtension returns the file extension for a built implant,
// mirroring sliver's server/generate naming rules. The stored config.Extension
// is often empty, so the extension is derived from the output format and OS.
func implantFileExtension(cfg *clientpb.ImplantConfig) string {
	switch cfg.Format {
	case clientpb.OutputFormat_SHARED_LIB:
		switch cfg.GOOS {
		case "windows":
			return ".dll"
		case "darwin":
			return ".dylib"
		default:
			return ".so"
		}
	case clientpb.OutputFormat_SHELLCODE:
		return ".bin"
	default: // EXECUTABLE
		if cfg.GOOS == "windows" {
			return ".exe"
		}
	}
	return ""
}

// ensureImplantExt appends the platform extension when the build name has none,
// so downloaded files keep a meaningful format instead of a bare name.
func ensureImplantExt(name string, cfg *clientpb.ImplantConfig) string {
	if name == "" || filepath.Ext(name) != "" {
		return name
	}
	return name + implantFileExtension(cfg)
}

// GenerateImplant generates and compiles an implant on the teamserver.
func (c *Client) GenerateImplant(req *GenerateRequest) (map[string]any, error) {
	return c.GenerateImplantWithHub(req, nil)
}

// GenerateImplantWithHub is GenerateImplant, waiting on hub when an external builder is selected.
func (c *Client) GenerateImplantWithHub(req *GenerateRequest, hub *EventHub) (map[string]any, error) {
	if req.Name == "" {
		return nil, fmt.Errorf("implant name is required")
	}
	if err := RejectDefaultHTTPC2(req); err != nil {
		return nil, err
	}
	if strings.TrimSpace(req.ExternalBuilderName) != "" {
		return c.generateExternalImplant(req, hub)
	}
	cfg := buildImplantConfig(req, req.IsBeacon)

	if req.ReplaceExisting {
		if err := c.deleteBuildIfExists(req.Name); err != nil {
			return nil, fmt.Errorf("replace existing: %w", err)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	resp, err := c.RPC.Generate(ctx, &clientpb.GenerateReq{Config: cfg, Name: req.Name})
	if err != nil {
		return nil, mapGenerateError(req.Name, err)
	}
	var raw []byte
	var data string
	if resp.File != nil {
		raw = resp.File.Data
		data = base64.StdEncoding.EncodeToString(raw)
	}
	name := ensureImplantExt(resp.File.Name, cfg)
	out := map[string]any{
		"success": true,
		"message": fmt.Sprintf("built %s (%s/%s)", name, req.OS, req.Arch),
		"name":    name,
		"data":    data,
	}
	attachArtifactHash(out, name, raw)
	return out, nil
}

func normalizeCanaryDomains(in []string) []string {
	out := make([]string, 0, len(in))
	seen := map[string]struct{}{}
	for _, raw := range in {
		for _, part := range strings.Split(raw, ",") {
			d := strings.ToLower(strings.TrimSpace(part))
			d = strings.TrimPrefix(d, "dns://")
			d = strings.TrimSuffix(d, ".")
			if d == "" {
				continue
			}
			if _, ok := seen[d]; ok {
				continue
			}
			seen[d] = struct{}{}
			out = append(out, d)
		}
	}
	return out
}

// deleteBuildIfExists removes a prior build so Generate can reuse the name.
// Sliver stores the build map key without requiring an extension match; try
// the bare name and common filename forms.
func (c *Client) deleteBuildIfExists(name string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil
	}
	candidates := []string{name}
	base := strings.TrimSuffix(name, filepath.Ext(name))
	if base != "" && base != name {
		candidates = append(candidates, base)
	}
	for _, ext := range []string{".exe", ".bin", ".dll", ".so", ".dylib", ".svc"} {
		candidates = append(candidates, base+ext)
	}

	builds, err := c.ImplantBuilds()
	if err != nil {
		return err
	}
	existing := map[string]struct{}{}
	for _, b := range builds {
		if b.Name != "" {
			existing[b.Name] = struct{}{}
		}
	}
	seen := map[string]struct{}{}
	for _, cand := range candidates {
		if _, ok := seen[cand]; ok {
			continue
		}
		seen[cand] = struct{}{}
		if _, ok := existing[cand]; !ok {
			continue
		}
		if err := c.DeleteImplantBuild(cand); err != nil {
			return fmt.Errorf("delete build %q: %w", cand, err)
		}
	}
	return nil
}

func mapGenerateError(name string, err error) error {
	if err == nil {
		return nil
	}
	msg := err.Error()
	lower := strings.ToLower(msg)
	if strings.Contains(lower, "unique constraint") || strings.Contains(lower, "implant_builds.name") {
		return fmt.Errorf(
			"build name %q already exists on the Sliver server — rename the implant, enable “Replace existing”, or delete the old build and retry",
			name,
		)
	}
	return err
}

// KillSession sends a kill command to the implant.
// Sliver v1.15.16 没有 KillSession RPC 方法 — 服务端在 implant
// 断开后自动清理 session 记录，无需显式调用。
func (c *Client) KillSession(id string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_, err := c.RPC.Kill(ctx, &cpmfczjv.KillReq{
		Force: true,
		Request: &commonpb.Request{
			SessionID: id,
		},
	})
	return err
}

// CompilerTargetView is the JSON shape of a compiler build target.
type CompilerTargetView struct {
	GOOS   string `json:"GOOS"`
	GOARCH string `json:"GOARCH"`
	Format string `json:"Format"`
}

// CrossCompilerView is the JSON shape of an installed cross-compiler.
type CrossCompilerView struct {
	TargetGOOS   string `json:"TargetGOOS"`
	TargetGOARCH string `json:"TargetGOARCH"`
	CCPath       string `json:"CCPath"`
	CXXPath      string `json:"CXXPath"`
}

// CompilerView is the JSON shape returned by GetCompiler.
type CompilerView struct {
	GOOS           string               `json:"GOOS"`
	GOARCH         string               `json:"GOARCH"`
	Targets        []CompilerTargetView `json:"Targets"`
	CrossCompilers []CrossCompilerView  `json:"CrossCompilers"`
}

// CompilerInfo fetches the Sliver server's compiler targets and cross-compilers.
func (c *Client) CompilerInfo() (*CompilerView, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	resp, err := c.RPC.GetCompiler(ctx, &commonpb.Empty{})
	if err != nil {
		return nil, err
	}
	v := &CompilerView{GOOS: resp.GOOS, GOARCH: resp.GOARCH}
	for _, t := range resp.Targets {
		if t == nil {
			continue
		}
		v.Targets = append(v.Targets, CompilerTargetView{
			GOOS:   t.GOOS,
			GOARCH: t.GOARCH,
			Format: t.Format.String(),
		})
	}
	for _, cc := range resp.CrossCompilers {
		if cc == nil {
			continue
		}
		v.CrossCompilers = append(v.CrossCompilers, CrossCompilerView{
			TargetGOOS:   cc.TargetGOOS,
			TargetGOARCH: cc.TargetGOARCH,
			CCPath:       cc.CCPath,
			CXXPath:      cc.CXXPath,
		})
	}
	return v, nil
}
