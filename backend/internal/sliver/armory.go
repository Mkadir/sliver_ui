package sliver

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/bishopfox/sliver/util/minisign"
)

// Official Sliver armory (Makefile ldflags in BishopFox/sliver).
const (
	DefaultArmoryPublicKey = "RWSBpxpRWDrD7Fe+VvRE3c2VEDC2NK80rlNCj+BX0gz44Xw07r6KQD9L"
	DefaultArmoryRepoURL   = "https://api.github.com/repos/sliverarmory/armory/releases"
)

const armoryCacheTTL = 2 * time.Minute

// ArmoryPackageView is one alias or extension from the armory index.
type ArmoryPackageView struct {
	Name        string `json:"name"`
	CommandName string `json:"command_name"`
	RepoURL     string `json:"repo_url"`
	PublicKey   string `json:"public_key"`
	Kind        string `json:"kind"` // "alias" | "extension"
}

// ArmoryIndexView is the JSON returned by GET /api/armory.
type ArmoryIndexView struct {
	Source    string              `json:"source"`
	FetchedAt int64               `json:"fetched_at"`
	Packages  []ArmoryPackageView `json:"packages"`
}

type armoryIndexFile struct {
	Aliases    []ArmoryPackageView `json:"aliases"`
	Extensions []ArmoryPackageView `json:"extensions"`
}

type githubAsset struct {
	Name               string `json:"name"`
	URL                string `json:"url"`
	BrowserDownloadURL string `json:"browser_download_url"`
}

type githubRelease struct {
	TagName string        `json:"tag_name"`
	Assets  []githubAsset `json:"assets"`
}

var (
	armoryMu    sync.Mutex
	armoryCache *ArmoryIndexView
	armoryUntil time.Time
)

// ArmoryHTTP is swapped in tests.
var ArmoryHTTP = &http.Client{Timeout: 45 * time.Second}

var errArmorySig = errors.New("armory signature verification failed")

func armoryGET(rawURL string, accept string) ([]byte, int, error) {
	req, err := http.NewRequest(http.MethodGet, rawURL, http.NoBody)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("User-Agent", "sliver-ui")
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	resp, err := ArmoryHTTP.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	return body, resp.StatusCode, err
}

func armoryDownload(rawURL string) ([]byte, error) {
	body, code, err := armoryGET(rawURL, "application/octet-stream")
	if err != nil {
		return nil, err
	}
	if code != http.StatusOK && code != http.StatusFound {
		if code == http.StatusForbidden {
			return nil, errors.New("GitHub API rate limit (60 req/hr); try later")
		}
		return nil, fmt.Errorf("download %s: HTTP %d", rawURL, code)
	}
	return body, nil
}

func assetURL(a githubAsset) string {
	if a.BrowserDownloadURL != "" {
		return a.BrowserDownloadURL
	}
	return a.URL
}

func verifyMinisign(pubText string, message, sigBytes []byte) error {
	var pk minisign.PublicKey
	if err := pk.UnmarshalText([]byte(pubText)); err != nil {
		return fmt.Errorf("armory public key: %w", err)
	}
	if !minisign.Verify(pk, message, sigBytes) {
		return errArmorySig
	}
	return nil
}

func parseArmoryReleases(body []byte) ([]githubRelease, error) {
	var many []githubRelease
	if err := json.Unmarshal(body, &many); err == nil && len(many) > 0 {
		return many, nil
	}
	var one githubRelease
	if err := json.Unmarshal(body, &one); err != nil {
		return nil, err
	}
	if len(one.Assets) == 0 {
		return nil, errors.New("no armory releases found")
	}
	return []githubRelease{one}, nil
}

func fetchArmoryIndexUncached() (*ArmoryIndexView, error) {
	body, code, err := armoryGET(DefaultArmoryRepoURL, "application/vnd.github+json")
	if err != nil {
		return nil, err
	}
	if code == http.StatusForbidden {
		return nil, errors.New("GitHub API rate limit (60 req/hr); try later")
	}
	if code != http.StatusOK {
		return nil, fmt.Errorf("armory index: HTTP %d", code)
	}
	releases, err := parseArmoryReleases(body)
	if err != nil {
		return nil, err
	}
	rel := releases[0]
	var indexData, sigData []byte
	for _, a := range rel.Assets {
		switch a.Name {
		case "armory.json":
			indexData, err = armoryDownload(assetURL(a))
			if err != nil {
				return nil, err
			}
		case "armory.minisig":
			sigData, err = armoryDownload(assetURL(a))
			if err != nil {
				return nil, err
			}
		}
	}
	if len(indexData) == 0 {
		return nil, errors.New("armory.json missing from latest release")
	}
	if err := verifyMinisign(DefaultArmoryPublicKey, indexData, sigData); err != nil {
		return nil, err
	}
	var file armoryIndexFile
	if err := json.Unmarshal(indexData, &file); err != nil {
		return nil, err
	}
	pkgs := make([]ArmoryPackageView, 0, len(file.Aliases)+len(file.Extensions))
	for _, p := range file.Aliases {
		p.Kind = "alias"
		pkgs = append(pkgs, p)
	}
	for _, p := range file.Extensions {
		p.Kind = "extension"
		pkgs = append(pkgs, p)
	}
	return &ArmoryIndexView{
		Source:    DefaultArmoryRepoURL,
		FetchedAt: time.Now().Unix(),
		Packages:  pkgs,
	}, nil
}

// ArmoryIndex fetches (and caches) the signed official armory catalog.
func ArmoryIndex() (*ArmoryIndexView, error) {
	armoryMu.Lock()
	if armoryCache != nil && time.Now().Before(armoryUntil) {
		v := *armoryCache
		armoryMu.Unlock()
		return &v, nil
	}
	armoryMu.Unlock()

	view, err := fetchArmoryIndexUncached()
	if err != nil {
		return nil, err
	}
	armoryMu.Lock()
	armoryCache = view
	armoryUntil = time.Now().Add(armoryCacheTTL)
	armoryMu.Unlock()
	return view, nil
}

func findArmoryPackage(commandName string) (*ArmoryPackageView, error) {
	idx, err := ArmoryIndex()
	if err != nil {
		return nil, err
	}
	want := strings.ToLower(strings.TrimSpace(commandName))
	for i := range idx.Packages {
		p := &idx.Packages[i]
		if strings.EqualFold(p.CommandName, want) || strings.EqualFold(p.Name, want) {
			return p, nil
		}
	}
	return nil, fmt.Errorf("armory package %q not found", commandName)
}

func githubLatestTag(repoURL string) (string, error) {
	u, err := url.Parse(repoURL)
	if err != nil {
		return "", err
	}
	u.Path = path.Join(u.Path, "releases", "latest")
	client := *ArmoryHTTP
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}
	req, err := http.NewRequest(http.MethodGet, u.String(), http.NoBody)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "sliver-ui")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound && resp.StatusCode != http.StatusMovedPermanently {
		return "", fmt.Errorf("latest tag redirect: HTTP %d", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	if loc == "" {
		return "", errors.New("latest tag: missing Location")
	}
	lu, err := url.Parse(loc)
	if err != nil {
		return "", err
	}
	parts := strings.Split(strings.Trim(lu.Path, "/"), "/")
	for i, p := range parts {
		if p == "tag" && i+1 < len(parts) {
			return parts[i+1], nil
		}
	}
	return "", errors.New("latest tag not found in Location")
}

func downloadGithubPackage(pkg *ArmoryPackageView) ([]byte, error) {
	tag, err := githubLatestTag(pkg.RepoURL)
	if err != nil {
		return nil, err
	}
	base, err := url.Parse(pkg.RepoURL)
	if err != nil {
		return nil, err
	}
	tarURL := *base
	tarURL.Path = path.Join(base.Path, "releases", "download", tag, pkg.CommandName+".tar.gz")
	sigURL := *base
	sigURL.Path = path.Join(base.Path, "releases", "download", tag, pkg.CommandName+".minisig")

	tarGz, err := armoryDownload(tarURL.String())
	if err != nil {
		return nil, err
	}
	sigBytes, err := armoryDownload(sigURL.String())
	if err != nil {
		return nil, err
	}
	if err := verifyMinisign(pkg.PublicKey, tarGz, sigBytes); err != nil {
		return nil, err
	}
	return tarGz, nil
}

// ArmoryInstallAlias downloads a Minisign-verified alias bundle and installs
// it into this process's aliases/ directory. Extensions are not installed
// here (they need a live session JgkiqfwfCnhefgsqp). Installs are client-local.
func ArmoryInstallAlias(commandName string) (*AliasView, error) {
	pkg, err := findArmoryPackage(commandName)
	if err != nil {
		return nil, err
	}
	if pkg.Kind != "alias" {
		return nil, fmt.Errorf("%q is an extension; this UI only installs aliases into aliases/. Use a session → Extensions to register a BOF", pkg.CommandName)
	}
	host := ""
	if u, err := url.Parse(pkg.RepoURL); err == nil {
		host = u.Hostname()
	}
	if host != "github.com" && host != "www.github.com" {
		return nil, fmt.Errorf("unsupported armory package host %q", host)
	}
	tarGz, err := downloadGithubPackage(pkg)
	if err != nil {
		return nil, err
	}
	return InstallAlias(base64.StdEncoding.EncodeToString(tarGz))
}

func resetArmoryCacheForTest() {
	armoryMu.Lock()
	armoryCache = nil
	armoryUntil = time.Time{}
	armoryMu.Unlock()
}
