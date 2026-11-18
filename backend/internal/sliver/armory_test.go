package sliver

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func seedArmoryCache(pkgs []ArmoryPackageView) {
	armoryMu.Lock()
	armoryCache = &ArmoryIndexView{Packages: pkgs}
	armoryUntil = time.Now().Add(time.Hour)
	armoryMu.Unlock()
}

func TestParseArmoryReleasesArray(t *testing.T) {
	body, _ := json.Marshal([]githubRelease{{
		TagName: "v1",
		Assets:  []githubAsset{{Name: "armory.json", BrowserDownloadURL: "http://x/armory.json"}},
	}})
	rels, err := parseArmoryReleases(body)
	if err != nil {
		t.Fatal(err)
	}
	if len(rels) != 1 || rels[0].TagName != "v1" {
		t.Fatalf("got %+v", rels)
	}
}

func TestParseArmoryReleasesObject(t *testing.T) {
	body, _ := json.Marshal(githubRelease{TagName: "v2", Assets: []githubAsset{{Name: "armory.json"}}})
	rels, err := parseArmoryReleases(body)
	if err != nil {
		t.Fatal(err)
	}
	if rels[0].TagName != "v2" {
		t.Fatalf("tag = %s", rels[0].TagName)
	}
}

func TestGithubLatestTag(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/org/pkg/releases/latest" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Location", "https://github.com/org/pkg/releases/tag/v9.9.9")
		w.WriteHeader(http.StatusFound)
	}))
	t.Cleanup(srv.Close)
	prev := ArmoryHTTP
	ArmoryHTTP = srv.Client()
	t.Cleanup(func() { ArmoryHTTP = prev })

	tag, err := githubLatestTag(srv.URL + "/org/pkg")
	if err != nil {
		t.Fatal(err)
	}
	if tag != "v9.9.9" {
		t.Fatalf("tag = %s", tag)
	}
}

func TestFindArmoryPackageUsesCache(t *testing.T) {
	resetArmoryCacheForTest()
	seedArmoryCache([]ArmoryPackageView{
		{Name: "Rubeus", CommandName: "rubeus", Kind: "alias"},
	})
	p, err := findArmoryPackage("rubeus")
	if err != nil {
		t.Fatal(err)
	}
	if p.Name != "Rubeus" {
		t.Fatalf("name = %s", p.Name)
	}
	if _, err := findArmoryPackage("missing"); err == nil {
		t.Fatal("expected missing package error")
	}
}

func TestArmoryInstallRejectsExtension(t *testing.T) {
	resetArmoryCacheForTest()
	seedArmoryCache([]ArmoryPackageView{
		{Name: "COFFLoader", CommandName: "coff-loader", Kind: "extension"},
	})
	_, err := ArmoryInstallAlias("coff-loader")
	if err == nil {
		t.Fatal("expected error installing extension as alias")
	}
}
