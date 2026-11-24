package sliver

import (
	"testing"
)

func TestBuildImplantConfigBeaconDurations(t *testing.T) {
	cfg := buildImplantConfig(&GenerateRequest{
		OS:       "windows",
		Arch:     "amd64",
		Format:   "shellcode",
		IsBeacon: true,
		Interval: 60,
		Jitter:   20,
	}, true)
	wantI := durationSeconds(60)
	wantJ := durationSeconds(20)
	if cfg.BeaconInterval != wantI || cfg.BeaconJitter != wantJ {
		t.Fatalf("beacon duration = %d/%d, want %d/%d (nanoseconds)", cfg.BeaconInterval, cfg.BeaconJitter, wantI, wantJ)
	}
	view := configToView(cfg, "lab")
	if view.Interval != 60 || view.Jitter != 20 || view.BeaconInt != 60 || view.BeaconJit != 20 {
		t.Fatalf("view still in nanos: %+v", view)
	}
}

func TestBuildImplantConfigSessionReconnect(t *testing.T) {
	cfg := buildImplantConfig(&GenerateRequest{OS: "windows", Interval: 45, IsBeacon: false}, false)
	if cfg.ReconnectInterval != durationSeconds(45) {
		t.Fatalf("reconnect = %d", cfg.ReconnectInterval)
	}
}

func TestBuildC2URL_WithScheme(t *testing.T) {
	cases := []struct {
		addr string
		want string
	}{
		{"mtls://1.2.3.4:8888", "mtls://1.2.3.4:8888"},
		{"https://example.com", "https://example.com"},
		{"dns://dns.example.com", "dns://dns.example.com"},
	}
	for _, tc := range cases {
		if got := buildC2URL(tc.addr, ""); got != tc.want {
			t.Errorf("buildC2URL(%q) = %q, want %q", tc.addr, got, tc.want)
		}
	}
}

func TestNormalizeCanaryDomains(t *testing.T) {
	got := normalizeCanaryDomains([]string{" Example.COM.", "dns://foo.net", "example.com", " bar.org,baz.org "})
	want := []string{"example.com", "foo.net", "bar.org", "baz.org"}
	if len(got) != len(want) {
		t.Fatalf("got %v want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v want %v", got, want)
		}
	}
}

func TestBuildC2URL_WithoutScheme(t *testing.T) {
	cases := []struct {
		addr     string
		protocol string
		want     string
	}{
		{"1.2.3.4:8888", "mtls", "mtls://1.2.3.4:8888"},
		{"example.com:443", "https", "https://example.com:443"},
		{"1.2.3.4:80", "http", "http://1.2.3.4:80"},
		{"dns.example.com", "dns", "dns://dns.example.com"},
		{"1.2.3.4", "wireguard", "wg://1.2.3.4"},
		{"1.2.3.4:8888", "", "mtls://1.2.3.4:8888"},
		{"1.2.3.4:8888", "unknown", "mtls://1.2.3.4:8888"},
	}
	for _, tc := range cases {
		if got := buildC2URL(tc.addr, tc.protocol); got != tc.want {
			t.Errorf("buildC2URL(%q, %q) = %q, want %q", tc.addr, tc.protocol, got, tc.want)
		}
	}
}
