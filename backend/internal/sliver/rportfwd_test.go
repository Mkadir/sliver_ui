package sliver

import "testing"

func TestNormalizeRportFwdAddr(t *testing.T) {
	if got := normalizeRportFwdAddr("8080", ""); got != ":8080" {
		t.Fatalf("bind port-only = %q", got)
	}
	if got := normalizeRportFwdAddr("22", "127.0.0.1"); got != "127.0.0.1:22" {
		t.Fatalf("fwd port-only = %q", got)
	}
	if got := normalizeRportFwdAddr("0.0.0.0:4444", ""); got != "0.0.0.0:4444" {
		t.Fatalf("full = %q", got)
	}
}

func TestRportFwdStartRequestAddrs(t *testing.T) {
	r := RportFwdStartRequest{Bind: "8080", Remote: "22"}
	if r.bindAddr() != ":8080" {
		t.Fatalf("bind = %q", r.bindAddr())
	}
	if r.forwardAddr() != "127.0.0.1:22" {
		t.Fatalf("fwd = %q", r.forwardAddr())
	}

	r = RportFwdStartRequest{BindHost: "", BindPort: 9000, ForwardHost: "10.0.0.1", ForwardPort: 445}
	if r.bindAddr() != ":9000" {
		t.Fatalf("bind host/port = %q", r.bindAddr())
	}
	if r.forwardAddr() != "10.0.0.1:445" {
		t.Fatalf("fwd host/port = %q", r.forwardAddr())
	}
}

func TestSessionLooksDNS(t *testing.T) {
	if !sessionLooksDNS("dns://example.com") {
		t.Fatal("dns://")
	}
	if sessionLooksDNS("mtls://10.0.0.1:8888") {
		t.Fatal("mtls should not look like dns")
	}
}
