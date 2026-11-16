package sliver

import "testing"

func TestAnalyzeHTTPC2FingerprintClassicDefault(t *testing.T) {
	fp := AnalyzeHTTPC2Fingerprint("default", []string{".woff", ".php", ".png", ".js", ".html"}, 1, "", []string{"JSESSIONID", "rememberMe"})
	if !fp.LooksDefault {
		t.Fatalf("classic default should look like Sliver, reasons=%v", fp.Reasons)
	}
	if len(fp.Reasons) < 3 {
		t.Fatalf("expected several reasons, got %v", fp.Reasons)
	}
}

func TestAnalyzeHTTPC2Fingerprint17Default(t *testing.T) {
	fp := AnalyzeHTTPC2Fingerprint("default", []string{"js", "", "php"}, 1, "", nil)
	if !fp.LooksDefault {
		t.Fatalf("1.7 default extensions should look like Sliver, reasons=%v", fp.Reasons)
	}
}

func TestAnalyzeHTTPC2FingerprintCustomTemplate(t *testing.T) {
	fp := AnalyzeHTTPC2Fingerprint("ms-update", []string{".cab", ".exe", ".ps1"}, 8, "Microsoft-Delivery-Optimization/10.0", []string{"do-session"})
	if fp.LooksDefault {
		t.Fatalf("custom template flagged as default: %v", fp.Reasons)
	}
}

func TestAnalyzeHTTPC2FingerprintJquery(t *testing.T) {
	fp := AnalyzeHTTPC2Fingerprint("jquery-cdn", []string{".js", ".css", ".map"}, 6, "Mozilla/5.0", []string{"csrftoken"})
	if fp.LooksDefault {
		t.Fatalf("jquery-cdn flagged as default: %v", fp.Reasons)
	}
}

func TestRejectDefaultHTTPC2(t *testing.T) {
	c2 := func(proto string) []struct {
		Address  string `json:"address"`
		Protocol string `json:"protocol"`
	} {
		return []struct {
			Address  string `json:"address"`
			Protocol string `json:"protocol"`
		}{{Address: "h:1", Protocol: proto}}
	}
	https := GenerateRequest{HTTPC2Profile: "default", C2: c2("https")}
	if err := RejectDefaultHTTPC2(&https); err != ErrDefaultHTTPC2 {
		t.Fatalf("default https: %v", err)
	}
	https.HTTPC2Profile = ""
	if err := RejectDefaultHTTPC2(&https); err != ErrDefaultHTTPC2 {
		t.Fatalf("empty https: %v", err)
	}
	https.HTTPC2Profile = "ms-update"
	if err := RejectDefaultHTTPC2(&https); err != nil {
		t.Fatalf("ms-update: %v", err)
	}
	mtls := GenerateRequest{HTTPC2Profile: "", C2: c2("mtls")}
	if err := RejectDefaultHTTPC2(&mtls); err != nil {
		t.Fatalf("mtls empty profile: %v", err)
	}
}
