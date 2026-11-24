package sliver

import (
	"errors"
	"strings"
)

// ErrDefaultHTTPC2 is returned when HTTP(S) generate still uses the public
// default URI fingerprint (name "default" or empty).
var ErrDefaultHTTPC2 = errors.New("http/https generate requires a non-default HTTP C2 profile")

// Default HTTP C2 IOCs from Sliver's own HTTPS C2 docs and the 1.7.3
// GenerateDefaultHTTPC2Config snapshot: stager .woff, poll .js, session
// .php, close .png, nonce length 1, profile name "default".
var defaultCookieIOCs = []string{"jsessionid", "rememberme"}

// HTTPC2Fingerprint is an honest "still looks like default Sliver" check.
type HTTPC2Fingerprint struct {
	LooksDefault bool     `json:"looks_default"`
	Reasons      []string `json:"reasons"`
}

func normalizeExt(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	return strings.TrimPrefix(s, ".")
}

func extSet(exts []string) map[string]bool {
	out := make(map[string]bool, len(exts))
	for _, e := range exts {
		out[normalizeExt(e)] = true
	}
	return out
}

// AnalyzeHTTPC2Fingerprint compares a profile to documented Sliver defaults.
// It never claims AV/VT scores — only public-detector similarity.
func AnalyzeHTTPC2Fingerprint(name string, extensions []string, nonce int32, userAgent string, cookies []string) HTTPC2Fingerprint {
	reasons := make([]string, 0, 6)
	set := extSet(extensions)
	has := func(x string) bool { return set[x] }

	if strings.EqualFold(strings.TrimSpace(name), "default") {
		reasons = append(reasons, "profile name is default")
	}
	if nonce == 1 {
		reasons = append(reasons, "nonce query length is 1")
	}
	if has("woff") && has("php") && has("png") {
		reasons = append(reasons, "extensions still include .woff, .php, and .png")
	}
	if has("php") && has("js") && has("") {
		reasons = append(reasons, "extensions still include .js, empty, and .php (1.7 default)")
	}
	if strings.TrimSpace(userAgent) == "" {
		reasons = append(reasons, "user-agent is empty (server fills the Sliver default)")
	}
	cookieHits := 0
	for _, c := range cookies {
		cl := strings.ToLower(strings.TrimSpace(c))
		for _, ioc := range defaultCookieIOCs {
			if cl == ioc {
				cookieHits++
			}
		}
	}
	if cookieHits >= 2 {
		reasons = append(reasons, "cookies still include JSESSIONID and rememberMe")
	}

	looks := false
	if has("woff") && has("php") && has("png") && nonce == 1 {
		looks = true
	}
	if nonce == 1 && has("php") && has("js") {
		looks = true
	}
	if strings.EqualFold(strings.TrimSpace(name), "default") && nonce == 1 {
		looks = true
	}
	return HTTPC2Fingerprint{LooksDefault: looks, Reasons: reasons}
}

func c2UsesHTTP(req *GenerateRequest) bool {
	if req == nil {
		return false
	}
	for _, c := range req.C2 {
		p := strings.ToLower(strings.TrimSpace(c.Protocol))
		if p == "http" || p == "https" {
			return true
		}
	}
	return false
}

// RejectDefaultHTTPC2 blocks HTTP(S) implants that still use the stock
// "default" profile (public .woff/.js/.php fingerprint).
func RejectDefaultHTTPC2(req *GenerateRequest) error {
	if !c2UsesHTTP(req) {
		return nil
	}
	name := strings.TrimSpace(req.HTTPC2Profile)
	if name == "" || strings.EqualFold(name, "default") {
		return ErrDefaultHTTPC2
	}
	return nil
}
