package sliver

import "testing"

func TestSpoofMetadataRequiresSelectorAndPE(t *testing.T) {
	c := &Client{}
	if err := c.GenerateSpoofMetadata(nil); err == nil {
		t.Fatal("nil req")
	}
	if err := c.GenerateSpoofMetadata(&SpoofMetadataRequest{}); err == nil {
		t.Fatal("empty selector")
	}
	if err := c.GenerateSpoofMetadata(&SpoofMetadataRequest{ImplantName: "x"}); err == nil {
		t.Fatal("missing source")
	}
	if err := c.GenerateSpoofMetadata(&SpoofMetadataRequest{ImplantName: "x", SourceB64: "!!!"}); err == nil {
		t.Fatal("bad b64")
	}
}

func TestExternalEventMatch(t *testing.T) {
	buildID := "abc"
	match := func(ev EventView) (implantName, failMsg string, done bool) {
		raw, _ := ev.Data["raw"].(string)
		switch ev.Type {
		case externalFailedEvent:
			if len(raw) > len(buildID)+1 && raw[:len(buildID)] == buildID && raw[len(buildID)] == ':' {
				return "", raw[len(buildID)+1:], true
			}
		case externalCompletedEvent:
			if len(raw) > len(buildID)+1 && raw[:len(buildID)] == buildID && raw[len(buildID)] == ':' {
				return raw[len(buildID)+1:], "", true
			}
		}
		return "", "", false
	}
	name, fail, done := match(EventView{Type: externalCompletedEvent, Data: map[string]any{"raw": "abc:OneDrive.exe"}})
	if !done || fail != "" || name != "OneDrive.exe" {
		t.Fatalf("complete: %q %q %v", name, fail, done)
	}
	_, fail, done = match(EventView{Type: externalFailedEvent, Data: map[string]any{"raw": "abc:boom"}})
	if !done || fail != "boom" {
		t.Fatalf("fail: %q %v", fail, done)
	}
	_, _, done = match(EventView{Type: externalCompletedEvent, Data: map[string]any{"raw": "other:x"}})
	if done {
		t.Fatal("other build should not match")
	}
}
