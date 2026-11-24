package sliver

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/bishopfox/sliver/protobuf/clientpb"
)

const (
	externalFailedEvent    = "external-build-failed"
	externalCompletedEvent = "external-build-completed"
	externalWaitTimeout    = 3 * time.Minute
)

// generateExternalImplant mirrors CLI `generate --external-builder`:
// GenerateExternal, wait for builder events, then Regenerate to fetch the file.
func (c *Client) generateExternalImplant(req *GenerateRequest, hub *EventHub) (map[string]any, error) {
	builder := strings.TrimSpace(req.ExternalBuilderName)
	if builder == "" {
		return nil, fmt.Errorf("external builder name is required")
	}
	cfg := buildImplantConfig(req, req.IsBeacon)
	if req.ReplaceExisting {
		if err := c.deleteBuildIfExists(req.Name); err != nil {
			return nil, fmt.Errorf("replace existing: %w", err)
		}
	}

	var subID int
	var ch <-chan EventView
	if hub != nil {
		subID, ch = hub.Subscribe()
		defer hub.Unsubscribe(subID)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	ext, err := c.RPC.GenerateExternal(ctx, &clientpb.ExternalGenerateReq{
		Name:        req.Name,
		Config:      cfg,
		BuilderName: builder,
	})
	if err != nil {
		return nil, mapGenerateError(req.Name, err)
	}
	buildID := ""
	if ext != nil && ext.Build != nil {
		buildID = ext.Build.ID
	}
	if buildID == "" {
		return nil, fmt.Errorf("external builder %q did not return a build id", builder)
	}

	if hub == nil || ch == nil {
		return map[string]any{
			"success":  true,
			"pending":  true,
			"build_id": buildID,
			"name":     req.Name,
			"message":  fmt.Sprintf("submitted to external builder %s (build %s); reconnect to wait for completion", builder, buildID),
		}, nil
	}

	match := func(ev EventView) (implantName, failMsg string, done bool) {
		raw, _ := ev.Data["raw"].(string)
		switch ev.Type {
		case externalFailedEvent:
			parts := strings.SplitN(raw, ":", 2)
			if len(parts) == 2 && parts[0] == buildID {
				return "", parts[1], true
			}
		case externalCompletedEvent:
			parts := strings.SplitN(raw, ":", 2)
			if len(parts) == 2 && parts[0] == buildID {
				return parts[1], "", true
			}
		}
		return "", "", false
	}

	waitCtx, waitCancel := context.WithTimeout(context.Background(), externalWaitTimeout)
	defer waitCancel()

	for _, ev := range hub.Snapshot() {
		if name, fail, done := match(ev); done {
			if fail != "" {
				return nil, fmt.Errorf("external build failed: %s", fail)
			}
			return c.regenerateAsGenerate(name, req)
		}
	}

	for {
		select {
		case <-waitCtx.Done():
			return nil, fmt.Errorf("timed out waiting for external builder %q (build %s)", builder, buildID)
		case ev, ok := <-ch:
			if !ok {
				return nil, fmt.Errorf("event hub closed while waiting for external builder %q", builder)
			}
			if name, fail, done := match(ev); done {
				if fail != "" {
					return nil, fmt.Errorf("external build failed: %s", fail)
				}
				return c.regenerateAsGenerate(name, req)
			}
		}
	}
}

func (c *Client) regenerateAsGenerate(name string, req *GenerateRequest) (map[string]any, error) {
	if name == "" {
		name = req.Name
	}
	res, err := c.Regenerate(name)
	if err != nil {
		return nil, err
	}
	out := map[string]any{
		"success": true,
		"message": fmt.Sprintf("external builder finished %s (%s/%s)", res.Name, req.OS, req.Arch),
		"name":    res.Name,
		"data":    res.Data,
	}
	if res.SHA256 != "" {
		out["sha256"] = res.SHA256
	}
	if res.CollisionWith != "" {
		out["collision_with"] = res.CollisionWith
	}
	return out, nil
}

// SpoofMetadataRequest is the JSON body for GenerateSpoofMetadata.
// This clones PE resources from a donor binary — it is not an AV bypass.
type SpoofMetadataRequest struct {
	ImplantName    string `json:"implant_name"`
	ImplantBuildID string `json:"implant_build_id"`
	SourceName     string `json:"source_name"`
	SourceB64      string `json:"source_b64"`
	IconName       string `json:"icon_name"`
	IconB64        string `json:"icon_b64"`
}

// GenerateSpoofMetadata applies donor PE resources/timestamps to an existing Windows build.
func (c *Client) GenerateSpoofMetadata(req *SpoofMetadataRequest) error {
	if req == nil {
		return fmt.Errorf("request is required")
	}
	name := strings.TrimSpace(req.ImplantName)
	buildID := strings.TrimSpace(req.ImplantBuildID)
	if name == "" && buildID == "" {
		return fmt.Errorf("implant_name or implant_build_id is required")
	}
	src, err := decodeOptionalB64(req.SourceB64)
	if err != nil {
		return fmt.Errorf("invalid source_b64: %w", err)
	}
	if len(src) == 0 {
		return fmt.Errorf("source PE is required")
	}
	srcName := strings.TrimSpace(req.SourceName)
	if srcName == "" {
		srcName = "donor.exe"
	}
	pe := &clientpb.PESpoofMetadataConfig{
		Source: &clientpb.SpoofMetadataFile{Name: srcName, Data: src},
	}
	if icon, err := decodeOptionalB64(req.IconB64); err != nil {
		return fmt.Errorf("invalid icon_b64: %w", err)
	} else if len(icon) > 0 {
		iconName := strings.TrimSpace(req.IconName)
		if iconName == "" {
			iconName = "icon.ico"
		}
		pe.Icon = &clientpb.SpoofMetadataFile{Name: iconName, Data: icon}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	_, err = c.RPC.GenerateSpoofMetadata(ctx, &clientpb.GenerateSpoofMetadataReq{
		ImplantBuildID: buildID,
		ImplantName:    name,
		SpoofMetadata:  &clientpb.SpoofMetadataConfig{PE: pe},
	})
	return err
}
