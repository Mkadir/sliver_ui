package sliver

import (
	"context"
	"fmt"
	"time"

	"github.com/bishopfox/sliver/protobuf/clientpb"
	"github.com/bishopfox/sliver/protobuf/commonpb"
)

// HTTPC2ProfileView is a JSON-friendly HTTP C2 profile summary / full document.
type HTTPC2ProfileView struct {
	Name          string         `json:"name"`
	Created       int64          `json:"created,omitempty"`
	ServerConfig  map[string]any `json:"server_config,omitempty"`
	ImplantConfig map[string]any `json:"implant_config,omitempty"`
	Raw           any            `json:"raw,omitempty"`
}

// ListHTTPC2Profiles returns HTTP C2 profiles known to the Sliver server.
func (c *Client) ListHTTPC2Profiles() ([]HTTPC2ProfileView, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	resp, err := c.RPC.GetHTTPC2Profiles(ctx, &commonpb.Empty{})
	if err != nil {
		return nil, err
	}
	out := make([]HTTPC2ProfileView, 0, len(resp.Configs))
	for _, cfg := range resp.Configs {
		if cfg == nil {
			continue
		}
		out = append(out, summarizeHTTPC2(cfg))
	}
	return out, nil
}

// GetHTTPC2Profile returns one profile by name (includes full nested config).
func (c *Client) GetHTTPC2Profile(name string) (*HTTPC2ProfileView, error) {
	if name == "" {
		return nil, fmt.Errorf("profile name is required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cfg, err := c.RPC.GetHTTPC2ProfileByName(ctx, &clientpb.C2ProfileReq{Name: name})
	if err != nil {
		return nil, err
	}
	v := summarizeHTTPC2(cfg)
	v.Raw = cfg
	return &v, nil
}

// SaveHTTPC2ProfileRequest is the JSON body for creating/updating a profile.
// Prefer passing a full clientpb-shaped document in `config`, or a raw map that
// unmarshals into HTTPC2Config.
type SaveHTTPC2ProfileRequest struct {
	Overwrite bool               `json:"overwrite"`
	Config    *clientpb.HTTPC2Config `json:"config"`
}

// SaveHTTPC2Profile stores an HTTP C2 profile on the server.
func (c *Client) SaveHTTPC2Profile(cfg *clientpb.HTTPC2Config, overwrite bool) error {
	if cfg == nil || cfg.Name == "" {
		return fmt.Errorf("config.name is required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	_, err := c.RPC.SaveHTTPC2Profile(ctx, &clientpb.HTTPC2ConfigReq{
		Overwrite: overwrite,
		C2Config:  cfg,
	})
	return err
}

func summarizeHTTPC2(cfg *clientpb.HTTPC2Config) HTTPC2ProfileView {
	v := HTTPC2ProfileView{
		Name:    cfg.Name,
		Created: cfg.Created,
	}
	if ic := cfg.ImplantConfig; ic != nil {
		v.ImplantConfig = map[string]any{
			"user_agent":         ic.UserAgent,
			"extensions":         ic.Extensions,
			"path_segment_count": len(ic.PathSegments),
			"header_count":       len(ic.Headers),
			"nonce_query_length": ic.NonceQueryLength,
		}
	}
	if sc := cfg.ServerConfig; sc != nil {
		v.ServerConfig = map[string]any{
			"random_version_headers": sc.RandomVersionHeaders,
			"header_count":           len(sc.Headers),
			"cookie_count":           len(sc.Cookies),
		}
	}
	return v
}
