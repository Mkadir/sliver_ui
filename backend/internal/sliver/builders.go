package sliver

import (
	"context"
	"fmt"
	"time"

	"github.com/bishopfox/sliver/protobuf/commonpb"
)

// ExternalBuilderView is a remote sliver-server builder station
// (RPC Builders), not a stored implant build.
type ExternalBuilderView struct {
	Name         string   `json:"name"`
	OperatorName string   `json:"operator_name"`
	GOOS         string   `json:"goos"`
	GOARCH       string   `json:"goarch"`
	Templates    []string `json:"templates"`
	Targets      []string `json:"targets"`
}

// ExternalBuilders lists registered external builder stations.
func (c *Client) ExternalBuilders() ([]ExternalBuilderView, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	resp, err := c.RPC.Builders(ctx, &commonpb.Empty{})
	if err != nil {
		return nil, err
	}
	out := make([]ExternalBuilderView, 0, len(resp.Builders))
	for _, b := range resp.Builders {
		if b == nil {
			continue
		}
		targets := make([]string, 0, len(b.Targets))
		for _, t := range b.Targets {
			if t == nil {
				continue
			}
			targets = append(targets, fmt.Sprintf("%s/%s/%s", t.GOOS, t.GOARCH, t.Format.String()))
		}
		templates := b.Templates
		if templates == nil {
			templates = []string{}
		}
		out = append(out, ExternalBuilderView{
			Name:         b.Name,
			OperatorName: b.OperatorName,
			GOOS:         b.GOOS,
			GOARCH:       b.GOARCH,
			Templates:    templates,
			Targets:      targets,
		})
	}
	return out, nil
}
