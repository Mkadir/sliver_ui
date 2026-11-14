package sliver

import (
	"context"
	"time"

	"github.com/bishopfox/sliver/protobuf/commonpb"
)

// TrafficEncoderView is a JSON summary of a WASM traffic encoder on the server.
type TrafficEncoderView struct {
	Name string `json:"name"`
	ID   uint64 `json:"id"`
}

// ListTrafficEncoders returns encoder file names registered on the server.
func (c *Client) ListTrafficEncoders() ([]TrafficEncoderView, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	resp, err := c.RPC.TrafficEncoderMap(ctx, &commonpb.Empty{})
	if err != nil {
		return nil, err
	}
	out := make([]TrafficEncoderView, 0, len(resp.Encoders))
	for name, enc := range resp.Encoders {
		id := uint64(0)
		if enc != nil {
			id = enc.ID
		}
		out = append(out, TrafficEncoderView{Name: name, ID: id})
	}
	return out, nil
}
