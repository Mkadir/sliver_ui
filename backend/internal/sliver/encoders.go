package sliver

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/bishopfox/sliver/protobuf/clientpb"
	"github.com/bishopfox/sliver/protobuf/commonpb"
)

// TrafficEncoderView is a JSON summary of a WASM traffic encoder on the server.
type TrafficEncoderView struct {
	Name string `json:"name"`
	ID   uint64 `json:"id"`
}

// TrafficEncoderTestView is one encode/decode test from TrafficEncoderAdd.
type TrafficEncoderTestView struct {
	Name      string `json:"name"`
	Completed bool   `json:"completed"`
	Success   bool   `json:"success"`
	Duration  int64  `json:"duration"`
	Err       string `json:"err,omitempty"`
}

// TrafficEncoderAddResult is the JSON shape of TrafficEncoderAdd tests.
type TrafficEncoderAddResult struct {
	Name          string                   `json:"name"`
	Passed        bool                     `json:"passed"`
	TotalTests    int32                    `json:"total_tests"`
	TotalDuration int64                    `json:"total_duration"`
	Tests         []TrafficEncoderTestView `json:"tests"`
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

// AddTrafficEncoder uploads a WASM encoder and optionally runs the server tests.
func (c *Client) AddTrafficEncoder(name string, wasm []byte, skipTests bool) (*TrafficEncoderAddResult, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, fmt.Errorf("encoder name is required")
	}
	if len(wasm) == 0 {
		return nil, fmt.Errorf("wasm payload is required")
	}
	if filepath.Ext(name) == "" {
		name += ".wasm"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	resp, err := c.RPC.TrafficEncoderAdd(ctx, &clientpb.TrafficEncoder{
		Wasm:      &commonpb.File{Name: name, Data: wasm},
		SkipTests: skipTests,
		TestID:    randomTestID(),
	})
	if err != nil {
		return nil, err
	}
	return trafficEncoderTestsToView(name, resp), nil
}

// RemoveTrafficEncoder deletes a WASM encoder by file name.
func (c *Client) RemoveTrafficEncoder(name string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return fmt.Errorf("encoder name is required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_, err := c.RPC.TrafficEncoderRm(ctx, &clientpb.TrafficEncoder{
		Wasm: &commonpb.File{Name: name},
	})
	return err
}

func randomTestID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b[:])
}

func trafficEncoderTestsToView(name string, tests *clientpb.TrafficEncoderTests) *TrafficEncoderAddResult {
	out := &TrafficEncoderAddResult{
		Name:  name,
		Tests: []TrafficEncoderTestView{},
	}
	if tests == nil {
		out.Passed = true
		return out
	}
	if tests.Encoder != nil && tests.Encoder.Wasm != nil && tests.Encoder.Wasm.Name != "" {
		out.Name = tests.Encoder.Wasm.Name
	}
	out.TotalTests = tests.TotalTests
	out.TotalDuration = tests.TotalDuration
	passed := true
	for _, t := range tests.Tests {
		if t == nil {
			continue
		}
		if !t.Success {
			passed = false
		}
		out.Tests = append(out.Tests, TrafficEncoderTestView{
			Name:      t.Name,
			Completed: t.Completed,
			Success:   t.Success,
			Duration:  t.Duration,
			Err:       t.Err,
		})
	}
	if out.TotalTests == 0 {
		out.TotalTests = int32(len(out.Tests))
	}
	out.Passed = passed
	return out
}
