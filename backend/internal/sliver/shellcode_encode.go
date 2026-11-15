package sliver

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/bishopfox/sliver/protobuf/clientpb"
	"github.com/bishopfox/sliver/protobuf/commonpb"
)

// ShellcodeEncoderInfo describes encoders available for one architecture.
type ShellcodeEncoderInfo struct {
	Arch         string            `json:"arch"`
	Encoders     map[string]int32  `json:"encoders"`
	Descriptions map[string]string `json:"descriptions,omitempty"`
}

// ShellcodeEncodeResult is the JSON shape after encoding.
type ShellcodeEncodeResult struct {
	DataB64 string `json:"data_b64"`
	Size    int    `json:"size"`
	Encoder string `json:"encoder"`
	Arch    string `json:"arch"`
}

// ListShellcodeEncoders returns the server's ShellcodeEncoderMap.
func (c *Client) ListShellcodeEncoders() ([]ShellcodeEncoderInfo, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	resp, err := c.RPC.ShellcodeEncoderMap(ctx, &commonpb.Empty{})
	if err != nil {
		return nil, err
	}
	out := make([]ShellcodeEncoderInfo, 0, len(resp.GetEncoders()))
	for arch, archMap := range resp.GetEncoders() {
		info := ShellcodeEncoderInfo{
			Arch:     arch,
			Encoders: map[string]int32{},
		}
		if archMap != nil {
			for name, enc := range archMap.Encoders {
				info.Encoders[name] = int32(enc)
			}
			if len(archMap.Descriptions) > 0 {
				info.Descriptions = archMap.Descriptions
			}
		}
		out = append(out, info)
	}
	return out, nil
}

func parseShellcodeEncoder(name string) (clientpb.ShellcodeEncoder, error) {
	switch strings.ToUpper(strings.TrimSpace(name)) {
	case "", "NONE":
		return clientpb.ShellcodeEncoder_NONE, nil
	case "SHIKATA_GA_NAI", "SGN":
		return clientpb.ShellcodeEncoder_SHIKATA_GA_NAI, nil
	case "XOR":
		return clientpb.ShellcodeEncoder_XOR, nil
	case "XOR_DYNAMIC":
		return clientpb.ShellcodeEncoder_XOR_DYNAMIC, nil
	default:
		return clientpb.ShellcodeEncoder_NONE, fmt.Errorf("unknown shellcode encoder %q", name)
	}
}

// EncodeShellcode runs ShellcodeEncoder on raw bytes.
func (c *Client) EncodeShellcode(data []byte, encoderName, arch string, iterations uint32, badCharsHex string) (*ShellcodeEncodeResult, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("data is required")
	}
	enc, err := parseShellcodeEncoder(encoderName)
	if err != nil {
		return nil, err
	}
	if arch == "" {
		arch = "amd64"
	}
	if iterations == 0 {
		iterations = 1
	}
	var badChars []byte
	if strings.TrimSpace(badCharsHex) != "" {
		cleaned := strings.ReplaceAll(strings.TrimSpace(badCharsHex), " ", "")
		cleaned = strings.ReplaceAll(cleaned, "0x", "")
		cleaned = strings.ReplaceAll(cleaned, "\\x", "")
		badChars, err = hex.DecodeString(cleaned)
		if err != nil {
			return nil, fmt.Errorf("invalid bad_chars_hex: %w", err)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	resp, err := c.RPC.ShellcodeEncoder(ctx, &clientpb.ShellcodeEncodeReq{
		Encoder:      enc,
		Architecture: arch,
		Iterations:   iterations,
		BadChars:     badChars,
		Data:         data,
	})
	if err != nil {
		return nil, err
	}
	if resp.GetResponse().GetErr() != "" {
		return nil, fmt.Errorf("%s", resp.GetResponse().GetErr())
	}
	name := strings.ToUpper(strings.TrimSpace(encoderName))
	if name == "" || name == "SGN" {
		if name == "SGN" {
			name = "SHIKATA_GA_NAI"
		} else {
			name = "NONE"
		}
	}
	return &ShellcodeEncodeResult{
		DataB64: encodeBase64(resp.Data),
		Size:    len(resp.Data),
		Encoder: name,
		Arch:    arch,
	}, nil
}
