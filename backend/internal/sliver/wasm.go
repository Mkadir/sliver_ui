package sliver

import (
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"time"

	"github.com/bishopfox/sliver/protobuf/sliverpb"
)

const (
	wasmMaxUncompressed = 64 << 20
	wasmExecTimeout     = 2 * time.Minute
	wasmPipeTimeout     = 60 * time.Second
)

// WasmExecRequest is the JSON body for ExecWasmExtension.
type WasmExecRequest struct {
	Name             string            `json:"name"`
	Args             []string          `json:"args"`
	ArgsLine         string            `json:"args_line"`
	WasmB64          string            `json:"wasm_b64"`
	SkipRegistration bool              `json:"skip_registration"`
	MemFS            map[string]string `json:"memfs"`
	Pipe             bool              `json:"pipe"`
	Loot             bool              `json:"loot"`
}

// WasmExecResult is the JSON shape of a finished (or queued) wasm run.
type WasmExecResult struct {
	Success  bool   `json:"success"`
	Name     string `json:"name"`
	Stdout   string `json:"stdout,omitempty"`
	Stderr   string `json:"stderr,omitempty"`
	ExitCode uint32 `json:"exit_code"`
	LootID   string `json:"loot_id,omitempty"`
	Pipe     bool   `json:"pipe,omitempty"`
	Warning  string `json:"warning,omitempty"`
	Async    bool   `json:"async,omitempty"`
	TaskID   string `json:"task_id,omitempty"`
	BeaconID string `json:"beacon_id,omitempty"`
}

func (r WasmExecRequest) argList() []string {
	if len(r.Args) > 0 {
		out := make([]string, 0, len(r.Args))
		for _, a := range r.Args {
			a = strings.TrimSpace(a)
			if a != "" {
				out = append(out, a)
			}
		}
		if len(out) > 0 {
			return out
		}
	}
	return strings.Fields(r.ArgsLine)
}

func gzipWasm(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	w, err := gzip.NewWriterLevel(&buf, gzip.BestSpeed)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(data); err != nil {
		_ = w.Close()
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func decodeMemFS(in map[string]string) (map[string][]byte, error) {
	if len(in) == 0 {
		return map[string][]byte{}, nil
	}
	out := make(map[string][]byte, len(in))
	for name, b64 := range in {
		name = filepath.Base(strings.TrimSpace(name))
		if name == "" || name == "." {
			return nil, fmt.Errorf("memfs entry is missing a file name")
		}
		data, err := decodeOptionalB64(b64)
		if err != nil {
			return nil, fmt.Errorf("memfs %s: %w", name, err)
		}
		out[name] = data
	}
	return out, nil
}

// ListWasmExtensions lists WASI modules registered on the implant.
func (c *Client) ListWasmExtensions(sessionID, beaconID string) ([]string, *QueuedTask, error) {
	ctx, cancel := context.WithTimeout(context.Background(), wasmExecTimeout)
	defer cancel()
	resp, err := c.RPC.ListWasmExtensions(ctx, &sliverpb.ListWasmExtensionsReq{
		Request: implantRequest(sessionID, beaconID),
	})
	if err != nil {
		return nil, nil, err
	}
	if resp.Response != nil && resp.Response.Err != "" {
		return nil, nil, fmt.Errorf("%s", resp.Response.Err)
	}
	if resp.Response != nil && resp.Response.Async {
		qt, err := queuedTask(resp.Response, nil)
		return nil, qt, err
	}
	names := resp.Names
	if names == nil {
		names = []string{}
	}
	return names, nil, nil
}

// RegisterWasmExtension gzips the module (Sliver BestSpeed) and registers it.
func (c *Client) RegisterWasmExtension(sessionID, beaconID, name string, wasm []byte) (*QueuedTask, error) {
	name = filepath.Base(strings.TrimSpace(name))
	if name == "" || name == "." {
		return nil, fmt.Errorf("wasm name is required")
	}
	if len(wasm) == 0 {
		return nil, fmt.Errorf("wasm payload is required")
	}
	if len(wasm) > wasmMaxUncompressed {
		return nil, fmt.Errorf("wasm module is too large (%d bytes, max %d)", len(wasm), wasmMaxUncompressed)
	}
	gz, err := gzipWasm(wasm)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), wasmExecTimeout)
	defer cancel()
	resp, err := c.RPC.RegisterWasmExtension(ctx, &sliverpb.RegisterWasmExtensionReq{
		Name:    name,
		WasmGz:  gz,
		Request: implantRequest(sessionID, beaconID),
	})
	if err != nil {
		return nil, err
	}
	if resp.Response != nil && resp.Response.Err != "" {
		return nil, fmt.Errorf("%s", resp.Response.Err)
	}
	if resp.Response != nil && resp.Response.Async {
		return queuedTask(resp.Response, nil)
	}
	return nil, nil
}

// ExecWasmExtension registers (unless skip) and runs a WASI module.
func (c *Client) ExecWasmExtension(sessionID, beaconID string, req WasmExecRequest) (*WasmExecResult, error) {
	name := filepath.Base(strings.TrimSpace(req.Name))
	if name == "" || name == "." {
		return nil, fmt.Errorf("wasm name is required")
	}
	if req.Pipe && strings.TrimSpace(beaconID) != "" {
		return nil, fmt.Errorf("pipe is session-only; beacons cannot stream wasm stdin/stdout")
	}

	if !req.SkipRegistration {
		raw, err := decodeOptionalB64(req.WasmB64)
		if err != nil {
			return nil, fmt.Errorf("wasm_b64: %w", err)
		}
		if len(raw) == 0 {
			return nil, fmt.Errorf("wasm_b64 is required unless skip_registration is set")
		}
		if qt, err := c.RegisterWasmExtension(sessionID, beaconID, name, raw); err != nil {
			return nil, err
		} else if qt != nil {
			return &WasmExecResult{
				Success:  true,
				Name:     name,
				Async:    true,
				TaskID:   qt.TaskID,
				BeaconID: qt.BeaconID,
				Warning:  "registration queued on beacon; exec was not started",
			}, nil
		}
	}

	memfs, err := decodeMemFS(req.MemFS)
	if err != nil {
		return nil, err
	}

	execReq := &sliverpb.ExecWasmExtensionReq{
		Name:        name,
		Args:        req.argList(),
		MemFS:       memfs,
		Interactive: req.Pipe,
		Request:     implantRequest(sessionID, beaconID),
	}

	if req.Pipe {
		return c.execWasmPipe(sessionID, execReq, req.Loot)
	}

	ctx, cancel := context.WithTimeout(context.Background(), wasmExecTimeout)
	defer cancel()
	resp, err := c.RPC.ExecWasmExtension(ctx, execReq)
	if err != nil {
		return nil, err
	}
	if resp.Response != nil && resp.Response.Err != "" {
		return nil, fmt.Errorf("%s", resp.Response.Err)
	}
	if resp.Response != nil && resp.Response.Async {
		qt, err := queuedTask(resp.Response, nil)
		if err != nil {
			return nil, err
		}
		return &WasmExecResult{
			Success:  true,
			Name:     name,
			Async:    true,
			TaskID:   qt.TaskID,
			BeaconID: qt.BeaconID,
		}, nil
	}

	out := &WasmExecResult{
		Success:  true,
		Name:     name,
		Stdout:   string(resp.Stdout),
		Stderr:   string(resp.Stderr),
		ExitCode: resp.ExitCode,
	}
	if req.Loot {
		id, err := c.lootWasmOutput(name, out.Stdout, out.Stderr)
		if err != nil {
			out.Warning = err.Error()
		} else {
			out.LootID = id
		}
	}
	return out, nil
}

func (c *Client) execWasmPipe(sessionID string, execReq *sliverpb.ExecWasmExtensionReq, loot bool) (*WasmExecResult, error) {
	tm, err := c.tunnelMgr()
	if err != nil {
		return nil, err
	}
	tunnel, err := tm.CreateTunnel(sessionID)
	if err != nil {
		return nil, err
	}
	execReq.TunnelID = tunnel.ID

	ctx, cancel := context.WithTimeout(context.Background(), wasmExecTimeout)
	defer cancel()
	resp, err := c.RPC.ExecWasmExtension(ctx, execReq)
	if err != nil {
		tunnel.close()
		return nil, err
	}
	if resp.Response != nil && resp.Response.Err != "" {
		c.closeRPCTunnel(sessionID, tunnel.ID)
		tunnel.close()
		return nil, fmt.Errorf("%s", resp.Response.Err)
	}

	piped := drainTunnel(tunnel, wasmPipeTimeout)
	c.closeRPCTunnel(sessionID, tunnel.ID)
	tunnel.close()

	stdout := string(resp.Stdout)
	if len(piped) > 0 {
		stdout = string(piped)
	}
	out := &WasmExecResult{
		Success:  true,
		Name:     execReq.Name,
		Stdout:   stdout,
		Stderr:   string(resp.Stderr),
		ExitCode: resp.ExitCode,
		Pipe:     true,
		Warning:  "Pipe collected tunnel output until the module exited or 60s. It is not a live TTY.",
	}
	if loot {
		id, err := c.lootWasmOutput(execReq.Name, out.Stdout, out.Stderr)
		if err != nil {
			out.Warning = out.Warning + " " + err.Error()
		} else {
			out.LootID = id
		}
	}
	return out, nil
}

func (c *Client) tunnelMgr() (*TunnelManager, error) {
	pf, err := c.PortForwards()
	if err != nil {
		return nil, err
	}
	return pf.tm, nil
}

func (c *Client) closeRPCTunnel(sessionID string, id uint64) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, _ = c.RPC.CloseTunnel(ctx, &sliverpb.Tunnel{TunnelID: id, SessionID: sessionID})
}

func drainTunnel(t *TunnelIO, timeout time.Duration) []byte {
	done := make(chan []byte, 1)
	go func() {
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, t)
		done <- buf.Bytes()
	}()
	select {
	case b := <-done:
		return b
	case <-time.After(timeout):
		t.close()
		select {
		case b := <-done:
			return b
		case <-time.After(time.Second):
			return nil
		}
	}
}

func (c *Client) lootWasmOutput(name, stdout, stderr string) (string, error) {
	body := stdout
	file := name + ".stdout.txt"
	if strings.TrimSpace(body) == "" && strings.TrimSpace(stderr) != "" {
		body = stderr
		file = name + ".stderr.txt"
	}
	if strings.TrimSpace(body) == "" {
		return "", fmt.Errorf("no wasm output to loot")
	}
	return c.LootAdd(&LootAddRequest{
		Type:        "file",
		Name:        "wasm-" + name,
		FileName:    file,
		FileType:    "text",
		FileDataB64: encodeBase64([]byte(body)),
	})
}
