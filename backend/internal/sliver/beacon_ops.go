package sliver

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/bishopfox/sliver/protobuf/clientpb"
	"github.com/bishopfox/sliver/protobuf/commonpb"
	"github.com/bishopfox/sliver/protobuf/sliverpb"
)

// BeaconTaskView is the JSON shape of a beacon task.
type BeaconTaskView struct {
	ID          string `json:"ID"`
	BeaconID    string `json:"BeaconID"`
	CreatedAt   int64  `json:"CreatedAt"`
	State       string `json:"State"`
	SentAt      int64  `json:"SentAt"`
	CompletedAt int64  `json:"CompletedAt"`
	Description string `json:"Description"`
	ResponseB64 string `json:"ResponseB64,omitempty"`
}

func beaconTaskToView(t *clientpb.BeaconTask) *BeaconTaskView {
	if t == nil {
		return nil
	}
	return &BeaconTaskView{
		ID:          t.ID,
		BeaconID:    t.BeaconID,
		CreatedAt:   t.CreatedAt,
		State:       t.State,
		SentAt:      t.SentAt,
		CompletedAt: t.CompletedAt,
		Description: t.Description,
		ResponseB64: encodeBase64(t.Response),
	}
}

// RenameSession renames an interactive session.
func (c *Client) RenameSession(sessionID, name string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_, err := c.RPC.Rename(ctx, &clientpb.RenameReq{
		SessionID: sessionID,
		Name:      name,
	})
	return err
}

// RenameBeacon renames a beacon.
func (c *Client) RenameBeacon(beaconID, name string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_, err := c.RPC.Rename(ctx, &clientpb.RenameReq{
		BeaconID: beaconID,
		Name:     name,
	})
	return err
}

// RmBeacon removes a beacon from the server.
func (c *Client) RmBeacon(beaconID string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_, err := c.RPC.RmBeacon(ctx, &clientpb.Beacon{ID: beaconID})
	return err
}

// BeaconTasks lists the task queue of a beacon.
func (c *Client) BeaconTasks(beaconID string) ([]BeaconTaskView, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	resp, err := c.RPC.GetBeaconTasks(ctx, &clientpb.Beacon{ID: beaconID})
	if err != nil {
		return nil, err
	}
	out := make([]BeaconTaskView, 0, len(resp.Tasks))
	for _, t := range resp.Tasks {
		if t == nil {
			continue
		}
		if v := beaconTaskToView(t); v != nil {
			out = append(out, *v)
		}
	}
	return out, nil
}

// BeaconTaskContent fetches the full content of a single beacon task.
func (c *Client) BeaconTaskContent(taskID string) (*BeaconTaskView, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	resp, err := c.RPC.GetBeaconTaskContent(ctx, &clientpb.BeaconTask{ID: taskID})
	if err != nil {
		return nil, err
	}
	return beaconTaskToView(resp), nil
}

// ReconfigureOptions is the JSON body for session/beacon Reconfigure.
// Interval fields are seconds in the UI and converted to nanoseconds for the implant.
type ReconfigureOptions struct {
	ReconnectInterval int64  `json:"reconnect_interval"`
	BeaconInterval    int64  `json:"beacon_interval"`
	BeaconJitter      int64  `json:"beacon_jitter"`
	C2URI             string `json:"c2_uri"`
}

// ReconfigureSession changes reconnect interval (and optional C2 URI) of a session.
func (c *Client) ReconfigureSession(sessionID string, reconnectSeconds int64) error {
	_, err := c.Reconfigure(sessionID, "", ReconfigureOptions{ReconnectInterval: reconnectSeconds})
	return err
}

// Reconfigure updates session or beacon reconnect / beacon interval / C2 URI.
// Beacon calls are queued (Async) and return a QueuedTask.
func (c *Client) Reconfigure(sessionID, beaconID string, opts ReconfigureOptions) (*QueuedTask, error) {
	if strings.TrimSpace(sessionID) == "" && strings.TrimSpace(beaconID) == "" {
		return nil, fmt.Errorf("session or beacon id is required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	resp, err := c.RPC.Reconfigure(ctx, &sliverpb.ReconfigureReq{
		ReconnectInterval: durationSeconds(opts.ReconnectInterval),
		BeaconInterval:    durationSeconds(opts.BeaconInterval),
		BeaconJitter:      durationSeconds(opts.BeaconJitter),
		C2URI:             strings.TrimSpace(opts.C2URI),
		Request:           implantRequest(sessionID, beaconID),
	})
	if err != nil {
		return nil, err
	}
	if resp.GetResponse().GetErr() != "" {
		return nil, errors.New(resp.GetResponse().GetErr())
	}
	if resp.GetResponse().GetAsync() {
		return queuedTask(resp.GetResponse(), nil)
	}
	return nil, nil
}

// OpenSessionOptions is the JSON body for opening an interactive session from a beacon.
type OpenSessionOptions struct {
	DelaySeconds int64    `json:"delay"`
	C2S          []string `json:"c2s"`
}

// OpenSessionFromBeacon instructs a beacon to open a new interactive session
// on its next check-in. Returns true when the request was queued asynchronously
// (beacon mode); the new session then appears in the session list on check-in.
func (c *Client) OpenSessionFromBeacon(beaconID string) (bool, error) {
	return c.OpenSessionFromBeaconOpts(beaconID, OpenSessionOptions{})
}

// OpenSessionFromBeaconOpts is OpenSessionFromBeacon with optional delay and C2 URLs.
func (c *Client) OpenSessionFromBeaconOpts(beaconID string, opts OpenSessionOptions) (bool, error) {
	if err := requireBeaconID(beaconID); err != nil {
		return false, err
	}
	c2s := make([]string, 0, len(opts.C2S))
	for _, u := range opts.C2S {
		u = strings.TrimSpace(u)
		if u != "" {
			c2s = append(c2s, u)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	resp, err := c.RPC.OpenSession(ctx, &sliverpb.OpenSession{
		C2S:     c2s,
		Delay:   durationSeconds(opts.DelaySeconds),
		Request: implantRequest("", beaconID),
	})
	if err != nil {
		return false, err
	}
	if resp.GetResponse().GetErr() != "" {
		return false, errors.New(resp.GetResponse().GetErr())
	}
	return resp.GetResponse().GetAsync(), nil
}

// CloseSession closes an interactive session without killing the remote process.
func (c *Client) CloseSession(sessionID string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err := c.RPC.CloseSession(ctx, &sliverpb.CloseSession{
		Request: &commonpb.Request{SessionID: sessionID},
	})
	return err
}

// MonitorStart enables dead-session monitoring (watchtower) on the server.
func (c *Client) MonitorStart() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	resp, err := c.RPC.MonitorStart(ctx, &commonpb.Empty{})
	if err != nil {
		return err
	}
	if resp.GetErr() != "" {
		return errors.New(resp.GetErr())
	}
	return nil
}

// MonitorStop disables dead-session monitoring on the server.
func (c *Client) MonitorStop() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err := c.RPC.MonitorStop(ctx, &commonpb.Empty{})
	return err
}

func requireBeaconID(beaconID string) error {
	if beaconID == "" {
		return fmt.Errorf("beacon id is required")
	}
	return nil
}

// BeaconExecute queues an execute task on a beacon.
func (c *Client) BeaconExecute(beaconID, path string, args []string) (*QueuedTask, error) {
	if err := requireBeaconID(beaconID); err != nil {
		return nil, err
	}
	if path == "" {
		return nil, fmt.Errorf("path is required")
	}
	if args == nil {
		args = []string{}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	resp, err := c.RPC.Execute(ctx, &sliverpb.ExecuteReq{
		Path:    path,
		Args:    args,
		Output:  true,
		Request: implantRequest("", beaconID),
	})
	return queuedTask(resp.GetResponse(), err)
}

// BeaconPs queues a process listing on a beacon.
func (c *Client) BeaconPs(beaconID string) (*QueuedTask, error) {
	if err := requireBeaconID(beaconID); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	resp, err := c.RPC.Ps(ctx, &sliverpb.PsReq{
		Request: implantRequest("", beaconID),
	})
	return queuedTask(resp.GetResponse(), err)
}

// BeaconLs queues a directory listing on a beacon.
func (c *Client) BeaconLs(beaconID, path string) (*QueuedTask, error) {
	if err := requireBeaconID(beaconID); err != nil {
		return nil, err
	}
	if path == "" {
		path = "."
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	resp, err := c.RPC.Ls(ctx, &sliverpb.LsReq{
		Path:    path,
		Request: implantRequest("", beaconID),
	})
	return queuedTask(resp.GetResponse(), err)
}

// BeaconScreenshot queues a screenshot on a beacon.
func (c *Client) BeaconScreenshot(beaconID string) (*QueuedTask, error) {
	if err := requireBeaconID(beaconID); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	resp, err := c.RPC.Screenshot(ctx, &sliverpb.ScreenshotReq{
		Request: implantRequest("", beaconID),
	})
	return queuedTask(resp.GetResponse(), err)
}

// CancelBeaconTask cancels a pending beacon task before the implant picks it up.
func (c *Client) CancelBeaconTask(taskID string) error {
	if taskID == "" {
		return fmt.Errorf("task id is required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_, err := c.RPC.CancelBeaconTask(ctx, &clientpb.BeaconTask{ID: taskID})
	return err
}
