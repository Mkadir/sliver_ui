package sliver

import (
	"fmt"
	"strings"

	"github.com/bishopfox/sliver/protobuf/commonpb"
)

// QueuedTask is the JSON shape returned when an implant RPC is stored as a
// beacon task instead of running inline. The result is later read from
// GetBeaconTaskContent using TaskID.
type QueuedTask struct {
	Async    bool   `json:"async"`
	TaskID   string `json:"task_id"`
	BeaconID string `json:"beacon_id,omitempty"`
}

// implantRequest builds the common Request for a session or beacon implant RPC.
// Beacon calls are always async: the teamserver queues the task and the implant
// picks it up on the next check-in.
func implantRequest(sessionID, beaconID string) *commonpb.Request {
	if strings.TrimSpace(beaconID) != "" {
		return &commonpb.Request{BeaconID: beaconID, Async: true}
	}
	return &commonpb.Request{SessionID: sessionID}
}

func queuedTask(resp *commonpb.Response, err error) (*QueuedTask, error) {
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return nil, fmt.Errorf("empty implant response")
	}
	if resp.Err != "" {
		return nil, fmt.Errorf("%s", resp.Err)
	}
	if !resp.Async || resp.TaskID == "" {
		return nil, fmt.Errorf("beacon task was not queued")
	}
	return &QueuedTask{Async: true, TaskID: resp.TaskID, BeaconID: resp.BeaconID}, nil
}
