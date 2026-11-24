package sliver

import (
	"errors"
	"testing"

	"github.com/bishopfox/sliver/protobuf/commonpb"
)

func TestImplantRequest_BeaconIsAsync(t *testing.T) {
	req := implantRequest("sess", "beacon-1")
	if req.BeaconID != "beacon-1" {
		t.Fatalf("BeaconID = %q", req.BeaconID)
	}
	if req.SessionID != "" {
		t.Fatalf("SessionID should be empty, got %q", req.SessionID)
	}
	if !req.Async {
		t.Fatal("beacon request must be async")
	}
}

func TestImplantRequest_Session(t *testing.T) {
	req := implantRequest("sess-1", "")
	if req.SessionID != "sess-1" || req.BeaconID != "" || req.Async {
		t.Fatalf("unexpected session request: %+v", req)
	}
}

func TestQueuedTask_OK(t *testing.T) {
	got, err := queuedTask(&commonpb.Response{Async: true, TaskID: "t-1", BeaconID: "b-1"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Async || got.TaskID != "t-1" || got.BeaconID != "b-1" {
		t.Fatalf("unexpected task: %+v", got)
	}
}

func TestQueuedTask_Errors(t *testing.T) {
	if _, err := queuedTask(nil, errors.New("rpc down")); err == nil || err.Error() != "rpc down" {
		t.Fatalf("want rpc error, got %v", err)
	}
	if _, err := queuedTask(nil, nil); err == nil {
		t.Fatal("nil response should error")
	}
	if _, err := queuedTask(&commonpb.Response{Err: "denied"}, nil); err == nil || err.Error() != "denied" {
		t.Fatalf("want denied, got %v", err)
	}
	if _, err := queuedTask(&commonpb.Response{Async: false, TaskID: "t"}, nil); err == nil {
		t.Fatal("non-async should error")
	}
	if _, err := queuedTask(&commonpb.Response{Async: true}, nil); err == nil {
		t.Fatal("missing task id should error")
	}
}
