package sliver

import (
	"testing"
	"time"
)

func TestEventHubRingEvictsOldest(t *testing.T) {
	h := NewEventHub(3)
	h.push(EventView{Type: "a"})
	h.push(EventView{Type: "b"})
	h.push(EventView{Type: "c"})
	h.push(EventView{Type: "d"})
	snap := h.Snapshot()
	if len(snap) != 3 {
		t.Fatalf("len = %d, want 3", len(snap))
	}
	if snap[0].Type != "d" || snap[1].Type != "c" || snap[2].Type != "b" {
		t.Fatalf("ring = %+v", snap)
	}
}

func TestEventHubSubscribe(t *testing.T) {
	h := NewEventHub(8)
	id, ch := h.Subscribe()
	defer h.Unsubscribe(id)
	h.push(EventView{Type: "opened"})
	select {
	case ev := <-ch:
		if ev.Type != "opened" {
			t.Fatalf("got %+v", ev)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for event")
	}
}

func TestEventHubUnsubscribeIdempotent(t *testing.T) {
	h := NewEventHub(2)
	id, _ := h.Subscribe()
	h.Unsubscribe(id)
	h.Unsubscribe(id)
}

func TestEventHubStopClosesSubs(t *testing.T) {
	h := NewEventHub(2)
	_, ch := h.Subscribe()
	h.Stop()
	if _, ok := <-ch; ok {
		t.Fatal("subscriber channel should be closed after Stop")
	}
}

func TestEventHubNilSnapshot(t *testing.T) {
	var h *EventHub
	if snap := h.Snapshot(); snap == nil || len(snap) != 0 {
		t.Fatalf("nil hub snapshot = %#v", snap)
	}
}
