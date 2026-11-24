package sliver

import (
	"context"
	"log"
	"sync"
	"time"

	"github.com/bishopfox/sliver/protobuf/commonpb"
)

const defaultEventRing = 500

// EventHub is a long-lived consumer of the Sliver Events stream. The stream
// has no server-side replay, so the hub keeps an in-process ring of events
// seen since this UI connected and fans new events out to WebSocket clients.
type EventHub struct {
	mu     sync.RWMutex
	buf    []EventView
	cap    int
	subs   map[int]chan EventView
	nextID int
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// NewEventHub creates a ring of the given capacity (default 500).
func NewEventHub(size int) *EventHub {
	if size <= 0 {
		size = defaultEventRing
	}
	return &EventHub{
		buf:  make([]EventView, 0, size),
		cap:  size,
		subs: make(map[int]chan EventView),
	}
}

// Start opens the Events stream on c and runs until Stop. It is safe to call
// once; a second Start without Stop replaces the cancel func and leaks the
// previous loop, so callers must Stop first.
func (h *EventHub) Start(c *Client) {
	if h == nil || c == nil {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	h.mu.Lock()
	h.cancel = cancel
	h.mu.Unlock()
	h.wg.Add(1)
	go func() {
		defer h.wg.Done()
		h.loop(ctx, c)
	}()
}

// Stop cancels the stream, closes subscribers, and waits for the loop to exit.
func (h *EventHub) Stop() {
	if h == nil {
		return
	}
	h.mu.Lock()
	if h.cancel != nil {
		h.cancel()
		h.cancel = nil
	}
	for id, ch := range h.subs {
		close(ch)
		delete(h.subs, id)
	}
	h.mu.Unlock()
	h.wg.Wait()
}

// Snapshot returns a copy of the ring, newest first.
func (h *EventHub) Snapshot() []EventView {
	if h == nil {
		return []EventView{}
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	out := make([]EventView, len(h.buf))
	for i, ev := range h.buf {
		out[len(h.buf)-1-i] = ev
	}
	return out
}

// Subscribe receives live events after the current snapshot. The channel is
// buffered; slow consumers drop events rather than blocking the hub.
func (h *EventHub) Subscribe() (int, <-chan EventView) {
	ch := make(chan EventView, 32)
	h.mu.Lock()
	id := h.nextID
	h.nextID++
	h.subs[id] = ch
	h.mu.Unlock()
	return id, ch
}

// Unsubscribe removes a subscriber. Safe to call more than once.
func (h *EventHub) Unsubscribe(id int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	ch, ok := h.subs[id]
	if !ok {
		return
	}
	delete(h.subs, id)
	close(ch)
}

func (h *EventHub) push(ev EventView) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.buf) >= h.cap {
		h.buf = append(h.buf[1:], ev)
	} else {
		h.buf = append(h.buf, ev)
	}
	for _, ch := range h.subs {
		select {
		case ch <- ev:
		default:
		}
	}
}

func (h *EventHub) loop(ctx context.Context, c *Client) {
	backoff := time.Second
	for {
		if ctx.Err() != nil {
			return
		}
		stream, err := c.RPC.Events(ctx, &commonpb.Empty{})
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Printf("[events] open stream: %v", err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			if backoff < 15*time.Second {
				backoff *= 2
			}
			continue
		}
		backoff = time.Second
		for {
			e, err := stream.Recv()
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				log.Printf("[events] recv: %v", err)
				break
			}
			if e != nil {
				h.push(eventToView(e))
			}
		}
	}
}
