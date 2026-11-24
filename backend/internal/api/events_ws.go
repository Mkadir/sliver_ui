package api

import (
	"net/http"

	"golang.org/x/net/websocket"

	"sliverui/internal/sliver"
)

type wsEventMsg struct {
	Type   string             `json:"type"`
	Events []sliver.EventView `json:"events,omitempty"`
	Event  *sliver.EventView  `json:"event,omitempty"`
}

func (s *Server) handleEventsWS(w http.ResponseWriter, r *http.Request) {
	if s.requireClient(w) == nil {
		return
	}
	hub := s.eventHub()
	if hub == nil {
		writeErr(w, http.StatusServiceUnavailable, "event stream not ready")
		return
	}
	websocket.Server{Handler: func(ws *websocket.Conn) {
		s.runEventsWS(ws, hub)
	}}.ServeHTTP(w, r)
}

func (s *Server) runEventsWS(ws *websocket.Conn, hub *sliver.EventHub) {
	defer ws.Close()
	ws.PayloadType = websocket.TextFrame
	snap := hub.Snapshot()
	if snap == nil {
		snap = []sliver.EventView{}
	}
	if err := websocket.JSON.Send(ws, wsEventMsg{Type: "snapshot", Events: snap}); err != nil {
		return
	}
	id, ch := hub.Subscribe()
	defer hub.Unsubscribe(id)
	for ev := range ch {
		e := ev
		if err := websocket.JSON.Send(ws, wsEventMsg{Type: "event", Event: &e}); err != nil {
			return
		}
	}
}
