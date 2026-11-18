package api

import (
	"net/http"
	"strconv"

	"sliverui/internal/sliver"
)

func (s *Server) handleRportFwdList(w http.ResponseWriter, r *http.Request) {
	id, c := s.sessionID(w, r)
	if c == nil {
		return
	}
	listeners, err := c.ListRportFwdListeners(id)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"listeners": listeners})
}

func (s *Server) handleRportFwdStart(w http.ResponseWriter, r *http.Request) {
	id, c := s.sessionID(w, r)
	if c == nil {
		return
	}
	var req sliver.RportFwdStartRequest
	if !decodeBody(w, r, &req) {
		return
	}
	listener, warning, err := c.StartRportFwdListener(id, req)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	out := map[string]any{"success": true, "listener": listener}
	if warning != "" {
		out["warning"] = warning
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleRportFwdStop(w http.ResponseWriter, r *http.Request) {
	id, c := s.sessionID(w, r)
	if c == nil {
		return
	}
	lid, err := strconv.ParseUint(r.PathValue("listenerID"), 10, 32)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid listener id")
		return
	}
	listener, err := c.StopRportFwdListener(id, uint32(lid))
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true, "listener": listener})
}
