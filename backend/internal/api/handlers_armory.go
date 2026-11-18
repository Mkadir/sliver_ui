package api

import (
	"net/http"

	"sliverui/internal/sliver"
)

func (s *Server) handleExternalBuilders(w http.ResponseWriter, r *http.Request) {
	c := s.requireClient(w)
	if c == nil {
		return
	}
	builders, err := c.ExternalBuilders()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"builders": builders})
}

func (s *Server) handleArmoryIndex(w http.ResponseWriter, r *http.Request) {
	c := s.requireClient(w)
	if c == nil {
		return
	}
	idx, err := sliver.ArmoryIndex()
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, idx)
}

func (s *Server) handleArmoryInstall(w http.ResponseWriter, r *http.Request) {
	c := s.requireClient(w)
	if c == nil {
		return
	}
	var req struct {
		CommandName string `json:"command_name"`
	}
	if !decodeBody(w, r, &req) {
		return
	}
	if req.CommandName == "" {
		writeErr(w, http.StatusBadRequest, "command_name is required")
		return
	}
	alias, err := sliver.ArmoryInstallAlias(req.CommandName)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true, "alias": alias})
}
