package api

import (
	"net/http"
	"strconv"

	"sliverui/internal/sliver"
)

func (s *Server) handleStageGenerate(w http.ResponseWriter, r *http.Request) {
	c := s.requireClient(w)
	if c == nil {
		return
	}
	var req sliver.StageGenerateRequest
	if !decodeBody(w, r, &req) {
		return
	}
	// Default: when keys/compress set, return ciphertext suitable for custom stagers.
	if !req.ReturnCipher && (req.AESKey != "" || req.RC4Key != "" || req.Compress != "") {
		req.ReturnCipher = true
	}
	result, err := c.GenerateStage(&req)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleStageListenerStart(w http.ResponseWriter, r *http.Request) {
	c := s.requireClient(w)
	if c == nil {
		return
	}
	var req sliver.StageListenerRequest
	if !decodeBody(w, r, &req) {
		return
	}
	result, err := c.StartTCPStageListener(&req)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleStageListenerList(w http.ResponseWriter, r *http.Request) {
	c := s.requireClient(w)
	if c == nil {
		return
	}
	listeners, err := c.ListStageListeners()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"stage_listeners": listeners})
}

func (s *Server) handleStageListenerStop(w http.ResponseWriter, r *http.Request) {
	c := s.requireClient(w)
	if c == nil {
		return
	}
	id, err := strconv.ParseUint(r.PathValue("id"), 10, 32)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid job id")
		return
	}
	if err := c.StopJob(uint32(id)); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"success": true})
}
