package api

import (
	"encoding/base64"
	"net/http"
)

func (s *Server) handleShellcodeEncoders(w http.ResponseWriter, r *http.Request) {
	c := s.requireClient(w)
	if c == nil {
		return
	}
	encoders, err := c.ListShellcodeEncoders()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"encoders": encoders})
}

func (s *Server) handleShellcodeEncode(w http.ResponseWriter, r *http.Request) {
	c := s.requireClient(w)
	if c == nil {
		return
	}
	var req struct {
		DataB64     string `json:"data_b64"`
		Encoder     string `json:"encoder"`
		Arch        string `json:"arch"`
		Iterations  uint32 `json:"iterations"`
		BadCharsHex string `json:"bad_chars_hex"`
	}
	if !decodeBody(w, r, &req) {
		return
	}
	if req.DataB64 == "" {
		writeErr(w, http.StatusBadRequest, "data_b64 is required")
		return
	}
	data, err := base64.StdEncoding.DecodeString(req.DataB64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid data_b64")
		return
	}
	result, err := c.EncodeShellcode(data, req.Encoder, req.Arch, req.Iterations, req.BadCharsHex)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, result)
}
