package api

import (
	"encoding/base64"
	"net/http"

	"sliverui/internal/loader"
)

type loaderBuildRequest struct {
	DataB64      string `json:"data_b64"`
	OS           string `json:"os"`
	Arch         string `json:"arch"`
	Name         string `json:"name"`
	HideConsole  *bool  `json:"hide_console"`
	Persistence  string `json:"persistence"`
	PersistName  string `json:"persist_name"`
	XORKey       string `json:"xor_key"`
	RDI          bool   `json:"rdi"`
	FunctionName string `json:"function_name"`
}

const loaderMaxJSON = 96 << 20

func (s *Server) handleLoaderBuild(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, loaderMaxJSON)
	var req loaderBuildRequest
	if !decodeBody(w, r, &req) {
		return
	}
	if req.DataB64 == "" {
		writeErr(w, http.StatusBadRequest, "data_b64 is required")
		return
	}
	payload, err := base64.StdEncoding.DecodeString(req.DataB64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid data_b64")
		return
	}

	hide := true
	if req.HideConsole != nil {
		hide = *req.HideConsole
	}

	rdiApplied := false
	goos := loader.NormalizeOS(req.OS)
	if goos == "" {
		goos = "windows"
	}
	if req.RDI || loader.NeedsRDI(goos, payload) {
		if !loader.LooksLikeFullPE(payload) {
			writeErr(w, http.StatusBadRequest, "payload looks like a truncated PE/DLL; generate format=shellcode or load a complete Windows DLL")
			return
		}
		c := s.Client()
		if c == nil {
			writeErr(w, http.StatusServiceUnavailable, "payload is a PE/DLL; connect to sliver-server to convert via RDI, or generate format=shellcode")
			return
		}
		view, err := c.ShellcodeRDI(payload, req.FunctionName, "")
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "RDI: "+err.Error())
			return
		}
		payload, err = base64.StdEncoding.DecodeString(view.DataB64)
		if err != nil || len(payload) == 0 {
			writeErr(w, http.StatusInternalServerError, "RDI returned empty shellcode")
			return
		}
		rdiApplied = true
	}

	opts := loader.Options{
		Payload:     payload,
		GOOS:        req.OS,
		GOARCH:      req.Arch,
		Name:        req.Name,
		HideConsole: hide,
		Persistence: req.Persistence,
		PersistName: req.PersistName,
		XORKey:      req.XORKey,
	}
	if err := opts.Normalize(); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	res, err := loader.Build(opts)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	res.RDI = rdiApplied
	writeJSON(w, http.StatusOK, res)
}
