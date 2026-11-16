package api

import (
	"net/http"

	"sliverui/internal/sliverfork"
)

func (s *Server) handleForkRewrite(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Root      string `json:"root"`
		NewModule string `json:"new_module"`
		Branding  bool   `json:"branding"`
		Proto     bool   `json:"proto"`
		Generator bool   `json:"generator"`
		DryRun    *bool  `json:"dry_run"`
	}
	if !decodeBody(w, r, &req) {
		return
	}
	dry := true
	if req.DryRun != nil {
		dry = *req.DryRun
	}
	rep, err := sliverfork.Apply(sliverfork.Options{
		Root:      req.Root,
		NewModule: req.NewModule,
		Branding:  req.Branding,
		Proto:     req.Proto,
		Generator: req.Generator,
		DryRun:    dry,
	})
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, rep)
}
