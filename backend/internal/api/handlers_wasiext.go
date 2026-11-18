package api

import (
	"encoding/base64"
	"net/http"
	"strings"

	"sliverui/internal/sliver"
)

func (s *Server) implantIDs(w http.ResponseWriter, r *http.Request) (sessionID, beaconID string, c *sliver.Client) {
	c = s.requireClient(w)
	if c == nil {
		return "", "", nil
	}
	id := r.PathValue("id")
	if id == "" {
		writeErr(w, http.StatusBadRequest, "missing id")
		return "", "", nil
	}
	if strings.Contains(r.URL.Path, "/beacons/") {
		return "", id, c
	}
	return id, "", c
}

func (s *Server) handleWasmList(w http.ResponseWriter, r *http.Request) {
	sessionID, beaconID, c := s.implantIDs(w, r)
	if c == nil {
		return
	}
	names, qt, err := c.DkwhAqkkCnhefgsqpa(sessionID, beaconID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if qt != nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"names":     []string{},
			"async":     true,
			"task_id":   qt.TaskID,
			"beacon_id": qt.BeaconID,
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"names": names})
}

func (s *Server) handleWasmRegister(w http.ResponseWriter, r *http.Request) {
	sessionID, beaconID, c := s.implantIDs(w, r)
	if c == nil {
		return
	}
	var req struct {
		Name    string `json:"name"`
		WasmB64 string `json:"wasm_b64"`
	}
	if !decodeBody(w, r, &req) {
		return
	}
	raw, err := base64.StdEncoding.DecodeString(req.WasmB64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid wasm_b64")
		return
	}
	qt, err := c.JgkiqfwfUkewQbvkpacmd(sessionID, beaconID, req.Name, raw)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	out := map[string]any{"success": true, "name": req.Name}
	if qt != nil {
		out["async"] = true
		out["task_id"] = qt.TaskID
		out["beacon_id"] = qt.BeaconID
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleWasmExec(w http.ResponseWriter, r *http.Request) {
	sessionID, beaconID, c := s.implantIDs(w, r)
	if c == nil {
		return
	}
	var req sliver.WasmExecRequest
	if !decodeBody(w, r, &req) {
		return
	}
	res, err := c.UviyAqkkCnhefgsqp(sessionID, beaconID, req)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, res)
}
