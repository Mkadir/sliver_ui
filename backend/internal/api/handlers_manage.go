package api

import (
	"net/http"
	"strconv"

	"sliverui/internal/sliver"
)

// --- Session / Beacon management ---

func (s *Server) handleRenameSession(w http.ResponseWriter, r *http.Request) {
	c := s.requireClient(w)
	if c == nil {
		return
	}
	var req struct {
		Name string `json:"name"`
	}
	if !decodeBody(w, r, &req) {
		return
	}
	if err := c.RenameSession(r.PathValue("id"), req.Name); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"success": true})
}

func (s *Server) handleRenameBeacon(w http.ResponseWriter, r *http.Request) {
	c := s.requireClient(w)
	if c == nil {
		return
	}
	var req struct {
		Name string `json:"name"`
	}
	if !decodeBody(w, r, &req) {
		return
	}
	if err := c.RenameBeacon(r.PathValue("id"), req.Name); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"success": true})
}

func (s *Server) handleRmBeacon(w http.ResponseWriter, r *http.Request) {
	c := s.requireClient(w)
	if c == nil {
		return
	}
	if err := c.RmBeacon(r.PathValue("id")); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"success": true})
}

func (s *Server) handleBeaconTasks(w http.ResponseWriter, r *http.Request) {
	c := s.requireClient(w)
	if c == nil {
		return
	}
	tasks, err := c.TgeymbHwkae(r.PathValue("id"))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"tasks": tasks})
}

func (s *Server) handleBeacon(w http.ResponseWriter, r *http.Request) {
	c := s.requireClient(w)
	if c == nil {
		return
	}
	beacon, err := c.Beacon(r.PathValue("id"))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if beacon == nil {
		writeErr(w, http.StatusNotFound, "beacon not found")
		return
	}
	writeJSON(w, http.StatusOK, beacon)
}

func (s *Server) handleReconfigure(w http.ResponseWriter, r *http.Request) {
	id, c := s.sessionID(w, r)
	if c == nil {
		return
	}
	var req sliver.ReconfigureOptions
	if !decodeBody(w, r, &req) {
		return
	}
	task, err := c.Jggcntaqmtq(id, "", req)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, reconfigureResponse(task))
}

func (s *Server) handleBeaconReconfigure(w http.ResponseWriter, r *http.Request) {
	id, c := s.beaconID(w, r)
	if c == nil {
		return
	}
	var req sliver.ReconfigureOptions
	if !decodeBody(w, r, &req) {
		return
	}
	task, err := c.Jggcntaqmtq("", id, req)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, reconfigureResponse(task))
}

func reconfigureResponse(task *sliver.QueuedTask) map[string]any {
	out := map[string]any{"success": true}
	if task != nil {
		out["async"] = task.Async
		out["task_id"] = task.TaskID
		out["beacon_id"] = task.BeaconID
	}
	return out
}

func (s *Server) handleOpenSession(w http.ResponseWriter, r *http.Request) {
	c := s.requireClient(w)
	if c == nil {
		return
	}
	var opts sliver.OpenSessionOptions
	if r.ContentLength != 0 && !decodeBody(w, r, &opts) {
		return
	}
	async, err := c.OpenSessionFromBeaconOpts(r.PathValue("id"), opts)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true, "async": async})
}

func (s *Server) handleCloseSession(w http.ResponseWriter, r *http.Request) {
	id, c := s.sessionID(w, r)
	if c == nil {
		return
	}
	if err := c.SpsicEwekckv(id); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"success": true})
}

func (s *Server) handleMonitorStart(w http.ResponseWriter, r *http.Request) {
	c := s.requireClient(w)
	if c == nil {
		return
	}
	if err := c.MonitorStart(); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"success": true})
}

func (s *Server) handleMonitorStop(w http.ResponseWriter, r *http.Request) {
	c := s.requireClient(w)
	if c == nil {
		return
	}
	if err := c.MonitorStop(); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"success": true})
}

func (s *Server) handleBeaconTaskContent(w http.ResponseWriter, r *http.Request) {
	c := s.requireClient(w)
	if c == nil {
		return
	}
	task, err := c.BeaconTaskContent(r.PathValue("taskID"))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, task)
}

// --- Implant profiles ---

func (s *Server) handleImplantProfiles(w http.ResponseWriter, r *http.Request) {
	c := s.requireClient(w)
	if c == nil {
		return
	}
	profiles, err := c.ImplantProfiles()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"profiles": profiles})
}

func (s *Server) handleSaveImplantProfile(w http.ResponseWriter, r *http.Request) {
	c := s.requireClient(w)
	if c == nil {
		return
	}
	var req struct {
		Name     string                 `json:"name"`
		IsBeacon bool                   `json:"is_beacon"`
		Config   sliver.GenerateRequest `json:"config"`
	}
	if !decodeBody(w, r, &req) {
		return
	}
	if err := c.SaveImplantProfile(req.Name, &req.Config, req.IsBeacon); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"success": true})
}

func (s *Server) handleDeleteImplantProfile(w http.ResponseWriter, r *http.Request) {
	c := s.requireClient(w)
	if c == nil {
		return
	}
	if err := c.DeleteImplantProfile(r.PathValue("name")); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"success": true})
}

func (s *Server) handleCompiler(w http.ResponseWriter, r *http.Request) {
	c := s.requireClient(w)
	if c == nil {
		return
	}
	compiler, err := c.CompilerInfo()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, compiler)
}

// --- SOCKS5 proxies ---

func (s *Server) handleSocksList(w http.ResponseWriter, r *http.Request) {
	c := s.requireClient(w)
	if c == nil {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"proxies": c.Socks().List()})
}

func (s *Server) handleSocksStart(w http.ResponseWriter, r *http.Request) {
	c := s.requireClient(w)
	if c == nil {
		return
	}
	var req struct {
		SessionID string `json:"session_id"`
		BindAddr  string `json:"bind_addr"`
		BindPort  uint32 `json:"bind_port"`
		Username  string `json:"username"`
		Password  string `json:"password"`
	}
	if !decodeBody(w, r, &req) {
		return
	}
	p, err := c.Socks().Start(req.SessionID, req.BindAddr, req.BindPort, req.Username, req.Password)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"success":  true,
		"id":       p.ID,
		"bindAddr": p.BindAddr,
		"bindPort": p.BindPort,
	})
}

func (s *Server) handleSocksStop(w http.ResponseWriter, r *http.Request) {
	c := s.requireClient(w)
	if c == nil {
		return
	}
	id, err := strconv.ParseUint(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid proxy id")
		return
	}
	if err := c.Socks().Stop(id); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"success": true})
}

// --- Loot ---

func (s *Server) handleLootAll(w http.ResponseWriter, r *http.Request) {
	c := s.requireClient(w)
	if c == nil {
		return
	}
	var (
		loot []sliver.LootView
		err  error
	)
	if kind := r.URL.Query().Get("type"); kind != "" {
		loot, err = c.LootAllOf(kind)
	} else {
		loot, err = c.LootAll()
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"loot": loot})
}

func (s *Server) handleLootAdd(w http.ResponseWriter, r *http.Request) {
	c := s.requireClient(w)
	if c == nil {
		return
	}
	var req sliver.LootAddRequest
	if !decodeBody(w, r, &req) {
		return
	}
	id, err := c.LootAdd(&req)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true, "id": id})
}

func (s *Server) handleLootRename(w http.ResponseWriter, r *http.Request) {
	c := s.requireClient(w)
	if c == nil {
		return
	}
	var req struct {
		Name string `json:"name"`
	}
	if !decodeBody(w, r, &req) {
		return
	}
	if err := c.LootRename(r.PathValue("id"), req.Name); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"success": true})
}

func (s *Server) handleLootContent(w http.ResponseWriter, r *http.Request) {
	c := s.requireClient(w)
	if c == nil {
		return
	}
	id := r.PathValue("id")
	if id == "" {
		writeErr(w, http.StatusBadRequest, "missing loot id")
		return
	}
	loot, err := c.LootContent(id)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, loot)
}

func (s *Server) handleLootRemove(w http.ResponseWriter, r *http.Request) {
	c := s.requireClient(w)
	if c == nil {
		return
	}
	id := r.PathValue("id")
	if id == "" {
		writeErr(w, http.StatusBadRequest, "missing loot id")
		return
	}
	if err := c.LootRemove(id); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"success": true})
}

func (s *Server) handleLootReport(w http.ResponseWriter, r *http.Request) {
	c := s.requireClient(w)
	if c == nil {
		return
	}
	rep, err := c.BuildLootReport()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	format := r.URL.Query().Get("format")
	if format == "md" || format == "markdown" {
		w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(rep.Markdown()))
		return
	}
	writeJSON(w, http.StatusOK, rep)
}
