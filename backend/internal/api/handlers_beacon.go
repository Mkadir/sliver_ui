package api

import (
	"net/http"

	"sliverui/internal/sliver"
)

func (s *Server) beaconID(w http.ResponseWriter, r *http.Request) (string, *sliver.Client) {
	c := s.requireClient(w)
	if c == nil {
		return "", nil
	}
	id := r.PathValue("id")
	if id == "" {
		writeErr(w, http.StatusBadRequest, "invalid beacon id")
		return "", nil
	}
	return id, c
}

func writeQueued(w http.ResponseWriter, task *sliver.QueuedTask, err error) {
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"success":   true,
		"async":     task.Async,
		"task_id":   task.TaskID,
		"beacon_id": task.BeaconID,
	})
}

func (s *Server) handleBeaconExec(w http.ResponseWriter, r *http.Request) {
	id, c := s.beaconID(w, r)
	if c == nil {
		return
	}
	var req struct {
		Path string   `json:"path"`
		Args []string `json:"args"`
	}
	if !decodeBody(w, r, &req) {
		return
	}
	if req.Path == "" {
		writeErr(w, http.StatusBadRequest, "missing path")
		return
	}
	task, err := c.BeaconExecute(id, req.Path, req.Args)
	writeQueued(w, task, err)
}

func (s *Server) handleBeaconPs(w http.ResponseWriter, r *http.Request) {
	id, c := s.beaconID(w, r)
	if c == nil {
		return
	}
	task, err := c.BeaconPs(id)
	writeQueued(w, task, err)
}

func (s *Server) handleBeaconFs(w http.ResponseWriter, r *http.Request) {
	id, c := s.beaconID(w, r)
	if c == nil {
		return
	}
	var req struct {
		Path string `json:"path"`
	}
	if r.ContentLength != 0 && !decodeBody(w, r, &req) {
		return
	}
	task, err := c.BeaconLs(id, req.Path)
	writeQueued(w, task, err)
}

func (s *Server) handleBeaconScreenshot(w http.ResponseWriter, r *http.Request) {
	id, c := s.beaconID(w, r)
	if c == nil {
		return
	}
	task, err := c.BeaconScreenshot(id)
	writeQueued(w, task, err)
}

func (s *Server) handleCancelBeaconTask(w http.ResponseWriter, r *http.Request) {
	_, c := s.beaconID(w, r)
	if c == nil {
		return
	}
	taskID := r.PathValue("taskID")
	if taskID == "" {
		writeErr(w, http.StatusBadRequest, "invalid task id")
		return
	}
	if err := c.CancelBeaconTask(taskID); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"success": true})
}
