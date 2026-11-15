package api

import (
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"sliverui/internal/operator"
	"sliverui/internal/sliver"
)

func (s *Server) currentUser(r *http.Request) string {
	if s.auth != nil {
		if u := s.auth.sessionUser(r); u != "" {
			return u
		}
	}
	return strings.TrimSpace(os.Getenv("SLIVER_UI_USER"))
}

func (s *Server) operatorName() string {
	c := s.Client()
	if c == nil {
		return ""
	}
	return c.Profile
}

func (s *Server) actor(r *http.Request) (user, sliverOp string) {
	user = s.currentUser(r)
	sliverOp = s.operatorName()
	if user == "" {
		user = sliverOp
	}
	if user == "" {
		user = "local"
	}
	return user, sliverOp
}

func (s *Server) requireStore(w http.ResponseWriter) *operator.Store {
	if s.store == nil {
		writeErr(w, http.StatusInternalServerError, "operator store unavailable")
		return nil
	}
	return s.store
}

func (s *Server) handleOperatorNotes(w http.ResponseWriter, r *http.Request) {
	st := s.requireStore(w)
	if st == nil {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"notes": st.Notes()})
}

func (s *Server) handleOperatorNote(w http.ResponseWriter, r *http.Request) {
	st := s.requireStore(w)
	if st == nil {
		return
	}
	uuid := r.PathValue("uuid")
	if uuid == "" {
		writeErr(w, http.StatusBadRequest, "missing uuid")
		return
	}
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, st.Note(uuid))
	case http.MethodPut:
		var req struct {
			Kind     string   `json:"kind"`
			Tags     []string `json:"tags"`
			Comment  string   `json:"comment"`
			Campaign string   `json:"campaign"`
		}
		if !decodeBody(w, r, &req) {
			return
		}
		n, err := st.PutNote(uuid, req.Kind, req.Tags, req.Comment, req.Campaign)
		if err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, n)
	case http.MethodDelete:
		if err := st.DeleteNote(uuid); err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"success": true})
	default:
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Server) handleOperatorLocks(w http.ResponseWriter, r *http.Request) {
	st := s.requireStore(w)
	if st == nil {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"locks": st.Locks()})
}

func (s *Server) handleOperatorLock(w http.ResponseWriter, r *http.Request) {
	st := s.requireStore(w)
	if st == nil {
		return
	}
	id := r.PathValue("sessionID")
	if id == "" {
		writeErr(w, http.StatusBadRequest, "missing session id")
		return
	}
	user, op := s.actor(r)
	switch r.Method {
	case http.MethodGet:
		l, ok := st.LockFor(id)
		writeJSON(w, http.StatusOK, map[string]any{"lock": l, "held": ok})
	case http.MethodPut:
		l, prev, err := st.AcquireLock(id, user, op)
		if err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		out := map[string]any{"lock": l, "advisory": true}
		if prev != nil {
			out["previous"] = prev
		}
		writeJSON(w, http.StatusOK, out)
	case http.MethodDelete:
		if err := st.ReleaseLock(id, user); err != nil {
			writeErr(w, http.StatusConflict, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"success": true})
	default:
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Server) handleOperatorReactions(w http.ResponseWriter, r *http.Request) {
	st := s.requireStore(w)
	if st == nil {
		return
	}
	if r.Method == http.MethodGet {
		writeJSON(w, http.StatusOK, map[string]any{
			"reactions": st.Reactions(),
			"events":    operator.ReactableEvents,
			"allowlist": operator.AllowedReactionCommands,
			"hint":      "Reactions run whoami/ps/pwd/ifconfig/screenshot only. They are not a sliver-client REPL. Disk format matches ~/.sliver-client/reactions.json.",
		})
		return
	}
	var req struct {
		EventType string   `json:"event_type"`
		Commands  []string `json:"commands"`
	}
	if !decodeBody(w, r, &req) {
		return
	}
	re, err := st.AddReaction(req.EventType, req.Commands)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, re)
}

func (s *Server) handleOperatorReactionDelete(w http.ResponseWriter, r *http.Request) {
	st := s.requireStore(w)
	if st == nil {
		return
	}
	id, err := strconv.Atoi(r.PathValue("id"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	if !st.RemoveReaction(id) {
		writeErr(w, http.StatusNotFound, "reaction not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"success": true})
}

func (s *Server) handleOperatorReactionLog(w http.ResponseWriter, r *http.Request) {
	st := s.requireStore(w)
	if st == nil {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"entries": st.ReactionLog()})
}

func (s *Server) handleOperatorAudit(w http.ResponseWriter, r *http.Request) {
	st := s.requireStore(w)
	if st == nil {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"entries": st.Audit(),
		"hint":    "This UI does not see other sliver-client operators. Full audit needs a new Sliver RPC.",
	})
}

func (s *Server) watchReactions(hub *sliver.EventHub, c *sliver.Client) {
	if s.store == nil || hub == nil {
		return
	}
	id, ch := hub.Subscribe()
	s.mu.Lock()
	s.reactID = id
	s.mu.Unlock()
	go func() {
		for ev := range ch {
			s.dispatchReactions(c, ev)
		}
	}()
}

func (s *Server) dispatchReactions(c *sliver.Client, ev sliver.EventView) {
	if s.store == nil || c == nil {
		return
	}
	reactions := s.store.On(ev.Type)
	if len(reactions) == 0 {
		return
	}
	target := ""
	sessionID := ""
	if ev.Session != nil {
		sessionID = ev.Session.ID
		target = ev.Session.ID
	}
	if ev.Beacon != nil && target == "" {
		target = ev.Beacon.ID
	}
	for _, re := range reactions {
		for _, line := range re.Commands {
			verb := operator.NormalizeCommand(line)
			if verb == "" {
				s.store.LogReaction(operator.ReactionHit{
					EventType: ev.Type,
					Command:   line,
					Target:    target,
					Result:    "skipped: this UI runs whoami/ps/pwd/ifconfig/screenshot only",
					Skipped:   true,
				})
				continue
			}
			result := s.runReactionCommand(c, ev, sessionID, verb)
			s.store.LogReaction(operator.ReactionHit{
				EventType: ev.Type,
				Command:   verb,
				Target:    target,
				Result:    result,
			})
		}
	}
}

func (s *Server) runReactionCommand(c *sliver.Client, ev sliver.EventView, sessionID, verb string) string {
	switch verb {
	case "whoami":
		user := ""
		osName := ""
		if ev.Session != nil {
			user = ev.Session.Username
			osName = ev.Session.OS
			sessionID = ev.Session.ID
		} else if ev.Beacon != nil {
			user = ev.Beacon.Username
			osName = ev.Beacon.OS
		}
		out := "Logon ID: " + user
		if strings.EqualFold(osName, "windows") && sessionID != "" {
			if tok, err := c.CurrentTokenOwner(sessionID); err == nil && tok != "" {
				out += "\nToken: " + tok
			}
		}
		return out
	case "pwd":
		if sessionID == "" {
			return "pwd needs an interactive session"
		}
		p, err := c.Pwd(sessionID)
		if err != nil {
			return err.Error()
		}
		return p
	case "ps":
		if sessionID == "" {
			return "ps needs an interactive session"
		}
		ps, err := c.Ps(sessionID)
		if err != nil {
			return err.Error()
		}
		return fmt.Sprintf("%d processes", len(ps))
	case "ifconfig":
		if sessionID == "" {
			return "ifconfig needs an interactive session"
		}
		ifs, err := c.Ifconfig(sessionID)
		if err != nil {
			return err.Error()
		}
		return fmt.Sprintf("%d interfaces", len(ifs))
	case "screenshot":
		if sessionID == "" {
			return "screenshot needs an interactive session"
		}
		b64, err := c.Screenshot(sessionID)
		if err != nil {
			return err.Error()
		}
		id, err := c.LootAdd(&sliver.LootAddRequest{
			Type:        "file",
			Name:        "reaction-screenshot",
			FileName:    "reaction-screenshot.png",
			FileType:    "binary",
			FileDataB64: b64,
		})
		if err != nil {
			return err.Error()
		}
		return "loot " + id
	default:
		return "skipped"
	}
}

func (s *Server) withAudit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		if s.store == nil {
			return
		}
		if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
			return
		}
		path := r.URL.Path
		if !strings.HasPrefix(path, "/api/") {
			return
		}
		if strings.HasPrefix(path, "/api/auth/") {
			return
		}
		user, op := s.actor(r)
		s.store.AppendAudit(operator.AuditEntry{
			Time:     time.Now().UTC().Format(time.RFC3339),
			User:     user,
			Operator: op,
			Method:   r.Method,
			Path:     path,
			Action:   r.Method + " " + path,
			Status:   rec.status,
		})
	})
}
