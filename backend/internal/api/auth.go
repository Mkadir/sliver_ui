package api

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	authCookieName = "sliverui_session"
	authSessionTTL = 24 * time.Hour
)

type authSession struct {
	user    string
	expires time.Time
}

// AuthGate protects /api and /ws when SLIVER_UI_USER and SLIVER_UI_PASS are set.
// If either env var is empty, authentication is disabled.
type AuthGate struct {
	user string
	pass string

	mu       sync.Mutex
	sessions map[string]authSession
}

func NewAuthGateFromEnv() *AuthGate {
	user := strings.TrimSpace(os.Getenv("SLIVER_UI_USER"))
	pass := os.Getenv("SLIVER_UI_PASS")
	g := &AuthGate{
		user:     user,
		pass:     pass,
		sessions: make(map[string]authSession),
	}
	if g.Enabled() {
		log.Printf("[auth] UI login enabled for user %q (set SLIVER_UI_USER/SLIVER_UI_PASS)", user)
	} else {
		log.Printf("[auth] UI login disabled (SLIVER_UI_USER / SLIVER_UI_PASS not both set)")
	}
	return g
}

func (g *AuthGate) Enabled() bool {
	return g != nil && g.user != "" && g.pass != ""
}

func (g *AuthGate) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !g.Enabled() {
			next.ServeHTTP(w, r)
			return
		}
		path := r.URL.Path
		// Public auth endpoints + static assets / SPA shell.
		if path == "/api/auth/login" || path == "/api/auth/me" {
			next.ServeHTTP(w, r)
			return
		}
		if !strings.HasPrefix(path, "/api/") && !strings.HasPrefix(path, "/ws/") {
			next.ServeHTTP(w, r)
			return
		}
		if g.sessionUser(r) == "" {
			writeErr(w, http.StatusUnauthorized, "authentication required")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (g *AuthGate) handleLogin(w http.ResponseWriter, r *http.Request) {
	if !g.Enabled() {
		writeJSON(w, http.StatusOK, map[string]any{"success": true, "enabled": false})
		return
	}
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	userOK := subtle.ConstantTimeCompare([]byte(req.Username), []byte(g.user)) == 1
	passOK := subtle.ConstantTimeCompare([]byte(req.Password), []byte(g.pass)) == 1
	if !userOK || !passOK {
		writeErr(w, http.StatusUnauthorized, "invalid username or password")
		return
	}
	token, err := g.createSession(req.Username)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "failed to create session")
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     authCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(authSessionTTL.Seconds()),
	})
	writeJSON(w, http.StatusOK, map[string]any{"success": true, "user": req.Username})
}

func (g *AuthGate) handleLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(authCookieName); err == nil && c.Value != "" {
		g.mu.Lock()
		delete(g.sessions, c.Value)
		g.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{
		Name:     authCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
	writeJSON(w, http.StatusOK, map[string]any{"success": true})
}

func (g *AuthGate) handleMe(w http.ResponseWriter, r *http.Request) {
	if !g.Enabled() {
		writeJSON(w, http.StatusOK, map[string]any{
			"enabled":       false,
			"authenticated": true,
			"user":          "",
		})
		return
	}
	user := g.sessionUser(r)
	writeJSON(w, http.StatusOK, map[string]any{
		"enabled":       true,
		"authenticated": user != "",
		"user":          user,
	})
}

func (g *AuthGate) createSession(user string) (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	token := hex.EncodeToString(b[:])
	g.mu.Lock()
	g.sessions[token] = authSession{user: user, expires: time.Now().Add(authSessionTTL)}
	g.mu.Unlock()
	return token, nil
}

func (g *AuthGate) sessionUser(r *http.Request) string {
	c, err := r.Cookie(authCookieName)
	if err != nil || c.Value == "" {
		return ""
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	sess, ok := g.sessions[c.Value]
	if !ok {
		return ""
	}
	if time.Now().After(sess.expires) {
		delete(g.sessions, c.Value)
		return ""
	}
	return sess.user
}
