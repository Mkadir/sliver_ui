package operator

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	storeFileName   = "operator-store.json"
	cliReactionFile = "reactions.json"
	maxAudit        = 500
	maxReactionLog  = 200
	defaultFilePerm = 0o600
	defaultDirPerm  = 0o700
)

// Note is local-only metadata keyed by a Sliver UUID.
type Note struct {
	UUID      string   `json:"uuid"`
	Kind      string   `json:"kind"`
	Tags      []string `json:"tags"`
	Comment   string   `json:"comment"`
	Campaign  string   `json:"campaign"`
	UpdatedAt string   `json:"updated_at"`
}

// Lock is an advisory session lock. sliver-client ignores it.
type Lock struct {
	SessionID string `json:"session_id"`
	User      string `json:"user"`
	Operator  string `json:"operator"`
	Since     string `json:"since"`
}

// AuditEntry is one MUTATE from this UI process.
type AuditEntry struct {
	Time     string `json:"time"`
	User     string `json:"user"`
	Operator string `json:"operator"`
	Method   string `json:"method"`
	Path     string `json:"path"`
	Action   string `json:"action"`
	Status   int    `json:"status"`
}

// Reaction matches the official CLI disk fields (event_type + commands).
// ID is assigned by this store; the CLI file omits it.
type Reaction struct {
	ID        int      `json:"id"`
	EventType string   `json:"event_type"`
	Commands  []string `json:"commands"`
}

// ReactionHit is one allowlisted command this UI actually ran.
type ReactionHit struct {
	Time      string `json:"time"`
	EventType string `json:"event_type"`
	Command   string `json:"command"`
	Target    string `json:"target"`
	Result    string `json:"result"`
	Skipped   bool   `json:"skipped,omitempty"`
}

type disk struct {
	Notes       map[string]Note `json:"notes"`
	Locks       map[string]Lock `json:"locks"`
	Audit       []AuditEntry    `json:"audit"`
	Reactions   []Reaction      `json:"reactions"`
	ReactionLog []ReactionHit   `json:"reaction_log"`
}

// Store is a JSON file on this UI host. It is not a Sliver RPC.
type Store struct {
	mu            sync.Mutex
	path          string
	reactionsPath string
}

// DefaultDir is $SLIVER_UI_DATA, else $XDG_DATA_HOME/sliver-ui, else ~/.local/share/sliver-ui.
func DefaultDir() string {
	if d := strings.TrimSpace(os.Getenv("SLIVER_UI_DATA")); d != "" {
		return d
	}
	if xdg := strings.TrimSpace(os.Getenv("XDG_DATA_HOME")); xdg != "" {
		return filepath.Join(xdg, "sliver-ui")
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return "sliver-ui-data"
	}
	return filepath.Join(home, ".local", "share", "sliver-ui")
}

// CLIReactionsPath is ~/.sliver-client/reactions.json (official sliver-client format).
// SLIVER_UI_REACTIONS overrides the path (tests use a temp file).
func CLIReactionsPath() string {
	if p := strings.TrimSpace(os.Getenv("SLIVER_UI_REACTIONS")); p != "" {
		return p
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return filepath.Join(".", cliReactionFile)
	}
	return filepath.Join(home, ".sliver-client", cliReactionFile)
}

// Open a store under dir. reactionsPath is the official CLI file (may be the same dir in tests).
func Open(dir, reactionsPath string) *Store {
	if dir == "" {
		dir = DefaultDir()
	}
	if reactionsPath == "" {
		reactionsPath = CLIReactionsPath()
	}
	_ = os.MkdirAll(dir, defaultDirPerm)
	return &Store{
		path:          filepath.Join(dir, storeFileName),
		reactionsPath: reactionsPath,
	}
}

func emptyDisk() *disk {
	return &disk{
		Notes:       map[string]Note{},
		Locks:       map[string]Lock{},
		Audit:       []AuditEntry{},
		Reactions:   []Reaction{},
		ReactionLog: []ReactionHit{},
	}
}

func (s *Store) load() (*disk, error) {
	data, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			d := emptyDisk()
			s.importCLIReactions(d)
			return d, nil
		}
		return nil, err
	}
	d := emptyDisk()
	if err := json.Unmarshal(data, d); err != nil {
		return nil, err
	}
	if d.Notes == nil {
		d.Notes = map[string]Note{}
	}
	if d.Locks == nil {
		d.Locks = map[string]Lock{}
	}
	if len(d.Reactions) == 0 {
		s.importCLIReactions(d)
	}
	return d, nil
}

func (s *Store) save(d *disk) error {
	if err := os.MkdirAll(filepath.Dir(s.path), defaultDirPerm); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, raw, defaultFilePerm); err != nil {
		return err
	}
	if err := os.Rename(tmp, s.path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return s.syncCLIReactions(d.Reactions)
}

func (s *Store) mutate(fn func(*disk) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, err := s.load()
	if err != nil {
		return err
	}
	if err := fn(d); err != nil {
		return err
	}
	return s.save(d)
}

func (s *Store) read(fn func(*disk)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, err := s.load()
	if err != nil {
		fn(emptyDisk())
		return
	}
	fn(d)
}

// Notes returns a copy of all notes.
func (s *Store) Notes() map[string]Note {
	out := map[string]Note{}
	s.read(func(d *disk) {
		for k, v := range d.Notes {
			out[k] = v
		}
	})
	return out
}

// Note returns the note for uuid, or a zero note with that uuid.
func (s *Store) Note(uuid string) Note {
	uuid = strings.TrimSpace(uuid)
	var n Note
	s.read(func(d *disk) {
		n = d.Notes[uuid]
	})
	if n.UUID == "" {
		n.UUID = uuid
		n.Tags = []string{}
	}
	if n.Tags == nil {
		n.Tags = []string{}
	}
	return n
}

// PutNote upserts tags/comment/campaign for uuid.
func (s *Store) PutNote(uuid, kind string, tags []string, comment, campaign string) (Note, error) {
	uuid = strings.TrimSpace(uuid)
	if uuid == "" {
		return Note{}, fmt.Errorf("uuid is required")
	}
	cleaned := uniqueTags(tags)
	var out Note
	err := s.mutate(func(d *disk) error {
		n := d.Notes[uuid]
		n.UUID = uuid
		if kind != "" {
			n.Kind = kind
		}
		n.Tags = cleaned
		n.Comment = comment
		n.Campaign = campaign
		n.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
		d.Notes[uuid] = n
		out = n
		return nil
	})
	return out, err
}

// DeleteNote removes the note for uuid.
func (s *Store) DeleteNote(uuid string) error {
	uuid = strings.TrimSpace(uuid)
	return s.mutate(func(d *disk) error {
		delete(d.Notes, uuid)
		return nil
	})
}

// Locks returns a copy of advisory session locks.
func (s *Store) Locks() map[string]Lock {
	out := map[string]Lock{}
	s.read(func(d *disk) {
		for k, v := range d.Locks {
			out[k] = v
		}
	})
	return out
}

// LockFor returns the lock for a session id, or ok=false.
func (s *Store) LockFor(sessionID string) (Lock, bool) {
	sessionID = strings.TrimSpace(sessionID)
	var l Lock
	var ok bool
	s.read(func(d *disk) {
		l, ok = d.Locks[sessionID]
	})
	return l, ok
}

// AcquireLock overwrites the advisory lock. Previous holder is returned.
func (s *Store) AcquireLock(sessionID, user, operator string) (Lock, *Lock, error) {
	sessionID = strings.TrimSpace(sessionID)
	if sessionID == "" {
		return Lock{}, nil, fmt.Errorf("session id is required")
	}
	if user == "" {
		user = "local"
	}
	var next Lock
	var prev *Lock
	err := s.mutate(func(d *disk) error {
		if old, ok := d.Locks[sessionID]; ok {
			cp := old
			prev = &cp
		}
		next = Lock{
			SessionID: sessionID,
			User:      user,
			Operator:  operator,
			Since:     time.Now().UTC().Format(time.RFC3339),
		}
		d.Locks[sessionID] = next
		return nil
	})
	return next, prev, err
}

// ReleaseLock drops the lock for sessionID. If user is non-empty, only that holder can release.
func (s *Store) ReleaseLock(sessionID, user string) error {
	sessionID = strings.TrimSpace(sessionID)
	return s.mutate(func(d *disk) error {
		cur, ok := d.Locks[sessionID]
		if !ok {
			return nil
		}
		if user != "" && cur.User != user {
			return fmt.Errorf("lock held by %s", cur.User)
		}
		delete(d.Locks, sessionID)
		return nil
	})
}

// AppendAudit records a successful or attempted MUTATE from this UI.
func (s *Store) AppendAudit(e AuditEntry) {
	if e.Time == "" {
		e.Time = time.Now().UTC().Format(time.RFC3339)
	}
	_ = s.mutate(func(d *disk) error {
		d.Audit = append(d.Audit, e)
		if len(d.Audit) > maxAudit {
			d.Audit = d.Audit[len(d.Audit)-maxAudit:]
		}
		return nil
	})
}

// Audit returns newest-first copies.
func (s *Store) Audit() []AuditEntry {
	var out []AuditEntry
	s.read(func(d *disk) {
		out = make([]AuditEntry, len(d.Audit))
		for i, e := range d.Audit {
			out[len(d.Audit)-1-i] = e
		}
	})
	return out
}

func uniqueTags(in []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(in))
	for _, t := range in {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}
		key := strings.ToLower(t)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, t)
	}
	return out
}
