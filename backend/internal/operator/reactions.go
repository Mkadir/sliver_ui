package operator

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ReactableEvents is the official sliver-client list (client/core/reactions.go).
var ReactableEvents = []string{
	"session-connected",
	"session-updated",
	"session-disconnected",
	"beacon-registered",
	"canary",
	"watchtower",
	"loot-added",
	"loot-removed",
}

// AllowedReactionCommands is what this UI will actually run. Other command
// lines are recorded as skipped — this is not a sliver-client REPL.
var AllowedReactionCommands = []string{
	"whoami",
	"ps",
	"pwd",
	"ifconfig",
	"screenshot",
}

type cliReaction struct {
	EventType string   `json:"event_type"`
	Commands  []string `json:"commands"`
}

func isReactable(eventType string) bool {
	for _, e := range ReactableEvents {
		if e == eventType {
			return true
		}
	}
	return false
}

// NormalizeCommand returns the allowlisted verb, or empty if this UI will skip it.
func NormalizeCommand(line string) string {
	fields := strings.Fields(strings.TrimSpace(line))
	if len(fields) == 0 {
		return ""
	}
	verb := strings.ToLower(fields[0])
	for _, a := range AllowedReactionCommands {
		if verb == a {
			return verb
		}
	}
	return ""
}

// Reactions returns a copy of configured reactions.
func (s *Store) Reactions() []Reaction {
	var out []Reaction
	s.read(func(d *disk) {
		out = append(out, d.Reactions...)
	})
	return out
}

// AddReaction appends a reaction and syncs ~/.sliver-client/reactions.json.
func (s *Store) AddReaction(eventType string, commands []string) (Reaction, error) {
	eventType = strings.TrimSpace(eventType)
	if !isReactable(eventType) {
		return Reaction{}, fmt.Errorf("non-reactable event type %q", eventType)
	}
	cleaned := make([]string, 0, len(commands))
	for _, c := range commands {
		c = strings.TrimSpace(c)
		if c != "" {
			cleaned = append(cleaned, c)
		}
	}
	if len(cleaned) == 0 {
		return Reaction{}, fmt.Errorf("at least one command is required")
	}
	var out Reaction
	err := s.mutate(func(d *disk) error {
		nextID := 1
		for _, r := range d.Reactions {
			if r.ID >= nextID {
				nextID = r.ID + 1
			}
		}
		out = Reaction{ID: nextID, EventType: eventType, Commands: cleaned}
		d.Reactions = append(d.Reactions, out)
		return nil
	})
	return out, err
}

// RemoveReaction deletes by id.
func (s *Store) RemoveReaction(id int) bool {
	removed := false
	_ = s.mutate(func(d *disk) error {
		keep := d.Reactions[:0]
		for _, r := range d.Reactions {
			if r.ID == id {
				removed = true
				continue
			}
			keep = append(keep, r)
		}
		d.Reactions = keep
		return nil
	})
	return removed
}

// On returns reactions for an event type.
func (s *Store) On(eventType string) []Reaction {
	var out []Reaction
	s.read(func(d *disk) {
		for _, r := range d.Reactions {
			if r.EventType == eventType {
				out = append(out, r)
			}
		}
	})
	return out
}

// LogReaction appends a hit (ran or skipped).
func (s *Store) LogReaction(h ReactionHit) {
	if h.Time == "" {
		h.Time = time.Now().UTC().Format(time.RFC3339)
	}
	_ = s.mutate(func(d *disk) error {
		d.ReactionLog = append(d.ReactionLog, h)
		if len(d.ReactionLog) > maxReactionLog {
			d.ReactionLog = d.ReactionLog[len(d.ReactionLog)-maxReactionLog:]
		}
		return nil
	})
}

// ReactionLog newest-first.
func (s *Store) ReactionLog() []ReactionHit {
	var out []ReactionHit
	s.read(func(d *disk) {
		out = make([]ReactionHit, len(d.ReactionLog))
		for i, e := range d.ReactionLog {
			out[len(d.ReactionLog)-1-i] = e
		}
	})
	return out
}

func (s *Store) importCLIReactions(d *disk) {
	raw, err := os.ReadFile(s.reactionsPath)
	if err != nil {
		return
	}
	var cli []cliReaction
	if err := json.Unmarshal(raw, &cli); err != nil {
		return
	}
	nextID := 1
	for _, r := range cli {
		if !isReactable(r.EventType) || len(r.Commands) == 0 {
			continue
		}
		d.Reactions = append(d.Reactions, Reaction{
			ID:        nextID,
			EventType: r.EventType,
			Commands:  r.Commands,
		})
		nextID++
	}
}

func (s *Store) syncCLIReactions(reactions []Reaction) error {
	cli := make([]cliReaction, 0, len(reactions))
	for _, r := range reactions {
		cli = append(cli, cliReaction{EventType: r.EventType, Commands: r.Commands})
	}
	raw, err := json.MarshalIndent(cli, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(s.reactionsPath)
	if err := os.MkdirAll(dir, defaultDirPerm); err != nil {
		return err
	}
	tmp := s.reactionsPath + ".tmp"
	if err := os.WriteFile(tmp, raw, defaultFilePerm); err != nil {
		return err
	}
	if err := os.Rename(tmp, s.reactionsPath); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}
