package sliver

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

// LootReport is a lite operator report over existing RPCs (loot, creds, hosts, canaries).
type LootReport struct {
	GeneratedAt string              `json:"generated_at"`
	Loot        []LootReportItem    `json:"loot"`
	Canaries    []CanaryView        `json:"canaries"`
	Hosts       []HostView          `json:"hosts"`
	Implants    []LootReportImplant `json:"implants"`
}

// LootReportItem is a loot/credential row without file blobs.
type LootReportItem struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	LootType string `json:"loot_type"`
	FileType string `json:"file_type,omitempty"`
	File     string `json:"file,omitempty"`
	Size     int64  `json:"size,omitempty"`
	CredUser string `json:"cred_user,omitempty"`
	HasCred  bool   `json:"has_cred,omitempty"`
}

// LootReportImplant is a stored build plus any process-local SHA-256.
type LootReportImplant struct {
	Name   string `json:"name"`
	OS     string `json:"os"`
	Arch   string `json:"arch"`
	SHA256 string `json:"sha256,omitempty"`
}

// BuildLootReport gathers loot, canaries, hosts, and implant names for a downloadable report.
func (c *Client) BuildLootReport() (*LootReport, error) {
	rep := &LootReport{
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Loot:        []LootReportItem{},
		Canaries:    []CanaryView{},
		Hosts:       []HostView{},
		Implants:    []LootReportImplant{},
	}
	if loot, err := c.LootAll(); err != nil {
		return nil, err
	} else {
		for _, l := range loot {
			rep.Loot = append(rep.Loot, LootReportItem{
				ID:       l.ID,
				Name:     l.Name,
				LootType: l.LootType,
				FileType: l.FileType,
				File:     l.File,
				Size:     l.Size,
				CredUser: l.CredUser,
				HasCred:  l.CredPassword != "" || l.CredAPIKey != "",
			})
		}
	}
	if cans, err := c.Canaries(); err != nil {
		return nil, err
	} else {
		rep.Canaries = cans
	}
	if hosts, err := c.Hosts(); err != nil {
		return nil, err
	} else {
		rep.Hosts = hosts
	}
	if builds, err := c.ImplantBuilds(); err != nil {
		return nil, err
	} else {
		hashes := artifactHashByName()
		for _, b := range builds {
			rep.Implants = append(rep.Implants, LootReportImplant{
				Name:   b.Name,
				OS:     b.OS,
				Arch:   b.Arch,
				SHA256: hashes[b.Name],
			})
		}
		sort.Slice(rep.Implants, func(i, j int) bool { return rep.Implants[i].Name < rep.Implants[j].Name })
	}
	return rep, nil
}

func artifactHashByName() map[string]string {
	artifactMu.Lock()
	defer artifactMu.Unlock()
	out := make(map[string]string, len(artifactHashes))
	for hash, name := range artifactHashes {
		out[name] = hash
	}
	return out
}

// LootReportJSON encodes the report.
func (r *LootReport) JSON() ([]byte, error) {
	if r == nil {
		return []byte("{}"), nil
	}
	return json.MarshalIndent(r, "", "  ")
}

// LootReportMarkdown is a lite Markdown export (credentials listed as present, not dumped).
func (r *LootReport) Markdown() string {
	if r == nil {
		return ""
	}
	var b bytes.Buffer
	fmt.Fprintf(&b, "# Sliver UI loot report\n\nGenerated %s\n\n", r.GeneratedAt)
	fmt.Fprintf(&b, "## Loot (%d)\n\n", len(r.Loot))
	if len(r.Loot) == 0 {
		b.WriteString("_None._\n\n")
	} else {
		b.WriteString("| Name | Type | File | Size |\n|---|---|---|---|\n")
		for _, l := range r.Loot {
			cred := ""
			if l.HasCred {
				cred = " (credential present)"
			}
			fmt.Fprintf(&b, "| %s | %s%s | %s | %d |\n", mdCell(l.Name), mdCell(l.LootType), cred, mdCell(l.File), l.Size)
		}
		b.WriteString("\n")
	}
	fmt.Fprintf(&b, "## Canaries (%d)\n\n", len(r.Canaries))
	if len(r.Canaries) == 0 {
		b.WriteString("_None._\n\n")
	} else {
		b.WriteString("| Domain | Implant | Status | Hits |\n|---|---|---|---|\n")
		for _, c := range r.Canaries {
			status := "clean"
			if c.Triggered {
				status = "burned"
			}
			fmt.Fprintf(&b, "| %s | %s | %s | %d |\n", mdCell(c.Domain), mdCell(c.ImplantName), status, c.Count)
		}
		b.WriteString("\n")
	}
	fmt.Fprintf(&b, "## Hosts (%d)\n\n", len(r.Hosts))
	if len(r.Hosts) == 0 {
		b.WriteString("_None._\n\n")
	} else {
		b.WriteString("| Hostname | UUID | OS | IOCs |\n|---|---|---|---|\n")
		for _, h := range r.Hosts {
			fmt.Fprintf(&b, "| %s | %s | %s | %d |\n", mdCell(h.Hostname), mdCell(h.HostUUID), mdCell(h.OSVersion), len(h.IOCs))
		}
		b.WriteString("\n")
	}
	fmt.Fprintf(&b, "## Implants (%d)\n\n", len(r.Implants))
	if len(r.Implants) == 0 {
		b.WriteString("_None._\n\n")
	} else {
		b.WriteString("| Name | OS/Arch | SHA-256 |\n|---|---|---|\n")
		for _, i := range r.Implants {
			hash := i.SHA256
			if hash == "" {
				hash = "—"
			}
			fmt.Fprintf(&b, "| %s | %s/%s | `%s` |\n", mdCell(i.Name), mdCell(i.OS), mdCell(i.Arch), hash)
		}
		b.WriteString("\n")
	}
	b.WriteString("Passwords and API keys are stored as loot on the teamserver; this report only notes that a credential exists.\n")
	return b.String()
}

func mdCell(s string) string {
	s = strings.ReplaceAll(s, "|", "\\|")
	s = strings.ReplaceAll(s, "\n", " ")
	if s == "" {
		return "—"
	}
	return s
}
