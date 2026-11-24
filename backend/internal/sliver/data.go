package sliver

import (
	"context"
	"fmt"
	"time"

	"github.com/bishopfox/sliver/protobuf/clientpb"
	"github.com/bishopfox/sliver/protobuf/commonpb"
	"google.golang.org/protobuf/proto"
)

// SessionView is the JSON shape returned by the API.
type SessionView struct {
	ID            string `json:"ID"`
	Name          string `json:"Name"`
	UUID          string `json:"UUID"`
	Hostname      string `json:"Hostname"`
	Username      string `json:"Username"`
	UID           string `json:"UID"`
	GID           string `json:"GID"`
	PID           int32  `json:"PID"`
	OS            string `json:"OS"`
	Arch          string `json:"Arch"`
	Transport     string `json:"Transport"`
	RemoteAddress string `json:"RemoteAddress"`
	LastCheckin   string `json:"LastCheckin"`
	ActiveC2      string `json:"ActiveC2"`
	Locale        string `json:"Locale"`
	AgentVersion  string `json:"AgentVersion"`
	IsDead        bool   `json:"IsDead"`
	IsInteractive bool   `json:"IsInteractive"`
}

// BeaconView is the JSON shape for a beacon.
type BeaconView struct {
	ID            string `json:"ID"`
	Name          string `json:"Name"`
	UUID          string `json:"UUID"`
	Hostname      string `json:"Hostname"`
	Username      string `json:"Username"`
	OS            string `json:"OS"`
	Arch          string `json:"Arch"`
	Transport     string `json:"Transport"`
	RemoteAddress string `json:"RemoteAddress"`
	LastCheckin   string `json:"LastCheckin"`
	NextCheckin   string `json:"NextCheckin"`
	Interval      int64  `json:"Interval"`
	Jitter        int64  `json:"Jitter"`
	ActiveC2      string `json:"ActiveC2"`
}

// JobView is the JSON shape for a job.
type JobView struct {
	ID      uint32   `json:"ID"`
	Name    string   `json:"Name"`
	Type    string   `json:"Protocol"`
	Port    uint32   `json:"Port"`
	Domains []string `json:"Domains"`
}

func unixTimeString(sec int64) string {
	if sec == 0 {
		return ""
	}
	return time.Unix(sec, 0).UTC().Format(time.RFC3339)
}

// Sessions lists active interactive sessions.
func (c *Client) Sessions() ([]SessionView, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	resp, err := c.RPC.GetSessions(ctx, &commonpb.Empty{})
	if err != nil {
		return nil, err
	}
	out := make([]SessionView, 0, len(resp.Sessions))
	for _, s := range resp.Sessions {
		if s == nil {
			continue
		}
		out = append(out, sessionToView(s))
	}
	return out, nil
}

// Beacons lists active beacons.
func (c *Client) Beacons() ([]BeaconView, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	resp, err := c.RPC.GetBeacons(ctx, &commonpb.Empty{})
	if err != nil {
		return nil, err
	}
	out := make([]BeaconView, 0, len(resp.Beacons))
	for _, b := range resp.Beacons {
		if b == nil {
			continue
		}
		out = append(out, beaconToView(b))
	}
	return out, nil
}

// Beacon fetches a single beacon by id.
func (c *Client) Beacon(id string) (*BeaconView, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	resp, err := c.RPC.GetBeacon(ctx, &clientpb.Beacon{ID: id})
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return nil, nil
	}
	v := beaconToView(resp)
	return &v, nil
}

// Jobs lists active listener jobs.
func (c *Client) Jobs() ([]JobView, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	resp, err := c.RPC.GetJobs(ctx, &commonpb.Empty{})
	if err != nil {
		return nil, err
	}
	out := make([]JobView, 0, len(resp.Active))
	for _, j := range resp.Active {
		if j == nil {
			continue
		}
		// The server reports its own client/gRPC listener as a job
		// ("grpc/mtls", Description "client listener"). That is the
		// port sliver clients (and this UI) connect to — not an implant
		// C2 listener — so it must not show up on the listeners page.
		if j.Description == "client listener" {
			continue
		}
		domains := j.Domains
		if domains == nil {
			domains = []string{}
		}
		out = append(out, JobView{
			ID:      j.ID,
			Name:    j.Name,
			Type:    j.Protocol,
			Port:    j.Port,
			Domains: domains,
		})
	}
	return out, nil
}

// ListenerStartOptions carries optional camouflage fields for HTTP(S) listeners.
type ListenerStartOptions struct {
	Domain          string
	Website         string
	ACME            bool
	EnforceOTP      bool
	LongPollTimeout int64
	LongPollJitter  int64
}

// StartListener starts a new listener (mTLS, HTTP(S), DNS, WireGuard).
func (c *Client) StartListener(jobType, addr string, port uint32, tls bool, opts *ListenerStartOptions) (uint32, error) {
	if opts == nil {
		opts = &ListenerStartOptions{}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	switch jobType {
	case "mtls":
		resp, err := c.RPC.StartMTLSListener(ctx, &clientpb.MTLSListenerReq{
			Host: addr,
			Port: port,
		})
		if err != nil {
			return 0, err
		}
		return resp.JobID, nil
	case "http", "https":
		req := &clientpb.HTTPListenerReq{
			Host:            addr,
			Port:            port,
			Domain:          opts.Domain,
			Website:         opts.Website,
			ACME:            opts.ACME,
			EnforceOTP:      opts.EnforceOTP,
			LongPollTimeout: opts.LongPollTimeout,
			LongPollJitter:  opts.LongPollJitter,
		}
		if jobType == "https" || tls {
			req.Secure = true
		}
		resp, err := c.RPC.StartHTTPListener(ctx, req)
		if err != nil {
			return 0, err
		}
		return resp.JobID, nil
	case "dns":
		domains := []string{addr}
		if opts.Domain != "" {
			domains = []string{opts.Domain}
		}
		resp, err := c.RPC.StartDNSListener(ctx, &clientpb.DNSListenerReq{
			Domains: domains,
		})
		if err != nil {
			return 0, err
		}
		return resp.JobID, nil
	case "wireguard":
		resp, err := c.RPC.StartWGListener(ctx, &clientpb.WGListenerReq{
			Host: addr,
			Port: port,
		})
		if err != nil {
			return 0, err
		}
		return resp.JobID, nil
	default:
		return 0, fmt.Errorf("unsupported listener type %q", jobType)
	}
}

// StopJob stops a job by ID.
func (c *Client) StopJob(jobID uint32) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err := c.RPC.KillJob(ctx, &clientpb.KillJobReq{ID: jobID})
	return err
}

// EventView is the JSON shape for a server event.
type EventView struct {
	Type    string         `json:"Type"`
	Err     string         `json:"Err"`
	Session *SessionView   `json:"Session,omitempty"`
	Beacon  *BeaconView    `json:"Beacon,omitempty"`
	Job     *JobView       `json:"Job,omitempty"`
	Data    map[string]any `json:"Data"`
}

func eventToView(e *clientpb.Event) EventView {
	ev := EventView{
		Type: e.EventType,
		Err:  e.Err,
		Data: map[string]any{},
	}
	if e.Session != nil {
		sv := sessionToView(e.Session)
		ev.Session = &sv
	}
	if e.Job != nil {
		domains := e.Job.Domains
		if domains == nil {
			domains = []string{}
		}
		ev.Job = &JobView{ID: e.Job.ID, Name: e.Job.Name, Type: e.Job.Protocol, Port: e.Job.Port, Domains: domains}
	}
	// v1.7.3 clientpb.Event has no Beacon field; the server marshals the
	// beacon (or task) into Data.
	if len(e.Data) > 0 {
		ev.Data["raw"] = string(e.Data)
		switch e.EventType {
		case "beacon-registered":
			b := &clientpb.Beacon{}
			if err := proto.Unmarshal(e.Data, b); err == nil && b.GetID() != "" {
				bv := beaconToView(b)
				ev.Beacon = &bv
			}
		case "beacon-taskresult":
			task := &clientpb.BeaconTask{}
			if err := proto.Unmarshal(e.Data, task); err == nil && task.GetID() != "" {
				ev.Data["task_id"] = task.ID
				ev.Data["beacon_id"] = task.BeaconID
				ev.Data["description"] = task.Description
				ev.Data["state"] = task.State
			}
		}
	}
	return ev
}

// Events is a one-shot drain of the Sliver Events stream with a timeout.
// The live UI uses EventHub (started from SetClient) instead: this method
// opens a second stream and still cannot replay history.
func (c *Client) Events() ([]EventView, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	stream, err := c.RPC.Events(ctx, &commonpb.Empty{})
	if err != nil {
		return nil, err
	}
	out := make([]EventView, 0, 50)
	for {
		e, err := stream.Recv()
		if err != nil {
			break
		}
		if e != nil {
			out = append(out, eventToView(e))
		}
	}
	return out, nil
}

func sessionToView(s *clientpb.Session) SessionView {
	return SessionView{
		ID:            s.ID,
		Name:          s.Name,
		UUID:          s.UUID,
		Hostname:      s.Hostname,
		Username:      s.Username,
		UID:           s.UID,
		GID:           s.GID,
		PID:           s.PID,
		OS:            s.OS,
		Arch:          s.Arch,
		Transport:     s.Transport,
		RemoteAddress: s.RemoteAddress,
		LastCheckin:   unixTimeString(s.LastCheckin),
		ActiveC2:      s.ActiveC2,
		// Sliver v1.15.16 的 clientpb.Session 无 Locale 字段，留空
		Locale:       "",
		AgentVersion: s.Version,
		IsDead:       s.IsDead,
		// Sliver v1.15.16 无 IsInteractive 字段，用 !IsDead 作为近似
		IsInteractive: !s.IsDead,
	}
}

func beaconToView(b *clientpb.Beacon) BeaconView {
	interval := durationToSeconds(b.Interval)
	jitter := durationToSeconds(b.Jitter)
	next := b.NextCheckin
	// Generate used to store interval as seconds-in-a-Duration-field (60ns).
	// The implant then reports NextCheckin = now+0, so the UI showed "now"
	// for both columns. Fall back to last+interval so the row looks alive.
	if next <= b.LastCheckin && interval > 0 {
		next = b.LastCheckin + interval
	}
	return BeaconView{
		ID:            b.ID,
		Name:          b.Name,
		UUID:          b.UUID,
		Hostname:      b.Hostname,
		Username:      b.Username,
		OS:            b.OS,
		Arch:          b.Arch,
		Transport:     b.Transport,
		RemoteAddress: b.RemoteAddress,
		LastCheckin:   unixTimeString(b.LastCheckin),
		NextCheckin:   unixTimeString(next),
		Interval:      interval,
		Jitter:        jitter,
		ActiveC2:      b.ActiveC2,
	}
}
