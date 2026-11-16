package sliver

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/bishopfox/sliver/protobuf/clientpb"
	"github.com/bishopfox/sliver/protobuf/commonpb"
	"github.com/bishopfox/sliver/protobuf/cpmfczjv"
)

// NetConnPivotView is the JSON shape of a single pivot peer connection.
type NetConnPivotView struct {
	PeerID        int64  `json:"PeerID"`
	RemoteAddress string `json:"RemoteAddress"`
}

// PivotListenerView is the JSON shape of a pivot listener.
type PivotListenerView struct {
	ID          uint32             `json:"ID"`
	Type        string             `json:"Type"`
	BindAddress string             `json:"BindAddress"`
	Pivots      []NetConnPivotView `json:"Pivots"`
}

func pivotTypeString(t cpmfczjv.HkbctLqhw) string {
	switch t {
	case cpmfczjv.PivotType_TCP:
		return "TCP"
	case cpmfczjv.PivotType_UDP:
		return "UDP"
	case cpmfczjv.PivotType_NamedPipe:
		return "NamedPipe"
	default:
		return "TCP"
	}
}

func pivotTypeFromString(s string) cpmfczjv.HkbctLqhw {
	switch strings.ToLower(s) {
	case "udp":
		return cpmfczjv.PivotType_UDP
	case "namedpipe", "named-pipe", "pipe":
		return cpmfczjv.PivotType_NamedPipe
	default:
		return cpmfczjv.PivotType_TCP
	}
}

func pivotListenerToView(l *cpmfczjv.HkbctJaenolez) PivotListenerView {
	v := PivotListenerView{Type: "TCP"}
	if l == nil {
		return v
	}
	v.ID = l.ID
	v.Type = pivotTypeString(l.Type)
	v.BindAddress = l.BindAddress
	v.Pivots = make([]NetConnPivotView, 0, len(l.Pivots))
	for _, p := range l.Pivots {
		if p == nil {
			continue
		}
		v.Pivots = append(v.Pivots, NetConnPivotView{
			PeerID:        p.PeerID,
			RemoteAddress: p.RemoteAddress,
		})
	}
	return v
}

// PivotSessionListeners lists all pivot listeners running on the session.
func (c *Client) PivotSessionListeners(sessionID string) ([]PivotListenerView, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	resp, err := c.RPC.PivotSessionListeners(ctx, &cpmfczjv.HkbctJaenolezgNkk{
		Request: &commonpb.Request{SessionID: sessionID},
	})
	if err != nil {
		return nil, err
	}
	if resp.GetResponse().GetErr() != "" {
		return nil, errors.New(resp.GetResponse().GetErr())
	}
	out := make([]PivotListenerView, 0, len(resp.Listeners))
	for _, l := range resp.Listeners {
		out = append(out, pivotListenerToView(l))
	}
	return out, nil
}

// PivotStartListener instructs the session to start a pivot listener.
func (c *Client) PivotStartListener(sessionID, pivotType, bindAddress string) (PivotListenerView, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	resp, err := c.RPC.PivotStartListener(ctx, &cpmfczjv.HkbctEnwlzDaynerebBgy{
		Type:        pivotTypeFromString(pivotType),
		BindAddress: bindAddress,
		Request:     &commonpb.Request{SessionID: sessionID},
	})
	if err != nil {
		return PivotListenerView{}, err
	}
	if resp.GetResponse().GetErr() != "" {
		return PivotListenerView{}, errors.New(resp.GetResponse().GetErr())
	}
	return pivotListenerToView(resp), nil
}

// PivotStopListener instructs the session to stop a pivot listener.
func (c *Client) PivotStopListener(sessionID string, id uint32) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_, err := c.RPC.PivotStopListener(ctx, &cpmfczjv.HkbctEnijNeqbczknHya{
		ID:      id,
		Request: &commonpb.Request{SessionID: sessionID},
	})
	return err
}

// PivotGraphEntryView is the JSON shape of a pivot graph node.
type PivotGraphEntryView struct {
	PeerID        int64                 `json:"PeerID"`
	Name          string                `json:"Name"`
	SessionID     string                `json:"SessionID"`
	Hostname      string                `json:"Hostname"`
	Username      string                `json:"Username"`
	OS            string                `json:"OS"`
	Transport     string                `json:"Transport"`
	RemoteAddress string                `json:"RemoteAddress"`
	Children      []PivotGraphEntryView `json:"Children"`
}

// PivotGraphView is the JSON shape of the server's pivot graph.
type PivotGraphView struct {
	Children []PivotGraphEntryView `json:"Children"`
}

func pivotGraphEntryToView(e *clientpb.PivotGraphEntry) PivotGraphEntryView {
	v := PivotGraphEntryView{}
	if e == nil {
		return v
	}
	v.PeerID = e.PeerID
	v.Name = e.Name
	if s := e.Session; s != nil {
		v.SessionID = s.ID
		v.Hostname = s.Hostname
		v.Username = s.Username
		v.OS = s.OS
		v.Transport = s.Transport
		v.RemoteAddress = s.RemoteAddress
	}
	v.Children = make([]PivotGraphEntryView, 0, len(e.Children))
	for _, ch := range e.Children {
		v.Children = append(v.Children, pivotGraphEntryToView(ch))
	}
	return v
}

// PivotGraph returns the server-wide pivot graph.
func (c *Client) PivotGraph() (PivotGraphView, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	resp, err := c.RPC.PivotGraph(ctx, &commonpb.Empty{})
	if err != nil {
		return PivotGraphView{}, err
	}
	out := PivotGraphView{Children: make([]PivotGraphEntryView, 0, len(resp.Children))}
	for _, e := range resp.Children {
		out.Children = append(out.Children, pivotGraphEntryToView(e))
	}
	return out, nil
}
