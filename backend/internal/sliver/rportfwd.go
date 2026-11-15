package sliver

import (
	"context"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"

	"github.com/bishopfox/sliver/protobuf/sliverpb"
)

var portNumberOnly = regexp.MustCompile(`^[0-9]+$`)

// RportFwdListenerView is the JSON shape of an implant reverse port-forward.
type RportFwdListenerView struct {
	ID             uint32 `json:"ID"`
	BindAddress    string `json:"BindAddress"`
	BindPort       uint32 `json:"BindPort"`
	ForwardAddress string `json:"ForwardAddress"`
	ForwardPort    uint32 `json:"ForwardPort"`
}

// RportFwdStartRequest is the JSON body for StartRportFwdListener.
type RportFwdStartRequest struct {
	Bind           string `json:"bind"`
	Remote         string `json:"remote"`
	BindAddress    string `json:"bind_address"`
	ForwardAddress string `json:"forward_address"`
	BindHost       string `json:"bind_host"`
	BindPort       uint32 `json:"bind_port"`
	ForwardHost    string `json:"forward_host"`
	ForwardPort    uint32 `json:"forward_port"`
}

func rportFwdToView(l *sliverpb.RportFwdListener) RportFwdListenerView {
	if l == nil {
		return RportFwdListenerView{}
	}
	return RportFwdListenerView{
		ID:             l.ID,
		BindAddress:    l.BindAddress,
		BindPort:       l.BindPort,
		ForwardAddress: l.ForwardAddress,
		ForwardPort:    l.ForwardPort,
	}
}

func normalizeRportFwdAddr(raw, defaultHost string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if portNumberOnly.MatchString(raw) {
		if defaultHost == "" {
			return ":" + raw
		}
		return net.JoinHostPort(defaultHost, raw)
	}
	if _, _, err := net.SplitHostPort(raw); err == nil {
		return raw
	}
	return raw
}

func joinRportFwd(host string, port uint32, defaultHost string) string {
	if port == 0 && host == "" {
		return ""
	}
	if host == "" {
		host = defaultHost
	}
	if port == 0 {
		return host
	}
	if host == "" {
		return ":" + strconv.FormatUint(uint64(port), 10)
	}
	return net.JoinHostPort(host, strconv.FormatUint(uint64(port), 10))
}

func (r RportFwdStartRequest) bindAddr() string {
	if v := normalizeRportFwdAddr(firstNonEmpty(r.Bind, r.BindAddress), ""); v != "" {
		return v
	}
	return joinRportFwd(r.BindHost, r.BindPort, "")
}

func (r RportFwdStartRequest) forwardAddr() string {
	if v := normalizeRportFwdAddr(firstNonEmpty(r.Remote, r.ForwardAddress), "127.0.0.1"); v != "" {
		return v
	}
	return joinRportFwd(r.ForwardHost, r.ForwardPort, "127.0.0.1")
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func sessionLooksDNS(activeC2 string) bool {
	s := strings.ToLower(activeC2)
	return strings.HasPrefix(s, "dns://") || strings.Contains(s, "://dns")
}

// ListRportFwdListeners lists reverse port-forwards on the implant.
func (c *Client) ListRportFwdListeners(sessionID string) ([]RportFwdListenerView, error) {
	ctx, cancel := context.WithTimeout(context.Background(), opTimeout)
	defer cancel()
	resp, err := c.RPC.GetRportFwdListeners(ctx, &sliverpb.RportFwdListenersReq{
		Request: implantRequest(sessionID, ""),
	})
	if err != nil {
		return nil, err
	}
	if resp.Response != nil && resp.Response.Err != "" {
		return nil, fmt.Errorf("%s", resp.Response.Err)
	}
	out := make([]RportFwdListenerView, 0, len(resp.Listeners))
	for _, l := range resp.Listeners {
		out = append(out, rportFwdToView(l))
	}
	return out, nil
}

// StartRportFwdListener starts a reverse port-forward on the implant.
// The teamserver tracks the listener and dials ForwardAddress when the implant
// accepts a connection. This UI does not proxy the bytes itself.
func (c *Client) StartRportFwdListener(sessionID string, req RportFwdStartRequest) (RportFwdListenerView, string, error) {
	bind := req.bindAddr()
	fwd := req.forwardAddr()
	if bind == "" {
		return RportFwdListenerView{}, "", fmt.Errorf("bind address is required")
	}
	if fwd == "" {
		return RportFwdListenerView{}, "", fmt.Errorf("forward address is required")
	}

	warning := ""
	if sess, err := c.sessionByID(sessionID); err == nil && sess != nil && sessionLooksDNS(sess.ActiveC2) {
		warning = "The current C2 is DNS; this tunnel will be very slow."
	}

	ctx, cancel := context.WithTimeout(context.Background(), opTimeout)
	defer cancel()
	resp, err := c.RPC.StartRportFwdListener(ctx, &sliverpb.RportFwdStartListenerReq{
		BindAddress:    bind,
		ForwardAddress: fwd,
		Request:        implantRequest(sessionID, ""),
	})
	if err != nil {
		return RportFwdListenerView{}, warning, err
	}
	if resp.Response != nil && resp.Response.Err != "" {
		return RportFwdListenerView{}, warning, fmt.Errorf("%s", resp.Response.Err)
	}
	return rportFwdToView(resp), warning, nil
}

// StopRportFwdListener stops a reverse port-forward by implant listener ID.
func (c *Client) StopRportFwdListener(sessionID string, id uint32) (RportFwdListenerView, error) {
	ctx, cancel := context.WithTimeout(context.Background(), opTimeout)
	defer cancel()
	resp, err := c.RPC.StopRportFwdListener(ctx, &sliverpb.RportFwdStopListenerReq{
		ID:      id,
		Request: implantRequest(sessionID, ""),
	})
	if err != nil {
		return RportFwdListenerView{}, err
	}
	if resp.Response != nil && resp.Response.Err != "" {
		return RportFwdListenerView{}, fmt.Errorf("%s", resp.Response.Err)
	}
	return rportFwdToView(resp), nil
}

func (c *Client) sessionByID(id string) (*SessionView, error) {
	sessions, err := c.Sessions()
	if err != nil {
		return nil, err
	}
	for i := range sessions {
		if sessions[i].ID == id {
			return &sessions[i], nil
		}
	}
	return nil, nil
}
