// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package attach

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"github.com/gorilla/websocket"

	"github.com/defenseclaw/defenseclaw/internal/substrate/relay"
)

// Port forward (B3.2): `defenseclaw substrate port NAME PORT[:LOCAL]`.
// The launcher listens on 127.0.0.1 only and opens one relay port stream
// (one WebSocket through the gateway) per accepted connection. There is no
// address flag: a forward on any other interface would hand the agent's
// app to the network.

// PortLoopback is the only address a forward listens on.
const PortLoopback = "127.0.0.1"

// portFreeTries is how many ports after PORT a default local port tries.
const portFreeTries = 20

// PortSpec is one forward: the agent's port and the laptop's. Local 0
// means PORT, or the next free port after it.
type PortSpec struct {
	Remote int
	Local  int
}

// ParsePortSpec reads PORT or PORT:LOCAL. An address part (0.0.0.0:3000,
// localhost:3000) is refused: a forward listens on 127.0.0.1 only.
func ParsePortSpec(s string) (PortSpec, error) {
	remote, local, two := strings.Cut(strings.TrimSpace(s), ":")
	r, err := portNumber(remote)
	if err != nil {
		return PortSpec{}, fmt.Errorf("%q is not PORT or PORT:LOCAL: a forward listens on %s only, so give port numbers, not an address", s, PortLoopback)
	}
	if r < relay.MinForwardPort {
		return PortSpec{}, fmt.Errorf("port %d can't be forwarded: allowed ports are %d-65535, except the relay's own port", r, relay.MinForwardPort)
	}
	spec := PortSpec{Remote: r}
	if two {
		l, err := portNumber(local)
		if err != nil || l == 0 {
			return PortSpec{}, fmt.Errorf("%q is not PORT or PORT:LOCAL: LOCAL must be a port number from 1 to 65535", s)
		}
		spec.Local = l
	}
	return spec, nil
}

func portNumber(s string) (int, error) {
	if s == "" || strings.TrimLeft(s, "0123456789") != "" || len(s) > 5 {
		return 0, errors.New("not a port")
	}
	n, err := strconv.Atoi(s)
	if err != nil || n > 65535 {
		return 0, errors.New("not a port")
	}
	return n, nil
}

// ListenPort opens the laptop end of a forward on 127.0.0.1. With no LOCAL
// it takes PORT, or the next free port after it.
func ListenPort(spec PortSpec) (net.Listener, error) {
	if spec.Local != 0 {
		l, err := net.Listen("tcp", net.JoinHostPort(PortLoopback, strconv.Itoa(spec.Local)))
		if err != nil {
			return nil, fmt.Errorf("could not listen on %s:%d (another program may use it; pick another with %d:LOCAL): %w", PortLoopback, spec.Local, spec.Remote, err)
		}
		return l, nil
	}
	var first error
	for p := spec.Remote; p <= 65535 && p < spec.Remote+portFreeTries; p++ {
		l, err := net.Listen("tcp", net.JoinHostPort(PortLoopback, strconv.Itoa(p)))
		if err == nil {
			return l, nil
		}
		if first == nil {
			first = err
		}
	}
	return nil, fmt.Errorf("no free local port from %d to %d; pick one with %d:LOCAL: %w", spec.Remote, spec.Remote+portFreeTries-1, spec.Remote, first)
}

// PortRefusal is a port stream the gateway refused: its HTTP status and
// reason code (the code is also in the audit row).
type PortRefusal struct {
	Status int
	Reason string
	Port   int
	Target Target
}

func (e *PortRefusal) Error() string {
	switch e.Reason {
	case "port_forward_off":
		return "port forwarding is turned off on this cluster. Ask your administrator"
	case "port_not_allowed":
		return fmt.Sprintf("port %d can't be forwarded: this cluster allows ports %d-65535 except the relay's own port, and your administrator may allow fewer", e.Port, relay.MinForwardPort)
	case "relay_too_old":
		return "this agent's image is too old for port forwarding. Rebuild its template (defenseclaw substrate template build) and start a new agent"
	case "websocket_required":
		return "port forwarding needs WebSocket, and the network between you and the cluster allows only the long-poll fallback"
	case "too_many_streams":
		return "this agent has too many open forwards; close a browser tab or another forward and try again"
	}
	return routeError(e.Status, nil, e.Target).Error()
}

// Unwrap returns the attach error kind of the status (ErrNotSignedIn,
// ErrNotAllowed, ...), so the launcher's exit codes apply.
func (e *PortRefusal) Unwrap() error { return routeError(e.Status, nil, e.Target).Kind }

// Final reports a refusal that holds for every later connection, so the
// forward stops. Too many streams and a starting agent can change.
func (e *PortRefusal) Final() bool {
	switch e.Reason {
	case "too_many_streams":
		return false
	}
	switch e.Status {
	case http.StatusTooManyRequests, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return false
	}
	return true
}

// streamRefusal is a stream the gateway refused on open: the HTTP status
// and the reason code of its JSON body.
type streamRefusal struct {
	Status int
	Reason string
}

// dialStream opens one WebSocket stream (port/N, mcp/NAME) through the
// gateway, under the person's bearer. A refusal comes back as ref; any
// other failure as err.
func (tu *Tunnel) dialStream(ctx context.Context, route string) (conn *websocket.Conn, ref *streamRefusal, err error) {
	tok, err := tu.Bearer(ctx)
	if err != nil {
		return nil, nil, err
	}
	d := *tu.Dialer()
	d.Subprotocols = []string{relay.Subprotocol}
	u := strings.Replace(relay.RouteURL(tu.BaseURL(), route), "https://", "wss://", 1)
	h := http.Header{}
	h.Set("Authorization", "Bearer "+tok)
	conn, resp, err := d.DialContext(ctx, u, h)
	if err == nil {
		return conn, nil, nil
	}
	if resp == nil {
		return nil, nil, tu.netError(err)
	}
	ref = &streamRefusal{Status: resp.StatusCode}
	if resp.Body != nil {
		var m struct {
			Reason string `json:"reason"`
		}
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		_ = resp.Body.Close()
		if json.Unmarshal(b, &m) == nil {
			ref.Reason = m.Reason
		}
	}
	return nil, ref, nil
}

// DialPort opens one port stream to the agent's port through the gateway.
func (tu *Tunnel) DialPort(ctx context.Context, port int) (*websocket.Conn, error) {
	conn, ref, err := tu.dialStream(ctx, relay.RoutePort+"/"+strconv.Itoa(port))
	if ref != nil {
		return nil, &PortRefusal{Status: ref.Status, Reason: ref.Reason, Port: port, Target: tu.target}
	}
	return conn, err
}

// PortForward serves one forward until ctx ends or a final refusal.
type PortForward struct {
	Tunnel   *Tunnel
	Spec     PortSpec
	Listener net.Listener
	// Note shows a line about one connection (nothing listening yet, too
	// many streams). It must be safe for concurrent use.
	Note func(string)
}

// Serve accepts connections and pipes each through its own port stream.
// It returns nil when ctx ends and a *PortRefusal that is final otherwise.
func (f *PortForward) Serve(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var (
		mu    sync.Mutex
		fatal error
		wg    sync.WaitGroup
	)
	go func() {
		<-ctx.Done()
		_ = f.Listener.Close()
	}()
	for {
		c, err := f.Listener.Accept()
		if err != nil {
			break
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := f.serveConn(ctx, c); err != nil {
				mu.Lock()
				if fatal == nil {
					fatal = err
				}
				mu.Unlock()
				cancel()
			}
		}()
	}
	cancel()
	wg.Wait()
	mu.Lock()
	defer mu.Unlock()
	return fatal
}

// serveConn returns an error only when the whole forward must stop.
func (f *PortForward) serveConn(ctx context.Context, c net.Conn) error {
	ws, err := f.Tunnel.DialPort(ctx, f.Spec.Remote)
	if err != nil {
		_ = c.Close()
		var ref *PortRefusal
		if errors.As(err, &ref) && ref.Final() {
			return ref
		}
		if ctx.Err() == nil {
			f.note("Could not open a connection to port " + strconv.Itoa(f.Spec.Remote) + ": " + err.Error())
		}
		return nil
	}
	stop := context.AfterFunc(ctx, func() { _ = ws.Close(); _ = c.Close() })
	defer stop()
	var pe *relay.PortStreamError
	if err := relay.PipePort(ws, c); errors.As(err, &pe) && pe.Code == relay.PortErrNothingListening {
		f.note(fmt.Sprintf("Nothing in the agent listens on port %d yet. The forward stays open; try again when the dev server is up.", f.Spec.Remote))
	}
	return nil
}

func (f *PortForward) note(s string) {
	if f.Note != nil {
		f.Note(s)
	}
}
