// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"net/url"
	"strings"
	"sync"
)

// Parked route-only renders (rel-1-0-10:GAP-1133). An agent HTTP client sends
// its model calls, with the route credential, its own provider credential and
// the conversation, to whatever process listens on the loopback address of
// its render; it cannot tell this account's gateway from another account's
// process that bound the port while the gateway was down. An OSS gateway
// therefore renders the real route only while it holds its API port. At every
// other time the agent config points at port 0 of the loopback address (no
// process can listen there, so connect fails and no byte leaves) and carries
// no route credential.

// routeOnlyParkedHost is the address of a parked render.
const routeOnlyParkedHost = "127.0.0.1:0"

// RouteOnlyGate decides, at the moment a render is written, whether it is the
// real route or the parked one. One gate serves every OSS route-only write of
// a gateway process (connector Setup, a reload, a rerender), so the last write
// always matches the port state: the owner flips Owned and renders again, and
// a write already in flight waits for the gate.
type RouteOnlyGate struct {
	mu    sync.Mutex
	owned bool
}

// SetOwned records whether this gateway holds its API port and reports a
// change. The caller renders every routed connector again after a change.
func (g *RouteOnlyGate) SetOwned(owned bool) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	changed := g.owned != owned
	g.owned = owned
	return changed
}

// Owned reports whether this gateway holds its API port.
func (g *RouteOnlyGate) Owned() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.owned
}

// lockedRoute returns the render to write, the function that releases the
// gate, and false when nothing is to be written: a ParkOnly render while the
// gate holds the port. A route without a gate (managed renders, restores) is
// written as is; a ParkOnly one always parked.
func lockedRoute(route *RouteOnlySetup) (*RouteOnlySetup, func(), bool) {
	noop := func() {}
	if route == nil {
		return nil, noop, true
	}
	if route.Gate == nil {
		if route.ParkOnly {
			parked := parkedRoute(*route)
			return &parked, noop, true
		}
		return route, noop, true
	}
	g := route.Gate
	g.mu.Lock()
	effective := *route
	effective.Gate = nil
	switch {
	case !g.owned:
		effective = parkedRoute(effective)
	case route.ParkOnly:
		g.mu.Unlock()
		return nil, noop, false
	}
	return &effective, g.mu.Unlock, true
}

// parkedRoute is route with its endpoint on port 0 and no route credential.
func parkedRoute(route RouteOnlySetup) RouteOnlySetup {
	route.BaseURL = ParkedRouteBaseURL(route.BaseURL)
	route.Token = ""
	return route
}

// ParkedRouteBaseURL is base with its host replaced by the parked address; the
// /r/<connector> path stays, so a restore after a lost record still finds it.
func ParkedRouteBaseURL(base string) string {
	u, err := url.Parse(strings.TrimSpace(base))
	if err != nil || u.Host == "" {
		return "http://" + routeOnlyParkedHost
	}
	u.Scheme, u.Host = "http", routeOnlyParkedHost
	return u.String()
}

// IsParkedRouteBaseURL reports a render ParkedRouteBaseURL wrote.
func IsParkedRouteBaseURL(v string) bool {
	u, err := url.Parse(strings.TrimSpace(v))
	return err == nil && u.Host == routeOnlyParkedHost
}
