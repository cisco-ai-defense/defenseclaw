// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"os"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// ossRouteOnlyGate parks the OSS route-only renders of this gateway process
// while it does not hold its API port (rel-1-0-10:GAP-1133): before the first
// bind, while another process holds the port, and from a stop on. Agents
// started then send nothing; the real route is rendered again right after the
// gateway owns the port. One gateway runs per process; tests replace it.
var ossRouteOnlyGate = &connector.RouteOnlyGate{}

// gatedRouteOnly is route behind the OSS gate (nil stays nil: a restore).
// Only an OSS gateway moves the gate (routeOnlyPortOwned), so any other
// gateway writes its route as is instead of parking it for good.
func gatedRouteOnly(cfg *config.Config, route *connector.RouteOnlySetup) *connector.RouteOnlySetup {
	if route == nil || !ossRouteOnlyGateway(cfg) {
		return route
	}
	gated := *route
	gated.Gate = ossRouteOnlyGate
	return &gated
}

// routeOnlyPortOwned records that this OSS gateway now holds (true) or is
// about to release (false) its API port, and renders every routed connector
// again when that changed: the real route once the port is ours, the parked
// one before it is closed. Managed gateways render through the guardian.
func (a *APIServer) routeOnlyPortOwned(owned bool) {
	cfg := a.liveConfig()
	if !ossRouteOnlyGateway(cfg) {
		return
	}
	if !ossRouteOnlyGate.SetOwned(owned) {
		return
	}
	if len(routeOnlyConnectorsOf(cfg)) == 0 || a.onRouteKeyRotated == nil {
		return
	}
	if !owned {
		fmt.Fprintf(os.Stderr, "[routing] route-only agents parked: this gateway is releasing %s, so agents started from now on send nothing until it holds the port again\n", a.addr)
	}
	a.onRouteKeyRotated()
}
