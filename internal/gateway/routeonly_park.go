// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"errors"
	"fmt"
	"net"
	"os"
	"slices"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/daemon"
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
	gated.HeldElsewhere = func() bool { return RouteOnlyHomeGatewayHolds(cfg) }
	return &gated
}

// routeOnlyHomeGatewayHoldsPort is daemon.HomeGatewayHoldsPort; tests
// replace it.
var routeOnlyHomeGatewayHoldsPort = daemon.HomeGatewayHoldsPort

// RouteOnlyHomeGatewayHolds is the one rule for whether the route-only agents
// of this home may be parked (rel-1-0-10:GAP-1133): false parks. It is true
// only when the socket table shows this home's own gateway, another process,
// holding the API port (daemon.HomeGatewayHoldsPort). It never connects to
// the port, and a table-read error counts as not held. The gateway applies it
// at every park write; defenseclaw-gateway start and stop apply it before
// they park.
func RouteOnlyHomeGatewayHolds(cfg *config.Config) bool {
	if cfg == nil {
		return false
	}
	return routeOnlyHomeGatewayHoldsPort(cfg.DataDir, routeOnlyClientHost(cfg), cfg.Gateway.APIPort)
}

// routeOnlyClientHost is the loopback address agents use for the API bind
// address of cfg (a wildcard bind is reached on loopback).
func routeOnlyClientHost(cfg *config.Config) string {
	host := strings.Trim(strings.TrimSpace(config.APIBindHost(cfg)), "[]")
	if ip := net.ParseIP(host); host == "" || host == "*" || (ip != nil && ip.IsUnspecified()) {
		if ip != nil && ip.To4() == nil {
			return "::1"
		}
		return "127.0.0.1"
	}
	return host
}

// routeOnlyParkSetupFor is the parked render of connectorName: the shape of
// its route from config alone, with no route token and no signing check, so
// a connector whose real route cannot be derived right now (an AWS
// credential fetch failing, an unreadable route key) is parked too. nil when
// the connector is not routed on this OSS gateway.
func routeOnlyParkSetupFor(cfg *config.Config, connectorName, apiAddr string) *connector.RouteOnlySetup {
	if cfg == nil || cfg.StandaloneEnterprise() || cfg.SecureClientIntegration() ||
		!slices.Contains(cfg.ActiveConnectors(), connectorName) {
		return nil
	}
	route := routeOnlyShape(cfg, connectorName, apiAddr)
	if route == nil {
		return nil
	}
	route.ParkOnly = true
	route.Gate = ossRouteOnlyGate
	route.HeldElsewhere = func() bool { return RouteOnlyHomeGatewayHolds(cfg) }
	return route
}

// ParkRouteOnlyAgents points the route-only agent config of every routed
// connector of an OSS install at the parked address (port 0, no route
// credential), where something is rendered and this home's own gateway does
// not hold the port (RouteOnlyHomeGatewayHolds), and returns the connectors
// it parked. The gateway calls it before it binds its API port and before it
// releases it; defenseclaw-gateway start and stop call it when no gateway of
// this account runs, which covers a stop that had to kill the process
// (Windows TerminateProcess) and a start after a crash. It never writes the
// real route: a park racing a gateway that already holds the port is
// skipped (that gateway renders the real route itself).
func ParkRouteOnlyAgents(cfg *config.Config) ([]string, error) {
	if !ossRouteOnlyGateway(cfg) {
		return nil, nil
	}
	if RouteOnlyHomeGatewayHolds(cfg) {
		return nil, nil
	}
	registry := connector.NewDefaultRegistry()
	var parked []string
	var errs []error
	for _, name := range routeOnlyConnectorsOf(cfg) {
		route := routeOnlyParkSetupFor(cfg, name, apiListenAddr(cfg))
		if route == nil {
			continue
		}
		conn, ok := registry.Get(name)
		if !ok {
			continue
		}
		rc, ok := conn.(connector.RouteOnlyConnector)
		if !ok {
			continue
		}
		if err := rc.ApplyRouteOnly(connector.SetupOpts{DataDir: cfg.DataDir}, route); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", name, err))
			continue
		}
		parked = append(parked, name)
	}
	return parked, errors.Join(errs...)
}

// routeOnlyPark is ParkRouteOnlyAgents; tests replace it.
var routeOnlyPark = ParkRouteOnlyAgents

// parkRouteOnly parks the route-only agents of this OSS gateway (before a
// bind, before a release) and logs it.
func (a *APIServer) parkRouteOnly(why string) {
	cfg := a.liveConfig()
	if !ossRouteOnlyGateway(cfg) || len(routeOnlyConnectorsOf(cfg)) == 0 {
		return
	}
	if _, err := routeOnlyPark(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "[routing] route-only park (%s): %v\n", why, err)
		return
	}
	fmt.Fprintf(os.Stderr, "[routing] route-only agents parked: %s, so agents started from now on send nothing until this gateway holds %s\n", why, a.addr)
}

// routeOnlyPortOwned records that this OSS gateway now holds (true) or is
// about to release (false) its API port. Owning it renders every routed
// connector again with the real route; releasing it parks every routed
// connector from config alone (routeOnlyParkSetupFor), so a connector whose
// live route cannot be derived at stop time is parked too. Managed gateways
// render through the guardian.
func (a *APIServer) routeOnlyPortOwned(owned bool) {
	cfg := a.liveConfig()
	if !ossRouteOnlyGateway(cfg) {
		return
	}
	if !ossRouteOnlyGate.SetOwned(owned) {
		return
	}
	if !owned {
		a.parkRouteOnly("this gateway is releasing its API port")
		return
	}
	if len(routeOnlyConnectorsOf(cfg)) == 0 || a.onRouteKeyRotated == nil {
		return
	}
	a.onRouteKeyRotated()
}
