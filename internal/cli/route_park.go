// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/daemon"
	"github.com/defenseclaw/defenseclaw/internal/gateway"
)

// parkRouteOnlyAgents is gateway.ParkRouteOnlyAgents; tests replace it.
var parkRouteOnlyAgents = gateway.ParkRouteOnlyAgents

// routeOnlyPortUnowned reports whether no process of this account holds the
// gateway API port: the socket table lists no listener there, or another
// account's process holds it. It reads the socket table and never connects
// to the port (a probe connection would reach another account's listener);
// on macOS, where lsof does not list other accounts' sockets, "no listener"
// can mean another account's, and parking is right for both. A foreground
// gateway of this account keeps its route. Tests replace it.
var routeOnlyPortUnowned = func(cfg *config.Config) bool {
	if _, err := gatewayPortHolder(gatewayClientHost(cfg), cfg.Gateway.APIPort); errors.Is(err, daemon.ErrNoListener) {
		return true
	}
	return foreignGatewayListener(cfg) != ""
}

// parkRouteOnlyWithoutGateway parks the route-only agent settings of an OSS
// install while no gateway of this account holds its port
// (rel-1-0-10:GAP-1133): a stop that had to kill the gateway (Windows
// TerminateProcess) left the real route in place, and so did a crash, a
// logoff or a reboot before a start. The agents then send nothing to a
// process of another account that binds the port; the gateway renders the
// real route once it holds it.
func parkRouteOnlyWithoutGateway(cfg *config.Config, announce bool) {
	if cfg == nil || !cfg.Routing.Enabled || len(cfg.Routing.RouteOnly.Connectors) == 0 || !routeOnlyPortUnowned(cfg) {
		return
	}
	parked, err := parkRouteOnlyAgents(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not park the route-only agent settings: %v\n", err)
	}
	if announce && len(parked) > 0 {
		fmt.Println(Dim("Route-only " + strings.Join(parked, ", ") +
			" parked: model calls go nowhere until the gateway holds its port again"))
	}
}
