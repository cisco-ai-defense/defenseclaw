// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"fmt"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway"
)

// parkRouteOnlyAgents is gateway.ParkRouteOnlyAgents; tests replace it.
var parkRouteOnlyAgents = gateway.ParkRouteOnlyAgents

// routeOnlyPortUnowned reports whether this home's own gateway does not hold
// the API port, by the gateway's one rule (gateway.RouteOnlyHomeGatewayHolds:
// the socket table only, never a connection; a table-read error parks). A
// foreground gateway of this home keeps its route. Tests replace it.
var routeOnlyPortUnowned = func(cfg *config.Config) bool { return !gateway.RouteOnlyHomeGatewayHolds(cfg) }

// parkRouteOnlyWithoutGateway parks the route-only agent settings of an OSS
// install while no gateway of this account holds its port
// (rel-1-0-10:GAP-1133): a stop that had to kill the gateway (Windows
// TerminateProcess) left the real route in place, and so did a crash, a
// logoff or a reboot before a start. The agents then send nothing to a
// process of another account that binds the port; the gateway renders the
// real route once it holds it.
//
// A park that could not be written is returned: stop fails with it, so
// "agents started after a stop send nothing" is never claimed silently.
func parkRouteOnlyWithoutGateway(cfg *config.Config, announce bool) error {
	if cfg == nil || !cfg.Routing.Enabled || len(cfg.Routing.RouteOnly.Connectors) == 0 || !routeOnlyPortUnowned(cfg) {
		return nil
	}
	parked, err := parkRouteOnlyAgents(cfg)
	if announce && len(parked) > 0 {
		fmt.Println(Dim("Route-only " + strings.Join(parked, ", ") +
			" parked: model calls go nowhere until the gateway holds its port again"))
	}
	if err != nil {
		return fmt.Errorf("the route-only agent settings could not be parked, so an agent started now still "+
			"sends its model calls to whatever process takes the gateway port: %w. Fix the agent file, then run "+
			"defenseclaw-gateway stop again; or restore direct model access: defenseclaw-gateway connector "+
			"route-restore --all", err)
	}
	return nil
}
