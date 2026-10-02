// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"fmt"
	"net"
	"os"
	"runtime"
	"strconv"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/daemon"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// Seams for tests.
var (
	gatewayPortHolder         = daemon.FindPortHolder
	gatewayPortAnswers        = gatewayPortAcceptsConnections
	gatewayManagedState       = func() (bool, int) { return daemon.New(config.DefaultDataPath()).IsRunning() }
	gatewayRunsReplacedBinary = func() bool { return daemon.New(config.DefaultDataPath()).RunsReplacedExecutable() }
)

// foreignGatewayListener explains a listener on the configured API port that
// is not the gateway this account started with `defenseclaw-gateway start`
// for this DefenseClaw home: a gateway left running by another home or test
// run, another account's process, or any other program. It returns "" when
// the port is free or held by the managed gateway.
//
// It never sends the gateway token to the listener. Managed deployments run
// the gateway as a service, so they keep their own checks. On Windows the
// holder is named by PID and program (GAP-1344): status showed another
// account's gateway on this account's port as this account's, rc 0.
func foreignGatewayListener(cfg *config.Config) string {
	if cfg == nil {
		return ""
	}
	return foreignGatewayListenerAt(cfg, gatewayClientHost(cfg), cfg.Gateway.APIPort)
}

// foreignGatewayListenerAt is foreignGatewayListener for the API listener at
// host:port, for a caller that resolved the address from its own view of the
// configuration (the observability-v8 helpers). cfg may be nil.
func foreignGatewayListenerAt(cfg *config.Config, host string, port int) string {
	if (cfg != nil && (cfg.StandaloneEnterprise() || managed.IsManagedEnterprise(cfg.DeploymentMode))) ||
		managed.IsManagedEnterprise(os.Getenv(managed.DeploymentModeEnv)) {
		return ""
	}
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	holder, holderErr := gatewayPortHolder(host, port)
	// lsof on macOS does not list another account's sockets, so a missing
	// holder is confirmed with a connection attempt.
	if holderErr != nil && !gatewayPortAnswers(addr) {
		return ""
	}
	if holderErr != nil {
		holder = daemon.PortHolder{UID: -1}
	}
	running, managedPID := gatewayManagedState()
	ownUID := os.Getuid()
	who := holder.String(ownUID)
	if label := listenerProcessLabel(holder.PID); label != "" {
		who += " (" + label + ")"
	}
	switch {
	case holderErr == nil && holder.UID >= 0 && holder.UID != ownUID:
		return fmt.Sprintf("%s is held by %s, not by this account's gateway", addr, who)
	case !running:
		return fmt.Sprintf(
			"%s is held by %s, not by this account's gateway: no gateway started for %s is running",
			addr, who, config.DefaultDataPath(),
		)
	case holderErr == nil && holder.PID > 0 && holder.PID != managedPID:
		return fmt.Sprintf(
			"%s is held by %s, not by this account's gateway (PID %d)", addr, who, managedPID,
		)
	}
	return ""
}

// foreignGatewayListenerFix is the next step for foreignGatewayListener. On a
// shared machine the holder is often another account's gateway on the same
// default port, so it names the command that moves this account's gateway
// and, when one is free, a port to use.
//
// status, start, restart and policy reload all use this text, so they give
// the same command; another account's process is not this account's to stop
// (GAP-1706).
func foreignGatewayListenerFix(cfg *config.Config) string {
	return foreignGatewayListenerFixAt(gatewayClientHost(cfg), cfg.Gateway.APIPort)
}

// foreignGatewayListenerFixAt is foreignGatewayListenerFix for the API
// listener at host:apiPort (the observability-v8 helpers, GAP-1670).
func foreignGatewayListenerFixAt(host string, apiPort int) string {
	port := "<free port>"
	if free := freeGatewayAPIPort(host, apiPort); free > 0 {
		port = strconv.Itoa(free)
	}
	move := fmt.Sprintf(
		"move this account's gateway to a free port with: defenseclaw setup gateway --api-port %s --non-interactive, then run: defenseclaw-gateway start",
		port,
	)
	if gatewayPortHeldByOtherAccount(host, apiPort) {
		return "That process belongs to another account, so " + move
	}
	return "Stop that process, or " + move
}

// gatewayPortHeldByOtherAccount reports whether another account's process
// holds host:port. An unnamed holder on Linux and macOS counts as another
// account's: lsof does not list other accounts' sockets. A seam for tests.
var gatewayPortHeldByOtherAccount = func(host string, port int) bool {
	if runtime.GOOS == "windows" {
		return gatewayListenerOfAnotherAccount(host, port, "")
	}
	holder, err := gatewayPortHolder(host, port)
	if err != nil {
		return true
	}
	return holder.UID >= 0 && holder.UID != os.Getuid()
}

// gatewayAPIPortStep keeps a suggested API port clear of the sandbox ingress
// and egress ports a gateway uses next to its own (api_port+1 and +2), the
// same step init uses when it moves a new account off a held port.
const gatewayAPIPortStep = 10

// gatewayAPIPortTries is how many candidates a suggestion looks at. It
// matches bootstrap._FIRST_RUN_API_PORT_TRIES, so the gateway, doctor,
// init and setup gateway search the same window (GAP-1807).
const gatewayAPIPortTries = 50

// freeGatewayAPIPort returns the first port after from, in steps of
// gatewayAPIPortStep, that host can bind right now together with its two
// sandbox ports and that no other account has claimed, or 0 when none of
// the next gatewayAPIPortTries is. setup gateway refuses a port another
// account claimed, so suggesting one sent the user in a circle (GAP-1762).
func freeGatewayAPIPort(host string, from int) int {
	for step := 1; step <= gatewayAPIPortTries; step++ {
		port := from + step*gatewayAPIPortStep
		if port+2 > 65535 {
			break
		}
		if !gatewayPortClaimedByOtherAccount(port) && gatewayPortsBindable(host, port, port+1, port+2) {
			return port
		}
	}
	return 0
}

func gatewayPortsBindable(host string, ports ...int) bool {
	for _, port := range ports {
		ln, err := net.Listen("tcp", net.JoinHostPort(host, strconv.Itoa(port)))
		if err != nil {
			return false
		}
		_ = ln.Close()
	}
	return true
}

func gatewayPortAcceptsConnections(addr string) bool {
	conn, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}
