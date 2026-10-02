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
// It never sends the gateway token to the listener. Windows start/restart
// prove listener ownership separately and managed deployments run the
// gateway as a service, so both keep their own checks.
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
	if runtime.GOOS == "windows" || (cfg != nil && cfg.StandaloneEnterprise()) ||
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
func foreignGatewayListenerFix(cfg *config.Config) string {
	port := "<port>"
	if free := freeGatewayAPIPort(gatewayClientHost(cfg), cfg.Gateway.APIPort); free > 0 {
		port = strconv.Itoa(free)
	}
	return fmt.Sprintf(
		"Stop that process, or move this account's gateway to a free port with: defenseclaw setup gateway --api-port %s, then run: defenseclaw-gateway start",
		port,
	)
}

// gatewayAPIPortStep keeps a suggested API port clear of the sandbox ingress
// and egress ports a gateway uses next to its own (api_port+1 and +2), the
// same step init uses when it moves a new account off a held port.
const gatewayAPIPortStep = 10

// freeGatewayAPIPort returns the first port after from, in steps of
// gatewayAPIPortStep, that host can bind right now together with its two
// sandbox ports, or 0 when none of the next few is free.
func freeGatewayAPIPort(host string, from int) int {
	for port := from + gatewayAPIPortStep; port+2 <= 65535 && port <= from+10*gatewayAPIPortStep; port += gatewayAPIPortStep {
		if gatewayPortsBindable(host, port, port+1, port+2) {
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
