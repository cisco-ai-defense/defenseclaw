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
	if cfg == nil || runtime.GOOS == "windows" || cfg.StandaloneEnterprise() ||
		managed.IsManagedEnterprise(os.Getenv(managed.DeploymentModeEnv)) {
		return ""
	}
	port := cfg.Gateway.APIPort
	host := gatewayClientHost(cfg)
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

// foreignGatewayListenerFix is the next step for foreignGatewayListener.
const foreignGatewayListenerFix = "Stop that process, or set gateway.api_port to a free port, then run: defenseclaw-gateway start"

func gatewayPortAcceptsConnections(addr string) bool {
	conn, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}
