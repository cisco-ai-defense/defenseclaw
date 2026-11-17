// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"strconv"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/daemon"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// gatewayOutOfReachAt is daemon.HomeGatewayOutOfReach on Windows, the one
// system where this account's own gateway can be a process this account may
// not open (started elevated in another logon session). Tests replace it.
var gatewayOutOfReachAt = func(dataDir, host string, port int) (int, bool) {
	if runtime.GOOS != "windows" {
		return 0, false
	}
	return daemon.HomeGatewayOutOfReach(dataDir, host, port)
}

// gatewayOutOfReach names this account's own per-user gateway when it holds
// the configured API port but runs where this shell may not open it
// (rel-1-0-10:GAP-1212). status, start, stop and restart then say so instead
// of calling it another account's, or not running. Managed deployments keep
// their own checks.
func gatewayOutOfReach(c *config.Config) (int, bool) {
	if c == nil || c.StandaloneEnterprise() || managed.IsManagedEnterprise(c.DeploymentMode) ||
		managed.IsManagedEnterprise(os.Getenv(managed.DeploymentModeEnv)) {
		return 0, false
	}
	return gatewayOutOfReachAt(c.DataDir, gatewayClientHost(c), c.Gateway.APIPort)
}

// errGatewayOutOfReach is the status failure for a gateway this shell cannot
// read.
var errGatewayOutOfReach = errors.New("this account's gateway runs elevated or in another logon session; its status cannot be read from this shell")

// gatewayOutOfReachText says why this shell cannot act on the gateway.
func gatewayOutOfReachText(pid int) string {
	return fmt.Sprintf("this account's gateway (PID %d) holds the port, but it runs elevated or in another Windows "+
		"logon session, so this shell cannot read its status or stop it", pid)
}

// gatewayOutOfReachFix is the next step.
func gatewayOutOfReachFix(action string) string {
	return "Run defenseclaw-gateway " + action + " from an elevated shell, or from the session that started it"
}

// gatewayOutOfReachLifecycleError refuses action (stop, restart) with nothing
// changed: this shell cannot stop that process, so it never claims it did, and
// never says no gateway runs.
func gatewayOutOfReachLifecycleError(action string, pid int) error {
	return fmt.Errorf("cannot %s the gateway from this shell: %s. %s", action, gatewayOutOfReachText(pid), gatewayOutOfReachFix(action))
}

// printGatewayOutOfReachStatus is gateway status for a gateway this shell
// cannot read: it runs, and it is this account's.
func printGatewayOutOfReachStatus(addr string, pid int) error {
	fmt.Println()
	Warn("Sidecar Status: RUNNING (elevated or in another session)")
	printGatewayKV("Endpoint", addr)
	printGatewayKV("PID", strconv.Itoa(pid))
	Subhead("This account's gateway runs elevated or in another Windows logon session, so this shell cannot read its status.")
	Subhead(gatewayOutOfReachFix("status"))
	return errGatewayOutOfReach
}

// gatewayOutOfReachDocument is the --json form of printGatewayOutOfReachStatus.
func gatewayOutOfReachDocument(doc *gatewayStatusDocument, pid int) error {
	doc.Running = true
	doc.Error = gatewayOutOfReachText(pid)
	doc.Hint = gatewayOutOfReachFix("status")
	return errGatewayOutOfReach
}
