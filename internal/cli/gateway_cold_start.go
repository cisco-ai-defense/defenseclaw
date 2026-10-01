// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// A per-user Linux or macOS gateway has no service unit, so nothing starts it
// after a reboot. The connector shell hooks start it instead: when the hook's
// request is refused, it runs `defenseclaw-gateway start --hook-cold-start`
// once and retries. These files keep that start from fighting the operator.
const (
	// hookColdStartFlag marks a start requested by a connector hook.
	hookColdStartFlag = "hook-cold-start"
	// gatewayStoppedMarkerName records `defenseclaw-gateway stop`. A hook does
	// not start a gateway the operator (or an install, uninstall or rotation)
	// stopped; the next successful start or restart removes it.
	gatewayStoppedMarkerName = "gateway.stopped"
	// gatewayColdStartFailedName records the last failed hook start so a broken
	// install costs one start per backoff window instead of one per hook.
	gatewayColdStartFailedName = "gateway.cold-start-failed"
	// gatewayStartLockName serializes start, restart and hook starts.
	gatewayStartLockName = "gateway.start.lock"
	// installLockName is install.sh's upgrade lock directory.
	installLockName = ".install.lock"

	hookColdStartBackoff          = 60 * time.Second
	hookColdStartReadinessTimeout = 30 * time.Second
	hookColdStartLockWait         = hookColdStartReadinessTimeout + 10*time.Second
	gatewayStartLockWait          = defaultStartReadinessTimeout + 15*time.Second
)

var errHookColdStartUnsupported = errors.New(
	"hook cold start is only for a per-user Linux or macOS gateway")

func gatewayStoppedMarkerPath(dataDir string) string {
	return filepath.Join(dataDir, gatewayStoppedMarkerName)
}

func gatewayColdStartFailedPath(dataDir string) string {
	return filepath.Join(dataDir, gatewayColdStartFailedName)
}

func hookColdStartRequested(cmdFlags interface {
	GetBool(string) (bool, error)
}) bool {
	if cmdFlags == nil {
		return false
	}
	enabled, err := cmdFlags.GetBool(hookColdStartFlag)
	return err == nil && enabled
}

// markGatewayStopped records an operator stop. Best effort: a data directory
// that cannot take the marker only loses the suppression, never the stop.
func markGatewayStopped(dataDir string) {
	if !hookColdStartSupported {
		return
	}
	if info, err := os.Stat(dataDir); err != nil || !info.IsDir() {
		return
	}
	body := "Stopped with defenseclaw-gateway stop at " + time.Now().UTC().Format(time.RFC3339) +
		". Agent hooks do not start the gateway until the next defenseclaw-gateway start.\n"
	_ = os.WriteFile(gatewayStoppedMarkerPath(dataDir), []byte(body), 0o600)
}

// clearGatewayColdStartState removes the stop marker and the failure backoff
// after the gateway is running again.
func clearGatewayColdStartState(dataDir string) {
	_ = os.Remove(gatewayStoppedMarkerPath(dataDir))
	_ = os.Remove(gatewayColdStartFailedPath(dataDir))
}

func recordHookColdStartFailure(dataDir string) {
	if info, err := os.Stat(dataDir); err != nil || !info.IsDir() {
		return
	}
	_ = os.WriteFile(gatewayColdStartFailedPath(dataDir), []byte(time.Now().UTC().Format(time.RFC3339)+"\n"), 0o600)
}

// hookColdStartRefusal returns why a hook may not start the gateway now, or
// nil when it may.
func hookColdStartRefusal(dataDir string, now time.Time) error {
	if !hookColdStartSupported {
		return errHookColdStartUnsupported
	}
	if _, err := os.Lstat(gatewayStoppedMarkerPath(dataDir)); err == nil {
		return errors.New("the gateway was stopped with defenseclaw-gateway stop; hooks do not start it")
	}
	if _, err := os.Lstat(filepath.Join(dataDir, installLockName)); err == nil {
		return errors.New("an install or upgrade is in progress")
	}
	if info, err := os.Lstat(gatewayColdStartFailedPath(dataDir)); err == nil {
		if since := now.Sub(info.ModTime()); since >= 0 && since < hookColdStartBackoff {
			return fmt.Errorf("a hook start failed %s ago; waiting %s between attempts",
				since.Round(time.Second), hookColdStartBackoff)
		}
	}
	return nil
}
