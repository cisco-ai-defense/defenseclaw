// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
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
	// gatewayLoginPathName records the PATH of the last start or restart run
	// from the account's own session. A hook cold start runs with the hook's
	// locked-down PATH, and the gateway it starts needs the account's PATH to
	// run the agents' CLIs (Codex's launcher needs node, often outside /usr/bin).
	gatewayLoginPathName = "gateway.path"
	maxGatewayLoginPath  = 32 * 1024

	hookColdStartBackoff          = 60 * time.Second
	hookColdStartReadinessTimeout = 30 * time.Second
	hookColdStartLockWait         = hookColdStartReadinessTimeout + 10*time.Second
	gatewayStartLockWait          = startReadinessProgressFactor*defaultStartReadinessTimeout + 15*time.Second
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

// recordGatewayLoginPath saves this process's PATH for later hook cold starts.
// Best effort: only absolute entries are kept.
func recordGatewayLoginPath(dataDir string) {
	if !hookColdStartSupported {
		return
	}
	if info, err := os.Stat(dataDir); err != nil || !info.IsDir() {
		return
	}
	path := absolutePathEntries(os.Getenv("PATH"))
	if path == "" || len(path) > maxGatewayLoginPath {
		return
	}
	target := filepath.Join(dataDir, gatewayLoginPathName)
	if existing, err := safefile.ReadRegularFileBounded(target, maxGatewayLoginPath+1); err == nil &&
		strings.TrimSpace(string(existing)) == path {
		return
	}
	tmp, err := os.CreateTemp(dataDir, gatewayLoginPathName+".*.tmp")
	if err != nil {
		return
	}
	_, err = tmp.WriteString(path + "\n")
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	if err == nil {
		err = os.Chmod(tmp.Name(), 0o600)
	}
	if err == nil {
		err = os.Rename(tmp.Name(), target)
	}
	if err != nil {
		_ = os.Remove(tmp.Name())
	}
}

// restoreGatewayLoginPath puts the recorded PATH in front of the hook's PATH
// for a hook cold start, so the gateway it starts sees the same tools as one
// started from the account's shell (GAP-1229).
func restoreGatewayLoginPath(dataDir string) {
	data, err := safefile.ReadRegularFileBounded(filepath.Join(dataDir, gatewayLoginPathName), maxGatewayLoginPath+1)
	if err != nil {
		return
	}
	recorded := absolutePathEntries(strings.TrimSpace(string(data)))
	if recorded == "" {
		return
	}
	merged := strings.Split(recorded, string(os.PathListSeparator))
	seen := make(map[string]bool, len(merged))
	for _, entry := range merged {
		seen[entry] = true
	}
	for _, entry := range filepath.SplitList(os.Getenv("PATH")) {
		if entry != "" && !seen[entry] {
			seen[entry] = true
			merged = append(merged, entry)
		}
	}
	_ = os.Setenv("PATH", strings.Join(merged, string(os.PathListSeparator)))
}

// absolutePathEntries drops empty, relative and malformed PATH entries.
func absolutePathEntries(path string) string {
	if strings.ContainsAny(path, "\x00\r\n") {
		return ""
	}
	kept := make([]string, 0, 16)
	for _, entry := range filepath.SplitList(path) {
		if filepath.IsAbs(entry) {
			kept = append(kept, entry)
		}
	}
	return strings.Join(kept, string(os.PathListSeparator))
}

// startConfigLoadError marks a start that failed because config.yaml does not
// load. Its message is the wrapped one.
type startConfigLoadError struct{ err error }

func (e startConfigLoadError) Error() string { return e.err.Error() }
func (e startConfigLoadError) Unwrap() error { return e.err }

// recordHookColdStartFailure writes the backoff marker. Its second line names
// a config.yaml that does not load, so the hook can say that a start cannot
// help until the file is fixed instead of "run defenseclaw-gateway start"
// (GAP-0409).
func recordHookColdStartFailure(dataDir string, cause error) {
	if info, err := os.Stat(dataDir); err != nil || !info.IsDir() {
		return
	}
	body := time.Now().UTC().Format(time.RFC3339) + "\n"
	var configErr startConfigLoadError
	if errors.As(cause, &configErr) {
		body += "config-invalid\n"
	}
	_ = os.WriteFile(gatewayColdStartFailedPath(dataDir), []byte(body), 0o600)
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
