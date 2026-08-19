// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/fsnotify/fsnotify"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// waitForConfigV8ManagedTimeout is the bounded window a managed-enterprise
// gateway daemon will wait for config.yaml to appear before returning a
// distinguishable error so the SCM restart cycle can pick it up cleanly.
// Spec 003 REQ-12 + AC-06. Kept as a package-level var (not a const) so a
// CI test can shorten it via a build-tag override file; there is no env
// var-configurable path — see spec 003 design.md § Tradeoffs #2.
var waitForConfigV8ManagedTimeout = 24 * time.Hour

// waitForConfigV8ManagedPoll is the interval at which the wait loop
// re-probes the config path even without an fsnotify event. Defensive
// against Windows fsnotify's event coalescing under load and against
// non-inotify filesystems (network shares) that never emit events.
var waitForConfigV8ManagedPoll = 30 * time.Second

// waitForConfigV8Managed is the bounded fsnotify wait for a missing
// managed-enterprise config.yaml. Called only from
// rootPersistentPreRunE when the initial loadGatewayConfigV8 call
// returned an os.ErrNotExist AND managed.PinnedDeploymentMode()
// reports managed_enterprise. Returns nil the moment the config path
// parses successfully; returns an error if the deadline elapses or
// the context is cancelled.
//
// This function does NOT return the loaded config — the caller
// re-invokes loadGatewayConfigV8 after we return so the normal error
// path handles any parse failure uniformly.
//
// Spec 003 § Data flow. REQ-08 through REQ-12.
func waitForConfigV8Managed(ctx context.Context, cfgPath string, w io.Writer) error {
	cfgPath = filepath.Clean(cfgPath)
	parentDir := filepath.Dir(cfgPath)

	fmt.Fprintf(w, "[gateway] managed-enterprise: config.yaml missing at %s, waiting on fsnotify (parent=%s)\n", cfgPath, parentDir)

	fsw, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("waitForConfigV8Managed: fsnotify.NewWatcher: %w", err)
	}
	defer fsw.Close()

	if err := fsw.Add(parentDir); err != nil {
		return fmt.Errorf("waitForConfigV8Managed: watch %s: %w", parentDir, err)
	}

	poll := time.NewTicker(waitForConfigV8ManagedPoll)
	defer poll.Stop()

	deadline, cancel := context.WithTimeout(ctx, waitForConfigV8ManagedTimeout)
	defer cancel()

	// Probe once on entry — the config file may have landed between
	// the initial loadGatewayConfigV8 failure and this fsw.Add call.
	// Without this we'd sit for one poll interval waiting for an
	// event that already fired.
	if isReadableRegularFile(cfgPath) {
		fmt.Fprintf(w, "[gateway] config.yaml present on entry to wait loop; resuming\n")
		return nil
	}

	for {
		select {
		case <-deadline.Done():
			// Distinguish our own bounded-wait timeout from the
			// caller cancelling us. The daemon's Ctx is fine; only
			// the 24-hour deadline hit.
			if errors.Is(deadline.Err(), context.DeadlineExceeded) {
				return fmt.Errorf("[gateway] configuration wait timeout after %s at %s — exiting for SCM restart", waitForConfigV8ManagedTimeout, cfgPath)
			}
			return deadline.Err()
		case event, ok := <-fsw.Events:
			if !ok {
				return fmt.Errorf("waitForConfigV8Managed: fsnotify events channel closed")
			}
			if filepath.Clean(event.Name) != cfgPath {
				continue
			}
			if event.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Rename) == 0 {
				continue
			}
			if isReadableRegularFile(cfgPath) {
				fmt.Fprintf(w, "[gateway] config.yaml appeared (%s); resuming\n", event.Op)
				return nil
			}
		case werr, ok := <-fsw.Errors:
			if !ok {
				return fmt.Errorf("waitForConfigV8Managed: fsnotify errors channel closed")
			}
			// fsnotify.Errors channel delivers recoverable errors
			// only (queue overflow etc.). Log and keep waiting; the
			// poll ticker guarantees we don't sit blind.
			if werr != nil {
				fmt.Fprintf(w, "[gateway] fsnotify wait error: %v\n", werr)
			}
		case <-poll.C:
			if isReadableRegularFile(cfgPath) {
				fmt.Fprintf(w, "[gateway] config.yaml present on poll; resuming\n")
				return nil
			}
		}
	}
}

// isReadableRegularFile is the low-cost probe the wait loop uses on
// every fsnotify wake + every poll tick. Deliberately NOT invoking the
// full YAML parse — that happens once inside the caller's
// loadGatewayConfigV8 retry after we return. A parse failure at that
// retry means either UCB dropped a malformed file (an operator
// problem, not a wait-loop problem) or a partial write; the wait
// loop's contract is "the file exists and is a regular file", which
// is the cheapest reliable signal that a full YAML load can be
// attempted without an unbounded retry storm.
func isReadableRegularFile(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return info.Mode().IsRegular() && info.Size() > 0
}

// managedEnterpriseFromPin resolves the deploy-mode envvar pin the
// Windows SCM installer sets (DEFENSECLAW_DEPLOYMENT_MODE=managed_enterprise).
// Returns true only for a validated managed_enterprise value. Spec 003
// REQ-13 + REQ-28: the wait loop is gated on this before the
// (possibly-missing) config.yaml has been read.
func managedEnterpriseFromPin() bool {
	return managed.IsManagedEnterprise(managed.PinnedDeploymentMode())
}

// enterConfigWaitLoopIfManaged is the small adapter
// rootPersistentPreRunE calls after its first loadGatewayConfigV8
// attempt fails. Returns true if the caller should retry
// loadGatewayConfigV8 (wait succeeded), false if the caller should
// propagate the original error (non-managed_enterprise mode, or the
// error was not a missing-file case).
//
// Kept as a small helper for readability at the PreRunE call site and
// so unit tests can drive the classifier without spinning up an
// actual fsnotify watcher.
func enterConfigWaitLoopIfManaged(ctx context.Context, cfgPath string, initialErr error, w io.Writer) (retry bool, waitErr error) {
	if !isMissingConfigErr(initialErr) {
		return false, nil
	}
	if !managedEnterpriseFromPin() {
		return false, nil
	}
	if err := waitForConfigV8Managed(ctx, cfgPath, w); err != nil {
		return false, err
	}
	return true, nil
}

// isMissingConfigErr classifies an error from loadGatewayConfigV8 as
// the specific "config.yaml is not on disk yet" case.
// loadGatewayConfigV8 wraps the underlying os.Open error via
// readConfigV8Source's %w, so errors.Is against os.ErrNotExist reaches
// the sentinel.
//
// Other errors (parse failure, oversize, permission denied) are NOT
// treated as wait-triggers: they represent real UCB / operator faults
// that must surface loudly rather than be masked by a 24-hour wait.
func isMissingConfigErr(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, os.ErrNotExist)
}
