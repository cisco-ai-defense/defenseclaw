//go:build darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"encoding/json"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

// Replaced in tests.
var (
	managedRestartNow    = time.Now
	managedServiceReexec = func() error {
		executable, err := os.Executable()
		if err != nil {
			return err
		}
		return syscall.Exec(executable, os.Args, os.Environ())
	}
	managedRestartHoldDelayFor = managedRestartHoldDelay
)

// managedStartLedgerPath is runtime/.restart-<role>.json under the pinned
// managed home.
func managedStartLedgerPath(role managedServiceRole) (string, bool) {
	if role == managedServiceNone {
		return "", false
	}
	layout, ok := managed.PinnedManagedServiceLayout()
	if !ok || !managed.SelfRepairEnabled() {
		return "", false
	}
	return filepath.Join(layout.RuntimeDir, ".restart-"+string(role)+".json"), true
}

func loadManagedStartLedger(path string) managedServiceStartLedger {
	var ledger managedServiceStartLedger
	data, err := safefile.ReadRegularFileBounded(path, 64<<10)
	if err != nil || json.Unmarshal(data, &ledger) != nil {
		return managedServiceStartLedger{}
	}
	return ledger
}

func saveManagedStartLedger(path string, ledger managedServiceStartLedger) error {
	data, err := json.Marshal(ledger)
	if err != nil {
		return err
	}
	temp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-")
	if err != nil {
		return err
	}
	name := temp.Name()
	defer func() { _ = os.Remove(name) }()
	if _, err := temp.Write(data); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Chmod(0o600); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}

// noteManagedServiceStartPlatform records this start of a managed service,
// and clears the record once the process has stayed up for the stable
// period, so only rapid repeated exits count as a restart loop.
func noteManagedServiceStartPlatform(role managedServiceRole) {
	path, ok := managedStartLedgerPath(role)
	if !ok {
		return
	}
	ledger := loadManagedStartLedger(path)
	ledger.record(managedRestartNow())
	if err := saveManagedStartLedger(path, ledger); err != nil {
		return
	}
	time.AfterFunc(managedRestartStableAfter, func() {
		_ = saveManagedStartLedger(path, managedServiceStartLedger{})
	})
}

// holdManagedServiceAfterFailurePlatform keeps a managed service up when it
// would otherwise exit into a launchd restart loop. When the recent starts
// show a loop, the process stays running, logs one degraded line per cause,
// waits with a backoff, repairs the managed paths and re-executes itself
// in place; launchd sees no exit. It returns true when the service was asked
// to stop while held, and false when the caller should exit as before.
func holdManagedServiceAfterFailurePlatform(ctx context.Context, role managedServiceRole, cause error) bool {
	path, ok := managedStartLedgerPath(role)
	if !ok || cause == nil {
		return false
	}
	ledger := loadManagedStartLedger(path)
	if !ledger.inLoop(managedRestartNow()) {
		return false
	}
	if ctx == nil {
		ctx = context.Background()
	}
	stop, cancel := signal.NotifyContext(ctx, syscall.SIGTERM, syscall.SIGINT)
	defer cancel()
	reason := cause.Error()
	for {
		if reason != ledger.LastCause {
			ledger.LastCause = reason
			_ = saveManagedStartLedger(path, ledger)
			managed.EmitResilienceEvent(managed.MarkerDegraded, map[string]string{
				"component": string(role),
				"reason":    "restart loop: staying up degraded and retrying instead of exiting: " + reason,
			})
		}
		timer := time.NewTimer(managedRestartHoldDelayFor(len(ledger.Starts)))
		select {
		case <-stop.Done():
			timer.Stop()
			return true
		case <-timer.C:
		}
		repairManagedServicePathsBeforeConfigLoadPlatform(role)
		err := managedServiceReexec()
		if err == nil {
			return true
		}
		reason = cause.Error() + "; re-exec failed: " + err.Error()
		ledger = loadManagedStartLedger(path)
		ledger.record(managedRestartNow())
		_ = saveManagedStartLedger(path, ledger)
	}
}
