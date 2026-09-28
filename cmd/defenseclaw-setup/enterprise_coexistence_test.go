// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunInstallRefusesBesideEnterpriseBeforeAnyStateChange(t *testing.T) {
	refusal := errors.New("enterprise deployment present")
	previous := refuseSetupBesideEnterprise
	refuseSetupBesideEnterprise = func() error { return refusal }
	t.Cleanup(func() { refuseSetupBesideEnterprise = previous })

	root := t.TempDir()
	installRoot := filepath.Join(root, "install")
	dataRoot := filepath.Join(root, "data")
	for _, action := range []string{"install", "upgrade", "repair"} {
		code, err := runInstallContext(
			context.Background(),
			options{Action: action, Quiet: true},
			installRoot,
			dataRoot,
		)
		if !errors.Is(err, refusal) || code != 1 {
			t.Fatalf("%s: runInstallContext = (%d, %v), want (1, enterprise refusal)", action, code, err)
		}
		if pathExists(installRoot) || pathExists(dataRoot) {
			t.Fatalf("%s: refused install created per-user state", action)
		}
	}
}

func stubRuntimeRestoreRefusal(t *testing.T, refusal error) *bytes.Buffer {
	t.Helper()
	previousRefusal, previousOutput := refuseRuntimeRestoreBesideEnterprise, setupNoticeOutput
	notices := &bytes.Buffer{}
	refuseRuntimeRestoreBesideEnterprise = func() error { return refusal }
	setupNoticeOutput = notices
	t.Cleanup(func() {
		refuseRuntimeRestoreBesideEnterprise, setupNoticeOutput = previousRefusal, previousOutput
	})
	return notices
}

// A per-user upgrade stopped a running gateway and was interrupted in the
// quiescing phase. An enterprise deployment was installed afterward. The next
// uninstall (or Setup run) recovers the journal through rollback. Rollback
// must restore the files but leave the per-user runtime stopped: the restored
// gateway's start is refused beside the deployment, and treating that as a
// rollback failure kept the journal open and blocked uninstall on every retry.
func TestQuiescingRecoveryLeavesPerUserRuntimeStoppedBesideEnterprise(t *testing.T) {
	refusal := errors.New("enterprise deployment present")
	notices := stubRuntimeRestoreRefusal(t, refusal)
	installRoot, dataRoot, maintenancePath := testTransactionRoots(t)
	previous := testInstallState(
		installRoot,
		dataRoot,
		maintenancePath,
		testPreviousTransactionID,
		"1.0.0",
	)
	transaction := testSetupTransactionForRoots(
		"install",
		installRoot,
		dataRoot,
		maintenancePath,
		&previous,
	)
	transaction.PreviousServices = serviceState{Gateway: true, Watchdog: true}
	transaction.PreviousStableHookStatus = stableHookSnapshotActive
	writeInstallTree(t, installRoot, previous)
	writeInstallTree(t, transaction.StagingPath, testInstallState(
		installRoot,
		dataRoot,
		maintenancePath,
		transaction.ID,
		transaction.TargetVersion,
	))

	phase := setupPhaseQuiescing
	err := recoverSetupJournalPhase(setupJournal{
		SchemaVersion: setupJournalSchemaVersion,
		Phase:         setupPhaseQuiescing,
		Transaction:   transaction,
	}, setupRecoveryOps{
		Rollback: func(got setupTransaction) error {
			return rollbackSetupTransactionWithRuntime(
				got,
				func(string, string) error { return nil },
				func(string, string) (serviceState, error) { return serviceState{}, nil },
				func(string, string) error { return nil },
				func(setupTransaction) error { return nil },
				func(string, string, serviceState) (serviceState, error) {
					return serviceState{}, fmt.Errorf("start gateway: exit status 1: %w", refusal)
				},
			)
		},
		Transition: func(_ setupTransaction, from, to string) error {
			if phase != from {
				return fmt.Errorf("journal phase = %q, want %q", phase, from)
			}
			phase = to
			return nil
		},
	})
	if err != nil {
		t.Fatalf("recovery = %v, want the rollback to complete", err)
	}
	if phase != setupPhaseComplete {
		t.Fatalf("journal phase = %q, want complete", phase)
	}
	assertInstallVersion(t, installRoot, transaction, previous.Version)
	assertPathAbsent(t, transaction.StagingPath)
	if got := notices.String(); !strings.Contains(got, "left the per-user gateway stopped") ||
		!strings.Contains(got, refusal.Error()) {
		t.Fatalf("notice = %q, want the skipped restart and its reason", got)
	}
}

// An uninstall found a per-user install journal in the published phase, left
// by an install interrupted before an enterprise deployment was installed.
// Recovery activates and commits the install, then converges it. Convergence
// must leave the per-user runtime stopped with auto-start off instead of
// running the refused gateway start, so the journal completes and the
// uninstall continues on its first attempt. Without the deployment, or with
// no runtime wanted, convergence is unchanged and prints no notice.
func TestPublishedRecoveryLeavesPerUserRuntimeStoppedBesideEnterprise(t *testing.T) {
	refusal := errors.New("enterprise deployment present")
	for _, test := range []struct {
		name       string
		refusal    error
		wanted     serviceState
		wantCalls  string
		wantNotice bool
	}{
		{
			name:       "beside enterprise",
			refusal:    refusal,
			wanted:     serviceState{Gateway: true, Watchdog: true},
			wantCalls:  "activate,journal:committed,autostart:false,stop,verify-stopped,journal:converged,journal:complete",
			wantNotice: true,
		},
		{
			name:       "watchdog only beside enterprise",
			refusal:    refusal,
			wanted:     serviceState{Watchdog: true},
			wantCalls:  "activate,journal:committed,autostart:false,stop,verify-stopped,journal:converged,journal:complete",
			wantNotice: true,
		},
		{
			name:      "without enterprise",
			wanted:    serviceState{Gateway: true, Watchdog: true},
			wantCalls: "activate,journal:committed,autostart:true,start,verify-running,journal:converged,journal:complete",
		},
		{
			name:      "no runtime wanted beside enterprise",
			refusal:   refusal,
			wantCalls: "activate,journal:committed,autostart:false,start,verify-running,journal:converged,journal:complete",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			notices := stubRuntimeRestoreRefusal(t, test.refusal)
			var calls []string
			ops := installRuntimeConvergenceOps{
				disableStableHook: func(string) error {
					t.Fatal("ready convergence disabled the stable hook")
					return nil
				},
				configureAutoStart: func(_ string, enabled bool) (gatewayAutoStartSnapshot, bool, error) {
					calls = append(calls, fmt.Sprintf("autostart:%v", enabled))
					return gatewayAutoStartSnapshot{}, true, nil
				},
				startServices: func(_ string, _ string, wanted serviceState) (serviceState, error) {
					calls = append(calls, "start")
					if test.refusal != nil && (wanted.Gateway || wanted.Watchdog) {
						return serviceState{}, fmt.Errorf("start gateway: exit status 1: %w", test.refusal)
					}
					return wanted, nil
				},
				verifyServices: func(string, string, serviceState) error {
					calls = append(calls, "verify-running")
					return nil
				},
				stopServices: func(string, string) (serviceState, error) {
					calls = append(calls, "stop")
					return serviceState{}, nil
				},
				verifyStopped: func(string, string) error {
					calls = append(calls, "verify-stopped")
					return nil
				},
			}
			phase := setupPhasePublished
			err := recoverSetupJournalPhase(setupJournal{
				SchemaVersion: setupJournalSchemaVersion,
				Phase:         setupPhasePublished,
				Transaction:   setupTransaction{Action: "install"},
			}, setupRecoveryOps{
				Activate: func(setupTransaction) error {
					calls = append(calls, "activate")
					return nil
				},
				Rollback: func(setupTransaction) error {
					t.Fatal("published recovery rolled back after a successful activation")
					return nil
				},
				Converge: func(setupTransaction) error {
					return convergeInstallRuntime(
						testCurrentTransactionID,
						false,
						`C:\DefenseClaw\bin\defenseclaw-gateway.exe`,
						`C:\Users\test\.defenseclaw`,
						test.wanted,
						ops,
					)
				},
				Cleanup: func(setupTransaction) error { return nil },
				Transition: func(_ setupTransaction, from, to string) error {
					if phase != from {
						return fmt.Errorf("journal phase = %q, want %q", phase, from)
					}
					calls = append(calls, "journal:"+to)
					phase = to
					return nil
				},
			})
			if err != nil {
				t.Fatalf("recovery = %v, want the journal to complete", err)
			}
			if phase != setupPhaseComplete {
				t.Fatalf("journal phase = %q, want complete", phase)
			}
			if got := strings.Join(calls, ","); got != test.wantCalls {
				t.Fatalf("recovery calls = %q, want %q", got, test.wantCalls)
			}
			got := notices.String()
			if test.wantNotice {
				if !strings.Contains(got, "left the per-user gateway stopped") ||
					!strings.Contains(got, refusal.Error()) {
					t.Fatalf("notice = %q, want the skipped start and its reason", got)
				}
			} else if got != "" {
				t.Fatalf("notice = %q, want none", got)
			}
		})
	}
}

// Without an enterprise deployment the rollback still restores the prior
// per-user runtime and prints no notice.
func TestRollbackRestoresPerUserRuntimeWithoutEnterpriseDeployment(t *testing.T) {
	notices := stubRuntimeRestoreRefusal(t, nil)
	installRoot, dataRoot, maintenancePath := testTransactionRoots(t)
	previous := testInstallState(
		installRoot,
		dataRoot,
		maintenancePath,
		testPreviousTransactionID,
		"1.0.0",
	)
	transaction := testSetupTransactionForRoots(
		"uninstall",
		installRoot,
		dataRoot,
		maintenancePath,
		&previous,
	)
	transaction.PreviousStableHookStatus = stableHookSnapshotActive
	transaction.PreviousServices = serviceState{Gateway: true, Watchdog: true}
	writeInstallTree(t, transaction.TrashPath, previous)

	var restored serviceState
	err := rollbackSetupTransactionWithRuntime(
		transaction,
		func(string, string) error { return nil },
		func(string, string) (serviceState, error) { return serviceState{}, nil },
		func(string, string) error { return nil },
		func(setupTransaction) error { return nil },
		func(_ string, _ string, wanted serviceState) (serviceState, error) {
			restored = wanted
			return wanted, nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if restored != transaction.PreviousServices {
		t.Fatalf("restored services = %+v, want %+v", restored, transaction.PreviousServices)
	}
	if notices.Len() != 0 {
		t.Fatalf("notice = %q, want none", notices.String())
	}
}
