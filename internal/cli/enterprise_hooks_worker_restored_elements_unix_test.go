// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
)

// GAP-0754: a restore is a protected element that did not match what
// DefenseClaw renders when the repair began and matches it when it ended. A
// write to a file the agent also writes for its own settings is no restore.

// The agent changes one of its own settings in the shared config while the
// install runs; the install never puts the hook entry or the script back. The
// target stays failed and nothing is counted, whether the worker exits or the
// install returns an error.
func TestEnterpriseHookWorkerAgentSettingWriteIsNoRestore(t *testing.T) {
	for _, mode := range []string{"unrelated-write-exit", "unrelated-write-fail"} {
		t.Run(mode, func(t *testing.T) {
			useEnterpriseHookWorkerHelper(t, mode)
			account := selfWorkerAccount(t)
			jobs := map[int]*enterpriseHookWorkerJob{account.UID: {Account: account, Request: enterpriseHookWorkerRequest{
				Operation: enterpriseHookWorkerOpApply, Standalone: true,
				Targets: []enterpriseHookWorkerTarget{workerTarget(account, 1, enterpriseHookWorkerModeVerifyOrRepair, "hermes", true)},
			}}}
			got, ok := dispatchEnterpriseHookStandaloneJobs(withEnterpriseHookWorkerInterruptDrain(context.Background()), jobs)[1]
			if !ok {
				t.Fatal("the dispatcher omitted the protected hermes target")
			}
			if _, err := os.Stat(filepath.Join(account.Home, ".hermes", "config.yaml")); err != nil {
				t.Fatalf("the agent setting was not written: %v", err)
			}
			if got.ok || got.pending || got.err == "" || got.repaired || len(got.restored) != 0 {
				t.Fatalf("outcome = %+v, want a failed target with no restore", got)
			}
		})
	}
}

// A restore of the hook entry alone, of the hook runtime files alone, and of
// both is named element by element, once each.
func TestEnterpriseHookWorkerNamesEachRestoredElementOnce(t *testing.T) {
	for _, tc := range []struct {
		mode string
		want []string
	}{
		{"entry-restore", entryElement},
		{"fail-after-write", runtimeElement},
		{"both-restore", slices.Concat(entryElement, runtimeElement)},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			useEnterpriseHookWorkerHelper(t, tc.mode)
			account := selfWorkerAccount(t)
			response, err := runEnterpriseHookWorker(withEnterpriseHookWorkerInterruptDrain(context.Background()), account,
				enterpriseHookWorkerRequest{Operation: enterpriseHookWorkerOpApply, Standalone: true,
					Targets: []enterpriseHookWorkerTarget{workerTarget(account, 1, enterpriseHookWorkerModeVerifyOrRepair, "hermes", true)}})
			if err != nil {
				t.Fatal(err)
			}
			if len(response.Targets) != 1 || !response.Targets[0].OK || !response.Targets[0].Repaired ||
				!slices.Equal(response.Targets[0].RestoredElements, tc.want) {
				t.Fatalf("answer = %+v, want a healthy target with %v restored", response.Targets, tc.want)
			}
		})
	}
}

// A worker that reports an element name the guardian does not know, or one
// twice, claims no more than the known element once.
func TestStandaloneOutcomeKeepsOnlyKnownRestoredElements(t *testing.T) {
	got, changes := knownEnterpriseHookElements(
		[]string{"shared agent config", enterprisehooks.HookElementRuntime, enterprisehooks.HookElementRuntime},
		[]string{enterprisehooks.HookChangeEdited, enterprisehooks.HookChangeAppended, enterprisehooks.HookChangeEdited})
	if !slices.Equal(got, runtimeElement) || !slices.Equal(changes, []string{enterprisehooks.HookChangeAppended}) {
		t.Fatalf("elements = %v changes = %v, want the runtime files once with the change reported for it", got, changes)
	}
	// A change kind the guardian does not know, or none, is kept as unknown.
	if _, changes := knownEnterpriseHookElements(entryElement, []string{"overwritten"}); !slices.Equal(changes, []string{""}) {
		t.Fatalf("changes = %v, want an unknown change left empty", changes)
	}
}
