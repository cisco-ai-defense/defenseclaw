// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"io"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/spf13/cobra"
)

// GAP-1540 refix: the guardian's first reconcile already runs as the
// guardian, so a check the guardian skips (the Windows Copilot row's Claude
// settings) never fails that pass and reinstalls the runtime at every start.
func TestEnterpriseHooksWatchIsTheGuardianFromItsFirstReconcile(t *testing.T) {
	restoreEnterpriseHooksLifecycleTestState(t)
	previousManifest := enterpriseHookManifest
	previousBefore := enterpriseHookBeforeWatchReconcile
	t.Cleanup(func() {
		enterpriseHookManifest = previousManifest
		enterpriseHookBeforeWatchReconcile = previousBefore
	})
	cfg = &config.Config{DeploymentMode: "local"}
	enterpriseHookManifest = filepath.Join(t.TempDir(), "targets.yaml")
	var watching []bool
	enterpriseHookBeforeWatchReconcile = func(io.Writer) { watching = append(watching, enterpriseHookGuardianWatching.Load()) }
	cmd := &cobra.Command{}
	cmd.SetContext(context.Background())
	cmd.SetErr(io.Discard)
	if err := runEnterpriseHooksWatch(cmd, nil); err == nil || len(watching) != 1 || !watching[0] {
		t.Fatalf("watch = %v; guardian flag at each reconcile = %v, want true from the first", err, watching)
	}
	if enterpriseHookGuardianWatching.Load() {
		t.Fatal("the guardian flag outlived the watch loop")
	}
}

// GAP-1540 refix: readiness notes are reported under warnings after the
// excused rows and never count as failures.
func TestEnterpriseHookReadinessNotesAreWarnings(t *testing.T) {
	notes := &enterpriseHookNoteSet{}
	notes.add(`C:\Users\u1\.claude\settings.json cannot be checked`)
	notes.add(`C:\Users\u1\.claude\settings.json cannot be checked`)
	run := enterpriseHookVerifyRun{}
	got := enterpriseHookVerifyWarnings(run, notes)
	if len(got) != 1 || !strings.Contains(got[0], "settings.json") {
		t.Fatalf("readiness warnings = %q, want the one note", got)
	}
	if run.Failures != 0 {
		t.Fatal("a readiness note counted as a failure")
	}
	if got := enterpriseHookVerifyWarnings(run, nil); len(got) != 0 {
		t.Fatalf("verify (no readiness notes) warnings = %q", got)
	}
}
