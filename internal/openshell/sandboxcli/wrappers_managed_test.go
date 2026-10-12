// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package sandboxcli

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// managedTestApp is a test app on a standalone managed computer: the
// configuration the launcher runs with, the daemon's managed status, and no
// per-user config.yaml.
func managedTestApp(t *testing.T, required ...string) *testApp {
	t.Helper()
	ta := newTestApp(t, "")
	ta.Cfg.DeploymentMode = managed.DeploymentModeManagedEnterprise
	ta.Cfg.Enterprise.Profile = managed.ProfileStandalone
	// The launcher's configuration may say sandboxes are off (a status it
	// could not read); the daemon decides.
	ta.Cfg.OpenShell.Enabled = false
	ta.daemon.status.Managed = &sandboxapi.ManagedStatus{Profile: "contractors"}
	ta.daemon.explain.Managed = &sandboxapi.ManagedExplain{Allowed: true, RequiredFor: required}
	ta.env["SHELL"] = "/bin/bash"
	return ta
}

// On a managed computer enable records the wrapper in the shell's rc file
// and nothing else: it does not write the user's config.yaml (and leak its
// path and validator codes), it creates no lock or sandboxes directory in
// the data directory, and it does not offer the bypass the gate refuses for
// a required agent (GAP-0292, GAP-0362).
func TestManagedEnableRecordsOnlyTheWrapper(t *testing.T) {
	ta := managedTestApp(t, "claudecode")
	ta.ok(t, ta.Enable(WrapperOptions{Harness: "claude"}))
	out := ta.output()
	has(t, out, "`claude` now runs in a DefenseClaw sandbox", "undo: defenseclaw sandbox disable claude")
	lacks(t, out, "bypass once", "could not record", "config.yaml", "migrate", "config_version_required")
	bashrc, _ := os.ReadFile(filepath.Join(ta.home, ".bashrc"))
	has(t, string(bashrc), "sandbox run claude")
	entries, err := os.ReadDir(ta.dataDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		t.Errorf("enable left %s in the data directory", e.Name())
	}
	ta.ok(t, ta.Disable(WrapperOptions{Harness: "claude"}))
	if entries, _ := os.ReadDir(ta.dataDir()); len(entries) != 0 {
		t.Errorf("disable left %d entries in the data directory", len(entries))
	}
}

// An agent the organization does not require keeps its one-time bypass, and
// an rc file other than the shell's usual one is recorded so that disable
// finds it again.
func TestManagedEnableOffersTheBypassOnlyForAnAgentThatIsNotRequired(t *testing.T) {
	ta := managedTestApp(t, "codex")
	custom := filepath.Join(ta.home, "dotfiles", "shell.rc")
	ta.ok(t, ta.Enable(WrapperOptions{Harness: "claude", Shell: "bash", RC: custom}))
	has(t, ta.output(), "bypass once: DEFENSECLAW_NO_SANDBOX=1 claude")
	if r, err := ta.loadReceipt(); err != nil || len(r.Wrappers) != 1 {
		t.Fatalf("receipt wrappers = %+v, %v", r, err)
	}
	if _, err := os.Stat(ta.ConfigPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("config.yaml was written: %v", err)
	}
}

// While the daemon says sandboxes are off on a managed computer, enable
// reports the organization's answer, not the per-user `sandbox setup`.
func TestManagedEnableReportsTheDaemonsAnswerWhileSandboxesAreOff(t *testing.T) {
	ta := managedTestApp(t)
	ta.daemon.status.Enabled = false
	err := ta.Enable(WrapperOptions{Harness: "claude"})
	if err == nil {
		t.Fatal("enable succeeded while sandboxes are off")
	}
	has(t, err.Error(), "not wrapping `claude`", "your organization manages this setting")
	lacks(t, err.Error(), "sandbox setup")
	// With sandboxes on the same configuration enables.
	ta.daemon.status.Enabled = true
	ta.ok(t, ta.Enable(WrapperOptions{Harness: "claude"}))
}
