// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

// A call the policy blocks in this bare API fixture; the live cell used a
// protected call to the sign-in key file, which the same hook path blocks.
const custodyScopeProtectedCall = "rm -rf /"

// An unsafe folder for one connector must stop only that connector. Before the
// fix a connector that was already active and met this refusal on a restart
// failed the whole start, so the co-resident connector ran unchecked
// (GAP-0798).
func TestCustodyRefusalOfOneActiveConnectorKeepsTheOthersEnforcing(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the open-folder fixture is a Unix mode bit")
	}
	s := multiBootSidecar(t)
	s.cfg.DataDir = testenv.PrivateTempDir(t)
	s.cfg.Guardrail.Enabled = true
	s.cfg.Guardrail.Mode = "observe"
	s.cfg.Guardrail.HookFailMode = "open"
	s.health = NewSidecarHealth()
	configDir := testenv.PrivateTempDir(t)
	t.Setenv("OPENCODE_CONFIG_DIR", configDir)
	prepareOpenCodeSetupAuthorityFixture(t, s.cfg.DataDir)
	pluginPath := filepath.Join(configDir, "plugins", "defenseclaw.js")

	boot := func() (multiConnectorSetupTransaction, error) {
		// The real OpenCode setup writes the shared hook sidecar, which has no
		// fail mode for the stub peer; a real peer would write its own.
		if err := os.Remove(filepath.Join(s.cfg.DataDir, "hooks", ".hookcfg")); err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
		peer := &bootStubConnector{stubConnector: stubConnector{name: "codex"}}
		return s.setupConnectorsIsolatedTransaction(
			context.Background(), []connector.Connector{peer, connector.NewOpenCodeConnector()},
			"tok", "127.0.0.1:0", "127.0.0.1:0", guardrail.NewRulePackCache(),
		)
	}

	// Benign twin: the private folder starts both, and OpenCode is registered.
	first, err := boot()
	if err != nil || !reflect.DeepEqual(first.succeeded, []string{"codex", "opencode"}) {
		t.Fatalf("first start: err=%v succeeded=%v", err, first.succeeded)
	}
	if err := connector.SaveActiveConnectors(s.cfg.DataDir, []string{"opencode"}); err != nil {
		t.Fatal(err)
	}
	// OpenCode is the previously active connector. The stub peer writes no hook
	// script, so it starts fresh each time and keeps no lock entry.
	if err := connector.ClearHookContractLockEntry(s.cfg.DataDir, "codex"); err != nil {
		t.Fatal(err)
	}
	pluginBefore, err := os.ReadFile(pluginPath)
	if err != nil {
		t.Fatalf("OpenCode plugin was not written: %v", err)
	}
	lockBefore := connector.LoadHookContractLockEntry(s.cfg.DataDir, "opencode")

	// Other accounts can now write the OpenCode folder.
	if err := os.Chmod(configDir, 0o757); err != nil {
		t.Fatal(err)
	}
	got, err := boot()
	if err != nil {
		t.Fatalf("an unsafe OpenCode folder stopped the start for every connector: %v", err)
	}
	if want := []string{"codex"}; !reflect.DeepEqual(got.succeeded, want) {
		t.Fatalf("survivors = %v, want %v (not started: %v)", got.succeeded, want, got.notStartedReasons)
	}
	if want := []string{"opencode"}; !reflect.DeepEqual(got.keptRegistrations, want) {
		t.Fatalf("kept registrations = %v, want %v", got.keptRegistrations, want)
	}
	reason := got.notStartedReasons["opencode"]
	if !strings.Contains(reason, configDir) {
		t.Errorf("reason does not name the folder %s: %q", configDir, reason)
	}
	if fix := got.notStartedRepairs["opencode"].Fix; !strings.Contains(fix, "chmod go-w") || !strings.Contains(fix, configDir) {
		t.Errorf("repair does not carry the one command for %s: %+v", configDir, got.notStartedRepairs["opencode"])
	}
	if after, err := os.ReadFile(pluginPath); err != nil || !bytes.Equal(after, pluginBefore) {
		t.Errorf("the refusal changed the OpenCode plugin: err=%v", err)
	}
	if after := connector.LoadHookContractLockEntry(s.cfg.DataDir, "opencode"); !reflect.DeepEqual(after, lockBefore) {
		t.Errorf("the refusal changed the OpenCode lock entry:\nbefore %+v\nafter  %+v", lockBefore, after)
	}

	// Codex stays protected and OpenCode is reported not started: the
	// protected call that ran unchecked is blocked, whatever the outage mode.
	s.health.finishConnectorSetup(got.succeeded, connectorsNotStarted(
		[]connector.Connector{&stubConnector{name: "codex"}, &stubConnector{name: "opencode"}}, got.succeeded))
	s.cfg.Guardrail.Mode = "action"
	s.cfg.Guardrail.Connectors = map[string]config.PerConnectorGuardrailConfig{"codex": {}, "opencode": {}}
	api := &APIServer{health: s.health, scannerCfg: s.cfg}
	if verdict := removedAgentHookVerdict(t, api, "codex", custodyScopeProtectedCall); verdict.Action != "block" {
		t.Fatalf("Codex protected call = %+v, want block", verdict)
	}
	if verdict := removedAgentHookVerdict(t, api, "codex", "echo benign"); verdict.Action != "allow" {
		t.Fatalf("Codex ordinary command = %+v, want allow", verdict)
	}

	// The printed fix and a restart bring OpenCode back.
	s.cfg.Guardrail.Mode = "observe"
	if err := os.Chmod(configDir, 0o700); err != nil {
		t.Fatal(err)
	}
	again, err := boot()
	if err != nil || !reflect.DeepEqual(again.succeeded, []string{"codex", "opencode"}) {
		t.Fatalf("start after the fix: err=%v succeeded=%v", err, again.succeeded)
	}
	if len(again.notStartedReasons) != 0 || len(again.keptRegistrations) != 0 {
		t.Errorf("start after the fix still reports %v / %v", again.notStartedReasons, again.keptRegistrations)
	}
}

// The same rule covers the other custody refusal made before Setup writes: the
// agent executable folder another account can write. Anything that is not a
// custody refusal keeps failing the refresh of an active connector, so an
// upgrade still rolls back.
func TestOnlyCustodyRefusalsOfAnActiveConnectorAreScopedToIt(t *testing.T) {
	for _, tc := range []struct {
		name    string
		err     error
		skipped bool
	}{
		{"agent folder another account can write", fmt.Errorf("opencode executable admission: %w: %w", connector.ErrExecutableAdmission, connector.ErrAgentInstallNotTrusted), true},
		{"executable admission alone", fmt.Errorf("opencode executable admission: %w", connector.ErrExecutableAdmission), false},
		{"a setup that failed after writing", errors.New("setup wrote state before it failed"), false},
		{"custody marker joined with a failed rollback", errors.Join(errors.New("capture plugin backup"), fmt.Errorf("%w", connector.ErrPluginFolderCustody)), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := multiBootSidecar(t)
			s.cfg.DataDir = testenv.PrivateTempDir(t)
			s.health = NewSidecarHealth()
			t.Setenv("PATH", testenv.PrivateTempDir(t))
			lock := stageAdmissionFixture(t, s.cfg.DataDir)
			if err := connector.SaveHookContractLockEntry(s.cfg.DataDir, lock); err != nil {
				t.Fatal(err)
			}
			if err := connector.SaveActiveConnectors(s.cfg.DataDir, []string{"claudecode", "codex"}); err != nil {
				t.Fatal(err)
			}
			refused := &bootStubConnector{stubConnector: stubConnector{name: "claudecode"}, setupErr: tc.err}
			peer := &bootStubConnector{stubConnector: stubConnector{name: "codex"}}
			got, err := s.setupConnectorsIsolatedTransaction(
				context.Background(), []connector.Connector{refused, peer},
				"tok", "127.0.0.1:0", "127.0.0.1:0", guardrail.NewRulePackCache(),
			)
			if !tc.skipped {
				if err == nil || !strings.Contains(err.Error(), "connector claudecode refresh failed") {
					t.Fatalf("error = %v, want the refresh of the active connector to fail", err)
				}
				return
			}
			if err != nil || !reflect.DeepEqual(got.succeeded, []string{"codex"}) {
				t.Fatalf("err=%v succeeded=%v, want only the refused connector skipped", err, got.succeeded)
			}
			if !strings.Contains(got.notStartedReasons["claudecode"], "executable admission") {
				t.Errorf("reason = %q", got.notStartedReasons["claudecode"])
			}
			if refused.teardownCalls != 0 {
				t.Errorf("teardownCalls = %d, want 0 (keep the earlier hooks)", refused.teardownCalls)
			}
		})
	}
}
