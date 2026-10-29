// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
	"github.com/defenseclaw/defenseclaw/internal/testenv"
	"github.com/defenseclaw/defenseclaw/internal/version"
)

// Claude Code reads its agent version from discovery on every host, so these
// fixtures can move the agent version independently of the recorded lock.
const admissionFixtureAgentVersion = "Claude Code v2.1.154"

func stageAdmissionFixture(t *testing.T, dataDir string) connector.HookContractLockEntry {
	t.Helper()
	resolution := connector.ResolveHookContract("claudecode", admissionFixtureAgentVersion)
	if resolution.Status != connector.HookCompatibilityKnown || resolution.Contract.ContractID == "" {
		t.Fatalf("fixture agent version does not resolve to a known contract: %+v", resolution)
	}
	raw, err := json.Marshal(map[string]any{
		"agents": map[string]any{"claudecode": map[string]any{"version": admissionFixtureAgentVersion}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dataDir, "agent_discovery.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return connector.HookContractLockEntry{
		Connector:              "claudecode",
		RawAgentVersion:        resolution.RawVersion,
		NormalizedAgentVersion: resolution.NormalizedVersion,
		ContractID:             resolution.Contract.ContractID,
		CompatibilityStatus:    resolution.Status,
	}
}

func admissionSidecar(t *testing.T) *Sidecar {
	t.Helper()
	s := multiBootSidecar(t)
	s.cfg.DataDir = testenv.PrivateTempDir(t)
	s.cfg.Guardrail.Mode = "action"
	s.cfg.Guardrail.Connectors = map[string]config.PerConnectorGuardrailConfig{
		"claudecode": {Mode: "action"},
	}
	return s
}

func TestHookContractAdmissionRefreshesDefenseClawReleaseContractChange(t *testing.T) {
	for _, writer := range []string{"0.8.10", ""} {
		t.Run("writer="+writer, func(t *testing.T) {
			s := admissionSidecar(t)
			current := stageAdmissionFixture(t, s.cfg.DataDir)
			previous := current
			previous.ContractID = "claudecode-hooks-retired"
			previous.DefenseClawVersion = writer
			if err := connector.SaveHookContractLockEntry(s.cfg.DataDir, previous); err != nil {
				t.Fatal(err)
			}

			conn := &bootStubConnector{stubConnector: stubConnector{name: "claudecode"}}
			transaction, err := s.setupConnectorsIsolatedTransaction(
				context.Background(), []connector.Connector{conn},
				"tok", "127.0.0.1:0", "127.0.0.1:0", "master", guardrail.NewRulePackCache(),
			)
			if err != nil {
				t.Fatalf("setup: %v", err)
			}
			if !reflect.DeepEqual(transaction.succeeded, []string{"claudecode"}) ||
				len(transaction.admissionRefused) != 0 || conn.setupCalls != 1 {
				t.Fatalf("succeeded=%v refused=%v setupCalls=%d, want a refreshed connector",
					transaction.succeeded, transaction.admissionRefused, conn.setupCalls)
			}
			refreshed := connector.LoadHookContractLockEntry(s.cfg.DataDir, "claudecode")
			if refreshed.ContractID != current.ContractID ||
				refreshed.DefenseClawVersion != version.Current().BinaryVersion {
				t.Fatalf("refreshed lock contract=%q writer=%q, want %q by %q",
					refreshed.ContractID, refreshed.DefenseClawVersion,
					current.ContractID, version.Current().BinaryVersion)
			}
		})
	}
}

// An agent update to a version that still resolves to a hook contract is
// routine: admission refreshes the lock instead of refusing the connector.
func TestHookContractAdmissionRefreshesCompatibleAgentUpdate(t *testing.T) {
	s := admissionSidecar(t)
	current := stageAdmissionFixture(t, s.cfg.DataDir)
	previous := current
	previous.RawAgentVersion = "Claude Code v1.0.0"
	previous.NormalizedAgentVersion = "1.0.0"
	previous.ContractID = "claudecode-hooks-retired"
	if err := connector.SaveHookContractLockEntry(s.cfg.DataDir, previous); err != nil {
		t.Fatal(err)
	}
	conn := &bootStubConnector{stubConnector: stubConnector{name: "claudecode"}}
	transaction, err := s.setupConnectorsIsolatedTransaction(
		context.Background(), []connector.Connector{conn},
		"tok", "127.0.0.1:0", "127.0.0.1:0", "master", guardrail.NewRulePackCache(),
	)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	if !reflect.DeepEqual(transaction.succeeded, []string{"claudecode"}) ||
		len(transaction.admissionRefused) != 0 || conn.setupCalls != 1 {
		t.Fatalf("succeeded=%v refused=%v setupCalls=%d, want a refreshed connector",
			transaction.succeeded, transaction.admissionRefused, conn.setupCalls)
	}
	if refreshed := connector.LoadHookContractLockEntry(s.cfg.DataDir, "claudecode"); refreshed.ContractID != current.ContractID ||
		refreshed.RawAgentVersion != current.RawAgentVersion {
		t.Fatalf("refreshed lock = %q %q, want %q %q", refreshed.ContractID, refreshed.RawAgentVersion, current.ContractID, current.RawAgentVersion)
	}
}

func TestHookContractAdmissionStillRefusesUpstreamAgentDrift(t *testing.T) {
	for name, mutate := range map[string]func(*connector.HookContractLockEntry){
		// Strict resolution (Secure Client) refuses every agent change.
		"agent update under strict resolution": func(entry *connector.HookContractLockEntry) {
			entry.RawAgentVersion = "Claude Code v1.0.0"
			entry.NormalizedAgentVersion = "1.0.0"
			entry.ContractID = "claudecode-hooks-retired"
		},
	} {
		t.Run(name, func(t *testing.T) {
			connector.SetStrictHookContractResolution(true)
			t.Cleanup(func() { connector.SetStrictHookContractResolution(false) })
			s := admissionSidecar(t)
			previous := stageAdmissionFixture(t, s.cfg.DataDir)
			mutate(&previous)
			if err := connector.SaveHookContractLockEntry(s.cfg.DataDir, previous); err != nil {
				t.Fatal(err)
			}

			conn := &bootStubConnector{stubConnector: stubConnector{name: "claudecode"}}
			transaction, err := s.setupConnectorsIsolatedTransaction(
				context.Background(), []connector.Connector{conn},
				"tok", "127.0.0.1:0", "127.0.0.1:0", "master", guardrail.NewRulePackCache(),
			)
			if err != nil {
				t.Fatalf("setup: %v", err)
			}
			if len(transaction.succeeded) != 0 || conn.setupCalls != 0 ||
				!reflect.DeepEqual(transaction.admissionRefused, []string{"claudecode"}) {
				t.Fatalf("succeeded=%v refused=%v setupCalls=%d, want a clean admission refusal",
					transaction.succeeded, transaction.admissionRefused, conn.setupCalls)
			}
			if kept := connector.LoadHookContractLockEntry(s.cfg.DataDir, "claudecode"); kept.ContractID != previous.ContractID {
				t.Fatalf("refused connector lock contract = %q, want unchanged %q", kept.ContractID, previous.ContractID)
			}
		})
	}
}

func TestHookContractAdmissionRefusalPublishesStructuredGuardrailDetail(t *testing.T) {
	err := error(&hookContractAdmissionRefusal{
		connectors: []string{"codex", "claudecode"},
		err:        errors.Join(ErrHookContractAdmission, errors.New("drift")),
	})
	if !errors.Is(err, ErrHookContractAdmission) {
		t.Fatal("admission refusal does not match ErrHookContractAdmission")
	}
	details := guardrailFailureDetails(err)
	if got := details[GuardrailHookContractAdmissionRefused]; !reflect.DeepEqual(got, []string{"codex", "claudecode"}) {
		t.Fatalf("admission detail = %#v, want both refused connectors", got)
	}
	if guardrailFailureDetails(ErrHookContractAdmission) != nil || guardrailFailureDetails(errors.New("setup failed")) != nil {
		t.Fatal("unstructured guardrail failures must not claim an admission refusal")
	}
}

func TestRunActiveGuardrailReportsSingleConnectorAdmissionRefusal(t *testing.T) {
	dataDir := testenv.PrivateTempDir(t)
	settings := filepath.Join(t.TempDir(), ".claude", "settings.json")
	previousSettings := connector.ClaudeCodeSettingsPathOverride
	connector.ClaudeCodeSettingsPathOverride = settings
	t.Cleanup(func() { connector.ClaudeCodeSettingsPathOverride = previousSettings })
	t.Setenv("CLAUDE_CONFIG_DIR", filepath.Dir(settings))

	s := &Sidecar{
		cfg: &config.Config{
			DataDir: dataDir,
			Gateway: config.GatewayConfig{Token: "gateway-token"},
			Guardrail: config.GuardrailConfig{
				Enabled:   true,
				Connector: "claudecode",
				Mode:      "action",
			},
		},
		health: NewSidecarHealth(),
		router: routerWithDefaultRulePack(t),
	}
	// A compatible agent update is admitted unless resolution is strict
	// (Secure Client), so the refused drift is an agent update under strict
	// resolution.
	connector.SetStrictHookContractResolution(true)
	t.Cleanup(func() { connector.SetStrictHookContractResolution(false) })
	previous := stageAdmissionFixture(t, dataDir)
	previous.RawAgentVersion = "Claude Code v1.0.0"
	previous.NormalizedAgentVersion = "1.0.0"
	previous.ContractID = "claudecode-hooks-retired"
	if err := connector.SaveHookContractLockEntry(dataDir, previous); err != nil {
		t.Fatal(err)
	}

	err := s.runActiveGuardrail(context.Background())
	if !errors.Is(err, ErrHookContractAdmission) || !strings.Contains(err.Error(), "hook contract drift detected") {
		t.Fatalf("runActiveGuardrail error = %v, want hook contract drift refusal", err)
	}
	assertPathMissing(t, settings)
	snapshot := s.health.Snapshot()
	if snapshot.Guardrail.State != StateError {
		t.Fatalf("guardrail state = %s, want %s", snapshot.Guardrail.State, StateError)
	}
	if got := snapshot.Guardrail.Details[GuardrailHookContractAdmissionRefused]; !reflect.DeepEqual(got, []string{"claudecode"}) {
		t.Fatalf("admission detail = %#v, want the refused connector", got)
	}
}

func TestRunActiveGuardrailReportsReleaseCausedRefusalAsFailure(t *testing.T) {
	dataDir := testenv.PrivateTempDir(t)
	settings := filepath.Join(t.TempDir(), ".claude", "settings.json")
	previousSettings := connector.ClaudeCodeSettingsPathOverride
	connector.ClaudeCodeSettingsPathOverride = settings
	t.Cleanup(func() { connector.ClaudeCodeSettingsPathOverride = previousSettings })
	t.Setenv("CLAUDE_CONFIG_DIR", filepath.Dir(settings))

	// An earlier release admitted this agent version; this release's contract
	// table no longer covers it.
	const unknownVersion = "Claude Code v0.0.1"
	if status := connector.ResolveHookContract("claudecode", unknownVersion).Status; status != connector.HookCompatibilityUnknown {
		t.Fatalf("fixture version resolves to %s, want unknown", status)
	}
	raw, err := json.Marshal(map[string]any{
		"agents": map[string]any{"claudecode": map[string]any{"version": unknownVersion}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dataDir, "agent_discovery.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := connector.SaveHookContractLockEntry(dataDir, connector.HookContractLockEntry{
		Connector:          "claudecode",
		RawAgentVersion:    unknownVersion,
		ContractID:         "claudecode-hooks-v1",
		DefenseClawVersion: "0.0.1-previous",
	}); err != nil {
		t.Fatal(err)
	}
	s := &Sidecar{
		cfg: &config.Config{
			DataDir: dataDir,
			Gateway: config.GatewayConfig{Token: "gateway-token"},
			Guardrail: config.GuardrailConfig{
				Enabled:   true,
				Connector: "claudecode",
				Mode:      "action",
			},
		},
		health: NewSidecarHealth(),
		router: routerWithDefaultRulePack(t),
	}

	err = s.runActiveGuardrail(context.Background())
	if !errors.Is(err, errReleaseContractRefusal) || !errors.Is(err, ErrHookContractAdmission) {
		t.Fatalf("runActiveGuardrail error = %v, want a release-caused admission failure", err)
	}
	var refusal *hookContractAdmissionRefusal
	if errors.As(err, &refusal) {
		t.Fatal("a release-caused refusal must not be reported as upstream drift")
	}
	if details := s.health.Snapshot().Guardrail.Details; details[GuardrailHookContractAdmissionRefused] != nil {
		t.Fatalf("admission detail = %#v, want none so start fails and an upgrade rolls back", details)
	}
}

// An upgrade refreshes an active connector whose agent binary discovery found
// but whose version it could not read: discovery records no version and why.
// The refusal is unchanged (the start still fails and the upgrade rolls back),
// but it names that cause and the fix for it instead of telling the user to
// close an agent that cannot be open (GAP-1167). Each cause gets its own next
// step: only an agent that ran and failed is told to fix its runtime on PATH
// (GAP-2479).
func TestRefreshOfAnAgentThatDidNotRunNamesTheCauseNotAnOpenAgent(t *testing.T) {
	const runtimeHint = "putting its runtime on PATH"
	longTimeout := strings.Repeat("/opt/dc-agents/bin/claude-untrusted: binary path is not in a trusted install prefix; ", 6) + "/opt/dc-agents/bin/claude: version probe timed out"
	for name, tc := range map[string]struct {
		probeError string
		want       []string
		unwanted   []string
	}{
		"agent did not run": {
			probeError: "/opt/dc-agents/bin/claude: version probe exited 127: /usr/bin/env: ‘node’: No such file or directory",
			want:       []string{"the agent did not run when discovery read its version", "version probe exited 127", "No such file or directory", runtimeHint},
		},
		"probe timed out": {
			probeError: "/opt/dc-agents/bin/claude: version probe timed out",
			want:       []string{"did not answer its version probe in time", "version probe timed out", "start it once from this account"},
			unwanted:   []string{runtimeHint, "the agent did not run"},
		},
		"timeout recorded past the quoted length": {
			probeError: longTimeout,
			want:       []string{"did not answer its version probe in time", "start it once from this account"},
			unwanted:   []string{runtimeHint, "is not trusted"},
		},
		"untrusted install path": {
			probeError: "/home/u/open/claude: binary path is not in a trusted install prefix",
			want:       []string{"its install path is not trusted", "not in a trusted install prefix", "only administrators or this account can write"},
			unwanted:   []string{runtimeHint, "the agent did not run"},
		},
		"not probed": {
			probeError: "version not probed: not being set up",
			want:       []string{"has not read the agent's version yet", "version not probed", "check that it starts from this account"},
			unwanted:   []string{runtimeHint, "the agent did not run"},
		},
		"other unreadable version": {
			probeError: "/opt/dc-agents/bin/claude: version metadata is unavailable",
			want:       []string{"could not read the agent's version", "version metadata is unavailable", "prints its version"},
			unwanted:   []string{runtimeHint, "the agent did not run"},
		},
		"no recorded probe err": {},
	} {
		t.Run(name, func(t *testing.T) {
			s := admissionSidecar(t)
			raw, err := json.Marshal(map[string]any{
				"agents": map[string]any{"claudecode": map[string]any{
					"version": "", "binary_path": "/opt/dc-agents/bin/claude", "installed": false, "error": tc.probeError,
				}},
			})
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(s.cfg.DataDir, "agent_discovery.json"), raw, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := connector.SaveActiveConnectors(s.cfg.DataDir, []string{"claudecode"}); err != nil {
				t.Fatal(err)
			}

			conn := &bootStubConnector{stubConnector: stubConnector{name: "claudecode"}}
			_, err = s.setupConnectorsIsolatedTransaction(
				context.Background(), []connector.Connector{conn},
				"tok", "127.0.0.1:0", "127.0.0.1:0", "master", guardrail.NewRulePackCache(),
			)
			if err == nil || !errors.Is(err, ErrHookContractAdmission) || conn.setupCalls != 0 {
				t.Fatalf("refresh error = %v, setupCalls = %d; want the unversioned agent refused before setup", err, conn.setupCalls)
			}
			message := err.Error()
			if tc.probeError == "" {
				if errors.As(err, new(agentVersionUnread)) || !strings.Contains(message, "close the agent holding its settings") {
					t.Fatalf("refresh error = %q, want the unchanged message", message)
				}
				return
			}
			if !errors.As(err, new(agentVersionUnread)) {
				t.Fatalf("refresh error = %q, want it marked as an agent whose version discovery could not read", message)
			}
			for _, want := range append([]string{"is not verified against a known hook contract", "then run: defenseclaw upgrade"}, tc.want...) {
				if !strings.Contains(message, want) {
					t.Fatalf("refresh error = %q, want %q", message, want)
				}
			}
			for _, unwanted := range append([]string{"close the agent holding its settings", "DEFENSECLAW_ALLOW_HOOK_CONTRACT_DRIFT"}, tc.unwanted...) {
				if strings.Contains(message, unwanted) {
					t.Fatalf("refresh error = %q, must not say %q", message, unwanted)
				}
			}
		})
	}
}

// An upgrade refreshes an active connector and fails for a cause no open
// agent explains: the enrolled agent is not on the PATH of the account, or
// it answers a setup probe (Codex configRequirements/read) too slowly on
// every call. The refusal is unchanged (the start still fails and the
// upgrade rolls back), but it names that cause and its own fix, never
// closing the agent or the drift env. A setup failure an open agent can
// explain keeps the close-the-agent step (GAP-2520).
func TestRefreshOfAnAbsentOrSlowAgentDoesNotSayCloseIt(t *testing.T) {
	const closeIt = "close the agent holding its settings"
	slowRead := fmt.Errorf("inspect effective Codex managed requirements: /opt/dc-agents/bin/codex configRequirements/read: timed out waiting for response 1: %w (%w)", context.DeadlineExceeded, connector.ErrAgentVersionProbeTimeout)
	for name, tc := range map[string]struct {
		notFound bool
		setupErr error
		want     []string
		unwanted []string
	}{
		"agent not on PATH": {
			notFound: true,
			want:     []string{"discovery did not find the agent on the PATH of this account", "put the agent back on the PATH of this account", "defenseclaw setup remove claudecode"},
			unwanted: []string{closeIt, "DEFENSECLAW_ALLOW_HOOK_CONTRACT_DRIFT", "agent version not probed"},
		},
		"slow agent on every call": {
			setupErr: slowRead,
			want:     []string{"configRequirements/read", "the agent answered too slowly", "start it once from this account"},
			unwanted: []string{closeIt},
		},
		"settings write an open agent can block": {
			setupErr: errors.New("write /Users/u/.claude/settings.json: resource busy"),
			want:     []string{closeIt},
			unwanted: []string{"answered too slowly"},
		},
	} {
		t.Run(name, func(t *testing.T) {
			s := admissionSidecar(t)
			if tc.notFound {
				raw, err := json.Marshal(map[string]any{
					"agents": map[string]any{"claudecode": map[string]any{
						"version": "", "binary_path": "", "installed": false, "error": "",
					}},
				})
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(s.cfg.DataDir, "agent_discovery.json"), raw, 0o600); err != nil {
					t.Fatal(err)
				}
			} else {
				stageAdmissionFixture(t, s.cfg.DataDir)
			}
			if err := connector.SaveActiveConnectors(s.cfg.DataDir, []string{"claudecode"}); err != nil {
				t.Fatal(err)
			}

			conn := &bootStubConnector{stubConnector: stubConnector{name: "claudecode"}, setupErr: tc.setupErr}
			_, err := s.setupConnectorsIsolatedTransaction(
				context.Background(), []connector.Connector{conn},
				"tok", "127.0.0.1:0", "127.0.0.1:0", "master", guardrail.NewRulePackCache(),
			)
			if err == nil {
				t.Fatal("refresh succeeded, want the refresh of the active connector refused")
			}
			message := err.Error()
			for _, want := range append([]string{"connector claudecode refresh failed", "then run: defenseclaw upgrade"}, tc.want...) {
				if !strings.Contains(message, want) {
					t.Fatalf("refresh error = %q, want %q", message, want)
				}
			}
			for _, unwanted := range tc.unwanted {
				if strings.Contains(message, unwanted) {
					t.Fatalf("refresh error = %q, must not say %q", message, unwanted)
				}
			}
		})
	}
}
