// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"errors"
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

func TestHookContractAdmissionStillRefusesUpstreamAgentDrift(t *testing.T) {
	for name, mutate := range map[string]func(*connector.HookContractLockEntry){
		"agent version changed": func(entry *connector.HookContractLockEntry) {
			entry.RawAgentVersion = "Claude Code v1.0.0"
			entry.NormalizedAgentVersion = "1.0.0"
			entry.ContractID = "claudecode-hooks-retired"
			entry.DefenseClawVersion = "0.8.10"
		},
		"same DefenseClaw release": func(entry *connector.HookContractLockEntry) {
			entry.ContractID = "claudecode-hooks-retired"
			entry.DefenseClawVersion = version.Current().BinaryVersion
		},
	} {
		t.Run(name, func(t *testing.T) {
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
