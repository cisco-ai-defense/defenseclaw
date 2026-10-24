// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway"
)

func everyConnectorTestConfig(t *testing.T) *config.Config {
	t.Helper()
	cfg := config.DefaultConfig()
	cfg.Guardrail.Enabled = true
	cfg.Guardrail.Connector = ""
	cfg.Guardrail.Connectors = map[string]config.PerConnectorGuardrailConfig{"codex": {}, "hermes": {}}
	return cfg
}

// GAP-0878, GAP-0899: an install or upgrade whose gateway boot skipped one of
// its connectors exited 0 with that connector unprotected. With the
// installers' flag, start names every connector it does not guard and exits 3.
func TestEveryConnectorGuardedErrorNamesEachSkippedConnector(t *testing.T) {
	cfg := everyConnectorTestConfig(t)
	snap := readinessSnapshot(gateway.StateRunning, gateway.StateDisabled)
	snap.Guardrail.Details = map[string]interface{}{
		"connectors_not_started": []interface{}{"hermes", "codex"},
		gateway.GuardrailAgentSettingsRefused: map[string]interface{}{
			"codex": "codex hooks are turned off in its settings; run: codex features enable hooks",
		},
	}
	err := everyConnectorGuardedError(cfg, snap)
	if code := commandExitCode(err); code != 3 {
		t.Fatalf("exit code = %d (err %v), want 3", code, err)
	}
	for _, want := range []string{
		"does not guard hermes, codex",
		"hermes: its setup failed (see gateway.log), then run: defenseclaw setup hermes",
		"codex: codex hooks are turned off in its settings",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q is missing %q", err, want)
		}
	}
}

func TestEveryConnectorGuardedErrorAcceptsAFullyGuardedGateway(t *testing.T) {
	cfg := everyConnectorTestConfig(t)
	snap := readinessSnapshot(gateway.StateRunning, gateway.StateDisabled)
	if err := everyConnectorGuardedError(cfg, snap); err != nil {
		t.Fatalf("every connector started: err = %v, want nil", err)
	}
	snap.Guardrail.Details = map[string]interface{}{"connectors_not_started": []interface{}{}}
	if err := everyConnectorGuardedError(cfg, snap); err != nil {
		t.Fatalf("empty not-started list: err = %v, want nil", err)
	}
	// Nothing is to be guarded: the guardrail is off, or every connector is.
	cfg.Guardrail.Enabled = false
	off := readinessSnapshot(gateway.StateDisabled, gateway.StateDisabled)
	if err := everyConnectorGuardedError(cfg, off); err != nil {
		t.Fatalf("guardrail off: err = %v, want nil", err)
	}
	cfg = everyConnectorTestConfig(t)
	disabled := false
	cfg.Guardrail.Connectors = map[string]config.PerConnectorGuardrailConfig{"hermes": {Enabled: &disabled}}
	if err := everyConnectorGuardedError(cfg, off); err != nil {
		t.Fatalf("every connector turned off: err = %v, want nil", err)
	}
}

// A guardrail that is not running guards nothing, whatever the reason: still
// starting when a slow start's wait ended, stopped by an error, or disabled
// while the config turns connectors on.
func TestEveryConnectorGuardedErrorRefusesAGuardrailThatIsNotRunning(t *testing.T) {
	cfg := everyConnectorTestConfig(t)
	for _, state := range []gateway.SubsystemState{gateway.StateStarting, gateway.StateError, gateway.StateDisabled, gateway.StateStopped} {
		snap := readinessSnapshot(state, gateway.StateDisabled)
		if state == gateway.StateError {
			snap.Guardrail.LastError = "multi-connector boot: all 2 configured connectors failed setup"
		}
		err := everyConnectorGuardedError(cfg, snap)
		if code := commandExitCode(err); code != 3 || !strings.Contains(err.Error(), "guards no connector yet") {
			t.Fatalf("guardrail %s: exit %d err %v, want 3 naming the unguarded state", state, code, err)
		}
	}
}

func TestEveryConnectorGuardedErrorKeepsTheAdmissionRefusal(t *testing.T) {
	cfg := everyConnectorTestConfig(t)
	snap := readinessSnapshot(gateway.StateError, gateway.StateDisabled)
	snap.Guardrail.LastError = "hook contract admission failed: connector codex hook contract drift detected"
	snap.Guardrail.Details = map[string]interface{}{gateway.GuardrailHookContractAdmissionRefused: []interface{}{"codex"}}
	err := everyConnectorGuardedError(cfg, snap)
	if code := commandExitCode(err); code != 3 || !strings.Contains(err.Error(), "hook-contract admission refused codex") {
		t.Fatalf("exit %d err %v, want the admission refusal", code, err)
	}
}

// The installers probe for the flag with `start --require-every-connector
// --help`, so it must be a real (hidden) start flag; hooks and setup never
// pass it.
func TestRequireEveryConnectorIsAHiddenStartFlag(t *testing.T) {
	flag := startCmd.Flags().Lookup(requireEveryConnectorFlag)
	if flag == nil || !flag.Hidden || flag.DefValue != "false" {
		t.Fatalf("start flag %s = %+v, want a hidden bool defaulting to false", requireEveryConnectorFlag, flag)
	}
	if requireEveryConnectorRequested(nil) || requireEveryConnectorRequested(stopCmd) {
		t.Fatal("a command without the flag must not require every connector")
	}
}
