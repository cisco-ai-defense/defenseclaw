// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/daemon"
)

// GAP-1174: a corrupt config.yaml used to make restart stop a healthy gateway
// and then refuse to start on the fallback default port, blaming its holder.
func TestRunRestartRefusesCorruptConfigBeforeStoppingGateway(t *testing.T) {
	dataDir := t.TempDir()
	t.Setenv("DEFENSECLAW_HOME", dataDir)
	marker := filepath.Join(t.TempDir(), "restart-probe-running")
	t.Setenv(cliRestartProbeEnv, marker)

	d := daemon.New(config.DefaultDataPath())
	pid, err := d.Start([]string{"-test.run=^TestCLIRestartProcessProbe$"})
	if err != nil {
		t.Fatalf("start CLI restart probe: %v", err)
	}
	t.Cleanup(func() { _ = d.Stop(3 * time.Second) })
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(marker); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("probe marker was not created: %v", err)
	}
	if err := os.WriteFile(config.ConfigPath(), []byte("config_version: 8\nguardrail: [unclosed\n"), 0o600); err != nil {
		t.Fatalf("write corrupt config: %v", err)
	}

	err = runRestart(restartCmd, nil)
	if err == nil {
		t.Fatal("runRestart with a corrupt config.yaml succeeded")
	}
	for _, want := range []string{"cannot restart the gateway", "config.yaml does not load", "defenseclaw config validate", "Nothing was stopped"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not contain %q", err, want)
		}
	}
	if strings.Contains(err.Error(), "--api-port") || strings.Contains(err.Error(), "held by another process") {
		t.Errorf("error %q blames the port", err)
	}
	if running, currentPID := d.IsRunning(); !running || currentPID != pid {
		t.Fatalf("gateway after refused restart = running %v PID %d, want running PID %d", running, currentPID, pid)
	}
	// GAP-1634: start on a running gateway says it still runs and names restart.
	err = daemonConfigLoadError("start", errors.New("config.yaml:2: not valid YAML"))
	for _, want := range []string{"is still running with the config it started with", "Nothing was changed", "then run: defenseclaw-gateway restart"} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("start refusal %v does not contain %q", err, want)
		}
	}
}

func TestDaemonConfigLoadErrorNamesTheConfig(t *testing.T) {
	t.Setenv("DEFENSECLAW_HOME", t.TempDir())
	if err := daemonConfigLoadError("start", nil); err != nil {
		t.Fatalf("nil load error = %v, want nil", err)
	}
	err := daemonConfigLoadError("start", os.ErrInvalid)
	if err == nil || !strings.Contains(err.Error(), "cannot start the gateway") ||
		!strings.Contains(err.Error(), "then run: defenseclaw-gateway start") ||
		strings.Contains(err.Error(), "Nothing was stopped") {
		t.Fatalf("start refusal = %v", err)
	}
}

// GAP-1431: gateway status on a config that does not load names the daemon
// state and the repair command, like start and restart do.
func TestGatewayStatusConfigLoadErrorNamesStateAndNextStep(t *testing.T) {
	t.Setenv("DEFENSECLAW_HOME", t.TempDir())
	if err := gatewayStatusConfigLoadError(nil); err != nil {
		t.Fatalf("nil = %v", err)
	}
	other := os.ErrInvalid
	if err := gatewayStatusConfigLoadError(other); err != other {
		t.Fatalf("unrelated error rewritten: %v", err)
	}
	err := gatewayStatusConfigLoadError(errors.New("failed to load config: config.yaml:3: [yaml_syntax_invalid] bad"))
	for _, want := range []string{"failed to load config", "The gateway is not running.", "defenseclaw config validate"} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("error %v does not contain %q", err, want)
		}
	}
}

// GAP-1785: an empty config.yaml gets the Python CLI's message (GAP-1633),
// not the YAML loader's "root must be a mapping" advice.
func TestGatewayConfigLoadErrorsCallAnEmptyConfigEmpty(t *testing.T) {
	t.Setenv("DEFENSECLAW_HOME", t.TempDir())
	loadErr := errors.New("failed to load config: config.yaml: [yaml_root_mapping_required] $: the YAML document root must be a mapping")
	for _, content := range []string{"", "\n  \n", "# only a comment\n"} {
		if err := os.WriteFile(config.ConfigPath(), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		for _, err := range []error{
			daemonConfigLoadError("start", loadErr),
			daemonConfigLoadError("restart", loadErr),
			gatewayStatusConfigLoadError(loadErr),
		} {
			msg := err.Error()
			for _, want := range []string{config.ConfigPath() + " is empty: it holds no settings",
				"nothing was changed", "run 'defenseclaw init'"} {
				if !strings.Contains(msg, want) {
					t.Errorf("content %q: error %q does not contain %q", content, msg, want)
				}
			}
			if strings.Contains(msg, "yaml_root_mapping_required") || strings.Contains(msg, "config_version") {
				t.Errorf("content %q: error %q still shows the loader detail", content, msg)
			}
		}
	}
	if err := os.WriteFile(config.ConfigPath(), []byte("config_version: 8\nguardrail: [unclosed\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := daemonConfigLoadError("start", loadErr); strings.Contains(err.Error(), "is empty") {
		t.Fatalf("a non-empty config was called empty: %v", err)
	}
}

// GAP-1876: the gateway's empty-config message dates the copy the last
// upgrade kept, as the Python CLI does (GAP-1786), and drops the clause when
// there is no copy.
func TestGatewayEmptyConfigMessageDatesThePreviousCopy(t *testing.T) {
	home := t.TempDir()
	t.Setenv("DEFENSECLAW_HOME", home)
	if err := os.WriteFile(config.ConfigPath(), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	loadErr := errors.New("failed to load config: config.yaml: [yaml_root_mapping_required] $: the YAML document root must be a mapping")
	if msg := gatewayStatusConfigLoadError(loadErr).Error(); strings.Contains(msg, "previous") {
		t.Fatalf("no previous copy, but the message names one: %q", msg)
	}
	kept := filepath.Join(home, "previous", "data", "config.yaml")
	if err := os.MkdirAll(filepath.Dir(kept), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(kept, []byte("config_version: 7\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, "previous", "VERSION"), []byte("0.8.10\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	when := time.Date(2026, 10, 2, 4, 40, 0, 0, time.UTC)
	if err := os.Chtimes(kept, when, when); err != nil {
		t.Fatal(err)
	}
	want := "Restore your copy of config.yaml (the last version upgrade kept the DefenseClaw 0.8.10 config from " +
		"2026-10-02 04:40 UTC in " + kept + "; it lacks every change made since then), " +
		"or remove the empty file and run 'defenseclaw init'."
	for _, err := range []error{
		daemonConfigLoadError("start", loadErr),
		daemonConfigLoadError("restart", loadErr),
		gatewayStatusConfigLoadError(loadErr),
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not contain %q", err, want)
		}
	}
}
