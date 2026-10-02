// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
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
