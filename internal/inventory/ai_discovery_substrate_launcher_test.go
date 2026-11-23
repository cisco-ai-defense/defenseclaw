// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package inventory

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/substrate/launcherpresence"
)

// E26: discovery labels a running Agent Substrate launcher, and nothing
// else that is named defenseclaw.
func TestDiscoveryLabelsTheSubstrateLauncher(t *testing.T) {
	home := t.TempDir()
	data := filepath.Join(home, ".defenseclaw")
	start := time.Now().UTC().Truncate(time.Second)
	remove, err := launcherpresence.Write(data, launcherpresence.Record{Command: "run", Connector: "claudecode", Context: "stk", Started: start})
	if err != nil {
		t.Fatal(err)
	}
	defer remove()
	me := os.Getpid()
	svc := &ContinuousDiscoveryService{opts: AIDiscoveryOptions{HomeDir: home, HomeDirs: []string{home}}}
	procs := []processInfo{
		{PID: me, Comm: "defenseclaw", StartedAt: start, User: "alice"},
		{PID: me + 1, Comm: "defenseclaw", StartedAt: start},                            // the gateway: no record
		{PID: me + 2, Comm: "claude", StartedAt: start},                                 // another program
		{PID: me + 3, Comm: "defenseclaw-gateway.exe", StartedAt: start, Windows: true}, // no record
	}
	out := svc.detectSubstrateLaunchers(procs, time.Now())
	if len(out) != 1 {
		t.Fatalf("signals %+v", out)
	}
	s := out[0]
	if s.SignatureID != SubstrateLauncherSignatureID || s.Name != "DefenseClaw Agent Substrate launcher" || s.Category != SignalActiveProcess || s.Runtime == nil || s.Runtime.PID != me {
		t.Fatalf("signal %+v", s)
	}
	// A reused PID (the process started an hour after the record) is not
	// the launcher.
	if out := svc.detectSubstrateLaunchers([]processInfo{{PID: me, Comm: "defenseclaw", StartedAt: start.Add(time.Hour)}}, time.Now()); len(out) != 0 {
		t.Errorf("a reused PID was labelled: %+v", out)
	}
	// A process with the record but another name is not the launcher.
	if out := svc.detectSubstrateLaunchers([]processInfo{{PID: me, Comm: "bash", StartedAt: start}}, time.Now()); len(out) != 0 {
		t.Errorf("another binary was labelled: %+v", out)
	}
	// The record goes when the launcher ends.
	remove()
	if out := svc.detectSubstrateLaunchers(procs, time.Now()); len(out) != 0 {
		t.Errorf("an ended launcher is still labelled: %+v", out)
	}
}
