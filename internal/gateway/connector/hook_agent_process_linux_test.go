// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
)

func TestAccountAgentProcessMayRunIgnoresManagementArguments(t *testing.T) {
	agent := "dcagentprobe-" + strconv.Itoa(os.Getpid())
	dataDir := t.TempDir()
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 unavailable")
	}
	// The removal command names the connector, but is not the agent process.
	managementScript := filepath.Join(t.TempDir(), "defenseclaw")
	if err := os.WriteFile(managementScript, []byte("import time\ntime.sleep(30)\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	management := exec.Command(python, managementScript, "setup", "remove", agent)
	if err := management.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = management.Process.Kill(); _ = management.Wait() })
	if accountAgentProcessMayRun(dataDir, agent) {
		t.Fatal("management command was counted as a running agent")
	}

	sleeper, err := exec.LookPath("sleep")
	if err != nil {
		t.Skip("sleep unavailable")
	}
	agentImage := filepath.Join(t.TempDir(), agent)
	if err := os.Symlink(sleeper, agentImage); err != nil {
		t.Fatal(err)
	}
	running := exec.Command(agentImage, "30")
	if err := running.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = running.Process.Kill(); _ = running.Wait() })
	if !accountAgentProcessMayRun(dataDir, agent) {
		t.Fatal("running agent process was missed")
	}
}
