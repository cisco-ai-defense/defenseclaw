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

package e2e

import (
	"os/exec"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/tui"
)

func TestTUICommandHelp(t *testing.T) {
	binary, err := buildGateway(t)
	if err != nil {
		t.Skipf("could not build gateway: %v", err)
	}

	out, err := exec.Command(binary, "tui", "--help").CombinedOutput()
	if err != nil {
		t.Fatalf("tui --help failed: %v\n%s", err, out)
	}

	output := string(out)
	if !strings.Contains(output, "interactive dashboard") {
		t.Errorf("expected 'interactive dashboard' in help output, got:\n%s", output)
	}
	if !strings.Contains(output, "command palette") {
		t.Errorf("expected 'command palette' in help output, got:\n%s", output)
	}
}

func TestTUIModelInit(t *testing.T) {
	deps := tui.Deps{
		Store:   nil,
		Config:  nil,
		Version: "test-0.0.1",
	}

	model := tui.New(deps)
	cmd := model.Init()

	if cmd == nil {
		t.Error("Init() should return a non-nil command (health poll tick)")
	}
}

func TestTUICommandRegistry(t *testing.T) {
	registry := tui.BuildRegistry()

	if len(registry) < 50 {
		t.Errorf("expected at least 50 commands in registry, got %d", len(registry))
	}

	essentialCommands := []string{
		"init", "status", "doctor", "start", "stop", "restart",
		"scan skill", "scan mcp", "block skill", "block mcp",
		"policy list", "setup guardrail",
	}

	tuiNames := make(map[string]bool)
	for _, entry := range registry {
		tuiNames[entry.TUIName] = true
	}

	for _, cmd := range essentialCommands {
		if !tuiNames[cmd] {
			t.Errorf("essential command %q missing from registry", cmd)
		}
	}
}

func buildGateway(t *testing.T) (string, error) {
	t.Helper()
	dir := t.TempDir()
	binPath := dir + "/defenseclaw-gateway"
	cmd := exec.Command("go", "build", "-o", binPath, "./cmd/defenseclaw")
	cmd.Dir = findRepoRoot(t)
	if out, err := cmd.CombinedOutput(); err != nil {
		return "", &exec.ExitError{Stderr: out}
	}
	return binPath, nil
}

func findRepoRoot(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("git", "rev-parse", "--show-toplevel").Output()
	if err != nil {
		t.Skipf("not in a git repo: %v", err)
	}
	return strings.TrimSpace(string(out))
}
