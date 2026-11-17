// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// s7-probe3 old-API probe for rel-1-0-10:GAP-0496 (P1 security): the s7-probe1
// probe TestCCP1GAP0496SedStarTakesTheOperandAsTyped and its helpers, self
// contained so this one file is overlaid on a pre-fix tree. GNU sed puts the
// operand as typed (with its directory part) in place of the star; that backup
// name is the keys file. The regression was observed at a4665b216c
// (s7/hlink-identity, a branch ruled out of 1.0.10), never on the rel line.
// Scratch, test-only branch s7/ccprobes-3.

package gateway

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

func ccp3Home(t *testing.T) (home, cwd string) {
	t.Helper()
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("POSIX home fixture, unprivileged user")
	}
	home = filepath.Join(t.TempDir(), "homes", "alice")
	cwd = filepath.Join(home, "project")
	for _, dir := range []string{filepath.Join(home, ".ssh"), filepath.Join(home, ".defenseclaw"), cwd} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, f := range []string{
		filepath.Join(home, ".ssh", "authorized_keys"), filepath.Join(home, ".bashrc"),
		filepath.Join(home, ".defenseclaw", "config.yaml"), filepath.Join(cwd, "notes.txt"),
	} {
		if err := os.WriteFile(f, []byte("marker\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	return home, cwd
}

func ccp3Bash(t *testing.T, connector, posture, cwd, command string) (string, []string) {
	t.Helper()
	installToolCallCorpusProfileConnector(t, connector, posture)
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = connector
	cfg.Guardrail.RulePackDir = filepath.Join(guardrailPoliciesRoot(t), posture)
	api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth()}
	raw, err := json.Marshal(map[string]any{"command": command})
	if err != nil {
		t.Fatal(err)
	}
	resp := api.evaluateAgentHook(context.Background(), agentHookRequest{
		ConnectorName: connector, CWD: cwd, HookEventName: "PreToolUse", ToolName: "Bash", ToolArgs: raw,
	})
	var ids []string
	for _, f := range resp.Findings {
		ids = append(ids, strings.SplitN(f, ":", 2)[0])
	}
	return resp.Action, ids
}

func TestCCP3GAP0496SedStarTakesTheOperandAsTyped(t *testing.T) {
	home, cwd := ccp3Home(t)
	if err := os.MkdirAll(filepath.Join(cwd, "ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cwd, "ssh", "authorized_keys"), []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, posture := range []string{"default", "strict"} {
		for name, command := range map[string]string{
			"HLR4-SFX-pfx-long":     "sed --in-place=" + home + "/.* s/x/y/ ssh/authorized_keys",
			"HLR4-SFX-pfx-attached": "sed -i" + home + "/.* s/x/y/ ssh/authorized_keys",
			"HLR4-SFX-pfx-cluster":  "sed -ni" + home + "/.* s/x/y/ ssh/authorized_keys",
		} {
			act, ids := ccp3Bash(t, "claudecode", posture, cwd, command)
			t.Logf("ROW %s %s: %s %v", posture, name, act, ids)
			if act != "block" {
				t.Errorf("%s %s: action %q rules %v, want block", posture, name, act, ids)
			}
		}
	}
}
