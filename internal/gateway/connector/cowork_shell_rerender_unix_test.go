// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package connector

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// The Cowork header block changed claude-code-hook.sh without a marker bump
// (v7, as the 1.0.5 to 1.0.7 script changes). Both writers still replace an
// older v7 render: a per-user Setup writes the scripts on every run, and the
// standalone guardian re-renders on any byte drift (HookScriptRenderDrift).
func TestOlderClaudeShellHookRenderIsReplaced(t *testing.T) {
	home := t.TempDir()
	installNativeGatewayForHookTest(t, home)
	hookDir := filepath.Join(home, "hooks")
	opts := SetupOpts{DataDir: home, APIAddr: "127.0.0.1:18970", APIToken: "test-hook-token", HookFailMode: "closed"}
	if err := WriteHookScriptsForConnectorObjectWithOpts(hookDir, opts, NewClaudeCodeConnector()); err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(hookDir, "claude-code-hook.sh")
	current, err := os.ReadFile(script)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(current, []byte("X-DefenseClaw-Cowork")) {
		t.Fatal("the render has no Cowork header block")
	}
	// An older v7 render: same marker, no Cowork block.
	start := bytes.Index(current, []byte("# Claude Cowork runs this hook"))
	end := bytes.Index(current, []byte("COWORK_HEADER_ARGS=()"))
	if start < 0 || end < start {
		t.Fatal("cannot find the Cowork block")
	}
	older := append(append([]byte(nil), current[:start]...), current[end:]...)
	if err := os.WriteFile(script, older, 0o700); err != nil {
		t.Fatal(err)
	}
	if drift, err := HookScriptRenderDrift(NewClaudeCodeConnector(), opts); err != nil || drift != script {
		t.Fatalf("HookScriptRenderDrift = %q, %v; want the older script %s", drift, err, script)
	}
	if err := WriteHookScriptsForConnectorObjectWithOpts(hookDir, opts, NewClaudeCodeConnector()); err != nil {
		t.Fatal(err)
	}
	rewritten, err := os.ReadFile(script)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(rewritten, current) {
		t.Fatal("a per-user setup kept the older v7 render")
	}
}
