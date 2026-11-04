// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"path/filepath"
	"runtime"
	"testing"
)

func TestClaudeCodeNativeUnixRollbackKeepsEarlierHookShape(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix registration")
	}
	root := t.TempDir()
	home := filepath.Join(root, "profile", ".defenseclaw")
	script := filepath.Join(home, "hooks", "claude-code-hook.sh")
	native := filepath.Join(root, ".local", "bin", "defenseclaw-hook-user")
	command := claudeCodeMissingHookGuard(posixHookCommandWord(native) +
		" hook --connector claudecode --hook-home " + posixHookCommandWord(home) +
		" --api-addr 127.0.0.1:18970")
	owned := func(path string) bool { return path == native }
	handler := map[string]interface{}{"command": command}
	if !claudeCodeHandlerInEarlierReleaseForm(handler, runtime.GOOS, script, owned) || handler["command"] != script {
		t.Fatalf("rollback form = %#v", handler)
	}
	foreign := map[string]interface{}{"command": claudeCodeMissingHookGuard(
		posixHookCommandWord(filepath.Join(root, "elsewhere", "defenseclaw-hook-user")) +
			" hook --connector claudecode --hook-home " + posixHookCommandWord(home))}
	if claudeCodeHandlerInEarlierReleaseForm(foreign, runtime.GOOS, script, owned) {
		t.Fatalf("foreign command changed: %#v", foreign)
	}
}
