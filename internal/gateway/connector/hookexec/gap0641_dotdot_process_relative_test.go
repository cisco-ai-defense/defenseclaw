// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

func TestGap0641DotDotThroughProcessRelativeLinkIsNotAnOrdinaryNoAnswerPayload(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux proc alias")
	}
	root := t.TempDir()
	home := filepath.Join(root, "home")
	protected := filepath.Join(home, ".defenseclaw", "cache", "entry")
	project := filepath.Join(root, "project")
	hookCWD := filepath.Join(root, "hook", "child")
	agentCWD := filepath.Join(root, "agent", "child")
	for _, dir := range []string{filepath.Dir(protected), project, hookCWD, agentCWD} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(protected, []byte("protected"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "hook", "status"), []byte("ordinary"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{filepath.Join(root, "agent", "status"), filepath.Join(project, "status")} {
		if err := os.Symlink(protected, path); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink("/proc/thread-self/cwd", filepath.Join(project, "jump")); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(project, "jump") + "/../status"
	t.Chdir(hookCWD)
	cmd := exec.Command("cat", target)
	cmd.Dir = agentCWD
	if data, err := cmd.Output(); err != nil || string(data) != "protected" {
		t.Fatalf("agent read=%q err=%v", data, err)
	}
	if ordinaryNoAnswerPayloadInHome(gap0641Payload(agentCWD, "cat "+target), home) {
		t.Error("shell payload was classified ordinary although the agent opens the protected file")
	}
	readPayload := fmt.Sprintf("{\"hook_event_name\":\"PreToolUse\",\"tool_name\":\"Read\",\"cwd\":%q,\"tool_input\":{\"file_path\":%q}}", agentCWD, target)
	if ordinaryNoAnswerPayloadInHome([]byte(readPayload), home) {
		t.Error("Read payload was classified ordinary although the agent opens the protected file")
	}
}
