// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package connector

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestManagedHermesShellDelegatesToReceiptingNativeHook(t *testing.T) {
	if _, err := exec.LookPath("jq"); err != nil {
		t.Skip("jq is required to run the Hermes shell hook")
	}
	f := newHookSocketFixture(t, "dchr", `{"action":"allow","hook_output":{}}`)
	root := filepath.Join(f.root, "home")
	hookDir := filepath.Join(root, ".defenseclaw", "hooks")
	binary := filepath.Join(f.root, "bin", "defenseclaw-hook")
	if err := os.MkdirAll(filepath.Dir(binary), 0o755); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(f.root, "native-args")
	neutral := filepath.Join(f.root, "native-neutral")
	stub := "#!/bin/bash\n" +
		"[ \"$*\" = \"hook session-facts\" ] && exit 0\n" +
		"printf '%s' \"$*\" > " + shellSingleQuoteForTest(marker) + "\n" +
		"[ -f " + shellSingleQuoteForTest(neutral) + " ] && exit 0\n" +
		"printf '%s\\n' '{\"action\":\"block\",\"message\":\"native-receipt-path\"}'\n" +
		"exit 0\n"
	if err := os.WriteFile(binary, []byte(stub), 0o755); err != nil {
		t.Fatal(err)
	}
	opts := SetupOpts{DataDir: filepath.Dir(hookDir), APIAddr: f.held.Addr().String(),
		ManagedEnterprise: true, ManagedHookSocket: f.socket, ManagedServiceUID: os.Getuid(),
		ManagedHookBinary: binary, HookFailMode: "closed"}
	if err := WriteHookScriptsForConnectorObjectWithOpts(hookDir, opts, NewHermesConnector()); err != nil {
		t.Fatal(err)
	}
	hook := filepath.Join(hookDir, "hermes-hook.sh")
	bakeHookPathForTest(t, hook, "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin")
	run := func() (int, string) {
		t.Helper()
		ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, "bash", hook)
		cmd.Env = append(os.Environ(), "HOME="+root)
		cmd.Stdin = strings.NewReader(`{"hook_event_name":"pre_tool_call","session_id":"receipt-native","tool_name":"terminal","tool_input":{"command":"echo ok"}}`)
		var output bytes.Buffer
		cmd.Stdout = &output
		cmd.Stderr = &bytes.Buffer{}
		err := cmd.Run()
		if exit, ok := err.(*exec.ExitError); ok {
			return exit.ExitCode(), output.String()
		}
		if err != nil {
			t.Fatal(err)
		}
		return 0, output.String()
	}
	if code, out := run(); code != 0 || !strings.Contains(out, "native-receipt-path") {
		t.Fatalf("native Hermes decision = status %d, output %q", code, out)
	}
	if args, err := os.ReadFile(marker); err != nil || string(args) != "hook --connector hermes --enterprise-managed" {
		t.Fatalf("native hook invocation = %q, %v", args, err)
	}
	if paths, _, _ := f.gateway.recorded(); len(paths) != 0 {
		t.Fatalf("shell sent a second gateway request: %v", paths)
	}
	if err := os.WriteFile(neutral, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if code, out := run(); code != 0 || out != "" {
		t.Fatalf("native Hermes neutral allow = status %d, output %q", code, out)
	}
	if err := os.Remove(binary); err != nil {
		t.Fatal(err)
	}
	if code, out := run(); code != 2 || !strings.Contains(out, `"action":"block"`) {
		t.Fatalf("missing native hook = status %d, output %q; want a Hermes block", code, out)
	}
}
