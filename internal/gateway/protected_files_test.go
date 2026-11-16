// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/protectedfiles"
)

func protectedFilesHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".ssh", "authorized_keys"), []byte("ssh-ed25519 AAAA user\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return home
}

// The hook's tool_call event opens the call the watch attributes a change
// to; its result closes it. The row names the session and the digests,
// never the content.
func TestProtectedFileWatchAttributesTheHookCall(t *testing.T) {
	home := protectedFilesHome(t)
	cfg := &config.Config{DataDir: t.TempDir()}
	var changes []protectedfiles.Change
	watch := newProtectedFileWatch(cfg, false, func(c protectedfiles.Change) { changes = append(changes, c) })
	if watch == nil {
		t.Fatal("the watch is on by default (alert)")
	}
	if got := watch.watcher.Homes(); len(got) != 1 || got[0] != filepath.Clean(home) {
		t.Fatalf("homes = %v", got)
	}
	api := &APIServer{protectedFiles: watch}
	ctx := context.Background()
	pre := agentHookRequest{HookEventName: "PreToolUse", SessionID: "sess-1", ToolInvocationID: "tool-1"}
	api.noteProtectedFileActivity(ctx, "claudecode", pre, "agt-1")
	secret := "ssh-ed25519 EVILKEYMATERIAL attacker\n"
	if err := os.WriteFile(filepath.Join(home, ".ssh", "authorized_keys"), []byte(secret), 0o600); err != nil {
		t.Fatal(err)
	}
	watch.watcher.Scan()
	if len(changes) != 1 || !changes[0].Attributed || changes[0].Session.SessionID != "sess-1" ||
		changes[0].Session.Connector != "claudecode" || changes[0].Session.AgentIdentityID != "agt-1" {
		t.Fatalf("changes = %+v", changes)
	}
	details := protectedFileChangeDetails(changes[0])
	for _, want := range []string{"rule=persistence.protected_file_changed", "class=authorized_keys", "session=sess-1", "tool_invocation=tool-1"} {
		if !strings.Contains(details, want) {
			t.Fatalf("details %q lack %q", details, want)
		}
	}
	if strings.Contains(details, "EVILKEYMATERIAL") || strings.Contains(details, "restored") {
		t.Fatalf("details %q carry content or a restore in alert mode", details)
	}
	if read, _ := os.ReadFile(filepath.Join(home, ".ssh", "authorized_keys")); string(read) != secret {
		t.Fatal("alert mode changed the file")
	}
}

func TestProtectedFileWatchOffBuildsNothing(t *testing.T) {
	protectedFilesHome(t)
	cfg := &config.Config{DataDir: t.TempDir()}
	cfg.Guardrail.ProtectedFiles.OnChange = "off"
	if watch := newProtectedFileWatch(cfg, false, nil); watch != nil {
		t.Fatal("off still built a watch")
	}
	// A server without a watch ignores hook events.
	(&APIServer{}).noteProtectedFileActivity(context.Background(), "codex", agentHookRequest{HookEventName: "PreToolUse"}, "")
}

// A managed gateway's service account cannot read users' homes, so it
// runs no watch (the kernel control is the managed Linux layer).
func TestManagedGatewayRunsNoProtectedFileWatch(t *testing.T) {
	protectedFilesHome(t)
	if watch := newProtectedFileWatch(&config.Config{DataDir: t.TempDir()}, true, nil); watch != nil {
		t.Fatal("a managed gateway built a watch it cannot read")
	}
}

func TestProtectedFilesConfigDefaultsAndValidation(t *testing.T) {
	var p config.ProtectedFilesConfig
	if p.EffectiveOnChange() != config.ProtectedFilesAlert || p.Validate() != nil {
		t.Fatal("the zero value is alert and valid")
	}
	for _, bad := range []config.ProtectedFilesConfig{
		{OnChange: "block"}, {Paths: []string{"/etc/passwd"}}, {Paths: []string{"../x"}}, {Paths: []string{`C:\x`}},
	} {
		if bad.Validate() == nil {
			t.Fatalf("%+v accepted", bad)
		}
	}
	if (config.ProtectedFilesConfig{OnChange: "restore", Paths: []string{".ssh/authorized_keys", ".config/autostart/"}}).Validate() != nil {
		t.Fatal("a valid restore config was refused")
	}
}
