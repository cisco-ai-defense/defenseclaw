// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
)

func TestApplyCoworkContextNeedsTheFlagAndTheDesktopEngine(t *testing.T) {
	oldEnv, oldExe := hookGetenv, hookAgentExecutable
	t.Cleanup(func() { hookGetenv, hookAgentExecutable = oldEnv, oldExe })
	const macEngine = "/Users/alice/Library/Application Support/Claude/claude-code/2.1.309/5af865b9901c/claude.app/Contents/MacOS/claude"
	const winEngine = `C:\Users\alice\AppData\Roaming\Claude\claude-code\2.1.309\claude.exe`
	cases := []struct {
		name, connector, flag, exe string
		secureClient               bool
		want                       bool
	}{
		{"macOS Cowork engine", "claudecode", "1", macEngine, false, true},
		{"Windows Cowork engine", "claudecode", "1", winEngine, false, true},
		{"no flag", "claudecode", "", macEngine, false, false},
		{"flag not 1", "claudecode", "true", macEngine, false, false},
		{"flag from a CLI build", "claudecode", "1", "/Users/alice/.local/share/claude/versions/2.1.309", false, false},
		{"engine unknown", "claudecode", "1", "", false, false},
		{"other connector", "codex", "1", macEngine, false, false},
		{"Secure Client keeps main", "claudecode", "1", macEngine, true, false},
	}
	for _, tc := range cases {
		hookGetenv = func(key string) string {
			switch key {
			case hookexec.CoworkEnvFlag:
				return tc.flag
			case hookexec.CoworkEnvSessionID:
				return "c29dbbfa-8209-4e91-84c4-7191c9491c94"
			case hookexec.CoworkEnvWorkspaceHostPaths:
				return `["/Users/alice/Desktop/work"]`
			}
			return ""
		}
		hookAgentExecutable = func() string { return tc.exe }
		opts := hookexec.Options{Connector: tc.connector, SecureClient: tc.secureClient}
		applyCoworkContext(&opts)
		if got := opts.Cowork != nil; got != tc.want {
			t.Errorf("%s: tagged=%v, want %v", tc.name, got, tc.want)
			continue
		}
		if tc.want && (opts.Cowork.SessionID != "c29dbbfa-8209-4e91-84c4-7191c9491c94" ||
			len(opts.Cowork.WorkspaceHostPaths) != 1 || opts.Cowork.WorkspaceHostPaths[0] != "/Users/alice/Desktop/work") {
			t.Errorf("%s: cowork context = %+v", tc.name, *opts.Cowork)
		}
	}
}

// The engine lookup runs only for a Cowork call.
func TestApplyCoworkContextSkipsTheProcessLookupOutsideCowork(t *testing.T) {
	oldEnv, oldExe := hookGetenv, hookAgentExecutable
	t.Cleanup(func() { hookGetenv, hookAgentExecutable = oldEnv, oldExe })
	hookGetenv = func(string) string { return "" }
	hookAgentExecutable = func() string { t.Fatal("process lookup outside Cowork"); return "" }
	opts := hookexec.Options{Connector: "claudecode"}
	applyCoworkContext(&opts)
	if opts.Cowork != nil {
		t.Fatal("tagged a call outside Cowork")
	}
}
