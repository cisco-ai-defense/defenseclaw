// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"reflect"
	"testing"
)

// Only an engine version selects a contract: a host version such as the
// Codex extension's 26.5908.31748 would satisfy the open-ended codex
// contract, so a surface that carries only a host version stays unknown.
func TestSurfaceHookContractUsesOnlyTheEngineVersion(t *testing.T) {
	for _, tc := range []struct{ connector, version string }{{"codex", "0.145.0"}, {"claudecode", "2.1.219"}, {"codex", ""}} {
		cli := ResolveSurfaceHookContract(tc.connector, HostSurfaceCLI, tc.version)
		if want := ResolveHookContract(tc.connector, tc.version); !reflect.DeepEqual(cli.HookContractResolution, want) {
			t.Fatalf("%s cli %q = %+v, want ResolveHookContract %+v", tc.connector, tc.version, cli.HookContractResolution, want)
		}
	}
	hostOnly := ResolveSurfaceHookContract("codex", HostSurfaceExtension, "")
	if ok, _ := hostOnly.Admitted(UnverifiedVersionsReport); ok || hostOnly.Status != HookCompatibilityUnknown {
		t.Fatalf("extension without an engine version = %+v, want unknown and not admitted", hostOnly)
	}
	engine := ResolveSurfaceHookContract("claudecode", HostSurfaceExtension, "2.1.219")
	if ok, _ := engine.Admitted(UnverifiedVersionsReport); !ok {
		t.Fatalf("report must admit an unverified surface with a known engine contract: %+v", engine)
	}
	if ok, reason := engine.Admitted(UnverifiedVersionsRefuse); ok || reason == "" {
		t.Fatalf("refuse must not admit an unverified surface")
	}
}

// A hook call's surface comes from the engine's executable path first
// (wherever the extensions folder is), then the vendor's surface variable;
// a call neither names stays unclassified, and only an unverified app or
// extension is refused under refuse.
func TestClassifyAgentSurface(t *testing.T) {
	env := func(name, value string) func(string) string {
		return func(key string) string {
			if key == name {
				return value
			}
			return ""
		}
	}
	cases := []struct {
		connector, executable string
		getenv                func(string) string
		want                  string
	}{
		{"claudecode", `C:\Users\u\.vscode\extensions\anthropic.claude-code-2.1.220-win32-x64\resources\native-binary\claude.exe`, nil, HostSurfaceExtension},
		{"claudecode", "/srv/ext/anthropic.claude-code-2.1.220-linux-x64/resources/native-binary/claude", nil, HostSurfaceExtension},
		{"claudecode", "/home/u/.local/bin/claude", env("CLAUDE_CODE_ENTRYPOINT", "claude-desktop"), HostSurfaceDesktop},
		{"claudecode", "/Users/u/Library/Application Support/Claude/claude-code/2.1.220/claude", env("CLAUDE_CODE_ENTRYPOINT", "cli"), HostSurfaceDesktop},
		{"codex", "/home/u/code-ext/extensions/openai.chatgpt-26.5908.31748-linux-x64/bin/linux-x86_64/codex", nil, HostSurfaceExtension},
		{"codex", "/usr/local/bin/codex", env("CODEX_INTERNAL_ORIGINATOR_OVERRIDE", "codex_cli_rs"), HostSurfaceCLI},
		{"antigravity", "/Applications/Antigravity.app/Contents/Resources/app/bin/agy", nil, HostSurfaceCLI},
		{"antigravity", "/usr/share/antigravity/resources/app/extensions/antigravity/bin/language_server_linux_x64", nil, HostSurfaceDesktop},
		{"codex", "/usr/local/bin/codex", nil, ""},
	}
	for _, tc := range cases {
		if got := ClassifyAgentSurface(tc.connector, tc.executable, tc.getenv); got != tc.want {
			t.Errorf("ClassifyAgentSurface(%s, %s) = %q, want %q", tc.connector, tc.executable, got, tc.want)
		}
	}
	if !SurfaceRefused("codex", HostSurfaceExtension, UnverifiedVersionsRefuse) ||
		SurfaceRefused("codex", HostSurfaceExtension, UnverifiedVersionsReport) ||
		SurfaceRefused("cursor", HostSurfaceDesktop, UnverifiedVersionsRefuse) ||
		SurfaceRefused("codex", "", UnverifiedVersionsRefuse) || SurfaceRefused("codex", HostSurfaceCLI, UnverifiedVersionsRefuse) {
		t.Fatal("SurfaceRefused must refuse only an unverified app or extension under refuse")
	}
}
