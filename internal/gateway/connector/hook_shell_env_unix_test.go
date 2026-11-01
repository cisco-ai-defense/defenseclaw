// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package connector

import (
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func hookShellEnvSource(name string, env map[string]interface{}) *claudeCodeSettingsSource {
	return &claudeCodeSettingsSource{name: name, path: "/x/" + name, settings: map[string]interface{}{"env": env}}
}

// rel-1-0-6:GAP-0322: the names are resolved as Claude Code applies env
// blocks: the highest source with a value Claude Code keeps decides a name;
// a dropped value (null, object, array, NUL) leaves the lower one in force.
func TestClaudeCodeSettingsHookShellEnvFollowsEnvPrecedence(t *testing.T) {
	type src = *claudeCodeSettingsSource
	s := hookShellEnvSource
	cases := []struct {
		name    string
		sources []src
		want    []string
		from    []string
	}{
		{
			name:    "project noexec",
			sources: []src{s("project", map[string]interface{}{"SHELLOPTS": "noexec", "PATH": "/bin"})},
			want:    []string{"SHELLOPTS"}, from: []string{"project"},
		},
		{
			name: "local empty clears project",
			sources: []src{
				s("local", map[string]interface{}{"SHELLOPTS": ""}),
				s("project", map[string]interface{}{"SHELLOPTS": "noexec"}),
			},
		},
		{
			name: "local null does not hide project (review finding 1)",
			sources: []src{
				s("local", map[string]interface{}{"SHELLOPTS": nil}),
				s("project", map[string]interface{}{"SHELLOPTS": "noexec"}),
			},
			want: []string{"SHELLOPTS"}, from: []string{"project"},
		},
		{
			name: "object, array and NUL values are dropped too",
			sources: []src{
				s("local", map[string]interface{}{"SHELLOPTS": map[string]interface{}{}, "BASH_ENV": []interface{}{""}, "FUNCNEST": "\x00"}),
				s("user", map[string]interface{}{"SHELLOPTS": "noexec", "BASH_ENV": "/tmp/x", "FUNCNEST": "1"}),
			},
			want: []string{"BASH_ENV", "FUNCNEST", "SHELLOPTS"}, from: []string{"user"},
		},
		{
			name:    "a number and a boolean count once stringified",
			sources: []src{s("user", map[string]interface{}{"FUNCNEST": float64(1), "BASHOPTS": false})},
			want:    []string{"BASHOPTS", "FUNCNEST"}, from: []string{"user"},
		},
		{
			name: "cli over local",
			sources: []src{
				s("cli", map[string]interface{}{"CLAUDE_CODE_SHELL_PREFIX": "/usr/bin/true"}),
				s("local", map[string]interface{}{"CLAUDE_CODE_SHELL_PREFIX": ""}),
			},
			want: []string{"CLAUDE_CODE_SHELL_PREFIX"}, from: []string{"cli"},
		},
		{
			name: "project over user",
			sources: []src{
				s("project", map[string]interface{}{"SHELLOPTS": ""}),
				s("user", map[string]interface{}{"SHELLOPTS": "noexec"}),
			},
		},
		{
			name: "managed empty over every lower tier",
			sources: []src{
				s("managed", map[string]interface{}{"SHELLOPTS": "", "CLAUDE_CODE_SHELL_PREFIX": ""}),
				s("local", map[string]interface{}{"SHELLOPTS": "noexec"}),
				s("global", map[string]interface{}{"CLAUDE_CODE_SHELL_PREFIX": "/usr/bin/true"}),
			},
		},
		{
			name: "global is the lowest tier",
			sources: []src{
				s("user", map[string]interface{}{"BASH_ENV": "/a"}),
				s("global", map[string]interface{}{"BASH_ENV": "", "SHELLOPTS": "noexec"}),
			},
			want: []string{"BASH_ENV", "SHELLOPTS"}, from: []string{"user", "global"},
		},
		{
			name:    "exported function with an empty value; ENV and POSIXLY_CORRECT are not on the list",
			sources: []src{s("user", map[string]interface{}{"BASH_FUNC_curl%%": "", "ENV": "/tmp/e", "POSIXLY_CORRECT": "1"})},
			want:    []string{"BASH_FUNC_curl%%"}, from: []string{"user"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			names, from := claudeCodeSettingsHookShellEnv(tc.sources)
			var fromNames []string
			for _, source := range from {
				fromNames = append(fromNames, source.name)
			}
			if !reflect.DeepEqual(names, tc.want) || !reflect.DeepEqual(fromNames, tc.from) {
				t.Fatalf("names = %v from %v, want %v from %v", names, fromNames, tc.want, tc.from)
			}
		})
	}
}

// The source order is the one Claude Code applies, read from the real
// source set: managed, cli, local, project, user, ~/.claude.json.
func TestClaudeCodeHookShellEnvSourceOrder(t *testing.T) {
	conn, opts, settingsPath, managedRoot := isolatedClaudePolicyFixture(t)
	_ = conn
	writeClaudePolicyJSON(t, filepath.Join(filepath.Dir(settingsPath), ".claude.json"), map[string]interface{}{"env": map[string]interface{}{"SHELLOPTS": "noexec"}})
	writeClaudePolicyJSON(t, filepath.Join(opts.WorkspaceDir, ".claude", "settings.json"), map[string]interface{}{"env": map[string]interface{}{"BASH_ENV": "/p"}})
	writeClaudePolicyJSON(t, filepath.Join(opts.WorkspaceDir, ".claude", "settings.local.json"), map[string]interface{}{"env": map[string]interface{}{"BASH_ENV": ""}})
	sources, err := inspectClaudeCodeUserSources(opts)
	if err != nil {
		t.Fatal(err)
	}
	names, from := claudeCodeSettingsHookShellEnv(claudeCodeHookShellEnvSources(sources))
	if !reflect.DeepEqual(names, []string{"SHELLOPTS"}) || len(from) != 1 || from[0].name != "global config" {
		t.Fatalf("names %v from %v, want SHELLOPTS from the global config (local clears the project's BASH_ENV)", names, from)
	}
	// A managed SHELLOPTS "" (the drop-in pin) decides over ~/.claude.json.
	writeClaudePolicyJSON(t, filepath.Join(managedRoot, "managed-settings.json"), map[string]interface{}{"env": map[string]interface{}{"SHELLOPTS": ""}})
	if names, _ := claudeCodeSettingsHookShellEnv(claudeCodeHookShellEnvSources(sources)); len(names) != 0 {
		t.Fatalf("names with a managed pin = %v, want none", names)
	}
}

// rel-1-0-6:GAP-0322: a project env block with SHELLOPTS=noexec stops
// Claude Code's /bin/sh from running any DefenseClaw hook. The default tier
// warns and keeps the connector; the strict tier refuses it as it refuses
// disableAllHooks, in Setup and in the effective-policy check.
func TestClaudeCodeHookShellEnvWarnsByDefaultAndStrictRefuses(t *testing.T) {
	conn, opts, _, _ := isolatedClaudePolicyFixture(t)
	project := filepath.Join(opts.WorkspaceDir, ".claude", "settings.json")
	writeClaudePolicyJSON(t, project, map[string]interface{}{"env": map[string]interface{}{"SHELLOPTS": "noexec"}})

	for _, tier := range []string{"", "default", "permissive"} {
		opts.PolicyTier = tier
		if err := CheckAgentSettings(conn, opts); err != nil {
			t.Fatalf("tier %q: CheckAgentSettings = %v, want no refusal", tier, err)
		}
		if present, err := OwnedHooksPresent(conn, opts); err != nil || !present {
			t.Fatalf("tier %q: OwnedHooksPresent = %v, %v; want the hooks kept", tier, present, err)
		}
		warning := HookShellEnvWarning(conn, opts)
		for _, want := range []string{project, "SHELLOPTS (with noexec, /bin/sh runs none of the hook command)", "remove SHELLOPTS"} {
			if !strings.Contains(warning, want) {
				t.Fatalf("tier %q: warning %q lacks %q", tier, warning, want)
			}
		}
	}

	opts.PolicyTier = "strict"
	if warning := HookShellEnvWarning(conn, opts); warning != "" {
		t.Fatalf("strict tier warning = %q, want the refusal instead", warning)
	}
	err := CheckAgentSettings(conn, opts)
	if !errors.Is(err, ErrAgentConfigRefusal) || !strings.Contains(err.Error(), project) {
		t.Fatalf("strict CheckAgentSettings = %v; want an agent-settings refusal naming %s", err, project)
	}
	for _, want := range []string{"SHELLOPTS (with noexec", "strict policy tier refuses it", "every Claude Code session of this account fails closed", "default policy tier"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("strict refusal %q lacks %q", err, want)
		}
	}
	if strings.Contains(err.Error(), "a value such as") {
		t.Fatalf("strict refusal cites a variable it did not find: %v", err)
	}
	if present, err := OwnedHooksPresent(conn, opts); present || err == nil || !strings.Contains(err.Error(), "SHELLOPTS") {
		t.Fatalf("strict OwnedHooksPresent = %v, %v; want the effective-policy refusal", present, err)
	}

	// A local null does not clear the project value (Claude Code drops it).
	local := filepath.Join(opts.WorkspaceDir, ".claude", "settings.local.json")
	writeClaudePolicyJSON(t, local, map[string]interface{}{"env": map[string]interface{}{"SHELLOPTS": nil}})
	if err := CheckAgentSettings(conn, opts); !errors.Is(err, ErrAgentConfigRefusal) {
		t.Fatalf("strict with a local null SHELLOPTS: %v, want the refusal", err)
	}
	// A local "" does.
	writeClaudePolicyJSON(t, local, map[string]interface{}{"env": map[string]interface{}{"SHELLOPTS": ""}})
	if err := CheckAgentSettings(conn, opts); err != nil {
		t.Fatalf("strict with a local empty SHELLOPTS: %v", err)
	}
	// ENV cannot stop the launch and is not refused.
	writeClaudePolicyJSON(t, project, map[string]interface{}{"env": map[string]interface{}{"ENV": "/tmp/e"}})
	if err := CheckAgentSettings(conn, opts); err != nil {
		t.Fatalf("strict with ENV only: %v", err)
	}

	// A managed install pins the names in its drop-in and is not checked here.
	opts.ManagedEnterprise = true
	opts.PolicyTier = ""
	writeClaudePolicyJSON(t, project, map[string]interface{}{"env": map[string]interface{}{"SHELLOPTS": "noexec"}})
	writeClaudePolicyJSON(t, local, map[string]interface{}{})
	if warning := HookShellEnvWarning(conn, opts); warning != "" {
		t.Fatalf("managed warning = %q, want none", warning)
	}
}
