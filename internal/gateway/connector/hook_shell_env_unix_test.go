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

// rel-1-0-6:GAP-0322: the names are resolved as Claude Code merges env
// blocks, highest source first, and only a value that takes effect counts.
func TestClaudeCodeSettingsHookShellEnvFollowsEnvPrecedence(t *testing.T) {
	cases := []struct {
		name    string
		sources claudeCodeUserSourceSet
		want    []string
		from    []string
	}{
		{
			name:    "project noexec",
			sources: claudeCodeUserSourceSet{project: hookShellEnvSource("project settings", map[string]interface{}{"SHELLOPTS": "noexec", "PATH": "/bin"})},
			want:    []string{"SHELLOPTS"}, from: []string{"project settings"},
		},
		{
			name: "local empty clears project",
			sources: claudeCodeUserSourceSet{
				local:   hookShellEnvSource("local project settings", map[string]interface{}{"SHELLOPTS": ""}),
				project: hookShellEnvSource("project settings", map[string]interface{}{"SHELLOPTS": "noexec"}),
			},
		},
		{
			name: "every name, two sources",
			sources: claudeCodeUserSourceSet{
				cli: hookShellEnvSource("CLI --settings", map[string]interface{}{"CLAUDE_CODE_SHELL_PREFIX": "/usr/bin/true"}),
				user: hookShellEnvSource("user settings", map[string]interface{}{
					"BASHOPTS": "extglob", "BASH_ENV": "/tmp/x", "ENV": "/tmp/y", "FUNCNEST": "1",
					"BASH_FUNC_[%%": "() { return 0; }", "POSIXLY_CORRECT": "1", "SHELL": "/bin/zsh",
				}),
			},
			want: []string{"BASHOPTS", "BASH_ENV", "BASH_FUNC_[%%", "CLAUDE_CODE_SHELL_PREFIX", "ENV", "FUNCNEST"},
			from: []string{"CLI --settings", "user settings"},
		},
		{
			name:    "an exported function counts with an empty value",
			sources: claudeCodeUserSourceSet{user: hookShellEnvSource("user settings", map[string]interface{}{"BASH_FUNC_echo%%": ""})},
			want:    []string{"BASH_FUNC_echo%%"}, from: []string{"user settings"},
		},
		{
			name:    "blank values and no env block",
			sources: claudeCodeUserSourceSet{user: hookShellEnvSource("user settings", map[string]interface{}{"SHELLOPTS": "  ", "BASH_ENV": ""}), project: &claudeCodeSettingsSource{name: "p", settings: map[string]interface{}{}}},
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
		for _, want := range []string{project, "SHELLOPTS", "/bin/sh", "remove SHELLOPTS"} {
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
	if !errors.Is(err, ErrAgentConfigRefusal) || !strings.Contains(err.Error(), "strict policy tier refuses it") ||
		!strings.Contains(err.Error(), project) {
		t.Fatalf("strict CheckAgentSettings = %v; want an agent-settings refusal naming %s", err, project)
	}
	if present, err := OwnedHooksPresent(conn, opts); present || err == nil || !strings.Contains(err.Error(), "SHELLOPTS") {
		t.Fatalf("strict OwnedHooksPresent = %v, %v; want the effective-policy refusal", present, err)
	}

	// A higher source that empties the name clears the finding.
	writeClaudePolicyJSON(t, filepath.Join(opts.WorkspaceDir, ".claude", "settings.local.json"),
		map[string]interface{}{"env": map[string]interface{}{"SHELLOPTS": ""}})
	if err := CheckAgentSettings(conn, opts); err != nil {
		t.Fatalf("strict with a local empty SHELLOPTS: %v", err)
	}

	// A managed install pins the names in its drop-in and is not checked here.
	opts.ManagedEnterprise = true
	opts.PolicyTier = ""
	writeClaudePolicyJSON(t, filepath.Join(opts.WorkspaceDir, ".claude", "settings.local.json"), map[string]interface{}{})
	if warning := HookShellEnvWarning(conn, opts); warning != "" {
		t.Fatalf("managed warning = %q, want none", warning)
	}
}
