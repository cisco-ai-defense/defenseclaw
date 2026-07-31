// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/hookruntime"
)

func TestConnectorLifecycleConfigHomeSelectsExactNativeBinding(t *testing.T) {
	root := t.TempDir()
	codexHome := filepath.Join(root, "codex")
	claudeHome := filepath.Join(root, "claude")
	copilotHome := filepath.Join(root, "copilot")
	cursorHome := filepath.Join(root, "cursor")
	windsurfHome := filepath.Join(root, "windsurf-profile")
	antigravityHome := filepath.Join(root, ".gemini", "config")
	openCodeHome := filepath.Join(root, "opencode")
	hermesHome := filepath.Join(root, "hermes")
	env := []string{
		"UNRELATED=preserved",
		"codex_home=" + codexHome,
		"CLAUDE_CONFIG_DIR=" + claudeHome,
		"COPILOT_HOME=" + copilotHome,
		"DEFENSECLAW_CURSOR_CONFIG_HOME=" + cursorHome,
		"WINDSURF_USER_HOME=" + windsurfHome,
		"ANTIGRAVITY_CONFIG_DIR=" + filepath.Join(root, "ignored-antigravity"),
		"GEMINI_CONFIG_DIR=" + filepath.Join(root, "ignored-gemini"),
		"DEFENSECLAW_ANTIGRAVITY_CONFIG_HOME=" + antigravityHome,
		"OPENCODE_CONFIG_DIR=" + openCodeHome,
		"HERMES_HOME=" + hermesHome,
	}
	for _, test := range []struct {
		connector string
		want      string
	}{
		{connector: "codex", want: codexHome},
		{connector: "claudecode", want: claudeHome},
		{connector: "copilot", want: copilotHome},
		{connector: "cursor", want: cursorHome},
		{connector: "windsurf", want: windsurfHome},
		{connector: "antigravity", want: antigravityHome},
		{connector: "opencode", want: openCodeHome},
		{connector: "hermes", want: hermesHome},
	} {
		t.Run(test.connector, func(t *testing.T) {
			got, err := connectorLifecycleConfigHome(env, test.connector)
			if err != nil {
				t.Fatal(err)
			}
			if got != test.want {
				t.Fatalf("config home = %q, want %q", got, test.want)
			}
		})
	}
}

func TestConnectorLifecycleCommandArgsBindsConfigHomeExplicitly(t *testing.T) {
	root := t.TempDir()
	dataRoot := filepath.Join(root, "data")
	codexHome := filepath.Join(root, "codex")
	args, err := connectorLifecycleCommandArgs(
		dataRoot,
		"codex",
		"teardown",
		[]string{"CODEX_HOME=" + codexHome},
	)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"connector", "teardown",
		"--connector", "codex",
		"--data-dir", dataRoot,
		"--config-home", codexHome,
		"--json",
	}
	if !reflect.DeepEqual(args, want) {
		t.Fatalf("connector lifecycle args = %q, want %q", args, want)
	}
}

func TestHermesLifecycleCommandArgsBindStableHookRuntimeExplicitly(t *testing.T) {
	root := t.TempDir()
	dataRoot := filepath.Join(root, "data")
	hermesHome := filepath.Join(root, "hermes")
	stableHook := filepath.Join(root, "HookRuntime", hookruntime.LauncherName)
	previous := currentUserHookRuntimePaths
	currentUserHookRuntimePaths = func() (hookruntime.Paths, error) {
		return hookruntime.Paths{Launcher: stableHook}, nil
	}
	t.Cleanup(func() { currentUserHookRuntimePaths = previous })

	args, err := connectorLifecycleCommandArgs(
		dataRoot,
		"hermes",
		"teardown",
		[]string{"HERMES_HOME=" + hermesHome},
	)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"connector", "teardown",
		"--connector", "hermes",
		"--data-dir", dataRoot,
		"--config-home", hermesHome,
		"--hook-executable", stableHook,
		"--json",
	}
	if !reflect.DeepEqual(args, want) {
		t.Fatalf("Hermes lifecycle args = %q, want %q", args, want)
	}
}

func TestCopilotLifecycleCommandArgsBindExactHome(t *testing.T) {
	root := t.TempDir()
	dataRoot := filepath.Join(root, "data")
	copilotHome := filepath.Join(root, "copilot")
	args, err := connectorLifecycleCommandArgs(
		dataRoot,
		"copilot",
		"reconcile",
		[]string{"COPILOT_HOME=" + copilotHome},
	)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"connector", "reconcile",
		"--connector", "copilot",
		"--data-dir", dataRoot,
		"--config-home", copilotHome,
		"--json",
	}
	if !reflect.DeepEqual(args, want) {
		t.Fatalf("Copilot lifecycle args = %q, want %q", args, want)
	}
}

func TestWindsurfLifecycleCommandArgsBindsProfileRootExplicitly(t *testing.T) {
	root := t.TempDir()
	dataRoot := filepath.Join(root, "data")
	profileRoot := filepath.Join(root, "windsurf-profile")
	args, err := connectorLifecycleCommandArgs(
		dataRoot,
		"windsurf",
		"teardown",
		[]string{"WINDSURF_USER_HOME=" + profileRoot, "USERPROFILE=" + filepath.Join(root, "ambient")},
	)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"connector", "teardown",
		"--connector", "windsurf",
		"--data-dir", dataRoot,
		"--config-home", profileRoot,
		"--json",
	}
	if !reflect.DeepEqual(args, want) {
		t.Fatalf("connector lifecycle args = %q, want %q", args, want)
	}
}

func TestCursorConnectorLifecycleCommandArgsBindsConfigHomeExplicitly(t *testing.T) {
	root := t.TempDir()
	dataRoot := filepath.Join(root, "data")
	cursorHome := filepath.Join(root, "cursor")
	args, err := connectorLifecycleCommandArgs(
		dataRoot,
		"cursor",
		"reconcile",
		[]string{"DEFENSECLAW_CURSOR_CONFIG_HOME=" + cursorHome},
	)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"connector", "reconcile",
		"--connector", "cursor",
		"--data-dir", dataRoot,
		"--config-home", cursorHome,
		"--json",
	}
	if !reflect.DeepEqual(args, want) {
		t.Fatalf("connector lifecycle args = %q, want %q", args, want)
	}
}

func TestOpenCodeLifecycleCommandArgsBindExactConfigDir(t *testing.T) {
	root := t.TempDir()
	dataRoot := filepath.Join(root, "data")
	openCodeConfigDir := filepath.Join(root, "opencode")
	args, err := connectorLifecycleCommandArgs(
		dataRoot,
		"opencode",
		"reconcile",
		[]string{"OPENCODE_CONFIG_DIR=" + openCodeConfigDir},
	)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"connector", "reconcile",
		"--connector", "opencode",
		"--data-dir", dataRoot,
		"--config-home", openCodeConfigDir,
		"--json",
	}
	if !reflect.DeepEqual(args, want) {
		t.Fatalf("OpenCode lifecycle args = %q, want %q", args, want)
	}
}

func TestConnectorLifecycleConfigHomeRejectsAmbiguousOrUnsafeBinding(t *testing.T) {
	root := t.TempDir()
	valid := filepath.Join(root, "codex")
	unnormalized := root + string(filepath.Separator) + "child" + string(filepath.Separator) + ".." + string(filepath.Separator) + "codex"
	for _, test := range []struct {
		name      string
		connector string
		env       []string
		want      string
	}{
		{name: "missing", connector: "codex", env: []string{"UNRELATED=1"}, want: "CODEX_HOME is empty"},
		{name: "duplicate", connector: "codex", env: []string{"CODEX_HOME=" + valid, "codex_home=" + valid}, want: "CODEX_HOME is duplicated"},
		{name: "relative", connector: "codex", env: []string{"CODEX_HOME=relative"}, want: "absolute normalized path"},
		{name: "unnormalized", connector: "codex", env: []string{"CODEX_HOME=" + unnormalized}, want: "absolute normalized path"},
		{name: "newline", connector: "codex", env: []string{"CODEX_HOME=" + valid + "\nother"}, want: "absolute normalized path"},
		{name: "missing Copilot", connector: "copilot", env: []string{"UNRELATED=1"}, want: "COPILOT_HOME is empty"},
		{name: "duplicate Copilot", connector: "copilot", env: []string{"COPILOT_HOME=" + valid, "copilot_home=" + valid}, want: "COPILOT_HOME is duplicated"},
		{name: "cursor missing", connector: "cursor", env: []string{"UNRELATED=1"}, want: "DEFENSECLAW_CURSOR_CONFIG_HOME is empty"},
		{name: "cursor duplicate", connector: "cursor", env: []string{"DEFENSECLAW_CURSOR_CONFIG_HOME=" + valid, "defenseclaw_cursor_config_home=" + valid}, want: "DEFENSECLAW_CURSOR_CONFIG_HOME is duplicated"},
		{name: "windsurf missing", connector: "windsurf", env: []string{"USERPROFILE=" + valid}, want: "WINDSURF_USER_HOME is empty"},
		{name: "hermes missing", connector: "hermes", env: []string{"USERPROFILE=" + valid}, want: "HERMES_HOME is empty"},
		{name: "OpenCode missing", connector: "opencode", env: []string{"USERPROFILE=" + valid}, want: "OPENCODE_CONFIG_DIR is empty"},
		{name: "OpenCode duplicate", connector: "opencode", env: []string{"OPENCODE_CONFIG_DIR=" + valid, "opencode_config_dir=" + valid}, want: "OPENCODE_CONFIG_DIR is duplicated"},
		{name: "unsupported", connector: "openclaw", env: []string{"CODEX_HOME=" + valid}, want: "unsupported native connector"},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := connectorLifecycleConfigHome(test.env, test.connector)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want substring %q", err, test.want)
			}
		})
	}
}
