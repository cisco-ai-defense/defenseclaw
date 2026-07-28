// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestConnectorLifecycleConfigHomeSelectsExactNativeBinding(t *testing.T) {
	root := t.TempDir()
	codexHome := filepath.Join(root, "codex")
	claudeHome := filepath.Join(root, "claude")
	env := []string{
		"UNRELATED=preserved",
		"codex_home=" + codexHome,
		"CLAUDE_CONFIG_DIR=" + claudeHome,
	}
	for _, test := range []struct {
		connector string
		want      string
	}{
		{connector: "codex", want: codexHome},
		{connector: "claudecode", want: claudeHome},
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
