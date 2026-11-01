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
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// GAP-0376: a notify entry that runs DefenseClaw's own hook launcher with
// arguments after "notify" was left by teardown (argv had to be exactly two
// items), so an uninstall left Codex calling a removed program. A user's own
// notifier stays.
func TestCodexTeardownRemovesADefenseClawNotifyWithExtraArguments(t *testing.T) {
	home := t.TempDir()
	restore, err := BindUserHomeDir(home)
	if err != nil {
		t.Fatal(err)
	}
	defer restore()
	launcher := filepath.Join(home, ".local", "bin", windowsHookBinaryName)
	cfg := map[string]interface{}{
		"notify": []interface{}{launcher, "notify", "--connector", "codex"},
		"model":  "keep",
	}
	if !codexNotifyLooksManaged(cfg["notify"], SetupOpts{}) {
		t.Fatal("DefenseClaw's launcher with extra notify arguments is not recognized")
	}
	if err := restoreCodexNotify(cfg, codexConfigBackup{}, SetupOpts{}); err != nil {
		t.Fatal(err)
	}
	if _, kept := cfg["notify"]; kept || cfg["model"] != "keep" {
		t.Fatalf("after restore: %v", cfg)
	}
	for _, own := range [][]interface{}{
		{"/usr/bin/notify-send", "notify", "--connector", "codex"},
		{"python3", "notify", "x"},
	} {
		if codexNotifyLooksManaged(own, SetupOpts{}) {
			t.Fatalf("a user's own notifier %v is claimed", own)
		}
	}
}

// GAP-0376 (L-win-J10-005): on Windows the notify entry that names the
// gateway executable with "codex-notify" survived uninstall, because only
// argv[1] == "notify" was claimed. Every spelling of a DefenseClaw launcher
// with a DefenseClaw notify subcommand goes; the user's own notifier and the
// rest of config.toml stay.
func TestCodexTeardownRemovesEveryDefenseClawNotifySpelling(t *testing.T) {
	home := t.TempDir()
	restore, err := BindUserHomeDir(home)
	if err != nil {
		t.Fatal(err)
	}
	defer restore()
	bin := filepath.Join(home, ".local", "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	gateway := filepath.Join(bin, windowsGatewayBinaryName)
	hook := filepath.Join(bin, windowsHookBinaryName)
	for _, exe := range []string{gateway, hook} {
		if err := os.WriteFile(exe, []byte("x"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	forward := func(p string) string { return strings.ReplaceAll(p, `\`, "/") }
	programs := map[string]string{
		"gateway full path":       gateway,
		"gateway forward slashes": forward(gateway),
		"gateway quoted":          `"` + gateway + `"`,
		"gateway bare name .exe":  windowsGatewayBinaryName,
		"gateway bare name":       "defenseclaw-gateway",
		"hook full path":          hook,
		"hook forward slashes":    forward(hook),
		"hook quoted":             `"` + hook + `"`,
		"hook bare name .exe":     windowsHookBinaryName,
	}
	if runtime.GOOS == "windows" {
		// The Windows fallback launcher lives in ~/.local/bin, so a renamed copy
		// next to it is ours (GAP-1248).
		programs["renamed launcher next door"] = filepath.Join(bin, "defenseclaw-hook-old.exe")
		programs["gateway upper case"] = strings.ToUpper(gateway)
		programs["gateway backslash-forward mix"] = strings.Replace(gateway, `\`, "/", 1)
	}
	for name, program := range programs {
		for _, sub := range []string{"codex-notify", "notify"} {
			for _, extra := range [][]string{nil, {"--connector", "codex"}} {
				argv := append([]interface{}{program, sub}, toInterfaces(extra)...)
				if !codexNotifyLooksManaged(argv, SetupOpts{}) {
					t.Errorf("%s %s %v: DefenseClaw's notify is not recognized", name, sub, extra)
				}
			}
		}
	}

	// The whole teardown path on the file text, in both TOML string styles.
	basic := strings.ReplaceAll(gateway, `\`, `\\`)
	for style, line := range map[string]string{
		"basic string":   `notify = ["` + basic + `", "codex-notify"]`,
		"literal string": `notify = ['` + gateway + `', 'codex-notify']`,
		"quoted program": `notify = ['"` + gateway + `"', 'codex-notify']`,
		"bare .exe":      `notify = ["defenseclaw-gateway.exe", "codex-notify"]`,
	} {
		raw := []byte(line + "\nmodel = \"keep-model\"\n\n[projects.'C:\\keepme']\ntrust_level = \"trusted\"\n")
		got, err := restoreOwnedCodexConfigFromTOML(raw, true, codexConfigBackup{}, SetupOpts{DataDir: filepath.Join(home, ".defenseclaw")}, filepath.Join(home, ".codex", "config.toml"))
		if err != nil {
			t.Fatalf("%s: %v", style, err)
		}
		out := string(got.Data)
		if got.Remove || got.Keep || strings.Contains(out, "notify") || strings.Contains(strings.ToLower(out), "defenseclaw") {
			t.Errorf("%s: DefenseClaw's notify left after teardown (keep=%v remove=%v):\n%s", style, got.Keep, got.Remove, out)
		}
		if !strings.Contains(out, "keep-model") || !strings.Contains(out, "keepme") {
			t.Errorf("%s: the user's entries were not kept:\n%s", style, out)
		}
	}

	// The user's own notifiers stay, whatever they are called.
	elsewhere := filepath.Join(t.TempDir(), "defenseclaw-gateway.exe")
	for _, own := range [][]interface{}{
		{"C:\\Tools\\notify.exe", "codex-notify"},
		{"C:/Users/someone/bin/my-notify.ps1", "notify"},
		{elsewhere, "codex-notify"},
		{"powershell.exe", "-File", "C:\\Users\\u\\notify.ps1"},
		{gateway, "watchdog"},
		{gateway},
	} {
		if codexNotifyLooksManaged(own, SetupOpts{}) {
			t.Errorf("a user's own notifier %v is claimed", own)
		}
	}
	userLine := []byte("notify = ['C:\\Tools\\notify.exe', 'codex-notify']\nmodel = \"keep-model\"\n")
	got, err := restoreOwnedCodexConfigFromTOML(userLine, true, codexConfigBackup{}, SetupOpts{DataDir: filepath.Join(home, ".defenseclaw")}, filepath.Join(home, ".codex", "config.toml"))
	if err != nil {
		t.Fatal(err)
	}
	if !got.Keep || string(got.Data) != string(userLine) {
		t.Errorf("a config with only the user's own notifier changed: keep=%v\n%s", got.Keep, got.Data)
	}
}

func toInterfaces(values []string) []interface{} {
	out := make([]interface{}, 0, len(values))
	for _, value := range values {
		out = append(out, value)
	}
	return out
}
