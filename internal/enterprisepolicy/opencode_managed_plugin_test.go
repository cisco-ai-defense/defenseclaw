// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

// The managed plugin is one file for every host: nothing in it may be a
// per-user or per-host value, and every call must go through the
// administrator-owned hook binary with the managed runtime.
func TestOpenCodeManagedPluginIsHostIndependent(t *testing.T) {
	plugin := string(OpenCodeManagedPlugin())
	if !strings.HasPrefix(plugin, "// defenseclaw-managed-opencode-plugin v1\n") {
		t.Fatalf("managed plugin must start with its version marker:\n%.80s", plugin)
	}
	for _, want := range []string{
		`"--connector", "opencode", "--enterprise-managed", "--event", event`,
		`"--connector", "opencode", "--foreign-hook-check"`,
		`"bin",`,
		`"defenseclaw-hook.exe" : "defenseclaw-hook"`,
		`"tool.execute.before": async`,
	} {
		if !strings.Contains(plugin, want) {
			t.Fatalf("managed plugin lacks %q", want)
		}
	}
	for _, forbidden := range []*regexp.Regexp{
		regexp.MustCompile(`\{\{`),                  // unrendered template data
		regexp.MustCompile(`DEFENSECLAW_[A-Z_]+`),   // environment the user controls
		regexp.MustCompile(`127\.0\.0\.1|18970`),    // a baked gateway address
		regexp.MustCompile(`\.token|Authorization`), // a credential path or header
		regexp.MustCompile(`\bfetch\(`),             // a direct gateway call
	} {
		if match := forbidden.FindString(plugin); match != "" {
			t.Fatalf("managed plugin must not contain %q", match)
		}
	}
	copied := OpenCodeManagedPlugin()
	copied[0] = 'X'
	if bytes.Equal(copied, OpenCodeManagedPlugin()) {
		t.Fatal("OpenCodeManagedPlugin must return a copy")
	}
}

// A managed plugin whose bytes are not this release's is reported, so
// status and verify show a stale or edited artifact instead of calling
// OpenCode covered.
func TestOpenCodeManagedPluginDriftIsAConflict(t *testing.T) {
	opts := testOptions(t)
	file := installTestOpenCodePlugin(t, &opts)
	state, err := opencodeTarget{}.Reconcile(opts)
	if err != nil {
		t.Fatal(err)
	}
	mustNoConflicts(t, state)
	if !state.Covered {
		t.Fatalf("the shipped plugin must be covered: %+v", state)
	}
	writeFile(t, file, "export default {}")
	if route := opts.Route("opencode"); route != RouteMachinePolicy {
		t.Fatalf("a present artifact keeps the machine route, got %s", route)
	}
	for name, run := range map[string]func(Options) (State, error){
		"reconcile": opencodeTarget{}.Reconcile,
		"verify":    opencodeTarget{}.Verify,
	} {
		state, err := run(opts)
		if err != nil {
			t.Fatal(err)
		}
		if state.Covered || !hasConflict(state, "does not match this release") {
			t.Fatalf("%s must report a drifted plugin: %+v", name, state)
		}
	}
}

// Every user's OpenCode runs the artifact, so one another user could write
// must never become the machine route.
func TestOpenCodeManagedPluginMustBeTrusted(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix ownership rule")
	}
	opts := testOptions(t)
	opts.SkipTrustChecks = false
	previous := trustedOwner
	uid := uint32(os.Getuid())
	trustedOwner = func(owner uint32) bool { return owner == uid }
	t.Cleanup(func() { trustedOwner = previous })
	if err := os.Chmod(opts.Root, 0o755); err != nil {
		t.Fatal(err)
	}
	file := installTestOpenCodePlugin(t, &opts)
	if route := opts.Route("opencode"); route != RouteMachinePolicy {
		t.Fatalf("a trusted artifact is the machine route, got %s", route)
	}
	if err := os.Chmod(file, 0o666); err != nil {
		t.Fatal(err)
	}
	if route := opts.Route("opencode"); route != RoutePerUser {
		t.Fatalf("a world-writable artifact must fall back to per-user, got %s", route)
	}
	for name, run := range map[string]func(Options) (State, error){
		"reconcile": opencodeTarget{}.Reconcile,
		"verify":    opencodeTarget{}.Verify,
		"publish": func(opts Options) (State, error) {
			result, err := Publish(opts, []string{"opencode"})
			return result.States[0], err
		},
		"policy show": func(opts Options) (State, error) {
			result, err := VerifyAll(opts, []string{"opencode"})
			return result.States[0], err
		},
	} {
		state, err := run(opts)
		if err != nil {
			t.Fatal(err)
		}
		if state.Route != RoutePerUser || !strings.Contains(strings.Join(state.Details, " "), "not trusted") {
			t.Fatalf("%s must stay per-user and say why: %+v", name, state)
		}
	}
	configPath, _ := OpenCodeManagedConfigPath(opts)
	if _, err := os.Lstat(configPath); !os.IsNotExist(err) {
		t.Fatalf("an untrusted artifact must not be published: %v", err)
	}
	if err := os.Chmod(file, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Dir(file), 0o777); err != nil {
		t.Fatal(err)
	}
	if route := opts.Route("opencode"); route != RoutePerUser {
		t.Fatalf("an artifact in a world-writable directory must fall back to per-user, got %s", route)
	}
}

// OpenCode's pure mode and its managed config directory override start a
// session without the managed plugin, which no machine file can prevent.
// Reconcile and verify must say so next to a covered state, so status does
// not read as a route users cannot skip.
func TestOpenCodeMachinePolicyStateNamesTheVendorLimit(t *testing.T) {
	opts := testOptions(t)
	installTestOpenCodePlugin(t, &opts)
	for _, step := range []struct {
		name string
		run  func(Options) (State, error)
	}{
		{"reconcile", opencodeTarget{}.Reconcile},
		{"verify", opencodeTarget{}.Verify},
	} {
		state, err := step.run(opts)
		if err != nil {
			t.Fatal(err)
		}
		details := strings.Join(state.Details, " ")
		if !state.Covered || !strings.Contains(details, "OPENCODE_PURE") {
			t.Fatalf("%s must name OpenCode's pure mode and managed config override: %+v", step.name, state)
		}
	}
}

// The unix lifecycle plans OpenCode onto machine policy before it renders
// the artifact; publishing still needs the installed file.
func TestOpenCodeManagedPluginPlannedRoute(t *testing.T) {
	opts := testOptions(t)
	opts.OpenCodePluginPath = testOpenCodePlugin
	opts.OpenCodePluginPlanned = true
	if got := MachinePolicyConnectors(opts, []string{"opencode", "devin"}); len(got) != 1 || got[0] != "opencode" {
		t.Fatalf("a planned artifact must put OpenCode on machine policy: %v", got)
	}
	state, err := opencodeTarget{}.Reconcile(opts)
	if err != nil {
		t.Fatal(err)
	}
	if state.Route != RoutePerUser || state.Covered {
		t.Fatalf("reconcile must not publish before the artifact exists: %+v", state)
	}
	opts.OpenCodePluginPath = ""
	if got := MachinePolicyConnectors(opts, []string{"opencode"}); len(got) != 0 {
		t.Fatalf("without an artifact path the plan cannot apply: %v", got)
	}
}

func TestInstallOpenCodeManagedPlugin(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("rooted unix tree; the Windows install is covered by TestPublishWindowsGoOwnedInstallsTheOpenCodePlugin")
	}
	opts := testOptions(t)
	if _, err := InstallOpenCodeManagedPlugin(opts); err == nil {
		t.Fatal("install must refuse an unset artifact path")
	}
	opts.OpenCodePluginPath = testOpenCodePlugin
	file := rooted(opts, testOpenCodePlugin)
	writeFile(t, filepath.Join(opts.Root, "opt/defenseclaw/bin/defenseclaw-hook"), "binary")
	changed, err := InstallOpenCodeManagedPlugin(opts)
	if err != nil || !changed {
		t.Fatalf("first install: changed=%v err=%v", changed, err)
	}
	if got := readFile(t, file); got != string(OpenCodeManagedPlugin()) {
		t.Fatal("install must write the shipped plugin")
	}
	if info, err := os.Stat(file); err != nil || info.Mode().Perm() != 0o644 {
		t.Fatalf("plugin must be readable by every user and writable only by its owner: %v %v", info, err)
	}
	if changed, err := InstallOpenCodeManagedPlugin(opts); err != nil || changed {
		t.Fatalf("install must be idempotent: changed=%v err=%v", changed, err)
	}
	writeFile(t, file, "stale")
	if changed, err := InstallOpenCodeManagedPlugin(opts); err != nil || !changed || readFile(t, file) != string(OpenCodeManagedPlugin()) {
		t.Fatalf("install must replace a stale plugin: changed=%v err=%v", changed, err)
	}
	if route := opts.Route("opencode"); route != RouteMachinePolicy {
		t.Fatalf("an installed plugin is the machine route, got %s", route)
	}

	if err := RemoveOpenCodeManagedPlugin(opts); err != nil {
		t.Fatal(err)
	}
	for _, gone := range []string{file, filepath.Dir(file), filepath.Dir(filepath.Dir(file))} {
		if _, err := os.Lstat(gone); !os.IsNotExist(err) {
			t.Fatalf("%s must be removed: %v", gone, err)
		}
	}
	if _, err := os.Stat(filepath.Join(opts.Root, "opt/defenseclaw/bin/defenseclaw-hook")); err != nil {
		t.Fatalf("removal must leave the rest of the install root: %v", err)
	}
	if err := RemoveOpenCodeManagedPlugin(opts); err != nil {
		t.Fatalf("removal must be idempotent: %v", err)
	}
	// A share directory holding anything else survives.
	if _, err := InstallOpenCodeManagedPlugin(opts); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(opts.Root, "opt/defenseclaw/share/policies/default.yaml"), "x")
	if err := RemoveOpenCodeManagedPlugin(opts); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(opts.Root, "opt/defenseclaw/share/policies/default.yaml")); err != nil {
		t.Fatalf("removal must keep other share content: %v", err)
	}
}

func TestOpenCodeManagedPluginRoute(t *testing.T) {
	opts := testOptions(t)
	if route := opts.Route("opencode"); route != RoutePerUser {
		t.Fatalf("without an artifact OpenCode stays per-user, got %s", route)
	}
	opts.OpenCodePluginPath = testOpenCodePlugin
	if route := opts.Route("opencode"); route != RoutePerUser {
		t.Fatalf("a configured but missing artifact must stay per-user, got %s", route)
	}
	installTestOpenCodePlugin(t, &opts)
	if route := opts.Route("opencode"); route != RouteMachinePolicy {
		t.Fatalf("with an artifact OpenCode uses machine policy, got %s", route)
	}
	configPath, _ := OpenCodeManagedConfigPath(opts)
	admin := "{\n  \"$schema\": \"https://opencode.ai/config.json\",\n  \"plugin\": [\"company-audit\"],\n  \"share\": \"disabled\"\n}\n"
	writeFile(t, configPath, admin)

	state, err := opencodeTarget{}.Reconcile(opts)
	if err != nil {
		t.Fatal(err)
	}
	mustNoConflicts(t, state)
	if !state.Covered || state.ForeignEntries != 1 || !state.Changed {
		t.Fatalf("state: %+v", state)
	}
	merged := readFile(t, configPath)
	if !strings.Contains(merged, `"company-audit",`) || !strings.Contains(merged, opts.OpenCodePluginPath) || strings.Index(merged, "$schema") > strings.Index(merged, "plugin") {
		t.Fatalf("merge must keep the administrator's keys and order:\n%s", merged)
	}
	again, err := opencodeTarget{}.Reconcile(opts)
	if err != nil || again.Changed {
		t.Fatalf("reconcile must be idempotent: %+v %v", again, err)
	}
	if _, err := (opencodeTarget{}).RemoveOwned(opts); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, configPath); got != admin {
		t.Fatalf("removal must restore the preimage exactly:\n%s", got)
	}

	jsonc := filepath.Join(filepath.Dir(configPath), "opencode.jsonc")
	writeFile(t, jsonc, "{\n  // company policy\n  \"plugin\": []\n}\n")
	state, err = opencodeTarget{}.Reconcile(opts)
	if err != nil {
		t.Fatal(err)
	}
	if state.Covered || !hasConflict(state, "verify_only") {
		t.Fatalf("a commented .jsonc cannot be merged: %+v", state)
	}
	if got := readFile(t, jsonc); !strings.Contains(got, "// company policy") {
		t.Fatalf("commented config must stay untouched:\n%s", got)
	}
}
