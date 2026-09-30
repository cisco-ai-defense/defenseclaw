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
	"bytes"
	"encoding/json"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

func resetEnterprisePolicyFlags(t *testing.T) {
	t.Helper()
	t.Cleanup(func() {
		enterprisePolicyConnector, enterprisePolicyFormat, enterprisePolicyUser, enterprisePolicyProject = "", "", "", ""
		enterprisePolicyJSON, enterprisePolicyLive = false, false
		enterprisePolicyAgentBinary, enterprisePolicyAuditDB = "", ""
	})
}

func withEnterprisePolicyTree(t *testing.T) enterprisePolicyContext {
	t.Helper()
	root := t.TempDir()
	opts := enterprisepolicy.Options{
		GOOS:             "linux",
		Root:             root,
		HookBinary:       "/opt/defenseclaw/bin/defenseclaw-hook",
		StateDir:         filepath.Join(root, "var/lib/defenseclaw-enterprise/machine-policy"),
		PublicPolicyPath: filepath.Join(root, "etc/defenseclaw/machine-policy.json"),
		Now:              func() time.Time { return time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC) },
		SkipTrustChecks:  true,
	}
	ctx := enterprisePolicyContext{
		layout:     managed.StandaloneLayout{GOOS: "linux", LogDir: root, DataDir: root},
		opts:       opts,
		connectors: []string{"claudecode", "codex", "copilot", "cursor", "devin"},
	}
	previous := standaloneEnterprisePolicyOptions
	standaloneEnterprisePolicyOptions = func() (enterprisePolicyContext, error) { return ctx, nil }
	t.Cleanup(func() { standaloneEnterprisePolicyOptions = previous })
	resetEnterprisePolicyFlags(t)
	return ctx
}

func runPolicyCommand(t *testing.T, run func(*cobra.Command, []string) error) (string, error) {
	t.Helper()
	var out bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetOut(&out)
	err := run(cmd, nil)
	return out.String(), err
}

func TestEnterprisePolicyCommandsRequireStandaloneProfile(t *testing.T) {
	resetEnterprisePolicyFlags(t)
	previous := cfg
	t.Cleanup(func() { cfg = previous })
	cfg = &config.Config{DeploymentMode: managed.DeploymentModeManagedEnterprise}
	for _, run := range []func(*cobra.Command, []string) error{runEnterprisePolicyShow, runEnterprisePolicyVerify, runEnterprisePolicyExport} {
		if _, err := runPolicyCommand(t, run); err == nil || !strings.Contains(err.Error(), "enterprise.profile: standalone") {
			t.Fatalf("a Secure Client config must be refused, got %v", err)
		}
	}
}

func TestEnterprisePolicyVerifyShowAndExport(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("this publishes the Linux machine-policy tree, which only Linux and macOS write")
	}
	ctx := withEnterprisePolicyTree(t)
	if _, err := enterprisepolicy.Publish(ctx.opts, ctx.connectors); err != nil {
		t.Fatal(err)
	}

	enterprisePolicyJSON = true
	out, err := runPolicyCommand(t, runEnterprisePolicyVerify)
	if err != nil {
		t.Fatalf("a freshly published tree must verify: %v\n%s", err, out)
	}
	var report enterprisePolicyReport
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatalf("verify --json: %v\n%s", err, out)
	}
	if !report.Complete || report.Profile != "standalone" || len(report.Result.States) != len(ctx.connectors) {
		t.Fatalf("report: %+v", report)
	}
	routes := map[string]string{}
	for _, state := range report.Result.States {
		routes[state.Connector] = state.Route
	}
	if routes["codex"] != enterprisepolicy.RouteMachinePolicy || routes["devin"] != enterprisepolicy.RoutePerUser {
		t.Fatalf("routes: %v", routes)
	}
	if !report.Guard["cursor"].Guard || !report.Guard["devin"].Guard || report.Guard["codex"].Guard {
		t.Fatalf("guard flags: %+v", report.Guard)
	}

	enterprisePolicyJSON = false
	enterprisePolicyConnector = "codex"
	out, err = runPolicyCommand(t, runEnterprisePolicyExport)
	if err != nil || !strings.Contains(out, "allow_managed_hooks_only = true") || !strings.Contains(out, "hooks = true") {
		t.Fatalf("codex export: %v\n%s", err, out)
	}
	enterprisePolicyFormat = "claude-hklm-json"
	enterprisePolicyConnector = "claudecode"
	out, err = runPolicyCommand(t, runEnterprisePolicyExport)
	if err != nil || strings.Count(strings.TrimSpace(out), "\n") != 0 || !strings.Contains(out, "allowManagedHooksOnly") {
		t.Fatalf("claude HKLM export must be one line: %v\n%s", err, out)
	}

	enterprisePolicyFormat, enterprisePolicyConnector = "", ""
	dir, _ := enterprisepolicy.ClaudeManagedDir(ctx.opts)
	if err := os.Remove(filepath.Join(dir, "managed-settings.d", enterprisepolicy.DefenseClawDropInName)); err != nil {
		t.Fatal(err)
	}
	out, err = runPolicyCommand(t, runEnterprisePolicyVerify)
	if err == nil || !strings.Contains(err.Error(), "incomplete") {
		t.Fatalf("a removed drop-in must fail verify, got %v", err)
	}
	if !strings.Contains(out, "claudecode") || !strings.Contains(out, "not covered") || !strings.Contains(out, "Result: INCOMPLETE") {
		t.Fatalf("human output must name the gap:\n%s", out)
	}
	out, err = runPolicyCommand(t, runEnterprisePolicyShow)
	if err != nil || !strings.Contains(out, "codex") || !strings.Contains(out, "covered") {
		t.Fatalf("show only reports: %v\n%s", err, out)
	}

	// Show names one account's unprotected agent without changing coverage.
	previousUnprotected := enterprisePolicyUnprotectedAgents
	t.Cleanup(func() { enterprisePolicyUnprotectedAgents = previousUnprotected })
	enterprisePolicyUnprotectedAgents = func(string) []enterprisehooks.UnprotectedAgent {
		return []enterprisehooks.UnprotectedAgent{{
			User: "alice", Connector: "cursor", Version: "4.1.0", Code: enterprisehooks.UnprotectedCodeHookContractUnverified,
			Reason: "version 4.1.0 is not verified against a known hook contract",
		}}
	}
	out, err = runPolicyCommand(t, runEnterprisePolicyShow)
	if err != nil || !strings.Contains(out, "hook_contract_unverified: cursor 4.1.0 for user alice is not protected") {
		t.Fatalf("show must name the unprotected agent: %v\n%s", err, out)
	}

	// The wsl row is Windows only; there an uncovered row fails verify.
	enterprisePolicyConnector = enterprisepolicy.ConnectorWSL
	if _, err := runPolicyCommand(t, runEnterprisePolicyVerify); err == nil || !strings.Contains(err.Error(), "only to Windows") {
		t.Fatalf("the wsl row must be refused off Windows, got %v", err)
	}
	out, err = runPolicyCommand(t, runEnterprisePolicyExport)
	if err != nil || !strings.Contains(out, `"disableWslSessions"="true"`) {
		t.Fatalf("wsl export: %v\n%s", err, out)
	}
	windowsCtx := ctx
	windowsCtx.opts.GOOS = "windows"
	standaloneEnterprisePolicyOptions = func() (enterprisePolicyContext, error) { return windowsCtx, nil }
	previousWSL := enterprisePolicyWSLState
	t.Cleanup(func() { enterprisePolicyWSLState = previousWSL })
	enterprisePolicyWSLState = func(enterprisePolicyContext) (enterprisepolicy.State, error) {
		return enterprisepolicy.State{Connector: enterprisepolicy.ConnectorWSL, Route: enterprisepolicy.RouteMachinePolicy, Conflicts: []string{"disableWslSessions is not set"}}, nil
	}
	out, err = runPolicyCommand(t, runEnterprisePolicyVerify)
	if err == nil || !strings.Contains(out, "disableWslSessions is not set") {
		t.Fatalf("an uncovered wsl row must fail verify: %v\n%s", err, out)
	}
}

func TestEnterprisePolicyLiveNeedsExplicitTarget(t *testing.T) {
	withEnterprisePolicyTree(t)
	enterprisePolicyLive = true
	if _, err := runPolicyCommand(t, runEnterprisePolicyVerify); err == nil || !strings.Contains(err.Error(), "--live needs") {
		t.Fatalf("live without a user, connector and binary must be refused, got %v", err)
	}
}

func TestForeignHookCleanupIsInertOutsideStandalone(t *testing.T) {
	previous := cfg
	t.Cleanup(func() { cfg = previous })
	cfg = &config.Config{DeploymentMode: managed.DeploymentModeManagedEnterprise}
	home := t.TempDir()
	hooks := filepath.Join(home, ".cursor", "hooks.json")
	if err := os.MkdirAll(filepath.Dir(hooks), 0o755); err != nil {
		t.Fatal(err)
	}
	original := `{"version": 1, "hooks": {"preToolUse": [{"command": "./rewrite.sh"}]}}`
	if err := os.WriteFile(hooks, []byte(original), 0o644); err != nil {
		t.Fatal(err)
	}
	result, err := enterpriseForeignHookCleanup(enterprisehooks.TargetCredentials{UserHome: home, UID: os.Getuid(), GID: os.Getgid()}, "cursor", "")
	if err != nil || len(result.Removed) != 0 {
		t.Fatalf("Secure Client reconcile must not touch user hooks: %+v %v", result, err)
	}
	if data, _ := os.ReadFile(hooks); string(data) != original {
		t.Fatalf("user hooks changed: %s", data)
	}

	var calls []string
	previousCleanup := enterpriseForeignHookCleanup
	enterpriseForeignHookCleanup = func(target enterprisehooks.TargetCredentials, name, dataDir string) (enterprisepolicy.CleanupResult, error) {
		calls = append(calls, target.UserHome+"|"+name+"|"+dataDir)
		return enterprisepolicy.CleanupResult{}, nil
	}
	t.Cleanup(func() { enterpriseForeignHookCleanup = previousCleanup })
	reconcileEnterpriseForeignHooks(enterprisehooks.InstallOptions{ConnectorName: "devin", UserHome: home, DataDir: "/data"})
	if len(calls) != 1 || calls[0] != home+"|devin|/data" {
		t.Fatalf("reconcile seam: %v", calls)
	}
}

func TestEnterprisePolicyShowsTheClaudeVersionFloor(t *testing.T) {
	ctx := withEnterprisePolicyTree(t)
	// Publish writes the summary under the host path; create its parent so
	// the linux-rooted tree also works on a Windows host.
	if err := os.MkdirAll(filepath.Dir(ctx.opts.PublicPolicyPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := enterprisepolicy.Publish(ctx.opts, ctx.connectors); err != nil {
		t.Fatal(err)
	}
	floorPath, err := enterprisepolicy.ClaudeVersionFloorPath(ctx.opts)
	if err != nil {
		t.Fatal(err)
	}
	enterprisePolicyConnector = "claudecode"
	out, err := runPolicyCommand(t, runEnterprisePolicyShow)
	if err != nil || !strings.Contains(out, "floor:     requiredMinimumVersion 2.1.154 set by DefenseClaw ("+floorPath+"), version_floor=enforce") {
		t.Fatalf("show must name who owns the floor: %v\n%s", err, out)
	}

	// An administrator value is kept and shown as theirs.
	dir, _ := enterprisepolicy.ClaudeManagedDir(ctx.opts)
	base := path.Join(dir, "managed-settings.json") // the rooted tree's own join
	if err := os.WriteFile(base, []byte(`{"requiredMinimumVersion": "2.1.100"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := enterprisepolicy.Publish(ctx.opts, ctx.connectors); err != nil {
		t.Fatal(err)
	}
	enterprisePolicyJSON = true
	out, err = runPolicyCommand(t, runEnterprisePolicyVerify)
	if err != nil {
		t.Fatalf("an administrator floor must still verify: %v\n%s", err, out)
	}
	var report enterprisePolicyReport
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatal(err)
	}
	floor := report.Result.States[0].VersionFloor
	if floor == nil || floor.Owner != "administrator" || floor.Source != base || floor.Value != "2.1.100" || !floor.BelowFloor {
		t.Fatalf("verify --json floor: %+v", floor)
	}
	if _, err := os.Stat(floorPath); !os.IsNotExist(err) {
		t.Fatalf("DefenseClaw's floor must be withdrawn: %v", err)
	}

	enterprisePolicyJSON = false
	enterprisePolicyFormat = "version-floor"
	out, err = runPolicyCommand(t, runEnterprisePolicyExport)
	if err != nil || out != "{\n  \"requiredMinimumVersion\": \"2.1.154\"\n}\n" {
		t.Fatalf("version-floor export: %v\n%q", err, out)
	}

	// Under enforce, a floor that should be DefenseClaw's and is missing
	// fails verify.
	enterprisePolicyFormat = ""
	if err := os.Remove(base); err != nil {
		t.Fatal(err)
	}
	out, err = runPolicyCommand(t, runEnterprisePolicyVerify)
	if err == nil || !strings.Contains(out, "requiredMinimumVersion not set") || !strings.Contains(out, "DefenseClaw's "+floorPath+" is missing") {
		t.Fatalf("a missing floor must fail verify: %v\n%s", err, out)
	}

	// ownership: "off" is the administrator's choice, not an unsupported
	// agent.
	ctx.opts.Policies = map[string]config.ResolvedConnectorPolicy{"claudecode": config.EnterpriseMachinePolicyConfig{
		Connectors: map[string]config.EnterpriseConnectorPolicy{"claudecode": {Ownership: config.MachinePolicyOwnershipOff}},
	}.PolicyFor("claudecode")}
	standaloneEnterprisePolicyOptions = func() (enterprisePolicyContext, error) { return ctx, nil }
	out, err = runPolicyCommand(t, runEnterprisePolicyShow)
	if err != nil || !strings.Contains(out, "claudecode   ownership off: machine policy not managed") || strings.Contains(out, "unsupported") {
		t.Fatalf("show must say that ownership off leaves Claude Code unmanaged: %v\n%s", err, out)
	}
	// OpenCode keeps its per-user plugin under ownership: "off".
	var opencode bytes.Buffer
	report = enterprisePolicyReport{goos: "linux", Result: enterprisepolicy.Result{States: []enterprisepolicy.State{
		{Connector: "opencode", Route: enterprisepolicy.RoutePerUser, Ownership: config.MachinePolicyOwnershipOff},
	}}}
	if err := writeEnterprisePolicyReport(&opencode, report); err != nil || strings.Contains(opencode.String(), "ownership off") {
		t.Fatalf("OpenCode with ownership off is on its per-user plugin: %v\n%s", err, opencode.String())
	}
}

// The --user section lists connectors in name order, so the output of two
// accounts can be compared line by line.
func TestEnterprisePolicyUserReportListsConnectorsInOrder(t *testing.T) {
	resetEnterprisePolicyFlags(t)
	names := []string{"opencode", "copilot", "cursor", "claudecode", "devin", "amp", "codex", "kiro"}
	decisions := map[string]enterprisepolicy.GuardDecision{}
	for _, name := range names {
		decisions[name] = enterprisepolicy.GuardDecision{}
	}
	report := enterprisePolicyReport{User: &enterprisePolicyUserReport{User: "u", Home: "/home/u", Decisions: decisions}}
	for i := 0; i < 20; i++ {
		var out bytes.Buffer
		if err := writeEnterprisePolicyReport(&out, report); err != nil {
			t.Fatal(err)
		}
		var listed []string
		for _, line := range strings.Split(out.String(), "\n") {
			if fields := strings.Fields(line); len(fields) > 1 && strings.HasSuffix(line, "no foreign hooks") {
				listed = append(listed, fields[0])
			}
		}
		if len(listed) != len(names) || !sort.StringsAreSorted(listed) {
			t.Fatalf("connectors must be listed in name order: %v", listed)
		}
	}
}
