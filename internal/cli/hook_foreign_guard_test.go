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
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

const foreignGuardHookBinary = "/opt/defenseclaw/bin/defenseclaw-hook"

type foreignGuardFixture struct {
	home    string
	project string
	summary *enterprisepolicy.PublicPolicy
	loadErr error
	// process is the agent process identity the guard sees ("" unknown).
	process string
}

func newForeignGuardFixture(t *testing.T, mode string) *foreignGuardFixture {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("fixture uses unix hook command forms")
	}
	return newPortableForeignGuardFixture(t, mode)
}

// newPortableForeignGuardFixture is the fixture for tests that use only
// foreign hook entries, which read the same on every OS.
func newPortableForeignGuardFixture(t *testing.T, mode string) *foreignGuardFixture {
	t.Helper()
	fixture := &foreignGuardFixture{home: t.TempDir()}
	fixture.project = filepath.Join(fixture.home, "work", "repo")
	if err := os.MkdirAll(filepath.Join(fixture.project, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	fixture.summary = &enterprisepolicy.PublicPolicy{
		SchemaVersion: 1,
		HookBinary:    foreignGuardHookBinary,
		Connectors: map[string]enterprisepolicy.PublicConnectorPolicy{
			"cursor": {Route: enterprisepolicy.RouteMachinePolicy, ForeignHooks: mode, Guard: true},
		},
	}
	previousPath, previousLoad := hookForeignGuardSummaryPath, hookForeignGuardLoad
	previousAccountHome, previousEnvHomes := hookForeignGuardAccountHome, hookForeignGuardEnvHomes
	previousProcess := hookForeignGuardAgentProcess
	previousExchange := hookForeignGuardExchange
	gatewayState := t.TempDir()
	hookForeignGuardSummaryPath = func() (string, bool) { return "/etc/defenseclaw/machine-policy.json", true }
	hookForeignGuardLoad = func(string) (*enterprisepolicy.PublicPolicy, error) {
		if fixture.loadErr != nil {
			return nil, fixture.loadErr
		}
		if fixture.summary == nil {
			return nil, enterprisepolicy.ErrNoPublicPolicy
		}
		return fixture.summary, nil
	}
	hookForeignGuardAccountHome = func() string { return fixture.home }
	hookForeignGuardEnvHomes = func() []string { return nil }
	hookForeignGuardAgentProcess = func() string { return fixture.process }
	hookForeignGuardExchange = func(_ string, _ string, _ time.Time, exchange enterprisepolicy.SessionExchange) (enterprisepolicy.GuardDecision, error) {
		if exchange.Key.Session == "" && exchange.Key.Process == "" {
			return exchange.Decision, nil
		}
		return enterprisepolicy.ApplyForeignHookSession(enterprisepolicy.SessionUpdate{
			StateDir: filepath.Join(gatewayState, exchange.Key.Connector),
			Key:      exchange.Key, SessionStart: exchange.SessionStart, Decision: exchange.Decision,
		}), nil
	}
	t.Cleanup(func() {
		hookForeignGuardSummaryPath, hookForeignGuardLoad = previousPath, previousLoad
		hookForeignGuardAccountHome, hookForeignGuardEnvHomes = previousAccountHome, previousEnvHomes
		hookForeignGuardAgentProcess = previousProcess
		hookForeignGuardExchange = previousExchange
	})
	return fixture
}

func (f *foreignGuardFixture) write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func (f *foreignGuardFixture) run(t *testing.T, managed bool) (hookexec.Options, string, string) {
	t.Helper()
	payload := `{"hook_event_name":"preToolUse","cwd":"` + filepath.Join(f.project, "src") + `","tool_name":"Shell"}`
	var stderr bytes.Buffer
	opts := hookexec.Options{Connector: "cursor", ManagedEnterprise: managed, Stdin: strings.NewReader(payload), Stderr: &stderr}
	applyEnterpriseForeignHookGuard(&opts)
	replayed, err := io.ReadAll(opts.Stdin)
	if err != nil {
		t.Fatal(err)
	}
	if string(replayed) != payload {
		t.Fatalf("hookexec must receive the identical payload, got %q", replayed)
	}
	return opts, stderr.String(), payload
}

func TestForeignHookGuardDenyAllowMatrix(t *testing.T) {
	fixture := newForeignGuardFixture(t, config.ForeignHooksRemove)
	if opts, _, _ := fixture.run(t, true); opts.ManagedRuntimeFailure != "" {
		t.Fatalf("no foreign hooks must allow: %q", opts.ManagedRuntimeFailure)
	}

	projectHooks := filepath.Join(fixture.project, ".cursor", "hooks.json")
	fixture.write(t, projectHooks, `{"version": 1, "hooks": {"preToolUse": [{"command": "./rewrite.sh"}]}}`)
	for _, managed := range []bool{true, false} {
		opts, _, _ := fixture.run(t, managed)
		if !opts.ManagedEnterprise || !strings.Contains(opts.ManagedRuntimeFailure, "enterprise_foreign_hook_blocked") || !strings.Contains(opts.ManagedRuntimeFailure, projectHooks) {
			t.Fatalf("managed=%v: a project hook found through the payload cwd must deny: %+v", managed, opts)
		}
	}

	decision := enterprisepolicy.EvaluateForeignHooks(enterprisepolicy.GuardRequest{
		Connector: "cursor", Home: fixture.home, WorkingDir: fixture.project, HookBinary: foreignGuardHookBinary,
		Policy: fixture.summary.Connectors["cursor"],
	})
	allowed := fixture.summary.Connectors["cursor"]
	allowed.AllowedHooks = []string{decision.Findings[0].Digest}
	fixture.summary.Connectors["cursor"] = allowed
	if opts, _, _ := fixture.run(t, true); opts.ManagedRuntimeFailure != "" {
		t.Fatalf("an allowlisted digest must allow: %q", opts.ManagedRuntimeFailure)
	}

	allowed.AllowedHooks = nil
	allowed.ForeignHooks = config.ForeignHooksReport
	fixture.summary.Connectors["cursor"] = allowed
	opts, stderr, _ := fixture.run(t, true)
	if opts.ManagedRuntimeFailure != "" || !strings.Contains(stderr, "reports it but allows it") {
		t.Fatalf("report mode must warn and allow: %q %q", opts.ManagedRuntimeFailure, stderr)
	}

	allowed.Guard = false
	fixture.summary.Connectors["cursor"] = allowed
	if opts, _, _ := fixture.run(t, true); opts.ManagedRuntimeFailure != "" {
		t.Fatalf("a connector without the guard must allow: %q", opts.ManagedRuntimeFailure)
	}
}

func TestForeignHookGuardIsInertWithoutStandaloneSummary(t *testing.T) {
	fixture := newForeignGuardFixture(t, config.ForeignHooksRemove)
	fixture.summary = nil
	fixture.write(t, filepath.Join(fixture.project, ".cursor", "hooks.json"), `{"version": 1, "hooks": {"preToolUse": [{"command": "./rewrite.sh"}]}}`)
	payload := strings.NewReader(`{"cwd":"/tmp"}`)
	opts := hookexec.Options{Connector: "cursor", ManagedEnterprise: true, Stdin: payload}
	applyEnterpriseForeignHookGuard(&opts)
	if opts.ManagedRuntimeFailure != "" || opts.Stdin != io.Reader(payload) || payload.Len() != len(`{"cwd":"/tmp"}`) {
		t.Fatalf("Secure Client and unmanaged hosts (no summary) must be untouched: %+v", opts)
	}
	previous := hookForeignGuardSummaryPath
	hookForeignGuardSummaryPath = func() (string, bool) { return "", false }
	defer func() { hookForeignGuardSummaryPath = previous }()
	opts = hookexec.Options{Connector: "cursor", ManagedEnterprise: false, Stdin: payload}
	applyEnterpriseForeignHookGuard(&opts)
	if opts.ManagedEnterprise || opts.ManagedRuntimeFailure != "" {
		t.Fatalf("a host without a standalone layout must be untouched: %+v", opts)
	}
}

func TestForeignHookGuardFailsClosedOnUntrustedSummary(t *testing.T) {
	fixture := newForeignGuardFixture(t, config.ForeignHooksRemove)
	fixture.loadErr = errors.New("machine policy summary is group-writable")
	opts := hookexec.Options{Connector: "cursor", Stdin: strings.NewReader("{}")}
	applyEnterpriseForeignHookGuard(&opts)
	if !opts.ManagedEnterprise || opts.ManagedRuntimeFailure != "enterprise_machine_policy_summary_untrusted" {
		t.Fatalf("an untrusted summary must fail closed: %+v", opts)
	}
	existing := hookexec.Options{Connector: "cursor", ManagedEnterprise: true, ManagedRuntimeFailure: "enterprise_managed_runtime_invalid"}
	applyEnterpriseForeignHookGuard(&existing)
	if existing.ManagedRuntimeFailure != "enterprise_managed_runtime_invalid" {
		t.Fatalf("an earlier runtime failure must be preserved: %q", existing.ManagedRuntimeFailure)
	}
}

// A per-user script lives in the user's home, so the user controls its
// bytes. On a machine-policy connector (Cursor) the guardian never repairs
// it: registering it must be treated like any other foreign hook, or a
// user-edited script rewrites the call after the machine hook checked it.
func TestForeignHookGuardTreatsPerUserScriptAsForeignOnMachinePolicy(t *testing.T) {
	fixture := newForeignGuardFixture(t, config.ForeignHooksRemove)
	userHooks := filepath.Join(fixture.home, ".cursor", "hooks.json")
	machine := `'` + foreignGuardHookBinary + `' hook --connector cursor --enterprise-managed`
	document, _ := json.Marshal(map[string]any{"version": 1, "hooks": map[string]any{
		"preToolUse": []any{map[string]any{"command": machine}},
	}})
	fixture.write(t, userHooks, string(document))
	if opts, _, _ := fixture.run(t, true); opts.ManagedRuntimeFailure != "" {
		t.Fatalf("a copy of the admin-binary registration is not foreign: %q", opts.ManagedRuntimeFailure)
	}

	script := filepath.Join(fixture.home, ".defenseclaw", "hooks", "cursor-hook.sh")
	fixture.write(t, script, "#!/bin/sh\necho '{\"permission\":\"allow\",\"updated_input\":{}}'\n")
	document, _ = json.Marshal(map[string]any{"version": 1, "hooks": map[string]any{
		"preToolUse": []any{map[string]any{"command": script}, map[string]any{"command": machine}},
	}})
	fixture.write(t, userHooks, string(document))
	opts, _, _ := fixture.run(t, true)
	if !strings.Contains(opts.ManagedRuntimeFailure, "enterprise_foreign_hook_blocked") || !strings.Contains(opts.ManagedRuntimeFailure, userHooks) {
		t.Fatalf("a per-user script registered for a machine-policy connector must deny: %q", opts.ManagedRuntimeFailure)
	}
}

// On a per-user connector (Devin) DefenseClaw's own registration is the
// per-user script the guardian installs and repairs, but only under the
// account's home: a data directory the agent's environment names
// (DEFENSECLAW_HOME, a different HOME) is user-chosen code.
func TestForeignHookGuardOwnsPerUserScriptOnlyUnderTheAccountHome(t *testing.T) {
	fixture := newForeignGuardFixture(t, config.ForeignHooksRemove)
	fixture.summary.Connectors["devin"] = enterprisepolicy.PublicConnectorPolicy{Route: enterprisepolicy.RoutePerUser, ForeignHooks: config.ForeignHooksRemove, Guard: true}
	agentHome := t.TempDir()
	hookForeignGuardEnvHomes = func() []string { return []string{agentHome} }
	t.Setenv("DEFENSECLAW_HOME", filepath.Join(agentHome, "dc"))
	t.Setenv("XDG_CONFIG_HOME", "")
	userConfig := filepath.Join(fixture.home, ".config", "devin", "config.json")
	register := func(script string) {
		document, _ := json.Marshal(map[string]any{"hooks": map[string]any{
			"PreToolUse": []any{map[string]any{"matcher": "", "hooks": []any{map[string]any{"type": "command", "command": script, "timeout": 10}}}},
		}})
		fixture.write(t, userConfig, string(document))
	}
	run := func() string {
		payload := `{"hook_event_name":"PreToolUse","cwd":"` + fixture.project + `"}`
		opts := hookexec.Options{Connector: "devin", Home: filepath.Join(agentHome, "dc"), Stdin: strings.NewReader(payload), Stderr: io.Discard}
		applyEnterpriseForeignHookGuard(&opts)
		return opts.ManagedRuntimeFailure
	}
	register(filepath.Join(fixture.home, ".defenseclaw", "hooks", "devin-hook.sh"))
	if reason := run(); reason != "" {
		t.Fatalf("DefenseClaw's per-user Devin registration under the account home is not foreign: %q", reason)
	}
	for _, dir := range []string{filepath.Join(agentHome, "dc"), filepath.Join(agentHome, ".defenseclaw")} {
		register(filepath.Join(dir, "hooks", "devin-hook.sh"))
		if reason := run(); !strings.Contains(reason, "enterprise_foreign_hook_blocked") {
			t.Fatalf("a script under %s (named by the agent's environment) must be foreign: %q", dir, reason)
		}
	}
}

func TestForeignHookGuardDenialUsesVendorBlockResponse(t *testing.T) {
	fixture := newForeignGuardFixture(t, config.ForeignHooksRemove)
	fixture.summary.Connectors["claudecode"] = enterprisepolicy.PublicConnectorPolicy{Route: enterprisepolicy.RouteMachinePolicy, ForeignHooks: config.ForeignHooksRemove, Guard: true}
	fixture.write(t, filepath.Join(fixture.project, ".claude", "settings.local.json"), `{"hooks": {"PreToolUse": [{"matcher": "*", "hooks": [{"type": "command", "command": "./rewrite.sh"}]}]}}`)
	var stdout, stderr bytes.Buffer
	opts := hookexec.Options{
		Connector:         "claudecode",
		Event:             "PreToolUse",
		ManagedEnterprise: true,
		FailMode:          "closed",
		Stdin:             strings.NewReader(`{"hook_event_name":"PreToolUse","cwd":"` + fixture.project + `","tool_name":"Bash","tool_input":{"command":"ls"}}`),
		Stdout:            &stdout,
		Stderr:            &stderr,
	}
	applyEnterpriseForeignHookGuard(&opts)
	// Claude Code blocks a PreToolUse call on exit 2 and shows stderr.
	if code := hookexec.Run(context.Background(), opts); code != 2 {
		t.Fatalf("the denial must block the tool call: code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stderr.String(), "enterprise_foreign_hook_blocked") || !strings.Contains(stderr.String(), "allowed_hooks") {
		t.Fatalf("the user must see which file to remove or allowlist: %s", stderr.String())
	}
}

// Copilot shows only the structured deny reason, not stderr. A repository
// .github/hooks file (even a sessionStart-only one) makes the managed
// preToolUse and permissionRequest hooks deny before any gateway contact;
// the reason must name that file and the allowlist key.
func TestForeignHookGuardCopilotDenialNamesTheFile(t *testing.T) {
	fixture := newForeignGuardFixture(t, config.ForeignHooksRemove)
	fixture.summary.Connectors["copilot"] = enterprisepolicy.PublicConnectorPolicy{Route: enterprisepolicy.RouteMachinePolicy, ForeignHooks: config.ForeignHooksRemove, Guard: true}
	foreign := filepath.Join(fixture.project, ".github", "hooks", "project.json")
	fixture.write(t, foreign, `{"version":1,"hooks":{"sessionStart":[{"type":"command","bash":"/bin/true"}]}}`)
	for event, field := range map[string]string{"preToolUse": "permissionDecisionReason", "permissionRequest": "message"} {
		var stdout, stderr bytes.Buffer
		opts := hookexec.Options{
			Connector:         "copilot",
			Event:             event,
			ManagedEnterprise: true,
			FailMode:          "closed",
			Stdin:             strings.NewReader(`{"timestamp":1,"cwd":"` + fixture.project + `","toolName":"bash","toolArgs":"{\"command\":\"ls\"}"}`),
			Stdout:            &stdout,
			Stderr:            &stderr,
		}
		applyEnterpriseForeignHookGuard(&opts)
		if code := hookexec.Run(context.Background(), opts); code != 0 {
			t.Fatalf("%s: Copilot reads the structured deny on exit 0: code=%d stderr=%s", event, code, stderr.String())
		}
		var decision map[string]string
		if err := json.Unmarshal(bytes.TrimSpace(stdout.Bytes()), &decision); err != nil {
			t.Fatalf("%s: deny body is not JSON: %v: %s", event, err, stdout.String())
		}
		if decision["permissionDecision"] != "deny" && decision["behavior"] != "deny" {
			t.Fatalf("%s: the call must be denied: %s", event, stdout.String())
		}
		message := decision[field]
		if !strings.HasPrefix(message, hookexec.ForeignHookBlockedReasonPrefix) || !strings.Contains(message, foreign) ||
			!strings.Contains(message, "enterprise.machine_policy.connectors.copilot.allowed_hooks") {
			t.Fatalf("%s: the deny reason must name %s and the allowlist key: %q", event, foreign, message)
		}
	}
}

// The standalone guard's scan is part of the hook invocation: hookexec's
// request budget must start before it. Hosts without a standalone summary
// (Secure Client, unmanaged) keep the unchanged budget start.
func TestForeignHookGuardStartsTheRequestBudgetBeforeScanning(t *testing.T) {
	fixture := newForeignGuardFixture(t, config.ForeignHooksRemove)
	before := time.Now()
	opts, _, _ := fixture.run(t, true)
	if opts.StartedAt.IsZero() || opts.StartedAt.Before(before) || opts.StartedAt.After(time.Now()) {
		t.Fatalf("the guard must start the request budget: %v", opts.StartedAt)
	}
	fixture.summary = nil
	opts, _, _ = fixture.run(t, true)
	if !opts.StartedAt.IsZero() {
		t.Fatalf("a host without a standalone summary must keep the budget start unchanged: %v", opts.StartedAt)
	}
	if budget := hookForeignGuardScanBudget("codex", "SessionEnd"); budget <= 0 || budget >= hookexec.RequestTimeout("codex", "SessionEnd") {
		t.Fatalf("the scan budget must fit inside the request budget: %v", budget)
	}
	if budget := hookForeignGuardScanBudget("copilot", "preToolUse"); budget != hookForeignGuardMaxScan {
		t.Fatalf("the scan budget is capped: %v", budget)
	}
}

// The hook-time block is recorded in the user's data directory for the
// guardian to report; an allowed call records nothing.
func TestForeignHookGuardRecordsTheBlockForTheGuardian(t *testing.T) {
	fixture := newForeignGuardFixture(t, config.ForeignHooksRemove)
	record := enterprisepolicy.BlockRecordPath(fixture.home)
	fixture.run(t, true)
	if _, err := os.Stat(record); !os.IsNotExist(err) {
		t.Fatalf("an allowed call must not record a block: %v", err)
	}
	foreign := filepath.Join(fixture.project, ".cursor", "hooks.json")
	fixture.write(t, foreign, `{"version": 1, "hooks": {"preToolUse": [{"command": "./rewrite.sh"}]}}`)
	fixture.run(t, true)
	blocks, dropped, err := enterprisepolicy.CollectForeignHookBlocks(fixture.home, time.Now())
	if err != nil || dropped != 0 || len(blocks) != 1 || blocks[0].Path != foreign || blocks[0].Connector != "cursor" || blocks[0].Event != "preToolUse" {
		t.Fatalf("the block must be recorded with its file and event: %+v %d %v", blocks, dropped, err)
	}
	if _, err := os.Stat(record); !os.IsNotExist(err) {
		t.Fatalf("collecting takes the records: %v", err)
	}
}

// The standalone Amp and OpenCode plugins call the gateway directly and
// never run `defenseclaw hook`; they ask `hook --foreign-hook-check` for the
// guard's decision. The answer is always one JSON object, and anything but
// {"deny": false} blocks in the plugin.
func TestForeignHookCheckAnswersInAgentPlugins(t *testing.T) {
	fixture := newForeignGuardFixture(t, config.ForeignHooksRemove)
	t.Setenv("XDG_CONFIG_HOME", "")
	fixture.summary.Connectors["opencode"] = enterprisepolicy.PublicConnectorPolicy{Route: enterprisepolicy.RoutePerUser, ForeignHooks: config.ForeignHooksRemove, Guard: true}
	check := func() foreignHookCheckResult {
		t.Helper()
		var out bytes.Buffer
		payload := `{"hook_event_name":"tool.execute.before","cwd":"` + fixture.project + `"}`
		if code := runForeignHookCheck("opencode", strings.NewReader(payload), &out); code != 0 {
			t.Fatalf("the check always exits 0, got %d", code)
		}
		var result foreignHookCheckResult
		if err := json.Unmarshal(out.Bytes(), &result); err != nil {
			t.Fatalf("the answer must be JSON: %v: %q", err, out.String())
		}
		return result
	}
	fixture.write(t, filepath.Join(fixture.home, ".config", "opencode", "plugins", "defenseclaw.js"), "// DefenseClaw")
	if result := check(); result.Deny {
		t.Fatalf("DefenseClaw's installed plugin alone allows: %+v", result)
	}
	foreign := filepath.Join(fixture.project, ".opencode", "plugins", "rewrite.js")
	fixture.write(t, foreign, "export const x = {}")
	result := check()
	if !result.Deny || !strings.Contains(result.Reason, foreign) || !strings.HasPrefix(result.Reason, hookexec.ForeignHookBlockedReasonPrefix) {
		t.Fatalf("a project plugin must deny and name its file: %+v", result)
	}
	if blocks, _, _ := enterprisepolicy.CollectForeignHookBlocks(fixture.home, time.Now()); len(blocks) != 1 || blocks[0].Path != foreign {
		t.Fatalf("the plugin block is recorded for the guardian: %+v", blocks)
	}

	fixture.loadErr = errors.New("machine policy summary is group-writable")
	if result := check(); !result.Deny || result.Reason != "enterprise_machine_policy_summary_untrusted" {
		t.Fatalf("an untrusted summary must deny: %+v", result)
	}
	fixture.loadErr = nil
	fixture.summary = nil
	if result := check(); result.Deny {
		t.Fatalf("a host without a standalone summary answers allow: %+v", result)
	}
}

// Only the standalone profile renders the guard into the Amp and OpenCode
// plugins; every other connector and profile (Secure Client, unmanaged)
// keeps the plugin unchanged.
func TestStandaloneForeignHookGuardBinaryOnlyForStandalonePlugins(t *testing.T) {
	previous := cfg
	t.Cleanup(func() { cfg = previous })
	cfg = &config.Config{
		DeploymentMode: managed.DeploymentModeManagedEnterprise,
		Enterprise:     config.EnterpriseConfig{Profile: managed.ProfileStandalone},
	}
	for _, name := range []string{"amp", "opencode", "OpenCode"} {
		if binary := standaloneForeignHookGuardBinary(name); !filepath.IsAbs(binary) || !strings.Contains(filepath.Base(binary), "defenseclaw-hook") {
			t.Fatalf("%s: standalone plugins run the admin hook binary, got %q", name, binary)
		}
	}
	for _, name := range []string{"cursor", "codex", ""} {
		if binary := standaloneForeignHookGuardBinary(name); binary != "" {
			t.Fatalf("%s: only plugin connectors and Devin get a guard binary, got %q", name, binary)
		}
	}
	// The Unix standalone Devin hook command runs the admin binary in
	// managed mode; Windows already registers that binary for Devin. The
	// Unix standalone hermes-hook.sh asks it for the guard's decision; the
	// Windows Hermes registration does not run the guard.
	for _, name := range []string{"devin", "hermes"} {
		if binary := standaloneForeignHookGuardBinary(name); (runtime.GOOS == "windows") != (binary == "") {
			t.Fatalf("%s on %s: guard binary %q", name, runtime.GOOS, binary)
		}
	}
	// Every connector's Linux and macOS shell hook gets the admin hook binary
	// for the session facts, guard or not (GAP-0194); Windows renders none.
	if binary := standaloneManagedHookBinary(); (runtime.GOOS == "windows") != (binary == "") ||
		(binary != "" && !filepath.IsAbs(binary)) {
		t.Fatalf("the standalone profile's session facts binary on %s: %q", runtime.GOOS, binary)
	}
	cfg = &config.Config{DeploymentMode: managed.DeploymentModeManagedEnterprise, Enterprise: config.EnterpriseConfig{Profile: managed.ProfileSecureClient}}
	if binary := standaloneForeignHookGuardBinary("amp"); binary != "" {
		t.Fatalf("the Secure Client profile must not render the guard: %q", binary)
	}
	if binary := standaloneManagedHookBinary(); binary != "" {
		t.Fatalf("the Secure Client profile must not name a session facts binary: %q", binary)
	}
	cfg = nil
	if binary := standaloneForeignHookGuardBinary("opencode"); binary != "" {
		t.Fatalf("an unmanaged install must not render the guard: %q", binary)
	}
}

// The managed OpenCode plugin sends every event through the hook; only the
// pre-tool event can block, so only it pays for (and can be denied by) the
// guard. A telemetry event never records a block for the guardian.
func TestForeignHookGuardOpenCodeGuardsOnlyThePreToolEvent(t *testing.T) {
	fixture := newForeignGuardFixture(t, config.ForeignHooksRemove)
	t.Setenv("XDG_CONFIG_HOME", "")
	fixture.summary.Connectors["opencode"] = enterprisepolicy.PublicConnectorPolicy{Route: enterprisepolicy.RouteMachinePolicy, ForeignHooks: config.ForeignHooksRemove, Guard: true}
	foreign := filepath.Join(fixture.project, ".opencode", "plugins", "rewrite.js")
	fixture.write(t, foreign, "export const x = {}")
	guard := func(event string) hookexec.Options {
		t.Helper()
		payload := `{"hook_event_name":"` + event + `","cwd":"` + fixture.project + `"}`
		opts := hookexec.Options{Connector: "opencode", Event: event, ManagedEnterprise: true, Stdin: strings.NewReader(payload), Stderr: io.Discard}
		applyEnterpriseForeignHookGuard(&opts)
		return opts
	}
	for _, event := range []string{"tool.execute.after", "defenseclaw.plugin.loaded", "session.updated"} {
		if opts := guard(event); opts.ManagedRuntimeFailure != "" {
			t.Fatalf("%s is telemetry and must not be guarded: %q", event, opts.ManagedRuntimeFailure)
		}
	}
	if blocks, _, _ := enterprisepolicy.CollectForeignHookBlocks(fixture.home, time.Now()); len(blocks) != 0 {
		t.Fatalf("telemetry events must not record blocks: %+v", blocks)
	}
	opts := guard("tool.execute.before")
	if !strings.HasPrefix(opts.ManagedRuntimeFailure, hookexec.ForeignHookBlockedReasonPrefix) || !strings.Contains(opts.ManagedRuntimeFailure, foreign) {
		t.Fatalf("the pre-tool event must deny and name the plugin: %q", opts.ManagedRuntimeFailure)
	}
	for _, name := range []string{"cursor", "copilot"} {
		if !foreignHookGuardedEvent(name, "") || !foreignHookGuardedEvent(name, "tool.execute.after") {
			t.Fatalf("%s is guarded on every event", name)
		}
	}
}

// On Windows the Amp plugin has no hook-binary runtime that could
// authenticate the gateway session exchange, so its check keeps the session
// under the account's home instead of failing closed on every tool call.
func TestForeignHookCheckAmpOnWindowsKeepsTheSessionLocally(t *testing.T) {
	fixture := newPortableForeignGuardFixture(t, config.ForeignHooksRemove)
	t.Setenv("XDG_CONFIG_HOME", "")
	fixture.summary.Connectors["amp"] = enterprisepolicy.PublicConnectorPolicy{Route: enterprisepolicy.RoutePerUser, ForeignHooks: config.ForeignHooksRemove, Guard: true}
	previousGOOS, previousExchange := hookForeignGuardGOOS, hookForeignGuardExchange
	hookForeignGuardGOOS = "windows"
	hookForeignGuardExchange = func(string, string, time.Time, enterprisepolicy.SessionExchange) (enterprisepolicy.GuardDecision, error) {
		return enterprisepolicy.GuardDecision{}, errors.New("standalone hook runtime unavailable")
	}
	t.Cleanup(func() { hookForeignGuardGOOS, hookForeignGuardExchange = previousGOOS, previousExchange })
	check := func(event string) foreignHookCheckResult {
		t.Helper()
		var out bytes.Buffer
		payload, err := json.Marshal(map[string]string{"hook_event_name": event, "cwd": fixture.project})
		if err != nil {
			t.Fatal(err)
		}
		if code := runForeignHookCheck("amp", bytes.NewReader(payload), &out); code != 0 {
			t.Fatalf("the check always exits 0, got %d", code)
		}
		var result foreignHookCheckResult
		if err := json.Unmarshal(out.Bytes(), &result); err != nil {
			t.Fatalf("the answer must be JSON: %v: %q", err, out.String())
		}
		return result
	}
	fixture.process = "amp-1"
	if result := check("session.load"); result.Deny {
		t.Fatalf("a clean Amp session must be allowed without the gateway exchange: %+v", result)
	}
	if result := check("tool.call"); result.Deny {
		t.Fatalf("a clean Amp tool call must be allowed: %+v", result)
	}
	foreign := filepath.Join(fixture.project, ".amp", "plugins", "rewrite.ts")
	fixture.write(t, foreign, "export default function () {}")
	fixture.process = "amp-2"
	if result := check("session.load"); !result.Deny || !strings.Contains(result.Reason, foreign) {
		t.Fatalf("an unapproved Amp plugin must deny and name its file: %+v", result)
	}
	if err := os.Remove(foreign); err != nil {
		t.Fatal(err)
	}
	if result := check("tool.call"); !result.Deny {
		t.Fatalf("a process that started with an unapproved plugin stays blocked: %+v", result)
	}
}
