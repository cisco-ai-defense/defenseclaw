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
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

func guardRequest(t *testing.T, connector string, mode string) GuardRequest {
	t.Helper()
	home := t.TempDir()
	project := filepath.Join(home, "work", "repo")
	if err := os.MkdirAll(filepath.Join(project, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	return GuardRequest{
		Connector:  connector,
		GOOS:       "linux",
		Home:       home,
		WorkingDir: filepath.Join(project, "src"),
		HookBinary: testHookBinary,
		Policy:     PublicConnectorPolicy{Route: RouteFor(connector, "linux"), ForeignHooks: mode, Guard: true},
	}
}

const ownedCursorEntry = `{"type": "command", "command": "'/opt/defenseclaw/bin/defenseclaw-hook' hook --connector cursor --enterprise-managed", "timeout": 30, "failClosed": true}`

func TestGuardDeniesForeignUserAndProjectHooks(t *testing.T) {
	req := guardRequest(t, "cursor", config.ForeignHooksRemove)
	writeFile(t, filepath.Join(req.Home, ".cursor", "hooks.json"), `{"version": 1, "hooks": {"preToolUse": [`+ownedCursorEntry+`]}}`)
	if decision := EvaluateForeignHooks(req); decision.Deny || len(decision.Findings) != 0 {
		t.Fatalf("DefenseClaw's own registration must not be flagged: %+v", decision)
	}
	projectHooks := filepath.Join(req.WorkingDir, "..", ".cursor", "hooks.json")
	writeFile(t, projectHooks, `{"version": 1, "hooks": {"preToolUse": [{"command": "./rewrite-everything.sh"}]}}`)
	decision := EvaluateForeignHooks(req)
	if !decision.Deny || len(decision.Findings) != 1 || decision.Findings[0].Scope != ScopeProject {
		t.Fatalf("a project preToolUse hook must deny: %+v", decision)
	}
	if !strings.Contains(decision.Reason, "enterprise_foreign_hook_blocked") || !strings.Contains(decision.Reason, "allowed_hooks") || !strings.Contains(decision.Reason, decision.Findings[0].Digest) {
		t.Fatalf("deny reason must name the file, digest and allowlist: %s", decision.Reason)
	}

	allowed := req
	allowed.Policy.AllowedHooks = []string{decision.Findings[0].Digest}
	if again := EvaluateForeignHooks(allowed); again.Deny || !again.Findings[0].Allowed {
		t.Fatalf("an allowlisted digest must pass: %+v", again)
	}
	report := req
	report.Policy.ForeignHooks = config.ForeignHooksReport
	if again := EvaluateForeignHooks(report); again.Deny || len(again.Findings) != 1 {
		t.Fatalf("report mode must allow but return findings: %+v", again)
	}
	off := req
	off.Policy.Guard = false
	if again := EvaluateForeignHooks(off); again.Deny || len(again.Findings) != 0 {
		t.Fatalf("a connector without the guard must not scan: %+v", again)
	}
}

// Copilot runs bash on Unix and powershell on Windows, Claude-format http
// hooks run url: a handler is DefenseClaw's only when every field the agent
// may execute is an owned command and it carries nothing DefenseClaw does
// not write.
func TestGuardOwnershipCoversEveryExecutableField(t *testing.T) {
	owned := `'` + testHookBinary + `' hook --connector copilot --enterprise-managed --event 'preToolUse'`
	req := guardRequest(t, "copilot", config.ForeignHooksRemove)
	path := filepath.Join(req.WorkingDir, "..", ".github", "hooks", "x.json")
	for name, handler := range map[string]string{
		"bash owned, powershell foreign":    `{"type": "command", "bash": "` + owned + `", "powershell": "& .\\rewrite.ps1"}`,
		"command owned, bash foreign":       `{"type": "command", "command": "` + owned + `", "bash": "./rewrite.sh"}`,
		"exec-form binary, bash foreign":    `{"type": "command", "bash": "` + testHookBinary + `", "powershell": "./rewrite.ps1"}`,
		"http hook with an owned command":   `{"type": "http", "url": "http://127.0.0.1:9/rewrite", "command": "` + owned + `"}`,
		"owned command with env":            `{"type": "command", "bash": "` + owned + `", "env": {"LD_PRELOAD": "./x.so"}}`,
		"owned command with an OS override": `{"type": "command", "bash": "` + owned + `", "windows": "./rewrite.cmd"}`,
		"exec form with unmanaged args":     `{"type": "command", "command": "` + testHookBinary + `", "args": ["hook", "--connector", "copilot", "--api-addr", "127.0.0.1:9"]}`,
		"non-string command":                `{"type": "command", "bash": ["` + owned + `"]}`,
	} {
		writeFile(t, path, `{"version": 1, "hooks": {"preToolUse": [`+handler+`]}}`)
		decision := EvaluateForeignHooks(req)
		if !decision.Deny || len(decision.Findings) != 1 {
			t.Fatalf("%s: must be foreign: %+v", name, decision)
		}
	}
	for name, handler := range map[string]string{
		"unix bash form":         `{"type": "command", "bash": "` + owned + `", "timeoutSec": 30}`,
		"exec form with args":    `{"type": "command", "command": "` + testHookBinary + `", "args": ["hook", "--connector", "claudecode", "--enterprise-managed"], "timeout": 30}`,
		"exec form with --event": `{"command": "` + testHookBinary + `", "args": ["hook", "--connector", "copilot", "--enterprise-managed", "--event", "preToolUse"]}`,
	} {
		writeFile(t, path, `{"version": 1, "hooks": {"preToolUse": [`+handler+`]}}`)
		if decision := EvaluateForeignHooks(req); decision.Deny || len(decision.Findings) != 0 {
			t.Fatalf("%s: DefenseClaw's own handler must not be flagged: %+v", name, decision)
		}
	}
}

// DefenseClaw's per-user registration names a user-owned script. It is
// DefenseClaw's hook only on a per-user route (where the guardian repairs
// it); on a machine-policy route the same command is foreign.
func TestGuardHonorsPerUserOwnedCommandsOnlyOnPerUserRoute(t *testing.T) {
	for _, tc := range []struct {
		connector, route string
		file, body       string
		foreign          bool
	}{
		{"cursor", RouteMachinePolicy, ".cursor/hooks.json", `{"version": 1, "hooks": {"preToolUse": [{"command": %s}]}}`, true},
		{"devin", RoutePerUser, ".config/devin/config.json", `{"hooks": {"PreToolUse": [{"matcher": "", "hooks": [{"type": "command", "command": %s, "timeout": 10}]}]}}`, false},
	} {
		req := guardRequest(t, tc.connector, config.ForeignHooksRemove)
		req.Policy.Route = tc.route
		script := filepath.Join(req.Home, ".defenseclaw", "hooks", tc.connector+"-hook.sh")
		req.OwnedCommands = []string{script}
		writeFile(t, filepath.Join(req.Home, filepath.FromSlash(tc.file)), strings.Replace(tc.body, "%s", jsonString(script), 1))
		decision := EvaluateForeignHooks(req)
		if decision.Deny != tc.foreign {
			t.Fatalf("%s (%s): deny=%v, want %v: %+v", tc.connector, tc.route, decision.Deny, tc.foreign, decision)
		}
	}
}

func TestGuardFailsClosedOnSymlinkedHookFile(t *testing.T) {
	req := guardRequest(t, "copilot", config.ForeignHooksRemove)
	target := filepath.Join(req.Home, "elsewhere.json")
	writeFile(t, target, `{"hooks": {}}`)
	link := filepath.Join(req.WorkingDir, "..", ".github", "hooks", "evil.json")
	if err := os.MkdirAll(filepath.Dir(link), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	decision := EvaluateForeignHooks(req)
	if !decision.Deny || !strings.Contains(decision.Reason, "cannot be verified") {
		t.Fatalf("a symlinked hook file must fail closed: %+v", decision)
	}
}

func TestGuardCoversCopilotDevinCodexAndPlugins(t *testing.T) {
	copilot := guardRequest(t, "copilot", config.ForeignHooksRemove)
	writeFile(t, filepath.Join(copilot.Home, ".copilot", "hooks", "mine.json"), `{"version": 1, "hooks": {"preToolUse": [{"type": "command", "bash": "./modify-args.sh"}]}}`)
	writeFile(t, filepath.Join(copilot.Home, ".copilot", "hooks", "defenseclaw.json"), `{"version": 1, "hooks": {"preToolUse": [{"type": "command", "bash": "'/opt/defenseclaw/bin/defenseclaw-hook' hook --connector copilot --enterprise-managed --event 'preToolUse'"}]}}`)
	if decision := EvaluateForeignHooks(copilot); !decision.Deny || len(decision.Findings) != 1 {
		t.Fatalf("copilot user hook: %+v", decision)
	}

	devin := guardRequest(t, "devin", config.ForeignHooksRemove)
	writeFile(t, filepath.Join(devin.WorkingDir, "..", ".devin", "hooks.v1.json"), `{"hooks": {"PreToolUse": [{"matcher": "*", "hooks": [{"type": "command", "command": "./x.sh"}]}]}}`)
	if decision := EvaluateForeignHooks(devin); !decision.Deny {
		t.Fatalf("devin project hook: %+v", decision)
	}

	codex := guardRequest(t, "codex", config.ForeignHooksRemove)
	writeFile(t, filepath.Join(codex.Home, ".codex", "config.toml"), "[[hooks.PreToolUse]]\nmatcher = \"*\"\n\n[[hooks.PreToolUse.hooks]]\ntype = \"command\"\ncommand = \"./rewrite.sh\"\n")
	if decision := EvaluateForeignHooks(codex); !decision.Deny {
		t.Fatalf("codex user hook under preserve: %+v", decision)
	}

	opencode := guardRequest(t, "opencode", config.ForeignHooksRemove)
	opencode.AccountHome = opencode.Home
	writeFile(t, filepath.Join(opencode.Home, ".config", "opencode", "plugins", "defenseclaw.js"), "// DefenseClaw")
	writeFile(t, filepath.Join(opencode.Home, ".config", "opencode", "plugins", "mutate.js"), "export default {}")
	decision := EvaluateForeignHooks(opencode)
	if !decision.Deny || len(decision.Findings) != 1 || !strings.Contains(decision.Reason, "adds a plugin") {
		t.Fatalf("opencode foreign plugin: %+v", decision)
	}
}

func TestGuardHonorsVendorConfigDirOverrides(t *testing.T) {
	req := guardRequest(t, "copilot", config.ForeignHooksRemove)
	custom := filepath.Join(req.Home, "alt-copilot")
	writeFile(t, filepath.Join(custom, "hooks", "x.json"), `{"hooks": {"preToolUse": [{"bash": "./x"}]}}`)
	if decision := EvaluateForeignHooks(req); decision.Deny {
		t.Fatalf("without COPILOT_HOME the alternate dir is not loaded by the agent: %+v", decision)
	}
	req.Getenv = func(key string) string {
		if key == "COPILOT_HOME" {
			return custom
		}
		return ""
	}
	if decision := EvaluateForeignHooks(req); !decision.Deny {
		t.Fatalf("COPILOT_HOME must be scanned when the agent sees it: %+v", decision)
	}
}

func TestCleanupRemovesUserForeignHooksAndBacksUp(t *testing.T) {
	req := guardRequest(t, "cursor", config.ForeignHooksRemove)
	userHooks := filepath.Join(req.Home, ".cursor", "hooks.json")
	original := `{"version": 1, "hooks": {"preToolUse": [` + ownedCursorEntry + `, {"command": "./rewrite.sh"}], "stop": [{"command": "./only-foreign.sh"}]}}`
	writeFile(t, userHooks, original)
	projectHooks := filepath.Join(req.WorkingDir, "..", ".cursor", "hooks.json")
	projectBody := `{"version": 1, "hooks": {"preToolUse": [{"command": "./project.sh"}]}}`
	writeFile(t, projectHooks, projectBody)

	result, err := CleanUserForeignHooks(req, time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Removed) != 2 || result.BackupDir == "" {
		t.Fatalf("cleanup result: %+v", result)
	}
	cleaned := readFile(t, userHooks)
	if strings.Contains(cleaned, "rewrite.sh") || strings.Contains(cleaned, `"stop"`) || !strings.Contains(cleaned, "--connector cursor --enterprise-managed") {
		t.Fatalf("user hooks after cleanup:\n%s", cleaned)
	}
	backups, _ := filepath.Glob(filepath.Join(result.BackupDir, "*-hooks.json"))
	if len(backups) != 1 || readFile(t, backups[0]) != original {
		t.Fatalf("original must be backed up verbatim: %v", backups)
	}
	if readFile(t, projectHooks) != projectBody {
		t.Fatal("project hook files must never be rewritten")
	}
	if decision := EvaluateForeignHooks(req); !decision.Deny || decision.Findings[0].Scope != ScopeProject {
		t.Fatalf("the remaining project hook still denies: %+v", decision)
	}

	report := req
	report.Policy.ForeignHooks = config.ForeignHooksReport
	writeFile(t, userHooks, original)
	if result, _ := CleanUserForeignHooks(report, time.Now()); len(result.Removed) != 0 || readFile(t, userHooks) != original {
		t.Fatal("report mode must not modify user files")
	}
}

func TestPublicPolicyGuardFlags(t *testing.T) {
	opts := testOptions(t)
	opts = withPolicy(opts, "claudecode", func(p *config.EnterpriseConnectorPolicy) { p.ManagedHooksOnly = "preserve" })
	opts = withPolicy(opts, "copilot", func(p *config.EnterpriseConnectorPolicy) { p.ForeignHooks = "allow" })
	summary := BuildPublicPolicy(opts, []string{"codex", "claudecode", "cursor", "copilot", "antigravity", "opencode"})
	want := map[string]bool{"codex": false, "claudecode": true, "cursor": true, "copilot": false, "antigravity": false, "opencode": true}
	for name, guard := range want {
		if summary.Connectors[name].Guard != guard {
			t.Errorf("%s guard = %v, want %v", name, summary.Connectors[name].Guard, guard)
		}
	}
	data, err := MarshalPublicPolicy(summary)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParsePublicPolicy(data)
	if err != nil || parsed.HookBinary != testHookBinary {
		t.Fatalf("round trip: %v %+v", err, parsed)
	}
	for _, bad := range []string{`{"schema_version": 2, "connectors": {}}`, `{"schema_version": 1, "hook_binary": "/x", "connectors": {}, "token": "x"}`, `{"schema_version": 1, "hook_binary": "/x", "connectors": {"cursor": {"foreign_hooks": "maybe"}}}`} {
		if _, err := ParsePublicPolicy([]byte(bad)); err == nil {
			t.Errorf("ParsePublicPolicy accepted %s", bad)
		}
	}
}

// OpenCode's managed config naming the trusted managed plugin moves OpenCode
// onto machine policy; the summary the hook-time guard reads must say so, or
// the guard would keep exempting the per-user plugin and per-user commands.
func TestPublicPolicyReportsTheOpenCodeMachinePolicyRoute(t *testing.T) {
	opts := publishTestOptions(t)
	if route := BuildPublicPolicy(opts, []string{"opencode"}).Connectors["opencode"].Route; route != RoutePerUser {
		t.Fatalf("without the artifact OpenCode is per-user, got %s", route)
	}
	installTestOpenCodePlugin(t, &opts)
	if route := BuildPublicPolicy(opts, []string{"opencode"}).Connectors["opencode"].Route; route != RoutePerUser {
		t.Fatalf("until the managed config names the installed plugin OpenCode is per-user, got %s", route)
	}
	if _, err := Publish(opts, []string{"opencode"}); err != nil {
		t.Fatal(err)
	}
	if route := BuildPublicPolicy(opts, []string{"opencode"}).Connectors["opencode"].Route; route != RouteMachinePolicy {
		t.Fatalf("with the published plugin the summary must report machine policy, got %s", route)
	}
	policy := writtenOpenCodeSummary(t, opts)
	if policy.Route != RouteMachinePolicy {
		t.Fatalf("written summary route %s, want machine policy", policy.Route)
	}
	if decision := EvaluateForeignHooks(perUserOpenCodeGuardRequest(t, policy)); !decision.Deny {
		t.Fatalf("on machine policy the per-user DefenseClaw plugin is foreign: %+v", decision)
	}
}

// Every deployment installs the managed OpenCode plugin file, so the file
// alone must not move the summary onto machine policy. With ownership: off,
// or when DefenseClaw cannot merge the administrator's managed config,
// OpenCode still loads the per-user plugin (reconcile, verify and the
// descriptor say per-user). A machine-policy summary there would make the
// per-user plugin's guard deny every OpenCode tool call on DefenseClaw's own
// plugin and make cleanup move it aside every cycle.
func TestPublicPolicyKeepsOpenCodePerUserUntilItsManagedConfigNamesThePlugin(t *testing.T) {
	ownershipOff := func(p *config.EnterpriseConnectorPolicy) { p.Ownership = config.MachinePolicyOwnershipOff }
	for name, setup := range map[string]func(*testing.T, *Options){
		"ownership off": func(t *testing.T, opts *Options) {
			*opts = withPolicy(*opts, "opencode", ownershipOff)
		},
		"unmergeable managed config": func(t *testing.T, opts *Options) {
			writeFile(t, rooted(*opts, "/etc/opencode/opencode.jsonc"), "// administrator note\n{\"plugin\": []}\n")
		},
	} {
		t.Run(name, func(t *testing.T) {
			opts := publishTestOptions(t)
			installTestOpenCodePlugin(t, &opts)
			setup(t, &opts)
			result, _ := Publish(opts, []string{"opencode"})
			if len(result.MachinePolicyConnectors) != 0 {
				t.Fatalf("OpenCode must not be published here: %+v", result)
			}
			policy := writtenOpenCodeSummary(t, opts)
			if policy.Route != RoutePerUser || !policy.Guard {
				t.Fatalf("written summary %+v, want the guarded per-user route", policy)
			}
			if decision := EvaluateForeignHooks(perUserOpenCodeGuardRequest(t, policy)); decision.Deny {
				t.Fatalf("the per-user DefenseClaw plugin must stay DefenseClaw's: %+v", decision)
			}
		})
	}
}

// writtenOpenCodeSummary reads OpenCode's entry of the summary Publish wrote.
func writtenOpenCodeSummary(t *testing.T, opts Options) PublicConnectorPolicy {
	t.Helper()
	parsed, err := ParsePublicPolicy([]byte(readFile(t, opts.PublicPolicyPath)))
	if err != nil {
		t.Fatal(err)
	}
	policy, ok := parsed.Connectors["opencode"]
	if !ok {
		t.Fatalf("summary has no OpenCode entry: %+v", parsed)
	}
	return policy
}

// perUserOpenCodeGuardRequest is the guard request of a user whose only
// OpenCode plugin is the per-user DefenseClaw plugin the guardian installs.
func perUserOpenCodeGuardRequest(t *testing.T, policy PublicConnectorPolicy) GuardRequest {
	t.Helper()
	req := guardRequest(t, "opencode", policy.ForeignHooks)
	req.Policy = policy
	req.AccountHome = req.Home
	writeFile(t, filepath.Join(req.Home, ".config", "opencode", "plugins", "defenseclaw.js"), "// DefenseClaw")
	return req
}

// Agents resolve project config up to the repository root however deep
// the working directory is; the walk must reach it or fail closed.
func TestGuardWalksToTheRepositoryRootAtAnyDepth(t *testing.T) {
	req := guardRequest(t, "copilot", config.ForeignHooksRemove)
	root := filepath.Dir(req.WorkingDir)
	writeFile(t, filepath.Join(root, ".github", "hooks", "rewrite.json"), `{"version": 1, "hooks": {"preToolUse": [{"type": "command", "bash": "./rewrite.sh"}]}}`)
	deep := root
	for i := 0; i < 13; i++ {
		deep = filepath.Join(deep, string(rune('a'+i)))
	}
	if err := os.MkdirAll(deep, 0o755); err != nil {
		t.Fatal(err)
	}
	req.WorkingDir = deep
	if decision := EvaluateForeignHooks(req); !decision.Deny || !strings.Contains(decision.Reason, "rewrite.json") {
		t.Fatalf("a hook at the repository root 13 levels up must deny: %+v", decision)
	}

	tooDeep := t.TempDir()
	for i := 0; i <= maxProjectWalk; i++ {
		tooDeep = filepath.Join(tooDeep, "d")
	}
	if err := os.MkdirAll(tooDeep, 0o755); err != nil {
		t.Fatal(err)
	}
	unbounded := guardRequest(t, "copilot", config.ForeignHooksRemove)
	unbounded.WorkingDir = tooDeep
	if decision := EvaluateForeignHooks(unbounded); !decision.Deny || !strings.Contains(decision.Reason, "cannot be verified") {
		t.Fatalf("a walk past the bound must fail closed: %+v", decision)
	}
}

// An agent started in the home directory (or under it outside any
// repository) loads the home's project-scoped files: ~/.devin, ~/.github,
// ~/.claude/settings.local.json. A path that is also a user source is
// reported once, as a user source.
func TestGuardScansTheHomeDirectoryAsAProject(t *testing.T) {
	devin := guardRequest(t, "devin", config.ForeignHooksRemove)
	devin.WorkingDir = devin.Home
	writeFile(t, filepath.Join(devin.Home, ".devin", "hooks.v1.json"), `{"PreToolUse": [{"matcher": "*", "hooks": [{"type": "command", "command": "./x.sh"}]}]}`)
	if decision := EvaluateForeignHooks(devin); !decision.Deny || decision.Findings[0].Scope != ScopeProject {
		t.Fatalf("cwd == home must scan ~/.devin/hooks.v1.json: %+v", decision)
	}

	copilot := guardRequest(t, "copilot", config.ForeignHooksRemove)
	copilot.WorkingDir = filepath.Join(copilot.Home, "scratch")
	if err := os.MkdirAll(copilot.WorkingDir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(copilot.Home, ".github", "hooks", "x.json"), `{"version": 1, "hooks": {"preToolUse": [{"bash": "./x"}]}}`)
	if decision := EvaluateForeignHooks(copilot); !decision.Deny {
		t.Fatalf("a walk that reaches home must scan ~/.github/hooks: %+v", decision)
	}

	cursor := guardRequest(t, "cursor", config.ForeignHooksRemove)
	cursor.WorkingDir = cursor.Home
	writeFile(t, filepath.Join(cursor.Home, ".cursor", "hooks.json"), `{"version": 1, "hooks": {"preToolUse": [{"command": "./rewrite.sh"}]}}`)
	decision := EvaluateForeignHooks(cursor)
	if !decision.Deny || len(decision.Findings) != 1 || decision.Findings[0].Scope != ScopeUser {
		t.Fatalf("~/.cursor/hooks.json is a user source even when the agent runs in home: %+v", decision)
	}
}

// Agents locate the repository root from the resolved working directory,
// so a symlink into another tree must not hide that tree's root hooks.
func TestGuardWalksTheResolvedWorkingDirectory(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation needs a privilege on windows")
	}
	req := guardRequest(t, "cursor", config.ForeignHooksRemove)
	repo := filepath.Join(t.TempDir(), "repo")
	if err := os.MkdirAll(filepath.Join(repo, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(repo, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(repo, ".cursor", "hooks.json"), `{"version": 1, "hooks": {"preToolUse": [{"command": "./rewrite.sh"}]}}`)
	link := filepath.Join(req.Home, "link")
	if err := os.Symlink(filepath.Join(repo, "sub"), link); err != nil {
		t.Fatal(err)
	}
	req.WorkingDir = link
	if decision := EvaluateForeignHooks(req); !decision.Deny || !strings.Contains(decision.Reason, repo) {
		t.Fatalf("the resolved repository root must be scanned: %+v", decision)
	}
}

// Standard users can create C:\.cursor and the like in a Windows drive
// root, so on Windows the walk includes the volume root; a Unix / is
// root-owned and stays out.
func TestGuardProjectWalkIncludesTheWindowsVolumeRoot(t *testing.T) {
	root := filepath.VolumeName(t.TempDir()) + string(filepath.Separator)
	if dirs, err := projectDirs(root, nil, true); err != nil || len(dirs) != 1 || dirs[0] != root {
		t.Fatalf("a walk started at the volume root must scan it on windows: %v %v", dirs, err)
	}
	if dirs, err := projectDirs(root, nil, false); err != nil || len(dirs) != 0 {
		t.Fatalf("the unix walk never scans /: %v %v", dirs, err)
	}
	below := filepath.Join(root, "dc-guard-no-such-dir", "work")
	dirs, err := projectDirs(below, nil, true)
	if err != nil || len(dirs) == 0 || dirs[len(dirs)-1] != root {
		t.Fatalf("a walk that reaches the volume root must scan it on windows: %v %v", dirs, err)
	}

	req := guardRequest(t, "cursor", config.ForeignHooksRemove)
	req.GOOS = "windows"
	req.WorkingDir = root
	want := filepath.Join(root, ".cursor", "hooks.json")
	found := false
	for _, source := range guardSources(req) {
		if source.scope == ScopeProject && samePath(source.path, want) {
			found = true
		}
	}
	if !found {
		t.Fatalf("an agent started in the volume root must have %s scanned", want)
	}
}

// The scan runs inside the agent's hook timeout, which several agents
// treat as allow. A flooded tree must hit a budget and fail closed.
func TestGuardScanBudgetsFailClosed(t *testing.T) {
	req := guardRequest(t, "copilot", config.ForeignHooksRemove)
	flooded := filepath.Join(req.WorkingDir, "..", ".github", "hooks")
	for i := 0; i <= guardDirEntryLimit; i++ {
		writeFile(t, filepath.Join(flooded, fmt.Sprintf("f%03d.json", i)), `{"version": 1}`)
	}
	if decision := EvaluateForeignHooks(req); !decision.Deny || !strings.Contains(decision.Reason, "more than 256 entries") {
		t.Fatalf("a directory over the entry budget must fail closed: %+v", decision)
	}

	req = guardRequest(t, "copilot", config.ForeignHooksRemove)
	for _, dir := range []string{filepath.Join(req.Home, ".copilot", "hooks"), filepath.Join(req.WorkingDir, ".github", "hooks"), filepath.Join(req.WorkingDir, "..", ".github", "hooks")} {
		for i := 0; i < 200; i++ {
			writeFile(t, filepath.Join(dir, fmt.Sprintf("f%03d.json", i)), `{"version": 1}`)
		}
	}
	if err := os.MkdirAll(req.WorkingDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if decision := EvaluateForeignHooks(req); !decision.Deny || !strings.Contains(decision.Reason, "more than 512 files") {
		t.Fatalf("a scan over the file budget must fail closed: %+v", decision)
	}

	req = guardRequest(t, "cursor", config.ForeignHooksRemove)
	req.Deadline = time.Now().Add(-time.Second)
	writeFile(t, filepath.Join(req.Home, ".cursor", "hooks.json"), `{"version": 1, "hooks": {}}`)
	if decision := EvaluateForeignHooks(req); !decision.Deny || !strings.Contains(decision.Reason, "time limit") {
		t.Fatalf("a scan past its deadline must fail closed: %+v", decision)
	}
}

// Every home and working directory is scanned in one pass: a path is read
// once however many homes and directories name it, and the hook's
// evaluation stops at the first unapproved finding.
func TestGuardScansEachPathOnceAndStopsAtFirstFinding(t *testing.T) {
	req := guardRequest(t, "cursor", config.ForeignHooksRemove)
	writeFile(t, filepath.Join(req.Home, ".cursor", "hooks.json"), `{"version": 1, "hooks": {}}`)
	writeFile(t, filepath.Join(req.WorkingDir, "..", ".cursor", "hooks.json"), `{"version": 1, "hooks": {}}`)
	if err := os.MkdirAll(req.WorkingDir, 0o755); err != nil {
		t.Fatal(err)
	}
	single := newGuardScan(req)
	single.scan(false)
	req.Homes = []string{req.Home, req.Home + string(filepath.Separator)}
	req.WorkingDirs = []string{req.WorkingDir, filepath.Dir(req.WorkingDir)}
	merged := newGuardScan(req)
	merged.scan(false)
	if merged.files != single.files || single.files != 2 {
		t.Fatalf("each path must be read once: single=%d merged=%d", single.files, merged.files)
	}

	writeFile(t, filepath.Join(req.Home, ".cursor", "hooks.json"), `{"version": 1, "hooks": {"preToolUse": [{"command": "./a.sh"}]}}`)
	writeFile(t, filepath.Join(req.WorkingDir, "..", ".cursor", "hooks.json"), `{"version": 1, "hooks": {"preToolUse": [{"command": "./b.sh"}]}}`)
	if full := EvaluateForeignHooks(req); len(full.Findings) != 2 || !strings.Contains(full.Reason, "and 1 more") {
		t.Fatalf("a full scan reports every finding: %+v", full)
	}
	req.StopAtFirstBlocking = true
	if quick := EvaluateForeignHooks(req); !quick.Deny || len(quick.Findings) != 1 || strings.Contains(quick.Reason, "more") {
		t.Fatalf("the hook's scan stops at the first finding: %+v", quick)
	}
}

// An approval must cover what runs. The same handler text in another
// repository, or an edited script behind an approved handler, gets a
// different digest and is blocked again.
func TestGuardApprovalCoversTheReferencedScript(t *testing.T) {
	req := guardRequest(t, "cursor", config.ForeignHooksRemove)
	repo := filepath.Dir(req.WorkingDir)
	handler := `{"version": 1, "hooks": {"preToolUse": [{"type": "command", "command": "./scripts/pre-tool.sh"}]}}`
	writeFile(t, filepath.Join(repo, ".cursor", "hooks.json"), handler)
	writeFile(t, filepath.Join(repo, "scripts", "pre-tool.sh"), "#!/bin/sh\necho reviewed\n")
	first := EvaluateForeignHooks(req)
	if !first.Deny || len(first.Findings) != 1 {
		t.Fatalf("unapproved project hook: %+v", first)
	}
	req.Policy.AllowedHooks = []string{first.Findings[0].Digest}
	if decision := EvaluateForeignHooks(req); decision.Deny {
		t.Fatalf("the reviewed hook is approved: %+v", decision)
	}
	writeFile(t, filepath.Join(repo, "scripts", "pre-tool.sh"), "#!/bin/sh\necho changed\n")
	if decision := EvaluateForeignHooks(req); !decision.Deny {
		t.Fatalf("an edited script behind an approved handler must deny: %+v", decision)
	}

	other := guardRequest(t, "cursor", config.ForeignHooksRemove)
	other.Policy.AllowedHooks = req.Policy.AllowedHooks
	otherRepo := filepath.Dir(other.WorkingDir)
	writeFile(t, filepath.Join(otherRepo, ".cursor", "hooks.json"), handler)
	writeFile(t, filepath.Join(otherRepo, "scripts", "pre-tool.sh"), "#!/bin/sh\necho reviewed\n")
	if decision := EvaluateForeignHooks(other); decision.Deny {
		t.Fatalf("an identical hook and script in another clone is the same approval: %+v", decision)
	}
	writeFile(t, filepath.Join(otherRepo, "scripts", "pre-tool.sh"), "#!/bin/sh\necho different\n")
	if decision := EvaluateForeignHooks(other); !decision.Deny {
		t.Fatalf("another repository's different script must not reuse the approval: %+v", decision)
	}

	claude := guardRequest(t, "claudecode", config.ForeignHooksRemove)
	claudeRepo := filepath.Dir(claude.WorkingDir)
	writeFile(t, filepath.Join(claudeRepo, ".claude", "settings.json"), `{"hooks": {"PreToolUse": [{"matcher": "*", "hooks": [{"type": "command", "command": "\"$CLAUDE_PROJECT_DIR\"/hooks/check.sh"}]}]}}`)
	writeFile(t, filepath.Join(claudeRepo, "hooks", "check.sh"), "one")
	before := EvaluateForeignHooks(claude)
	if len(before.Findings) != 1 || strings.HasPrefix(before.Findings[0].Reason, "cannot verify") {
		t.Fatalf("the Claude project hook must be a reviewable finding: %+v", before)
	}
	writeFile(t, filepath.Join(claudeRepo, "hooks", "check.sh"), "two")
	if after := EvaluateForeignHooks(claude); after.Findings[0].Digest == before.Findings[0].Digest {
		t.Fatal("a script named through $CLAUDE_PROJECT_DIR must be part of the digest")
	}
}

// A plugin directory is approved by its content, not its name.
func TestGuardApprovalCoversPluginDirectoryContent(t *testing.T) {
	req := guardRequest(t, "opencode", config.ForeignHooksRemove)
	plugin := filepath.Join(filepath.Dir(req.WorkingDir), ".opencode", "plugins", "helper")
	writeFile(t, filepath.Join(plugin, "index.ts"), "export default {}")
	first := EvaluateForeignHooks(req)
	if !first.Deny || len(first.Findings) != 1 || first.Findings[0].Reason != "plugin directory" {
		t.Fatalf("a project plugin directory must deny: %+v", first)
	}
	req.Policy.AllowedHooks = []string{first.Findings[0].Digest}
	if decision := EvaluateForeignHooks(req); decision.Deny {
		t.Fatalf("the reviewed directory is approved: %+v", decision)
	}
	writeFile(t, filepath.Join(plugin, "lib", "rewrite.ts"), "export const x = 1")
	if decision := EvaluateForeignHooks(req); !decision.Deny {
		t.Fatalf("a changed plugin directory must deny: %+v", decision)
	}
}

// "This path could not be read" is not a reviewable hook.
func TestGuardUnverifiableFindingsAreNeverApproved(t *testing.T) {
	req := guardRequest(t, "cursor", config.ForeignHooksRemove)
	path := filepath.Join(filepath.Dir(req.WorkingDir), ".cursor", "hooks.json")
	writeFile(t, path, `{not json`)
	first := EvaluateForeignHooks(req)
	if !first.Deny || !strings.Contains(first.Reason, "cannot be verified") {
		t.Fatalf("an unreadable hook file must deny: %+v", first)
	}
	req.Policy.AllowedHooks = []string{first.Findings[0].Digest}
	if decision := EvaluateForeignHooks(req); !decision.Deny {
		t.Fatalf("an unverifiable finding must not be approvable: %+v", decision)
	}
}

// Only the per-user plugin the guardian installs, at its exact path and on
// a per-user route, is DefenseClaw's. The same file name in a project, in
// another user directory, or behind a plugin-list entry is foreign.
func TestGuardExemptsOnlyTheInstalledPerUserPlugin(t *testing.T) {
	req := guardRequest(t, "opencode", config.ForeignHooksRemove)
	req.AccountHome = req.Home
	userPlugins := filepath.Join(req.Home, ".config", "opencode", "plugins")
	writeFile(t, filepath.Join(userPlugins, "defenseclaw.js"), "// DefenseClaw")
	if decision := EvaluateForeignHooks(req); decision.Deny {
		t.Fatalf("the installed per-user plugin is DefenseClaw's: %+v", decision)
	}
	repo := filepath.Dir(req.WorkingDir)
	for name, path := range map[string]string{
		"project plugin":            filepath.Join(repo, ".opencode", "plugins", "defenseclaw.ts"),
		"same name, other ext":      filepath.Join(userPlugins, "defenseclaw.mjs"),
		"singular plugin directory": filepath.Join(req.Home, ".config", "opencode", "plugin", "defenseclaw.js"),
	} {
		writeFile(t, path, "export default {}")
		if decision := EvaluateForeignHooks(req); !decision.Deny || !strings.Contains(decision.Reason, path) {
			t.Fatalf("%s: %s must be foreign: %+v", name, path, decision)
		}
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
	}
	configPath := filepath.Join(req.Home, ".config", "opencode", "opencode.json")
	writeFile(t, configPath, `{"plugin": ["file:///home/alice/x/defenseclaw.js"]}`)
	if decision := EvaluateForeignHooks(req); !decision.Deny {
		t.Fatalf("a plugin-list entry naming another defenseclaw.js must be foreign: %+v", decision)
	}
	writeFile(t, configPath, `{"plugin": ["file://`+filepath.ToSlash(filepath.Join(userPlugins, "defenseclaw.js"))+`"]}`)
	if decision := EvaluateForeignHooks(req); decision.Deny {
		t.Fatalf("a plugin-list entry naming the installed plugin is DefenseClaw's: %+v", decision)
	}

	machine := req
	machine.Policy.Route = RouteMachinePolicy
	if decision := EvaluateForeignHooks(machine); !decision.Deny {
		t.Fatalf("on a machine-policy route a per-user DefenseClaw plugin is foreign: %+v", decision)
	}

	amp := guardRequest(t, "amp", config.ForeignHooksRemove)
	amp.AccountHome = amp.Home
	writeFile(t, filepath.Join(amp.Home, ".config", "amp", "plugins", "defenseclaw.ts"), "// DefenseClaw")
	if decision := EvaluateForeignHooks(amp); decision.Deny {
		t.Fatalf("the installed Amp plugin is DefenseClaw's: %+v", decision)
	}
	projectAmp := filepath.Join(filepath.Dir(amp.WorkingDir), ".amp", "plugins", "defenseclaw.ts")
	writeFile(t, projectAmp, "export default function () {}")
	if decision := EvaluateForeignHooks(amp); !decision.Deny || !strings.Contains(decision.Reason, projectAmp) {
		t.Fatalf("a project defenseclaw.ts must be foreign: %+v", decision)
	}

	cleanup := guardRequest(t, "opencode", config.ForeignHooksRemove)
	cleanup.AccountHome = cleanup.Home
	cleanupPlugins := filepath.Join(cleanup.Home, ".config", "opencode", "plugins")
	writeFile(t, filepath.Join(cleanupPlugins, "defenseclaw.js"), "// DefenseClaw")
	writeFile(t, filepath.Join(cleanupPlugins, "defenseclaw.mjs"), "export default {}")
	result, err := CleanUserForeignHooks(cleanup, time.Now())
	if err != nil || len(result.Removed) != 1 || !strings.HasSuffix(result.Removed[0].Path, "defenseclaw.mjs") {
		t.Fatalf("cleanup must move aside only the foreign same-named plugin: %+v %v", result, err)
	}
	if _, err := os.Stat(filepath.Join(cleanupPlugins, "defenseclaw.js")); err != nil {
		t.Fatalf("the installed plugin must stay: %v", err)
	}
}

// OpenCode loads plugins from opencode.jsonc and the legacy config.json,
// from OPENCODE_CONFIG_DIR like a .opencode directory, and from
// OPENCODE_CONFIG_CONTENT; project .opencode may carry its own config.
func TestGuardCoversOpenCodeConfigLocations(t *testing.T) {
	plugin := `{
  // a JSONC comment
  "plugin": ["file:///srv/rewrite.js",],
}`
	for name, locate := range map[string]func(req GuardRequest) (map[string]string, string){
		"global opencode.jsonc": func(req GuardRequest) (map[string]string, string) {
			return nil, filepath.Join(req.Home, ".config", "opencode", "opencode.jsonc")
		},
		"legacy config.json": func(req GuardRequest) (map[string]string, string) {
			return nil, filepath.Join(req.Home, ".config", "opencode", "config.json")
		},
		"project .opencode config": func(req GuardRequest) (map[string]string, string) {
			return nil, filepath.Join(filepath.Dir(req.WorkingDir), ".opencode", "opencode.jsonc")
		},
		"relative OPENCODE_CONFIG": func(req GuardRequest) (map[string]string, string) {
			return map[string]string{"OPENCODE_CONFIG": "cfg/oc.json"}, filepath.Join(req.WorkingDir, "cfg", "oc.json")
		},
		"OPENCODE_CONFIG_DIR config": func(req GuardRequest) (map[string]string, string) {
			dir := filepath.Join(req.Home, ".oc")
			return map[string]string{"OPENCODE_CONFIG_DIR": dir}, filepath.Join(dir, "opencode.json")
		},
	} {
		req := guardRequest(t, "opencode", config.ForeignHooksRemove)
		env, path := locate(req)
		req.Getenv = func(key string) string { return env[key] }
		writeFile(t, path, plugin)
		if decision := EvaluateForeignHooks(req); !decision.Deny || !strings.Contains(decision.Reason, path) || strings.Contains(decision.Reason, "cannot be verified") {
			t.Fatalf("%s: a plugin listed in %s must deny as a reviewable finding: %+v", name, path, decision)
		}
	}

	req := guardRequest(t, "opencode", config.ForeignHooksRemove)
	dir := filepath.Join(req.Home, ".oc")
	req.Getenv = func(key string) string {
		if key == "OPENCODE_CONFIG_DIR" {
			return dir
		}
		return ""
	}
	writeFile(t, filepath.Join(dir, "plugins", "x.ts"), "export default {}")
	if decision := EvaluateForeignHooks(req); !decision.Deny || !strings.Contains(decision.Reason, filepath.Join(dir, "plugins", "x.ts")) {
		t.Fatalf("OPENCODE_CONFIG_DIR/plugins must be scanned: %+v", decision)
	}

	inline := guardRequest(t, "opencode", config.ForeignHooksRemove)
	inline.Getenv = func(key string) string {
		if key == "OPENCODE_CONFIG_CONTENT" {
			return `{"plugin": ["file:///srv/rewrite.js"]}`
		}
		return ""
	}
	if decision := EvaluateForeignHooks(inline); !decision.Deny || !strings.Contains(decision.Reason, "OPENCODE_CONFIG_CONTENT") {
		t.Fatalf("a plugin in OPENCODE_CONFIG_CONTENT must deny: %+v", decision)
	}
	inline.Getenv = func(key string) string {
		if key == "OPENCODE_CONFIG_CONTENT" {
			return `{"plugin": []}`
		}
		return ""
	}
	if decision := EvaluateForeignHooks(inline); decision.Deny {
		t.Fatalf("OPENCODE_CONFIG_CONTENT without plugins allows: %+v", decision)
	}
	inline.Getenv = func(key string) string {
		if key == "OPENCODE_CONFIG_CONTENT" {
			return `{"plugin": [`
		}
		return ""
	}
	if decision := EvaluateForeignHooks(inline); !decision.Deny || !strings.Contains(decision.Reason, "cannot be verified") {
		t.Fatalf("an unparsable OPENCODE_CONFIG_CONTENT must fail closed: %+v", decision)
	}
}

// Devin reads user hooks from ~/.claude.json too. Claude Code owns that
// file, so the guardian reports instead of rewriting it; a JSONC file with
// comments is also reported, never re-rendered without them.
func TestGuardCoversDevinClaudeJSONAndKeepsForeignOwnedFiles(t *testing.T) {
	req := guardRequest(t, "devin", config.ForeignHooksRemove)
	claudeJSON := filepath.Join(req.Home, ".claude.json")
	body := `{"numStartups": 3, "hooks": {"PreToolUse": [{"matcher": "*", "hooks": [{"type": "command", "command": "./rewrite.sh"}]}]}}`
	writeFile(t, claudeJSON, body)
	if decision := EvaluateForeignHooks(req); !decision.Deny || !strings.Contains(decision.Reason, claudeJSON) {
		t.Fatalf("~/.claude.json hooks must deny for Devin: %+v", decision)
	}
	result, err := CleanUserForeignHooks(req, time.Now())
	if err != nil || len(result.Removed) != 0 || len(result.Reported) != 1 || readFile(t, claudeJSON) != body {
		t.Fatalf("~/.claude.json must be reported and left unchanged: %+v %v", result, err)
	}

	jsonc := filepath.Join(req.Home, ".config", "devin", "config.json")
	withComment := "{\n  // keep me\n  \"hooks\": {\"PreToolUse\": [{\"matcher\": \"*\", \"hooks\": [{\"type\": \"command\", \"command\": \"./x.sh\"}]}]}\n}\n"
	writeFile(t, jsonc, withComment)
	result, err = CleanUserForeignHooks(req, time.Now())
	if err != nil || len(result.Removed) != 0 || readFile(t, jsonc) != withComment {
		t.Fatalf("a JSONC user file must be reported, not rewritten without its comments: %+v %v", result, err)
	}
}

// The guardian's cleanup has no user environment; on Windows it must still
// find Devin's config under the profile's default roaming folder.
func TestGuardFindsDevinWindowsConfigWithoutAPPDATA(t *testing.T) {
	req := guardRequest(t, "devin", config.ForeignHooksRemove)
	req.GOOS = "windows"
	path := filepath.Join(req.Home, "AppData", "Roaming", "devin", "config.json")
	writeFile(t, path, `{"hooks": {"PreToolUse": [{"matcher": "*", "hooks": [{"type": "command", "command": "./x.sh"}]}]}}`)
	result, err := CleanUserForeignHooks(req, time.Now())
	if err != nil || len(result.Removed) != 1 || result.Removed[0].Path != path {
		t.Fatalf("the default roaming Devin config must be cleaned without APPDATA: %+v %v", result, err)
	}
}

// Block records are advisory and user-writable: bounded, one line per
// field set, summarized per file and digest, taken on collection, and
// never written through a link.
func TestForeignHookBlockRecordsRoundTrip(t *testing.T) {
	home := t.TempDir()
	deny := func(path, digest string) GuardDecision {
		return GuardDecision{Deny: true, Findings: []Finding{{Connector: "cursor", Scope: ScopeProject, Path: path, Digest: digest}}}
	}
	now := time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)
	for i, decision := range []GuardDecision{deny("/r/a.json", "aa"), deny("/r/a.json", "aa"), deny("/r/b.json\nx", "bb"), {Deny: false}} {
		if err := RecordForeignHookBlock(home, "cursor", "preToolUse", decision, now.Add(time.Duration(i)*time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	blocks, dropped, err := CollectForeignHookBlocks(home, now)
	if err != nil || dropped != 0 || len(blocks) != 2 {
		t.Fatalf("collect: %+v %d %v", blocks, dropped, err)
	}
	if blocks[0].Path != "/r/a.json" || blocks[0].Count != 2 || blocks[1].Path != "/r/b.json x" {
		t.Fatalf("summaries: %+v", blocks)
	}
	if again, _, _ := CollectForeignHookBlocks(home, now); len(again) != 0 {
		t.Fatalf("records are taken once: %+v", again)
	}

	for i := 0; i < 4000; i++ {
		if err := RecordForeignHookBlock(home, "cursor", "preToolUse", deny("/r/a.json", "aa"), now); err != nil {
			t.Fatal(err)
		}
	}
	if info, err := os.Stat(BlockRecordPath(home)); err != nil || info.Size() > blockRecordLimit {
		t.Fatalf("the record file must stay capped: %v %v", info, err)
	}

	if runtime.GOOS != "windows" {
		linked := t.TempDir()
		target := filepath.Join(linked, "target")
		writeFile(t, target, "")
		if err := os.MkdirAll(filepath.Join(linked, ".defenseclaw"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, BlockRecordPath(linked)); err != nil {
			t.Fatal(err)
		}
		if err := RecordForeignHookBlock(linked, "cursor", "", deny("/r/a.json", "aa"), now); err == nil {
			t.Fatal("a linked record file must be refused")
		}
		if readFile(t, target) != "" {
			t.Fatal("nothing may be written through the link")
		}
	}
}

// With Claude's managed-hooks-only lock relaxed, a plugin enabled in user
// or project settings runs its own hooks, which can return updatedInput.
func TestGuardScansEnabledClaudePluginHooks(t *testing.T) {
	req := guardRequest(t, "claudecode", config.ForeignHooksRemove)
	root := filepath.Join(req.Home, ".claude", "plugins", "cache", "mkt", "rewriter", "1.0.0")
	registry := filepath.Join(req.Home, ".claude", "plugins", "installed_plugins.json")
	writeFile(t, registry, `{"version": 2, "plugins": {"rewriter@mkt": [{"scope": "user", "installPath": `+jsonString(root)+`, "version": "1.0.0"}], "other@mkt": [{"scope": "user", "installPath": `+jsonString(filepath.Join(req.Home, "missing"))+`}]}}`)
	hooks := filepath.Join(root, "hooks", "hooks.json")
	writeFile(t, hooks, `{"hooks": {"PreToolUse": [{"matcher": "*", "hooks": [{"type": "command", "command": "${CLAUDE_PLUGIN_ROOT}/rewrite.sh"}]}]}}`)
	writeFile(t, filepath.Join(root, "rewrite.sh"), "#!/bin/sh\n")
	settings := filepath.Join(req.Home, ".claude", "settings.json")

	writeFile(t, settings, `{"enabledPlugins": {"rewriter@mkt": false, "other@mkt": true}}`)
	if decision := EvaluateForeignHooks(req); decision.Deny {
		t.Fatalf("a disabled or not-installed plugin cannot run: %+v", decision)
	}
	writeFile(t, settings, `{"enabledPlugins": {"rewriter@mkt": true}}`)
	decision := EvaluateForeignHooks(req)
	if !decision.Deny || !strings.Contains(decision.Reason, hooks) {
		t.Fatalf("an enabled plugin's PreToolUse hook must deny: %+v", decision)
	}
	before := decision.Findings[0].Digest
	writeFile(t, filepath.Join(root, "rewrite.sh"), "#!/bin/sh\necho changed\n")
	if after := EvaluateForeignHooks(req); after.Findings[0].Digest == before {
		t.Fatal("the digest must cover the script under CLAUDE_PLUGIN_ROOT")
	}
	result, err := CleanUserForeignHooks(req, time.Now())
	if err != nil || len(result.Removed) != 0 || len(result.Reported) != 1 || !strings.Contains(readFile(t, settings), "rewriter@mkt") {
		t.Fatalf("plugin hooks are reported, never removed: %+v %v", result, err)
	}

	project := guardRequest(t, "claudecode", config.ForeignHooksRemove)
	projectRoot := filepath.Join(project.Home, "plugins", "inline")
	writeFile(t, filepath.Join(project.Home, ".claude", "plugins", "installed_plugins.json"), `{"version": 1, "plugins": {"inline@local": {"installPath": `+jsonString(projectRoot)+`, "isLocal": true}}}`)
	writeFile(t, filepath.Join(projectRoot, ".claude-plugin", "plugin.json"), `{"name": "inline", "hooks": {"PreToolUse": [{"matcher": "*", "hooks": [{"type": "command", "command": "./x.sh"}]}]}}`)
	writeFile(t, filepath.Join(filepath.Dir(project.WorkingDir), ".claude", "settings.json"), `{"enabledPlugins": {"inline@local": true}}`)
	if decision := EvaluateForeignHooks(project); !decision.Deny || decision.Findings[0].Scope != ScopeProject {
		t.Fatalf("a project-enabled plugin with inline hooks must deny: %+v", decision)
	}

	broken := guardRequest(t, "claudecode", config.ForeignHooksRemove)
	writeFile(t, filepath.Join(broken.Home, ".claude", "plugins", "installed_plugins.json"), `{not json`)
	writeFile(t, filepath.Join(broken.Home, ".claude", "settings.json"), `{"enabledPlugins": {"x@mkt": true}}`)
	if decision := EvaluateForeignHooks(broken); !decision.Deny || !strings.Contains(decision.Reason, "cannot be verified") {
		t.Fatalf("an unreadable plugin registry with enabled plugins must fail closed: %+v", decision)
	}
}

// jsonString renders value as a JSON string literal (Windows paths carry
// backslashes).
func jsonString(value string) string {
	encoded, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return string(encoded)
}

func TestGuardScansClaudeFormatFilesOtherAgentsLoad(t *testing.T) {
	cursor := guardRequest(t, "cursor", config.ForeignHooksRemove)
	writeFile(t, filepath.Join(cursor.Home, ".claude", "settings.json"), foreignClaudeSettings)
	if decision := EvaluateForeignHooks(cursor); !decision.Deny || decision.Findings[0].Scope != ScopeUser {
		t.Fatalf("cursor loads ~/.claude/settings.json: %+v", decision)
	}
	// The Claude Code cleanup removes such a hook first, so its removal is
	// recorded for every agent that loads the file.
	settings := filepath.Join(cursor.Home, ".claude", "settings.json")
	if got := ForeignHookRemovalConnectors(cursor.Home, settings, "claudecode", []string{"claudecode", "codex", "copilot", "cursor", "devin"}); strings.Join(got, ",") != "claudecode,cursor,devin" {
		t.Fatalf("a removal from ~/.claude/settings.json holds %v", got)
	}

	copilot := guardRequest(t, "copilot", config.ForeignHooksRemove)
	writeFile(t, filepath.Join(copilot.Home, ".claude", "settings.json"), foreignClaudeSettings)
	if decision := EvaluateForeignHooks(copilot); decision.Deny || len(decision.Findings) != 0 {
		t.Fatalf("copilot does not load the user Claude settings: %+v", decision)
	}
	writeFile(t, filepath.Join(copilot.WorkingDir, "..", ".claude", "settings.local.json"), foreignClaudeSettings)
	if decision := EvaluateForeignHooks(copilot); !decision.Deny || decision.Findings[0].Scope != ScopeProject {
		t.Fatalf("copilot loads project Claude settings: %+v", decision)
	}

	devin := guardRequest(t, "devin", config.ForeignHooksRemove)
	writeFile(t, filepath.Join(devin.WorkingDir, "..", ".devin", "hooks.v1.json"), `{"PreToolUse": [{"matcher": "*", "hooks": [{"type": "command", "command": "./x.sh"}]}]}`)
	if decision := EvaluateForeignHooks(devin); !decision.Deny {
		t.Fatalf("devin hooks.v1.json is a bare hooks object: %+v", decision)
	}
}

const foreignClaudeSettings = `{"hooks": {"PreToolUse": [{"matcher": "*", "hooks": [{"type": "command", "command": "./rewrite.sh"}]}]}}`
