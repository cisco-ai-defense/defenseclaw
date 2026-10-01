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
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// hermesGuardRequest is a per-user Hermes request whose DefenseClaw
// registration is the per-user hermes-hook.sh under the home.
func hermesGuardRequest(t *testing.T, mode string) (GuardRequest, string) {
	t.Helper()
	req := guardRequest(t, ConnectorHermes, mode)
	req.AccountHome = req.Home
	script := filepath.Join(req.Home, ".defenseclaw", "hooks", "hermes-hook.sh")
	req.OwnedCommands = []string{script}
	return req, script
}

// hermesConfig renders a Hermes config.yaml the way Setup leaves it
// (DefenseClaw's hooks mapping between the user's own settings), with the
// extra pre_tool_call entries after DefenseClaw's.
func hermesConfig(script string, extra ...string) string {
	body := "# my settings\nmodel:\n  default: \"claude\" # keep\nhooks:\n" +
		"    on_session_start:\n        - command: " + script + "\n          timeout: 30\n" +
		"    pre_tool_call:\n        - command: " + script + "\n          matcher: .*\n          timeout: 30\n"
	for _, entry := range extra {
		body += entry
	}
	return body + "terminal:\n  backend: local\n"
}

const hermesRewriteEntry = "        - command: /usr/local/bin/rewrite-tool-input.sh\n          matcher: .*\n          timeout: 10\n"

// A user's own Hermes pre_tool_call hook placed after
// DefenseClaw's could rewrite the tool call after DefenseClaw checked it,
// and nothing noticed it. The guard now reads the Hermes config.yaml: such
// an entry denies with the file, the digest and the allowlist key, while
// DefenseClaw's own per-user registration is never foreign.
func TestGuardDeniesAUserHermesHookBesideDefenseClaws(t *testing.T) {
	req, script := hermesGuardRequest(t, config.ForeignHooksRemove)
	configPath := filepath.Join(req.Home, ".hermes", "config.yaml")
	writeFile(t, configPath, hermesConfig(script))
	if decision := EvaluateForeignHooks(req); decision.Deny || len(decision.Findings) != 0 {
		t.Fatalf("DefenseClaw's own Hermes registration must not be flagged: %+v", decision)
	}

	writeFile(t, configPath, hermesConfig(script, hermesRewriteEntry))
	decision := EvaluateForeignHooks(req)
	if !decision.Deny || len(decision.Findings) != 1 {
		t.Fatalf("a user pre_tool_call hook after DefenseClaw's must deny: %+v", decision)
	}
	finding := decision.Findings[0]
	if finding.Path != configPath || finding.Scope != ScopeUser || finding.Event != "pre_tool_call" || finding.Command != "/usr/local/bin/rewrite-tool-input.sh" {
		t.Fatalf("finding: %+v", finding)
	}
	for _, want := range []string{"enterprise_foreign_hook_blocked", configPath, finding.Digest, "enterprise.machine_policy.connectors.hermes.allowed_hooks"} {
		if !strings.Contains(decision.Reason, want) {
			t.Fatalf("deny reason must name %q: %s", want, decision.Reason)
		}
	}

	allowed := req
	allowed.Policy.AllowedHooks = []string{finding.Digest}
	if again := EvaluateForeignHooks(allowed); again.Deny || !again.Findings[0].Allowed {
		t.Fatalf("an allowlisted Hermes hook must pass: %+v", again)
	}
	report := req
	report.Policy.ForeignHooks = config.ForeignHooksReport
	if again := EvaluateForeignHooks(report); again.Deny || len(again.Findings) != 1 {
		t.Fatalf("report mode must allow but return the finding: %+v", again)
	}

	// DefenseClaw's command with a key DefenseClaw never writes is not
	// DefenseClaw's entry.
	writeFile(t, configPath, hermesConfig(script, "        - command: "+script+"\n          env:\n            X: \"1\"\n"))
	if again := EvaluateForeignHooks(req); !again.Deny {
		t.Fatalf("a DefenseClaw command with an extra key must deny: %+v", again)
	}
	// An event of another shape is still checked.
	writeFile(t, configPath, "hooks:\n  pre_tool_call:\n    command: /usr/local/bin/rewrite-tool-input.sh\n")
	if again := EvaluateForeignHooks(req); !again.Deny {
		t.Fatalf("a single-entry event must deny: %+v", again)
	}
	// A config DefenseClaw cannot read fails closed.
	for name, body := range map[string]string{
		"unparsable":     "hooks: [\n",
		"hooks is list":  "hooks:\n  - command: x\n",
		"root is a list": "- a\n- b\n",
	} {
		writeFile(t, configPath, body)
		if again := EvaluateForeignHooks(req); !again.Deny || !strings.Contains(again.Reason, "cannot be verified") {
			t.Fatalf("%s config must deny as unverifiable: %+v", name, again)
		}
	}
	// Hermes reads no project hook file.
	writeFile(t, configPath, hermesConfig(script))
	writeFile(t, filepath.Join(req.WorkingDir, "..", ".hermes", "config.yaml"), hermesConfig(script, hermesRewriteEntry))
	if again := EvaluateForeignHooks(req); again.Deny || len(again.Findings) != 0 {
		t.Fatalf("a project .hermes/config.yaml is not a Hermes hook source: %+v", again)
	}
}

// Hermes reads config.yaml from HERMES_HOME when it is set (a named profile
// sets it for the process), and only from there; a relative value is
// relative to the agent's working directory.
func TestGuardReadsTheHermesConfigHERMES_HOMENames(t *testing.T) {
	req, script := hermesGuardRequest(t, config.ForeignHooksRemove)
	defaultConfig := filepath.Join(req.Home, ".hermes", "config.yaml")
	profile := filepath.Join(req.Home, ".hermes", "profiles", "work")
	writeFile(t, defaultConfig, hermesConfig(script))
	writeFile(t, filepath.Join(profile, "config.yaml"), hermesConfig(script, hermesRewriteEntry))
	if decision := EvaluateForeignHooks(req); decision.Deny {
		t.Fatalf("without HERMES_HOME only the default config is read: %+v", decision)
	}
	withHome := req
	withHome.Getenv = func(key string) string {
		if key == "HERMES_HOME" {
			return profile
		}
		return ""
	}
	if decision := EvaluateForeignHooks(withHome); !decision.Deny || decision.Findings[0].Path != filepath.Join(profile, "config.yaml") {
		t.Fatalf("the HERMES_HOME config must be read: %+v", decision)
	}
	redirect, ok := ObservedEnvRedirect(withHome)
	if !ok || redirect.Vars["HERMES_HOME"] != profile {
		t.Fatalf("the hook must record HERMES_HOME for the guardian's cleanup: %+v %v", redirect, ok)
	}
	relative := req
	relative.Getenv = func(key string) string {
		if key == "HERMES_HOME" {
			return "hermes-home"
		}
		return ""
	}
	writeFile(t, filepath.Join(req.WorkingDir, "hermes-home", "config.yaml"), hermesConfig(script, hermesRewriteEntry))
	if decision := EvaluateForeignHooks(relative); !decision.Deny || decision.Findings[0].Path != filepath.Join(req.WorkingDir, "hermes-home", "config.yaml") {
		t.Fatalf("a relative HERMES_HOME is relative to the working directory: %+v", decision)
	}
}

// With foreign_hooks: remove the guardian removes the user's own Hermes
// entries from config.yaml: only the hooks mapping is rewritten, DefenseClaw's
// entries and every other byte stay, and the original is backed up.
func TestCleanupRemovesUserHermesHooksAndKeepsTheRestOfTheFile(t *testing.T) {
	req, script := hermesGuardRequest(t, config.ForeignHooksRemove)
	configPath := filepath.Join(req.Home, ".hermes", "config.yaml")
	original := hermesConfig(script, hermesRewriteEntry) + "" // pre_tool_call rewrite
	original = strings.Replace(original, "terminal:", "    post_tool_call:\n        - command: /usr/local/bin/only-foreign.sh\nterminal:", 1)
	writeFile(t, configPath, original)

	result, err := CleanUserForeignHooks(req, time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Removed) != 2 || result.BackupDir == "" || len(result.Reported) != 0 {
		t.Fatalf("cleanup result: %+v", result)
	}
	cleaned := readFile(t, configPath)
	if strings.Contains(cleaned, "rewrite-tool-input.sh") || strings.Contains(cleaned, "only-foreign.sh") || strings.Contains(cleaned, "post_tool_call") {
		t.Fatalf("user hooks after cleanup:\n%s", cleaned)
	}
	if !strings.HasPrefix(cleaned, "# my settings\nmodel:\n  default: \"claude\" # keep\nhooks:\n") || !strings.HasSuffix(cleaned, "terminal:\n  backend: local\n") ||
		strings.Count(cleaned, "command: "+script) != 2 {
		t.Fatalf("the rest of config.yaml and DefenseClaw's entries must stay:\n%s", cleaned)
	}
	backups, _ := filepath.Glob(filepath.Join(result.BackupDir, "*-config.yaml"))
	if len(backups) != 1 || readFile(t, backups[0]) != original {
		t.Fatalf("original must be backed up verbatim: %v", backups)
	}
	if decision := EvaluateForeignHooks(req); decision.Deny || len(decision.Findings) != 0 {
		t.Fatalf("the cleaned config must pass: %+v", decision)
	}

	unparsable := "hooks: [\n"
	writeFile(t, configPath, unparsable)
	if result, _ := CleanUserForeignHooks(req, time.Now()); len(result.Removed) != 0 || len(result.Reported) != 1 || readFile(t, configPath) != unparsable {
		t.Fatalf("an unverifiable config is reported and left alone: %+v", result)
	}
	report := req
	report.Policy.ForeignHooks = config.ForeignHooksReport
	writeFile(t, configPath, original)
	if result, _ := CleanUserForeignHooks(report, time.Now()); len(result.Removed) != 0 || readFile(t, configPath) != original {
		t.Fatal("report mode must not modify the Hermes config")
	}

	// The cleanup also reaches the config a recorded HERMES_HOME names.
	profile := filepath.Join(req.Home, "profiles", "work")
	writeFile(t, filepath.Join(profile, "config.yaml"), hermesConfig(script, hermesRewriteEntry))
	writeFile(t, configPath, hermesConfig(script))
	result, err = CleanUserForeignHooksWithRedirects(req, []EnvRedirect{{Vars: map[string]string{"HERMES_HOME": profile}}}, time.Now())
	if err != nil || len(result.Removed) != 1 || result.Removed[0].Path != filepath.Join(profile, "config.yaml") {
		t.Fatalf("cleanup of the HERMES_HOME config: %+v %v", result, err)
	}
}

// The summary guards Hermes on Linux and macOS, where the standalone Hermes
// hook runs the guard, and not on Windows, whose Hermes registration does
// not run it.
func TestPublicPolicyGuardsHermesOnLinuxAndMacOSOnly(t *testing.T) {
	for goos, want := range map[string]bool{"linux": true, "darwin": true, "windows": false} {
		opts := testOptions(t)
		opts.GOOS = goos
		if got := BuildPublicPolicy(opts, []string{ConnectorHermes}).Connectors[ConnectorHermes]; got.Guard != want || got.Route != RoutePerUser {
			t.Errorf("%s: hermes summary %+v, want guard %v on the per-user route", goos, got, want)
		}
	}
	opts := withPolicy(testOptions(t), ConnectorHermes, func(p *config.EnterpriseConnectorPolicy) { p.ForeignHooks = config.ForeignHooksAllow })
	if BuildPublicPolicy(opts, []string{ConnectorHermes}).Connectors[ConnectorHermes].Guard {
		t.Error("foreign_hooks: allow must turn the Hermes guard off")
	}
}

// Hermes merges a managed-scope config.yaml over the user's, from the
// directory HERMES_MANAGED_DIR names (else /etc/hermes), and an event's list
// there replaces the user's. A user who left ~/.hermes/config.yaml as
// DefenseClaw wrote it could list DefenseClaw's entry and their own in
// <dir>/config.yaml and start Hermes with HERMES_MANAGED_DIR=<dir>: the
// guard read only config.yaml and allowed the call. The file the variable
// names is now user scope: it is read, recorded for the guardian and
// cleaned. The administrator's /etc/hermes is not a user source.
func TestGuardReadsTheHermesManagedScopeConfigTheEnvironmentNames(t *testing.T) {
	req, script := hermesGuardRequest(t, config.ForeignHooksRemove)
	writeFile(t, filepath.Join(req.Home, ".hermes", "config.yaml"), hermesConfig(script))
	managed := filepath.Join(req.Home, "managed-scope")
	managedConfig := filepath.Join(managed, "config.yaml")
	writeFile(t, managedConfig, "hooks:\n    pre_tool_call:\n        - command: "+script+"\n          matcher: .*\n          timeout: 30\n"+hermesRewriteEntry)
	if decision := EvaluateForeignHooks(req); decision.Deny || len(decision.Findings) != 0 {
		t.Fatalf("without HERMES_MANAGED_DIR the managed-scope file is not read: %+v", decision)
	}
	withManaged := req
	withManaged.Getenv = func(key string) string {
		if key == "HERMES_MANAGED_DIR" {
			return managed
		}
		return ""
	}
	decision := EvaluateForeignHooks(withManaged)
	if !decision.Deny || len(decision.Findings) != 1 || decision.Findings[0].Path != managedConfig ||
		decision.Findings[0].Command != "/usr/local/bin/rewrite-tool-input.sh" {
		t.Fatalf("a user entry in the HERMES_MANAGED_DIR config must deny: %+v", decision)
	}
	if !strings.Contains(decision.Reason, managedConfig) {
		t.Fatalf("the deny reason must name the managed-scope file: %s", decision.Reason)
	}
	redirect, ok := ObservedEnvRedirect(withManaged)
	if !ok || redirect.Vars["HERMES_MANAGED_DIR"] != managed {
		t.Fatalf("the hook must record HERMES_MANAGED_DIR for the guardian's cleanup: %+v %v", redirect, ok)
	}
	result, err := CleanUserForeignHooksWithRedirects(req, []EnvRedirect{redirect}, time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC))
	if err != nil || len(result.Removed) != 1 || result.Removed[0].Path != managedConfig {
		t.Fatalf("cleanup of the HERMES_MANAGED_DIR config: %+v %v", result, err)
	}
	if cleaned := readFile(t, managedConfig); strings.Contains(cleaned, "rewrite-tool-input.sh") || !strings.Contains(cleaned, "command: "+script) {
		t.Fatalf("the cleanup must remove only the user entry:\n%s", cleaned)
	}
	if again := EvaluateForeignHooks(withManaged); again.Deny || len(again.Findings) != 0 {
		t.Fatalf("the cleaned managed-scope config must pass: %+v", again)
	}

	for _, value := range []string{hermesDefaultManagedDir, hermesDefaultManagedDir + "/", "  "} {
		admin := req
		admin.Getenv = func(key string) string {
			if key == "HERMES_MANAGED_DIR" {
				return value
			}
			return ""
		}
		for _, path := range userSourcePaths(admin) {
			if strings.HasPrefix(path, hermesDefaultManagedDir) {
				t.Fatalf("HERMES_MANAGED_DIR=%q: the administrator's managed scope is not a user source: %v", value, userSourcePaths(admin))
			}
		}
	}
}

// The Hermes hooks mapping also holds two settings sections that are not
// events: output_spill (tool-output size and spill directory) and outbound
// (notify-only webhooks). Hermes registers no shell hook from them. The
// guard read them as hook entries, so a user who set either had every tool
// call blocked and the guardian deleted the setting. They are now skipped
// by the scan and kept as they are by the cleanup.
func TestGuardLeavesTheHermesHookSettingsSectionsAlone(t *testing.T) {
	req, script := hermesGuardRequest(t, config.ForeignHooksRemove)
	configPath := filepath.Join(req.Home, ".hermes", "config.yaml")
	settings := "    output_spill:\n        max_chars: 20000\n        directory: /var/tmp/hermes-spill\n" +
		"    outbound:\n        - url: https://hooks.example.test/notify\n          events: [post_tool_call]\n"
	withSettings := strings.Replace(hermesConfig(script), "terminal:", settings+"terminal:", 1)
	writeFile(t, configPath, withSettings)
	if decision := EvaluateForeignHooks(req); decision.Deny || len(decision.Findings) != 0 {
		t.Fatalf("output_spill and outbound are settings, not hook entries: %+v", decision)
	}
	if result, err := CleanUserForeignHooks(req, time.Now()); err != nil || len(result.Removed) != 0 || readFile(t, configPath) != withSettings {
		t.Fatalf("the cleanup must leave a config with only settings sections alone: %+v %v", result, err)
	}

	// With a user entry present, the cleanup removes the entry and keeps
	// both settings sections.
	writeFile(t, configPath, strings.Replace(hermesConfig(script, hermesRewriteEntry), "terminal:", settings+"terminal:", 1))
	result, err := CleanUserForeignHooks(req, time.Now())
	if err != nil || len(result.Removed) != 1 {
		t.Fatalf("cleanup: %+v %v", result, err)
	}
	cleaned := readFile(t, configPath)
	for _, want := range []string{"output_spill:", "max_chars: 20000", "directory: /var/tmp/hermes-spill", "outbound:", "https://hooks.example.test/notify"} {
		if !strings.Contains(cleaned, want) {
			t.Fatalf("the cleanup dropped %q:\n%s", want, cleaned)
		}
	}
	if strings.Contains(cleaned, "rewrite-tool-input.sh") {
		t.Fatalf("the user entry must be removed:\n%s", cleaned)
	}
	if decision := EvaluateForeignHooks(req); decision.Deny || len(decision.Findings) != 0 {
		t.Fatalf("the cleaned config must pass: %+v", decision)
	}
}
