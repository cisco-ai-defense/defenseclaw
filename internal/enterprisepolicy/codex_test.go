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
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/pelletier/go-toml/v2"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

func codexPath(t *testing.T, opts Options) string {
	t.Helper()
	path, err := CodexRequirementsPath(opts)
	if err != nil {
		t.Fatal(err)
	}
	return path
}

func TestCodexReconcileFreshIsCoveredAndIdempotent(t *testing.T) {
	opts := testOptions(t)
	state, err := codexTarget{}.Reconcile(opts)
	if err != nil {
		t.Fatal(err)
	}
	mustNoConflicts(t, state)
	if !state.Covered || !state.Changed || state.OwnedEntries != 10 || state.EffectiveLock != config.ManagedHooksOnlyEnforce {
		t.Fatalf("fresh reconcile: %+v", state)
	}
	first := readFile(t, codexPath(t, opts))
	for _, want := range []string{"allow_managed_hooks_only = true", "[features]", "hooks = true", `managed_dir = "/opt/defenseclaw/bin"`, "[[hooks.PreToolUse]]", `command = "'/opt/defenseclaw/bin/defenseclaw-hook' hook --connector codex --enterprise-managed --event PreToolUse --hook-contract codex-hooks-v4"`} {
		if !strings.Contains(first, want) {
			t.Fatalf("rendered requirements missing %q:\n%s", want, first)
		}
	}
	again, err := codexTarget{}.Reconcile(opts)
	if err != nil {
		t.Fatal(err)
	}
	if again.Changed || readFile(t, codexPath(t, opts)) != first {
		t.Fatalf("second reconcile is not a byte-identical no-op")
	}
}

// The unix hook refuses a Codex invocation that does not name its event and
// hook contract (live on RHEL every prompt was blocked), so each managed
// group binds its own event and a contract that registers it.
func TestCodexManagedCommandsBindEventAndContract(t *testing.T) {
	opts := testOptions(t)
	if _, err := (codexTarget{}).Reconcile(opts); err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	if err := toml.Unmarshal([]byte(readFile(t, codexPath(t, opts))), &cfg); err != nil {
		t.Fatal(err)
	}
	hooks, _ := cfg["hooks"].(map[string]any)
	contract := connector.ResolveHookContract("codex", "").Contract
	checked := 0
	for event, raw := range hooks {
		list, ok := raw.([]any)
		if !ok {
			continue
		}
		for _, group := range list {
			handlers := group.(map[string]any)["hooks"].([]any)
			command := handlers[0].(map[string]any)["command"].(string)
			want := " --event " + event + " --hook-contract " + contract.ContractID
			if !strings.HasSuffix(command, want) {
				t.Fatalf("hooks.%s command %q does not end with %q", event, command, want)
			}
			allowed := false
			for _, e := range contract.Events {
				allowed = allowed || e == event
			}
			if !allowed {
				t.Fatalf("contract %s does not register %s", contract.ContractID, event)
			}
			checked++
		}
	}
	if checked == 0 {
		t.Fatal("no managed Codex groups rendered")
	}
}

const adminCodexRequirements = `# Corporate Codex requirements — owned by the platform team.
allowed_approval_policies = ["on-request"] # keep approvals on

[features]
# Company feature flags.
web_search = false

[hooks]
state_dir_comment = "not a hooks.state key"

[[hooks.PreToolUse]]
matcher = "Bash"

[[hooks.PreToolUse.hooks]]
type = "command"
command = "/usr/local/bin/company-audit"
timeout = 5
`

func TestCodexReconcilePreservesAdministratorBytes(t *testing.T) {
	opts := testOptions(t)
	path := codexPath(t, opts)
	writeFile(t, path, adminCodexRequirements)
	state, err := codexTarget{}.Reconcile(opts)
	if err != nil {
		t.Fatal(err)
	}
	mustNoConflicts(t, state)
	merged := readFile(t, path)
	if got := string(stripCodexOwned([]byte(merged))); got != adminCodexRequirements {
		t.Fatalf("stripping DefenseClaw content must return the exact administrator bytes:\n--- got\n%s\n--- want\n%s", got, adminCodexRequirements)
	}
	// Only DefenseClaw's own lines are added: no blank separators around
	// its blocks (GAP-0903).
	var others []string
	inBlock := false
	for _, line := range strings.SplitAfter(merged, "\n") {
		trimmed := strings.TrimSpace(line)
		switch {
		case trimmed == codexHeadBegin || trimmed == codexTailBegin:
			inBlock = true
		case trimmed == codexHeadEnd || trimmed == codexTailEnd:
			inBlock = false
		case !inBlock && !strings.HasSuffix(trimmed, codexOwnedMark):
			others = append(others, line)
		}
	}
	if got := strings.Join(others, ""); got != adminCodexRequirements {
		t.Fatalf("DefenseClaw added lines outside its blocks:\n--- got\n%s\n--- want\n%s", got, adminCodexRequirements)
	}
	if !strings.Contains(merged, "hooks = true "+codexOwnedMark) || !strings.Contains(merged, "managed_dir = \"/opt/defenseclaw/bin\" "+codexOwnedMark) {
		t.Fatalf("owned lines not inserted into administrator tables:\n%s", merged)
	}
	cfg := map[string]any{}
	if err := toml.Unmarshal([]byte(merged), &cfg); err != nil {
		t.Fatalf("merged document is not valid TOML: %v\n%s", err, merged)
	}
	pre := cfg["hooks"].(map[string]any)["PreToolUse"].([]any)
	if len(pre) != 2 {
		t.Fatalf("administrator PreToolUse group must survive beside DefenseClaw's: %v", pre)
	}
	if state.ForeignEntries != 1 || state.OwnedEntries != 10 {
		t.Fatalf("entry counts: owned=%d foreign=%d", state.OwnedEntries, state.ForeignEntries)
	}
	again, err := codexTarget{}.Reconcile(opts)
	if err != nil || again.Changed {
		t.Fatalf("second reconcile changed the file: %v %+v", err, again)
	}
}

func TestCodexConflictsAreReportedNotRewritten(t *testing.T) {
	opts := testOptions(t)
	path := codexPath(t, opts)
	admin := "allow_managed_hooks_only = false\n"
	writeFile(t, path, admin)
	state, err := codexTarget{}.Reconcile(opts)
	if err != nil {
		t.Fatal(err)
	}
	if !hasConflict(state, "allow_managed_hooks_only = false") || state.Covered {
		t.Fatalf("expected an unresolved lock conflict: %+v", state)
	}
	if !strings.HasPrefix(readFile(t, path), admin) {
		t.Fatal("the administrator's allow_managed_hooks_only value must not be rewritten")
	}

	inline := testOptions(t)
	writeFile(t, codexPath(t, inline), "hooks = { managed_dir = \"/x\" }\n")
	state, err = codexTarget{}.Reconcile(inline)
	if err != nil {
		t.Fatal(err)
	}
	if !hasConflict(state, "inline tables") || readFile(t, codexPath(t, inline)) != "hooks = { managed_dir = \"/x\" }\n" {
		t.Fatalf("an unmergeable layout must be reported and left untouched: %+v", state)
	}
}

func TestCodexPreserveLeavesLockToAdministrator(t *testing.T) {
	opts := withPolicy(testOptions(t), "codex", func(p *config.EnterpriseConnectorPolicy) { p.ManagedHooksOnly = "preserve" })
	state, err := codexTarget{}.Reconcile(opts)
	if err != nil {
		t.Fatal(err)
	}
	mustNoConflicts(t, state)
	if strings.Contains(readFile(t, codexPath(t, opts)), "allow_managed_hooks_only") {
		t.Fatal("preserve must not write the managed-hooks lock")
	}
	if state.EffectiveLock != config.ManagedHooksOnlyPreserve || !strings.Contains(strings.Join(state.Details, " "), "updatedInput") {
		t.Fatalf("preserve must report the rewrite risk: %+v", state)
	}
}

func TestCodexRemoveRestoresPreimageOrStripsOwned(t *testing.T) {
	opts := testOptions(t)
	path := codexPath(t, opts)
	writeFile(t, path, adminCodexRequirements)
	if _, err := (codexTarget{}).Reconcile(opts); err != nil {
		t.Fatal(err)
	}
	if _, err := (codexTarget{}).RemoveOwned(opts); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, path); got != adminCodexRequirements {
		t.Fatalf("remove must restore the exact preimage:\n%s", got)
	}

	// An administrator edit after install survives removal.
	if _, err := (codexTarget{}).Reconcile(opts); err != nil {
		t.Fatal(err)
	}
	edited := readFile(t, path) + "# added by admin later\n"
	writeFile(t, path, edited)
	if _, err := (codexTarget{}).RemoveOwned(opts); err != nil {
		t.Fatal(err)
	}
	got := readFile(t, path)
	if strings.Contains(got, "defenseclaw-hook") || !strings.Contains(got, "# added by admin later") || !strings.HasPrefix(got, adminCodexRequirements) {
		t.Fatalf("remove after an admin edit must strip only DefenseClaw content:\n%s", got)
	}

	// A file DefenseClaw created is removed entirely.
	fresh := testOptions(t)
	if _, err := (codexTarget{}).Reconcile(fresh); err != nil {
		t.Fatal(err)
	}
	if _, err := (codexTarget{}).RemoveOwned(fresh); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(codexPath(t, fresh)); !os.IsNotExist(err) {
		t.Fatalf("requirements.toml created by DefenseClaw must be removed, err=%v", err)
	}
}

// A DefenseClaw hook entry changed to run something else leaves the other
// entries in place, but the connector is no longer in place: ensure sees the
// drift and republishes (GAP-0077).
func TestCodexTamperedEntryIsNotInPlaceUntilRepublished(t *testing.T) {
	opts := testOptions(t)
	if _, err := (codexTarget{}).Reconcile(opts); err != nil {
		t.Fatal(err)
	}
	path := codexPath(t, opts)
	writeFile(t, path, strings.Replace(readFile(t, path), "/opt/defenseclaw/bin/defenseclaw-hook", "/bin/true", 1))
	result, _ := VerifyAll(opts, []string{"codex"})
	if len(result.MachinePolicyConnectors) != 0 {
		t.Fatalf("a tampered requirements.toml still verifies as in place: %+v", result.MachinePolicyConnectors)
	}
	if _, err := (codexTarget{}).Reconcile(opts); err != nil {
		t.Fatal(err)
	}
	if result, _ = VerifyAll(opts, []string{"codex"}); len(result.MachinePolicyConnectors) != 1 {
		t.Fatalf("a republished requirements.toml is not in place: %+v", result.MachinePolicyConnectors)
	}
}

func TestCodexVerifyOnlyNeverWrites(t *testing.T) {
	opts := withPolicy(testOptions(t), "codex", func(p *config.EnterpriseConnectorPolicy) { p.Ownership = "verify_only" })
	path := codexPath(t, opts)
	writeFile(t, path, adminCodexRequirements)
	state, err := codexTarget{}.Reconcile(opts)
	if err != nil {
		t.Fatal(err)
	}
	if readFile(t, path) != adminCodexRequirements || state.Covered || !strings.Contains(strings.Join(state.Details, " "), "missing_defenseclaw_hooks") {
		t.Fatalf("verify_only must report missing hooks without writing: %+v", state)
	}
	// enterprise policy verify names the export too, not only one conflict
	// per missing entry (GAP-0918).
	if verified, _ := VerifyAll(opts, []string{"codex"}); len(verified.States) == 0 ||
		!strings.Contains(strings.Join(verified.States[0].Details, " "), "policy export --connector codex") {
		t.Fatalf("policy verify does not name the export: %+v", verified.States)
	}
	exported, err := codexTarget{}.Export(opts, "toml")
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, path, string(exported))
	state, err = codexTarget{}.Verify(opts)
	if err != nil {
		t.Fatal(err)
	}
	if !state.Covered {
		t.Fatalf("admin-deployed export must verify as covered: %+v", state)
	}
}

func TestCodexFlappingSecondWriterIsReported(t *testing.T) {
	opts := testOptions(t)
	path := codexPath(t, opts)
	now := time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)
	opts.Now = func() time.Time { return now }
	for i := 0; i < flapThreshold; i++ {
		if _, err := (codexTarget{}).Reconcile(opts); err != nil {
			t.Fatal(err)
		}
		writeFile(t, path, adminCodexRequirements) // an MDM template overwrites the file
		now = now.Add(time.Hour)
	}
	state, err := codexTarget{}.Reconcile(opts)
	if err != nil {
		t.Fatal(err)
	}
	if !hasConflict(state, "verify_only") {
		t.Fatalf("repeated overwrites must be reported with a verify_only hint: %+v", state.Conflicts)
	}
}

func TestCodexWindowsRendering(t *testing.T) {
	opts := Options{
		GOOS:                "windows",
		HookBinary:          `C:\Program Files\Cisco\DefenseClaw\bin\defenseclaw-hook.exe`,
		WindowsProgramFiles: `C:\Program Files`,
		WindowsProgramData:  `C:\ProgramData`,
	}
	rendered, conflicts, err := renderCodex(opts, nil, opts.PolicyFor("codex"))
	if err != nil || len(conflicts) != 0 {
		t.Fatalf("render: %v %v", err, conflicts)
	}
	text := string(rendered)
	if !strings.Contains(text, `windows_managed_dir = "C:\\Program Files\\Cisco\\DefenseClaw\\bin"`) || !strings.Contains(text, "command_windows = ") {
		t.Fatalf("windows requirements must pin windows_managed_dir and command_windows:\n%s", text)
	}
	if path, _ := CodexRequirementsPath(opts); path != `C:\ProgramData\OpenAI\Codex\requirements.toml` {
		t.Fatalf("windows path = %q", path)
	}
	// Every group carries the command the standalone Windows requirements
	// writer publishes: bound to its event and the default contract (the
	// hook refuses an unbound Codex call), never the unbound form.
	var cfg map[string]any
	if err := toml.Unmarshal(rendered, &cfg); err != nil {
		t.Fatal(err)
	}
	hooks, _ := cfg["hooks"].(map[string]any)
	contract := connector.ResolveHookContract("codex", "").Contract.ContractID
	groups, err := connector.ManagedHookGroupsForOS("codex", "", "windows")
	if err != nil {
		t.Fatal(err)
	}
	for _, group := range groups {
		want := connector.WindowsCodexStandaloneManagedHookCommand(opts.HookBinary, group.Event, contract)
		list, _ := hooks[group.Event].([]any)
		if len(list) != 1 {
			t.Fatalf("hooks.%s has %d groups", group.Event, len(list))
		}
		handler := list[0].(map[string]any)["hooks"].([]any)[0].(map[string]any)
		if handler["command"] != want || handler["command_windows"] != want {
			t.Fatalf("hooks.%s command is not the bound standalone command", group.Event)
		}
	}
	if strings.Contains(text, connector.WindowsCodexManagedHookCommand(opts.HookBinary)) {
		t.Fatal("the unbound Secure Client command must not appear in standalone requirements")
	}
}

func withCodexHigherSources(t *testing.T, sources map[string][]byte) {
	t.Helper()
	previous := codexHigherSources
	codexHigherSources = func(Options) (map[string][]byte, error) { return sources, nil }
	t.Cleanup(func() { codexHigherSources = previous })
}

func TestCodexMDMRequirementsOutrankTheSystemFile(t *testing.T) {
	opts := testOptions(t)
	withCodexHigherSources(t, map[string][]byte{"MDM com.openai.codex": []byte("allowed_approval_policies = [\"never\"]\n")})
	state, err := codexTarget{}.Reconcile(opts)
	if err != nil {
		t.Fatal(err)
	}
	if state.Covered || len(state.HigherPrecedence) != 1 || !hasConflict(state, "--format plist") {
		t.Fatalf("an MDM layer without DefenseClaw's hooks must block coverage: %+v", state)
	}

	warn := withPolicy(testOptions(t), "codex", func(p *config.EnterpriseConnectorPolicy) { p.HigherPrecedenceSources = config.HigherPrecedenceWarn })
	state, err = codexTarget{}.Reconcile(warn)
	if err != nil {
		t.Fatal(err)
	}
	if !state.Covered || len(state.HigherPrecedence) != 0 {
		t.Fatalf("warn must report without blocking: %+v", state)
	}

	embedded := testOptions(t)
	plist, err := codexTarget{}.Export(embedded, "plist")
	if err != nil {
		t.Fatal(err)
	}
	var payload map[string]string
	if err := json.Unmarshal(plistJSONForTest(t, plist), &payload); err != nil {
		t.Fatal(err)
	}
	decoded, err := base64.StdEncoding.DecodeString(payload["requirements_toml_base64"])
	if err != nil {
		t.Fatal(err)
	}
	withCodexHigherSources(t, map[string][]byte{"MDM com.openai.codex": decoded})
	state, err = codexTarget{}.Reconcile(embedded)
	if err != nil {
		t.Fatal(err)
	}
	if !state.Covered {
		t.Fatalf("an MDM layer carrying the exported requirements must be covered: %+v", state)
	}
}

// plistJSONForTest extracts the single string key from the rendered plist.
func plistJSONForTest(t *testing.T, plist []byte) []byte {
	t.Helper()
	text := string(plist)
	const key = "<key>requirements_toml_base64</key>"
	start := strings.Index(text, key)
	if start < 0 {
		t.Fatalf("plist lacks requirements_toml_base64: %s", text)
	}
	rest := text[start+len(key):]
	open := strings.Index(rest, "<string>")
	end := strings.Index(rest, "</string>")
	if open < 0 || end < open {
		t.Fatalf("plist value: %s", text)
	}
	value, _ := json.Marshal(map[string]string{"requirements_toml_base64": rest[open+len("<string>") : end]})
	return value
}

func TestCodexPinsFeaturesHooksInEveryLockMode(t *testing.T) {
	for _, mode := range []string{config.ManagedHooksOnlyEnforce, config.ManagedHooksOnlyPreserve} {
		opts := withPolicy(testOptions(t), "codex", func(p *config.EnterpriseConnectorPolicy) { p.ManagedHooksOnly = mode })
		if _, err := (codexTarget{}).Reconcile(opts); err != nil {
			t.Fatal(err)
		}
		data := readFile(t, codexPath(t, opts))
		if !strings.Contains(data, "[features]") || !strings.Contains(data, "hooks = true") {
			t.Fatalf("%s: features.hooks must be pinned:\n%s", mode, data)
		}
		if got := strings.Contains(data, "allow_managed_hooks_only = true"); got != (mode == config.ManagedHooksOnlyEnforce) {
			t.Fatalf("%s: lock line present = %v:\n%s", mode, got, data)
		}
	}
}
