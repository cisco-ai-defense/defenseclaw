// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

func claudeOSAdminTestOpts(t *testing.T, agentVersion string) SetupOpts {
	t.Helper()
	root := t.TempDir()
	return SetupOpts{
		ManagedEnterprise: true,
		HookFailMode:      "closed",
		HookExecutable:    filepath.Join(root, "bin", "defenseclaw-hook.exe"),
		DataDir:           filepath.Join(root, "defenseclaw"),
		AgentVersion:      agentVersion,
	}
}

// claudeOSAdminSettings embeds the exported DefenseClaw matrix for exportOpts
// into an administrator's existing policy.
func claudeOSAdminSettings(t *testing.T, exportOpts SetupOpts, extra map[string]interface{}) string {
	t.Helper()
	document, err := ClaudeCodeManagedHookPolicyDocument(exportOpts)
	if err != nil {
		t.Fatalf("export managed hook policy: %v", err)
	}
	var exported map[string]interface{}
	if err := json.Unmarshal(document, &exported); err != nil {
		t.Fatal(err)
	}
	settings := map[string]interface{}{"model": "managed-by-mdm", "hooks": exported["hooks"]}
	if lock, present := exported["allowManagedHooksOnly"]; present {
		settings["allowManagedHooksOnly"] = lock
	}
	for key, value := range extra {
		settings[key] = value
	}
	raw, err := json.Marshal(settings)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

const claudeOSAdminLabel = `HKLM Settings policy (HKLM\SOFTWARE\Policies\ClaudeCode\Settings)`

func TestClaudeOSAdminPolicyAdmitsTheExportedMatrix(t *testing.T) {
	for _, version := range []string{"2.1.154", "2.1.230"} {
		t.Run(version, func(t *testing.T) {
			opts := claudeOSAdminTestOpts(t, version)
			raw := claudeOSAdminSettings(t, opts, nil)
			if err := ClaudeCodeOSAdminPolicyAdmitsManagedHooks(raw, claudeOSAdminLabel, opts); err != nil {
				t.Fatalf("policy carrying the exported matrix was refused: %v", err)
			}
		})
	}
}

func TestClaudeOSAdminPolicyRejectsAMatrixForAnotherContractOrHook(t *testing.T) {
	// A v1 export lacks DirectoryAdded, which the v2 contract requires.
	opts := claudeOSAdminTestOpts(t, "2.1.230")
	stale := opts
	stale.AgentVersion = "2.1.200"
	if err := ClaudeCodeOSAdminPolicyAdmitsManagedHooks(
		claudeOSAdminSettings(t, stale, nil), claudeOSAdminLabel, opts,
	); err == nil {
		t.Fatal("a matrix exported for an older hook contract was accepted")
	}
	other := opts
	other.HookExecutable = filepath.Join(t.TempDir(), "defenseclaw-hook.exe")
	other.DataDir = filepath.Join(t.TempDir(), "defenseclaw")
	if err := ClaudeCodeOSAdminPolicyAdmitsManagedHooks(
		claudeOSAdminSettings(t, other, nil), claudeOSAdminLabel, opts,
	); err == nil {
		t.Fatal("a matrix naming another hook executable was accepted")
	}
}

// TestClaudeOSAdminPolicyMergeDoesNotTrustTheRecordedClientVersion is the
// #899 review regression. The recorded agent_version is written once, at
// discovery, and is often the installer's placeholder (2.1.154 for a user
// with no detected client), so refusing on it failed every lifecycle on an
// AVC-first host even after its users upgraded. It is not proof in the other
// direction either. The client floor for merge is enforced host-wide by the
// lifecycle module's application-control gate, never per target here.
func TestClaudeOSAdminPolicyMergeDoesNotTrustTheRecordedClientVersion(t *testing.T) {
	raw := `{"managedSourcesBehavior":"merge","model":"managed-by-mdm"}`
	for _, version := range []string{
		ClaudeCodeManagedSourcesMergeMinimumVersion,
		"2.1.250",
		"Claude Code 2.1.242",
		"2.1.241",
		"2.1.154",
		"not-a-version",
		"",
	} {
		if err := ClaudeCodeOSAdminPolicyAdmitsManagedHooks(raw, claudeOSAdminLabel, claudeOSAdminTestOpts(t, version)); err != nil {
			t.Fatalf("merge with recorded Claude %q was refused: %v", version, err)
		}
	}
	// Any other value keeps first-wins precedence.
	if err := ClaudeCodeOSAdminPolicyAdmitsManagedHooks(
		`{"managedSourcesBehavior":"first-wins"}`, claudeOSAdminLabel, claudeOSAdminTestOpts(t, "2.1.250"),
	); err == nil {
		t.Fatal("a non-merge managedSourcesBehavior was treated as merge")
	}
}

func TestClaudeOSAdminPolicyRefusalNamesBothFixes(t *testing.T) {
	err := ClaudeCodeOSAdminPolicyAdmitsManagedHooks(`{"model":"managed-by-mdm"}`, claudeOSAdminLabel, claudeOSAdminTestOpts(t, "2.1.250"))
	if err == nil {
		t.Fatalf("shadowing policy = %v, want a refusal", err)
	}
	for _, want := range []string{claudeOSAdminLabel, `"managedSourcesBehavior": "merge"`, ClaudeCodeManagedPolicyExportCommand} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("refusal %q does not mention %q", err, want)
		}
	}
	if err := ClaudeCodeOSAdminPolicyAdmitsManagedHooks("{not json", claudeOSAdminLabel, claudeOSAdminTestOpts(t, "2.1.250")); err == nil ||
		!strings.Contains(err.Error(), ClaudeCodeManagedPolicyExportCommand) {
		t.Fatalf("malformed policy = %v, want an actionable refusal", err)
	}
	if err := ClaudeCodeOSAdminPolicyAdmitsManagedHooks("   ", claudeOSAdminLabel, claudeOSAdminTestOpts(t, "2.1.250")); err != nil {
		t.Fatalf("empty Settings value = %v, want no policy", err)
	}
}

// Hook-defeating gates in the outranking policy win however sources combine.
func TestClaudeOSAdminPolicyHookGatesStillFailClosed(t *testing.T) {
	opts := claudeOSAdminTestOpts(t, "2.1.250")
	for name, raw := range map[string]string{
		"merge disables hooks":   `{"managedSourcesBehavior":"merge","disableAllHooks":true}`,
		"matrix disables hooks":  claudeOSAdminSettings(t, opts, map[string]interface{}{"disableAllHooks": true}),
		"malformed gate":         `{"managedSourcesBehavior":"merge","disableAllHooks":"yes"}`,
		"merge with a helper":    `{"managedSourcesBehavior":"merge","policyHelper":{"path":"C:\\helper.exe"}}`,
		"matrix with a helper":   claudeOSAdminSettings(t, opts, map[string]interface{}{"policyHelper": map[string]interface{}{"path": `C:\helper.exe`}}),
		"merge with bad hooks":   `{"managedSourcesBehavior":"merge","hooks":"none"}`,
		"merge with bad entries": `{"managedSourcesBehavior":"merge","hooks":{"PreToolUse":{}}}`,
	} {
		t.Run(name, func(t *testing.T) {
			if err := ClaudeCodeOSAdminPolicyAdmitsManagedHooks(raw, claudeOSAdminLabel, opts); err == nil {
				t.Fatal("hook-defeating outranking policy was accepted")
			}
		})
	}
}

func TestClaudeMergedManagedSourceUnionsBothTiersHooks(t *testing.T) {
	opts := claudeOSAdminTestOpts(t, "2.1.250")
	document, err := ClaudeCodeManagedHookPolicyDocument(opts)
	if err != nil {
		t.Fatal(err)
	}
	file := &claudeCodeSettingsSource{name: "file"}
	if file.settings, err = decodeClaudeCodeSettings(document, "file"); err != nil {
		t.Fatal(err)
	}
	osAdmin := &claudeCodeSettingsSource{name: "MDM", settings: map[string]interface{}{
		"managedSourcesBehavior": "merge",
		"hooks": map[string]interface{}{"PreToolUse": []interface{}{
			map[string]interface{}{"hooks": []interface{}{map[string]interface{}{"type": "command", "command": "C:\\audit.exe"}}},
		}},
	}}
	merged, err := claudeCodeMergedManagedSource(osAdmin, file)
	if err != nil {
		t.Fatal(err)
	}
	if present, err := claudeCodeSourceHasHookContract(merged, opts, false); err != nil || !present {
		t.Fatalf("merged tiers = (present=%v, err=%v), want the DefenseClaw contract", present, err)
	}
	fileEntries := len(file.settings["hooks"].(map[string]interface{})["PreToolUse"].([]interface{}))
	if got := len(merged.settings["hooks"].(map[string]interface{})["PreToolUse"].([]interface{})); got != fileEntries+1 {
		t.Fatalf("merged PreToolUse entries = %d, want %d", got, fileEntries+1)
	}
	withoutFile, err := claudeCodeMergedManagedSource(osAdmin, nil)
	if err != nil {
		t.Fatal(err)
	}
	if present, err := claudeCodeSourceHasHookContract(withoutFile, opts, false); err != nil || present {
		t.Fatalf("merge without the DefenseClaw tier = (present=%v, err=%v), want repairable absence", present, err)
	}
}

func TestClaudeCodeManagedHookPolicyDocumentMatchesTheInstalledRendering(t *testing.T) {
	opts := claudeOSAdminTestOpts(t, "2.1.230")
	document, err := ClaudeCodeManagedHookPolicyDocument(opts)
	if err != nil {
		t.Fatal(err)
	}
	rendered, err := renderClaudeCodeManagedHookPolicy(opts)
	if err != nil {
		t.Fatal(err)
	}
	if string(document) != string(rendered) {
		t.Fatal("exported document differs from the policy the guardian installs")
	}
	if !strings.Contains(string(document), `"DirectoryAdded"`) {
		t.Fatal("v2 export is missing the v2-only DirectoryAdded hook")
	}
	unmanaged := opts
	unmanaged.ManagedEnterprise = false
	if _, err := ClaudeCodeManagedHookPolicyDocument(unmanaged); err == nil {
		t.Fatal("export rendered a policy outside managed enterprise setup")
	}
}

// claudeOSAdminSettingsEdited is claudeOSAdminSettings with edit applied to
// every DefenseClaw handler of the exported matrix.
func claudeOSAdminSettingsEdited(
	t *testing.T, exportOpts SetupOpts, extra map[string]interface{}, edit func(event string, handler map[string]interface{}),
) string {
	t.Helper()
	var settings map[string]interface{}
	if err := json.Unmarshal([]byte(claudeOSAdminSettings(t, exportOpts, extra)), &settings); err != nil {
		t.Fatal(err)
	}
	for event, entries := range settings["hooks"].(map[string]interface{}) {
		for _, entry := range entries.([]interface{}) {
			for _, handler := range entry.(map[string]interface{})["hooks"].([]interface{}) {
				edit(event, handler.(map[string]interface{}))
			}
		}
	}
	raw, err := json.Marshal(settings)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func claudeOSAdminSource(t *testing.T, raw string) *claudeCodeSettingsSource {
	t.Helper()
	settings, err := decodeClaudeCodeSettings([]byte(raw), "test policy")
	if err != nil {
		t.Fatal(err)
	}
	return &claudeCodeSettingsSource{name: "MDM/OS managed settings", settings: settings}
}

// TestClaudeOSAdminPolicyHoldsTheCarriedHooksToTheRenderedTimeouts is the
// #899 review regression for a carried copy whose handlers time out first.
// Claude stops a handler at its registered timeout and lets the action run,
// so a policy that lowers it would make the fail-closed hook fail open.
func TestClaudeOSAdminPolicyHoldsTheCarriedHooksToTheRenderedTimeouts(t *testing.T) {
	opts := claudeOSAdminTestOpts(t, "2.1.250")
	setTimeout := func(timeout interface{}, events ...string) func(string, map[string]interface{}) {
		return func(event string, handler map[string]interface{}) {
			if len(events) == 0 || event == events[0] {
				if timeout == nil {
					delete(handler, "timeout")
				} else {
					handler["timeout"] = timeout
				}
			}
		}
	}
	for name, edit := range map[string]func(string, map[string]interface{}){
		"every handler at one second": setTimeout(1),
		"PreToolUse at one second":    setTimeout(1, "PreToolUse"),
		"Stop without a timeout":      setTimeout(nil, "Stop"),
		"Stop longer than rendered":   setTimeout(600, "Stop"),
	} {
		t.Run(name, func(t *testing.T) {
			raw := claudeOSAdminSettingsEdited(t, opts, nil, edit)
			if err := ClaudeCodeOSAdminPolicyAdmitsManagedHooks(raw, claudeOSAdminLabel, opts); err == nil {
				t.Fatal("an HKLM copy that differs from the rendered DefenseClaw hooks was admitted")
			}
		})
	}
	// The exact rule covers the matcher too, as the drop-in verify does.
	var wider map[string]interface{}
	if err := json.Unmarshal([]byte(claudeOSAdminSettings(t, opts, nil)), &wider); err != nil {
		t.Fatal(err)
	}
	for _, entry := range wider["hooks"].(map[string]interface{})["PreToolUse"].([]interface{}) {
		delete(entry.(map[string]interface{}), "matcher")
	}
	if raw, err := json.Marshal(wider); err != nil {
		t.Fatal(err)
	} else if err := ClaudeCodeOSAdminPolicyAdmitsManagedHooks(string(raw), claudeOSAdminLabel, opts); err == nil {
		t.Fatal("an HKLM copy with a different PreToolUse matcher was admitted")
	}
	// The guardian audit of an outranking policy checks the security
	// property rather than the exact bytes: a shorter or missing timeout is
	// not the contract, a longer one still lets the hook answer.
	short := claudeOSAdminSource(t, claudeOSAdminSettingsEdited(t, opts, nil, setTimeout(1, "PreToolUse")))
	if present, err := claudeCodeSourceHasHookContract(short, opts, true); present || err == nil ||
		!strings.Contains(err.Error(), "PreToolUse") {
		t.Fatalf("audit of a one-second PreToolUse copy = (present=%v, err=%v), want the missing PreToolUse hook", present, err)
	}
	missing := claudeOSAdminSource(t, claudeOSAdminSettingsEdited(t, opts, nil, setTimeout(nil, "Stop")))
	if present, err := claudeCodeSourceHasHookContract(missing, opts, true); present || err == nil ||
		!strings.Contains(err.Error(), "Stop") {
		t.Fatalf("audit of a Stop copy without a timeout = (present=%v, err=%v), want the missing Stop hook", present, err)
	}
	long := claudeOSAdminSource(t, claudeOSAdminSettingsEdited(t, opts, nil, setTimeout(600, "Stop")))
	if present, err := claudeCodeSourceHasHookContract(long, opts, true); err != nil || !present {
		t.Fatalf("audit of a longer Stop timeout = (present=%v, err=%v), want the contract", present, err)
	}
	exact := claudeOSAdminSource(t, claudeOSAdminSettings(t, opts, nil))
	if present, err := claudeCodeSourceHasHookContract(exact, opts, true); err != nil || !present {
		t.Fatalf("audit of the exported copy = (present=%v, err=%v), want the contract", present, err)
	}
}

// TestClaudeOSAdminPolicyRefusesDefenseClawHooksOutsideTheTargetContract is
// the #899 review regression for an export made for another Claude Code
// version. Merge unions the policy's hooks with the drop-in, so a DefenseClaw
// handler on an event outside the target's contract made the guardian audit
// report the hooks missing forever while Setup kept succeeding.
func TestClaudeOSAdminPolicyRefusesDefenseClawHooksOutsideTheTargetContract(t *testing.T) {
	target := claudeOSAdminTestOpts(t, "2.1.152")
	for name, extra := range map[string]map[string]interface{}{
		"carried": nil,
		"merged":  {"managedSourcesBehavior": "merge"},
	} {
		t.Run(name, func(t *testing.T) {
			var policy map[string]interface{}
			if err := json.Unmarshal([]byte(claudeOSAdminSettings(t, target, extra)), &policy); err != nil {
				t.Fatal(err)
			}
			// 0.8.6 has only the v1 contract. Inject a DefenseClaw handler
			// on a later event to prove the HKLM gate rejects it.
			hooks := policy["hooks"].(map[string]interface{})
			hooks["DirectoryAdded"] = hooks["PreToolUse"]
			body, err := json.Marshal(policy)
			if err != nil {
				t.Fatal(err)
			}
			err = ClaudeCodeOSAdminPolicyAdmitsManagedHooks(string(body), claudeOSAdminLabel, target)
			if err == nil {
				t.Fatal("a policy with a DefenseClaw hook outside the target contract was admitted")
			}
			for _, want := range []string{"DirectoryAdded", ClaudeCodeManagedPolicyExportCommand + " --agent-version 2.1.152"} {
				if !strings.Contains(err.Error(), want) {
					t.Fatalf("refusal %q does not mention %q", err, want)
				}
			}
		})
	}
	// Another administrator's hook on that event is not DefenseClaw's.
	other := `{"managedSourcesBehavior":"merge","hooks":{"DirectoryAdded":[{"hooks":[{"type":"command","command":"C:\\audit.exe"}]}]}}`
	if err := ClaudeCodeOSAdminPolicyAdmitsManagedHooks(other, claudeOSAdminLabel, target); err != nil {
		t.Fatalf("merge with another administrator's DirectoryAdded hook was refused: %v", err)
	}
}

// TestClaudeOSAdminRefusalNamesTheExportForTheTargetContract is the #899
// review regression for the refusal's remedy. Without --agent-version the
// export prints the default (oldest) contract, which a target on a newer
// contract refuses with the same message, so following it never succeeded.
func TestClaudeOSAdminRefusalNamesTheExportForTheTargetContract(t *testing.T) {
	v2 := ResolveHookContract("claudecode", "2.1.250").Contract
	for _, tc := range []struct {
		recorded, pinned, want string
	}{
		{recorded: "2.1.250", want: "2.1.250"},
		{recorded: "2.1.154", want: "2.1.154"},
		{recorded: "Claude Code 2.1.230", want: "2.1.230"},
		// Identity checks pin the contract without a recorded version.
		{pinned: v2.ContractID, want: NormalizeAgentVersion("claudecode", v2.MinAgentVersion)},
	} {
		t.Run(tc.recorded+tc.pinned, func(t *testing.T) {
			opts := claudeOSAdminTestOpts(t, tc.recorded)
			opts.HookContractID = tc.pinned
			err := ClaudeCodeOSAdminPolicyAdmitsManagedHooks(`{"model":"managed-by-mdm"}`, claudeOSAdminLabel, opts)
			command := ClaudeCodeManagedPolicyExportCommand + " --agent-version "
			if err == nil || !strings.Contains(err.Error(), command+tc.want+" ") {
				t.Fatalf("refusal = %v, want it to name %q", err, command+tc.want)
			}
			// Following the refusal: export that version, as the command
			// does, and embed it with its lock.
			export := opts
			export.AgentVersion = tc.want
			export.HookContractID = ResolveHookContract("claudecode", tc.want).Contract.ContractID
			if err := ClaudeCodeOSAdminPolicyAdmitsManagedHooks(
				claudeOSAdminSettings(t, export, nil), claudeOSAdminLabel, opts,
			); err != nil {
				t.Fatalf("the export the refusal names was refused: %v", err)
			}
			// The missing-lock refusal names the same export.
			unlocked := export
			unlocked.ClaudeCodeAllowUnmanagedHooks = true
			if err := ClaudeCodeOSAdminPolicyAdmitsManagedHooks(
				claudeOSAdminSettings(t, unlocked, nil), claudeOSAdminLabel, opts,
			); err == nil || !strings.Contains(err.Error(), command+tc.want+")") {
				t.Fatalf("missing-lock refusal = %v, want it to name %q", err, command+tc.want)
			}
		})
	}
}

// claudeOSAdminRenderedEntry is a fresh copy of the one hook entry DefenseClaw
// renders for event.
func claudeOSAdminRenderedEntry(t *testing.T, opts SetupOpts, event string) map[string]interface{} {
	t.Helper()
	document, err := ClaudeCodeManagedHookPolicyDocument(opts)
	if err != nil {
		t.Fatal(err)
	}
	var exported struct {
		Hooks map[string][]map[string]interface{} `json:"hooks"`
	}
	if err := json.Unmarshal(document, &exported); err != nil {
		t.Fatal(err)
	}
	if len(exported.Hooks[event]) != 1 {
		t.Fatalf("rendered %s entries = %d, want 1", event, len(exported.Hooks[event]))
	}
	return exported.Hooks[event][0]
}

// claudeOSAdminAppendEntries appends entries to the event's hook list in a
// policy document.
func claudeOSAdminAppendEntries(t *testing.T, raw, event string, entries ...map[string]interface{}) string {
	t.Helper()
	var settings map[string]interface{}
	if err := json.Unmarshal([]byte(raw), &settings); err != nil {
		t.Fatal(err)
	}
	hooks, _ := settings["hooks"].(map[string]interface{})
	if hooks == nil {
		hooks = map[string]interface{}{}
		settings["hooks"] = hooks
	}
	list, _ := hooks[event].([]interface{})
	for _, entry := range entries {
		list = append(list, entry)
	}
	hooks[event] = list
	body, err := json.Marshal(settings)
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

// TestClaudeOSAdminPolicyRefusesAChangedDefenseClawCopyBesideTheRenderedOne
// is the #899 review regression for a second DefenseClaw copy beside the
// rendered entry. Claude Code runs one copy of a repeated command hook (keyed
// by command, argv and condition, not by timeout or async flag; Claude Code
// 2.1.283 keeps the last one registered), so a one-second or asynchronous copy
// after the rendered entry is the one that runs, and PreToolUse fails open.
// Admission took the rendered entry as proof, under carry and merge, and so
// did the guardian audit.
func TestClaudeOSAdminPolicyRefusesAChangedDefenseClawCopyBesideTheRenderedOne(t *testing.T) {
	opts := claudeOSAdminTestOpts(t, "2.1.250")
	handler := func(entry map[string]interface{}) map[string]interface{} {
		return entry["hooks"].([]interface{})[0].(map[string]interface{})
	}
	changes := map[string]func(map[string]interface{}){
		"one-second copy": func(entry map[string]interface{}) { handler(entry)["timeout"] = 1 },
		"async copy":      func(entry map[string]interface{}) { handler(entry)["async"] = true },
		"one-second copy under a narrower matcher": func(entry map[string]interface{}) {
			entry["matcher"] = "Bash"
			handler(entry)["timeout"] = 1
		},
	}
	changed := func(t *testing.T, change func(map[string]interface{})) map[string]interface{} {
		entry := claudeOSAdminRenderedEntry(t, opts, "PreToolUse")
		change(entry)
		return entry
	}
	bases := map[string]string{
		"carried":            claudeOSAdminSettings(t, opts, nil),
		"carried and merged": claudeOSAdminSettings(t, opts, map[string]interface{}{"managedSourcesBehavior": "merge"}),
		"merged":             claudeOSAdminAppendEntries(t, `{"managedSourcesBehavior":"merge"}`, "PreToolUse", claudeOSAdminRenderedEntry(t, opts, "PreToolUse")),
		// The drop-in supplies the rendered entry under merge.
		"merged without the rendered entry": `{"managedSourcesBehavior":"merge"}`,
	}
	for baseName, base := range bases {
		for changeName, change := range changes {
			base, change := base, change
			t.Run(baseName+"/"+changeName, func(t *testing.T) {
				raw := claudeOSAdminAppendEntries(t, base, "PreToolUse", changed(t, change))
				err := ClaudeCodeOSAdminPolicyAdmitsManagedHooks(raw, claudeOSAdminLabel, opts)
				if err == nil {
					t.Fatal("a changed DefenseClaw copy was admitted")
				}
				for _, want := range []string{claudeOSAdminLabel, "PreToolUse", ClaudeCodeManagedPolicyExportCommand + " --agent-version 2.1.250"} {
					if !strings.Contains(err.Error(), want) {
						t.Fatalf("refusal %q does not mention %q", err, want)
					}
				}
			})
		}
	}

	// A carried policy keeps one DefenseClaw handler per event, as the drop-in
	// verify requires. Under merge the drop-in repeats the rendered entry
	// anyway, and identical copies run once.
	rendered := claudeOSAdminRenderedEntry(t, opts, "PreToolUse")
	twice := claudeOSAdminAppendEntries(t, claudeOSAdminSettings(t, opts, nil), "PreToolUse", rendered)
	if err := ClaudeCodeOSAdminPolicyAdmitsManagedHooks(twice, claudeOSAdminLabel, opts); err == nil ||
		!strings.Contains(err.Error(), "PreToolUse hook 2 times") {
		t.Fatalf("carried policy with the PreToolUse entry twice = %v, want a repeat refusal", err)
	}
	mergedTwice := claudeOSAdminAppendEntries(t, `{"managedSourcesBehavior":"merge"}`, "PreToolUse", rendered, rendered)
	if err := ClaudeCodeOSAdminPolicyAdmitsManagedHooks(mergedTwice, claudeOSAdminLabel, opts); err != nil {
		t.Fatalf("merge with the rendered PreToolUse entry twice was refused: %v", err)
	}
	// A DefenseClaw handler inside another administrator entry is not the
	// rendered entry either.
	shared := claudeOSAdminRenderedEntry(t, opts, "PreToolUse")
	shared["hooks"] = append([]interface{}{map[string]interface{}{"type": "command", "command": `C:\audit.exe`}}, shared["hooks"].([]interface{})...)
	if err := ClaudeCodeOSAdminPolicyAdmitsManagedHooks(
		claudeOSAdminAppendEntries(t, `{"managedSourcesBehavior":"merge"}`, "PreToolUse", shared), claudeOSAdminLabel, opts,
	); err == nil {
		t.Fatal("merge with a DefenseClaw handler inside another administrator entry was admitted")
	}

	// The guardian audit fails when any DefenseClaw copy falls short, for the
	// carried policy alone and for the union with the drop-in under merge.
	short := changed(t, changes["one-second copy"])
	carried := claudeOSAdminSource(t, claudeOSAdminAppendEntries(t, claudeOSAdminSettings(t, opts, nil), "PreToolUse", short))
	if present, err := claudeCodeSourceHasHookContract(carried, opts, true); present || err == nil ||
		!strings.Contains(err.Error(), "PreToolUse") || !strings.Contains(err.Error(), "does not meet the hook contract") {
		t.Fatalf("audit of a carried policy with a one-second copy = (present=%v, err=%v)", present, err)
	}
	document, err := ClaudeCodeManagedHookPolicyDocument(opts)
	if err != nil {
		t.Fatal(err)
	}
	file := &claudeCodeSettingsSource{name: "file"}
	if file.settings, err = decodeClaudeCodeSettings(document, "file"); err != nil {
		t.Fatal(err)
	}
	for name, change := range changes {
		osAdmin := claudeOSAdminSource(t, claudeOSAdminAppendEntries(t, `{"managedSourcesBehavior":"merge"}`, "PreToolUse", changed(t, change)))
		merged, err := claudeCodeMergedManagedSource(osAdmin, file)
		if err != nil {
			t.Fatal(err)
		}
		if present, err := claudeCodeSourceHasHookContract(merged, opts, false); present || err != nil {
			t.Fatalf("audit of the union with a %s = (present=%v, err=%v), want the contract missing", name, present, err)
		}
	}
	exact := claudeOSAdminSource(t, mergedTwice)
	merged, err := claudeCodeMergedManagedSource(exact, file)
	if err != nil {
		t.Fatal(err)
	}
	if present, err := claudeCodeSourceHasHookContract(merged, opts, false); !present || err != nil {
		t.Fatalf("audit of the union with rendered copies = (present=%v, err=%v), want the contract", present, err)
	}
}
