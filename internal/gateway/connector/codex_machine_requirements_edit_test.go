// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"bytes"
	"strings"
	"testing"

	"github.com/pelletier/go-toml/v2"
)

// commentedAdminCodexRequirements is a representative administrator-authored
// requirements.toml: header comments, inline comments, deliberate ordering, an
// existing [features] table, and unrelated tables.
const commentedAdminCodexRequirements = `# Codex requirements managed by Contoso IT (Intune profile CX-12).
# Do not remove the sandbox restriction.
allowed_sandbox_modes = ["read-only", "workspace-write"] # regulated tenants
allowed_approval_policies = ["on-request"]

[features]
# Web search stays off for regulated tenants.
web_search_request = false

[mcp_servers.docs]
url = "https://docs.contoso.example/mcp" # internal only
`

// goldenCommentedAdminCodexRequirements is the exact install/repair output for
// commentedAdminCodexRequirements. {{CMD}} is the literal managed command.
const goldenCommentedAdminCodexRequirements = `allow_managed_hooks_only = true # managed by DefenseClaw
# Codex requirements managed by Contoso IT (Intune profile CX-12).
# Do not remove the sandbox restriction.
allowed_sandbox_modes = ["read-only", "workspace-write"] # regulated tenants
allowed_approval_policies = ["on-request"]

[features]
hooks = true # managed by DefenseClaw
# Web search stays off for regulated tenants.
web_search_request = false

[mcp_servers.docs]
url = "https://docs.contoso.example/mcp" # internal only

# BEGIN DefenseClaw managed hooks (generated; do not edit inside this block)
[hooks]
windows_managed_dir = 'C:\Program Files\DefenseClaw\bin'

[[hooks.SessionStart]]
matcher = 'startup|resume|clear'
[[hooks.SessionStart.hooks]]
type = 'command'
command = {{CMD}}
command_windows = {{CMD}}
timeout = 30

[[hooks.UserPromptSubmit]]
[[hooks.UserPromptSubmit.hooks]]
type = 'command'
command = {{CMD}}
command_windows = {{CMD}}
timeout = 30

[[hooks.PreToolUse]]
matcher = '*'
[[hooks.PreToolUse.hooks]]
type = 'command'
command = {{CMD}}
command_windows = {{CMD}}
timeout = 30

[[hooks.PermissionRequest]]
matcher = '*'
[[hooks.PermissionRequest.hooks]]
type = 'command'
command = {{CMD}}
command_windows = {{CMD}}
timeout = 30

[[hooks.PostToolUse]]
matcher = '*'
[[hooks.PostToolUse.hooks]]
type = 'command'
command = {{CMD}}
command_windows = {{CMD}}
timeout = 30

[[hooks.SubagentStart]]
matcher = '*'
[[hooks.SubagentStart.hooks]]
type = 'command'
command = {{CMD}}
command_windows = {{CMD}}
timeout = 30

[[hooks.SubagentStop]]
matcher = '*'
[[hooks.SubagentStop.hooks]]
type = 'command'
command = {{CMD}}
command_windows = {{CMD}}
timeout = 90

[[hooks.PreCompact]]
[[hooks.PreCompact.hooks]]
type = 'command'
command = {{CMD}}
command_windows = {{CMD}}
timeout = 30

[[hooks.PostCompact]]
[[hooks.PostCompact.hooks]]
type = 'command'
command = {{CMD}}
command_windows = {{CMD}}
timeout = 30

[[hooks.Stop]]
[[hooks.Stop.hooks]]
type = 'command'
command = {{CMD}}
command_windows = {{CMD}}
timeout = 90
# END DefenseClaw managed hooks
`

func codexRequirementsGolden(t *testing.T, template string, opts WindowsCodexMachineRequirementsOptions) []byte {
	t.Helper()
	command := windowsCodexManagedHookCommand(opts.HookBinary)
	if strings.ContainsAny(command, "'\r\n") {
		t.Fatalf("managed command %q cannot be a TOML literal string", command)
	}
	return []byte(strings.ReplaceAll(template, "{{CMD}}", "'"+command+"'"))
}

func reconcileCodexRequirementsForTest(
	t *testing.T,
	raw []byte,
	opts WindowsCodexMachineRequirementsOptions,
) []byte {
	t.Helper()
	rendered, _, err := reconcileWindowsCodexRequirements(raw, opts)
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if err := verifyWindowsCodexRequirementsBytes(rendered, opts); err != nil {
		t.Fatalf("reconciled requirements do not verify: %v\n%s", err, rendered)
	}
	return rendered
}

func removeCodexRequirementsForTest(
	t *testing.T,
	current []byte,
	baseline []byte,
	opts WindowsCodexMachineRequirementsOptions,
) []byte {
	t.Helper()
	cleaned, _, err := removeWindowsCodexRequirementsOwnedChanges(current, baseline, opts)
	if err != nil {
		t.Fatalf("remove: %v", err)
	}
	if contains, err := windowsCodexRequirementsContainExactManagedHook(cleaned, opts); err != nil || contains {
		t.Fatalf("managed hooks survive removal (err=%v):\n%s", err, cleaned)
	}
	return cleaned
}

func requireCodexRequirementsBytes(t *testing.T, label string, got, want []byte) {
	t.Helper()
	if !bytes.Equal(got, want) {
		t.Fatalf("%s mismatch\n--- got ---\n%s\n--- want ---\n%s", label, got, want)
	}
}

func TestReconcileWindowsCodexRequirementsPreservesCommentedAdminDocument(t *testing.T) {
	opts := testWindowsCodexMachineOptions()
	admin := []byte(commentedAdminCodexRequirements)

	installed, changed, err := reconcileWindowsCodexRequirements(admin, opts)
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("install must report a change")
	}
	requireCodexRequirementsBytes(t, "install", installed,
		codexRequirementsGolden(t, goldenCommentedAdminCodexRequirements, opts))
	if err := verifyWindowsCodexRequirementsBytes(installed, opts); err != nil {
		t.Fatalf("installed requirements do not verify: %v", err)
	}

	// Repair of an intact policy is byte-for-byte idempotent.
	repaired, changed, err := reconcileWindowsCodexRequirements(installed, opts)
	if err != nil {
		t.Fatal(err)
	}
	if changed {
		t.Fatal("repair of an intact policy must not report a change")
	}
	requireCodexRequirementsBytes(t, "repair", repaired, installed)

	// Uninstall (surgical path) returns the administrator's original bytes.
	requireCodexRequirementsBytes(t, "uninstall",
		removeCodexRequirementsForTest(t, installed, admin, opts), admin)
}

func TestRemoveWindowsCodexRequirementsKeepsLaterAdminEditsByteForByte(t *testing.T) {
	opts := testWindowsCodexMachineOptions()
	admin := []byte(commentedAdminCodexRequirements)
	installed := reconcileCodexRequirementsForTest(t, admin, opts)

	// The administrator later edits their own sections: a new comment and
	// key in [features] and a new trailing table after the DefenseClaw block.
	edited := bytes.Replace(installed,
		[]byte("web_search_request = false\n"),
		[]byte("web_search_request = false\n# Added by change CHG-7781.\nundo = true   # spacing kept\n"),
		1)
	edited = append(edited, []byte("\n[profiles.audit]\nmodel = \"gpt-5\" # pinned\n")...)

	// Repair keeps every administrator byte.
	repaired := reconcileCodexRequirementsForTest(t, edited, opts)
	requireCodexRequirementsBytes(t, "repair after admin edit", repaired, edited)

	want := bytes.Replace(admin,
		[]byte("web_search_request = false\n"),
		[]byte("web_search_request = false\n# Added by change CHG-7781.\nundo = true   # spacing kept\n"),
		1)
	want = append(want, []byte("\n[profiles.audit]\nmodel = \"gpt-5\" # pinned\n")...)
	requireCodexRequirementsBytes(t, "uninstall after admin edit",
		removeCodexRequirementsForTest(t, repaired, admin, opts), want)
}

func TestWindowsCodexRequirementsCRLFDocumentRoundTrips(t *testing.T) {
	opts := testWindowsCodexMachineOptions()
	admin := []byte(strings.ReplaceAll(commentedAdminCodexRequirements, "\n", "\r\n"))
	installed := reconcileCodexRequirementsForTest(t, admin, opts)
	want := bytes.ReplaceAll(codexRequirementsGolden(t, goldenCommentedAdminCodexRequirements, opts),
		[]byte("\n"), []byte("\r\n"))
	requireCodexRequirementsBytes(t, "CRLF install", installed, want)
	requireCodexRequirementsBytes(t, "CRLF uninstall",
		removeCodexRequirementsForTest(t, installed, admin, opts), admin)
}

func TestWindowsCodexRequirementsAdminHooksTableKeepsAdminGroups(t *testing.T) {
	opts := testWindowsCodexMachineOptions()
	admin := []byte(`# Contoso audit hooks.
[hooks] # administrator-owned
# Audit every session.
[[hooks.SessionStart]]
matcher = "startup"
[[hooks.SessionStart.hooks]]
type = "command"
command = 'C:\Contoso\audit.exe'
command_windows = 'C:\Contoso\audit.exe'
timeout = 9
`)
	installed := reconcileCodexRequirementsForTest(t, admin, opts)
	wantPrefix := []byte("allow_managed_hooks_only = true # managed by DefenseClaw\n" +
		string(bytes.Replace(admin,
			[]byte("[hooks] # administrator-owned\n"),
			[]byte("[hooks] # administrator-owned\n"+
				"windows_managed_dir = 'C:\\Program Files\\DefenseClaw\\bin' # managed by DefenseClaw\n"),
			1)) +
		"\n" + windowsCodexRequirementsRegionBegin + "\n[features]\nhooks = true\n\n[[hooks.SessionStart]]\n")
	if !bytes.HasPrefix(installed, wantPrefix) {
		t.Fatalf("install layout mismatch\n--- got ---\n%s\n--- want prefix ---\n%s", installed, wantPrefix)
	}
	cfg, err := parseWindowsCodexRequirements(installed)
	if err != nil {
		t.Fatal(err)
	}
	sessionStart := cfg["hooks"].(map[string]interface{})["SessionStart"].([]interface{})
	if len(sessionStart) != 2 ||
		sessionStart[0].(map[string]interface{})["matcher"] != "startup" ||
		!windowsCodexMachineGroupMatches(sessionStart[1], codexHookGroups[0], opts.HookBinary) {
		t.Fatalf("SessionStart groups = %#v, want administrator group then DefenseClaw group", sessionStart)
	}

	// The administrator hook survives uninstall, so the shared isolation
	// controls transfer to it exactly as before; only DefenseClaw groups go.
	cleaned := removeCodexRequirementsForTest(t, installed, admin, opts)
	want := []byte(`allow_managed_hooks_only = true # managed by DefenseClaw
# Contoso audit hooks.
[hooks] # administrator-owned
windows_managed_dir = 'C:\Program Files\DefenseClaw\bin' # managed by DefenseClaw
# Audit every session.
[[hooks.SessionStart]]
matcher = "startup"
[[hooks.SessionStart.hooks]]
type = "command"
command = 'C:\Contoso\audit.exe'
command_windows = 'C:\Contoso\audit.exe'
timeout = 9

# BEGIN DefenseClaw managed hooks (generated; do not edit inside this block)
[features]
hooks = true
# END DefenseClaw managed hooks
`)
	requireCodexRequirementsBytes(t, "shared-control transfer", cleaned, want)
}

func TestReconcileWindowsCodexRequirementsRepairsInsideManagedRegion(t *testing.T) {
	opts := testWindowsCodexMachineOptions()
	admin := []byte(commentedAdminCodexRequirements)
	installed := reconcileCodexRequirementsForTest(t, admin, opts)

	// Remove the DefenseClaw Stop group, as a careless template might.
	stop := []byte("\n[[hooks.Stop]]\n")
	start := bytes.Index(installed, stop)
	end := bytes.Index(installed, []byte(windowsCodexRequirementsRegionEnd))
	if start < 0 || end < start {
		t.Fatalf("golden layout changed:\n%s", installed)
	}
	drifted := append(append([]byte(nil), installed[:start+1]...), installed[end:]...)
	if err := verifyWindowsCodexRequirementsBytes(drifted, opts); err == nil {
		t.Fatal("drifted policy unexpectedly verifies")
	}

	repaired := reconcileCodexRequirementsForTest(t, drifted, opts)
	requireCodexRequirementsBytes(t, "repair inside region", repaired, installed)
}

func TestReconcileWindowsCodexRequirementsAppendsRegionAfterTrailingAdminTable(t *testing.T) {
	opts := testWindowsCodexMachineOptions()
	installed := reconcileCodexRequirementsForTest(t, []byte(commentedAdminCodexRequirements), opts)
	stop := bytes.Index(installed, []byte("\n[[hooks.Stop]]\n"))
	end := bytes.Index(installed, []byte(windowsCodexRequirementsRegionEnd))
	drifted := append(append([]byte(nil), installed[:stop+1]...), installed[end:]...)
	drifted = append(drifted, []byte("\n[profiles.audit] # admin\nmodel = \"gpt-5\"\n")...)

	repaired := reconcileCodexRequirementsForTest(t, drifted, opts)
	if !bytes.HasPrefix(repaired, drifted) {
		t.Fatalf("repair changed administrator bytes:\n%s", repaired)
	}
	tail := string(repaired[len(drifted):])
	if !strings.HasPrefix(tail, "\n"+windowsCodexRequirementsRegionBegin+"\n[[hooks.Stop]]\n") ||
		!strings.HasSuffix(tail, windowsCodexRequirementsRegionEnd+"\n") {
		t.Fatalf("missing group was not appended in a new managed region:\n%s", tail)
	}
	requireCodexRequirementsBytes(t, "uninstall with two regions",
		removeCodexRequirementsForTest(t, repaired, []byte(commentedAdminCodexRequirements), opts),
		[]byte(commentedAdminCodexRequirements+"\n[profiles.audit] # admin\nmodel = \"gpt-5\"\n"))
}

func TestReconcileWindowsCodexRequirementsLegacyMarshaledDocumentIsUntouched(t *testing.T) {
	opts := testWindowsCodexMachineOptions()
	// Earlier releases re-marshaled the whole document; such a policy must
	// now verify and repair without any rewrite.
	cfg, err := parseWindowsCodexRequirements([]byte(commentedAdminCodexRequirements))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := mergeWindowsCodexRequirementsModel(cfg, opts); err != nil {
		t.Fatal(err)
	}
	legacy, err := toml.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	repaired, changed, err := reconcileWindowsCodexRequirements(legacy, opts)
	if err != nil {
		t.Fatal(err)
	}
	if changed {
		t.Fatal("repair rewrote an already-managed legacy policy")
	}
	requireCodexRequirementsBytes(t, "legacy repair", repaired, legacy)

	cleaned := removeCodexRequirementsForTest(t, legacy, []byte(commentedAdminCodexRequirements), opts)
	cleanedCfg, err := parseWindowsCodexRequirements(cleaned)
	if err != nil {
		t.Fatal(err)
	}
	wantCfg, err := parseWindowsCodexRequirements([]byte(commentedAdminCodexRequirements))
	if err != nil {
		t.Fatal(err)
	}
	gotCanonical, _ := toml.Marshal(cleanedCfg)
	wantCanonical, _ := toml.Marshal(wantCfg)
	requireCodexRequirementsBytes(t, "legacy uninstall semantics", gotCanonical, wantCanonical)
}

func TestWindowsCodexRequirementsDottedRootTablesRoundTrip(t *testing.T) {
	opts := testWindowsCodexMachineOptions()
	admin := []byte("# dotted form\nfeatures.web_search_request = false\nhooks.SessionStart = []\n")
	if _, _, err := reconcileWindowsCodexRequirements(admin, opts); err == nil {
		t.Fatal("static hook array must not be extended by rewriting it")
	}

	admin = []byte("# dotted form\nfeatures.web_search_request = false # keep\n")
	installed := reconcileCodexRequirementsForTest(t, admin, opts)
	if !bytes.HasPrefix(installed, []byte(
		"allow_managed_hooks_only = true # managed by DefenseClaw\n"+
			"features.hooks = true # managed by DefenseClaw\n"+
			"# dotted form\nfeatures.web_search_request = false # keep\n")) {
		t.Fatalf("dotted features table was not extended at the root:\n%s", installed)
	}
	requireCodexRequirementsBytes(t, "dotted uninstall",
		removeCodexRequirementsForTest(t, installed, admin, opts), admin)
}

func TestReconcileWindowsCodexRequirementsRefusesUneditableForms(t *testing.T) {
	opts := testWindowsCodexMachineOptions()
	for name, raw := range map[string]string{
		"inline features":   "features = { web_search_request = false } # admin\n",
		"inline hooks":      "hooks = { } # admin\n",
		"static hook array": "[hooks]\nSessionStart = [\n  # admin\n  { matcher = \"x\", hooks = [] },\n]\n",
	} {
		t.Run(name, func(t *testing.T) {
			rendered, changed, err := reconcileWindowsCodexRequirements([]byte(raw), opts)
			if err == nil || !strings.Contains(err.Error(), "cannot edit without rewriting") {
				t.Fatalf("reconcile = %q, %v, %v; want uneditable error", rendered, changed, err)
			}
		})
	}
}

func TestWindowsCodexRequirementsEmptyAndUnterminatedDocuments(t *testing.T) {
	opts := testWindowsCodexMachineOptions()

	created := reconcileCodexRequirementsForTest(t, nil, opts)
	if !bytes.HasPrefix(created, []byte("allow_managed_hooks_only = true # managed by DefenseClaw\n\n"+
		windowsCodexRequirementsRegionBegin+"\n[features]\nhooks = true\n\n[hooks]\n")) {
		t.Fatalf("created policy layout:\n%s", created)
	}
	if cleaned := removeCodexRequirementsForTest(t, created, nil, opts); len(cleaned) != 0 {
		t.Fatalf("removal from a created policy left %q", cleaned)
	}

	// A final line without a newline stays intact; removal can only restore
	// it with the newline the region separator required.
	admin := []byte("[features]\nweb_search_request = false # no final newline")
	installed := reconcileCodexRequirementsForTest(t, admin, opts)
	if !bytes.Contains(installed, []byte("[features]\nhooks = true # managed by DefenseClaw\n"+
		"web_search_request = false # no final newline\n\n"+windowsCodexRequirementsRegionBegin)) {
		t.Fatalf("unterminated document layout:\n%s", installed)
	}
	requireCodexRequirementsBytes(t, "unterminated uninstall",
		removeCodexRequirementsForTest(t, installed, admin, opts), append(admin, '\n'))

	// A header on an unterminated final line still receives the key below it.
	admin = []byte("model = \"gpt-5\"\n[features]")
	installed = reconcileCodexRequirementsForTest(t, admin, opts)
	if !bytes.Contains(installed, []byte("model = \"gpt-5\"\n[features]\nhooks = true # managed by DefenseClaw\n")) {
		t.Fatalf("unterminated header layout:\n%s", installed)
	}
}

func TestReconcileWindowsCodexRequirementsNormalizesEquivalentManagedDirInPlace(t *testing.T) {
	opts := testWindowsCodexMachineOptions()
	installed := reconcileCodexRequirementsForTest(t, []byte(commentedAdminCodexRequirements), opts)
	variant := bytes.Replace(installed,
		[]byte(`windows_managed_dir = 'C:\Program Files\DefenseClaw\bin'`),
		[]byte(`windows_managed_dir = "c:\\program files\\defenseclaw\\bin"`),
		1)
	repaired := reconcileCodexRequirementsForTest(t, variant, opts)
	requireCodexRequirementsBytes(t, "managed dir normalization", repaired, installed)
}

func TestRemoveWindowsCodexRequirementsRefusesUneditableManagedGroups(t *testing.T) {
	opts := testWindowsCodexMachineOptions()
	installed := reconcileCodexRequirementsForTest(t, nil, opts)

	// Rewrite the managed Stop group into a static inline array. Removing it
	// would require rewriting that value, so uninstall must refuse instead.
	start := bytes.Index(installed, []byte("[[hooks.Stop]]"))
	end := bytes.Index(installed, []byte(windowsCodexRequirementsRegionEnd))
	if start < 0 || end < start {
		t.Fatalf("golden layout changed:\n%s", installed)
	}
	command := windowsCodexManagedHookCommand(opts.HookBinary)
	rewritten := append(append([]byte(nil), installed[:start]...), installed[end:]...)
	rewritten = bytes.Replace(rewritten,
		[]byte("[hooks]\n"),
		[]byte("[hooks]\nStop = [{ hooks = [{ type = 'command', command = '"+command+
			"', command_windows = '"+command+"', timeout = 90 }] }]\n"),
		1)
	if err := verifyWindowsCodexRequirementsBytes(rewritten, opts); err != nil {
		t.Fatalf("rewritten policy must still verify: %v", err)
	}
	if _, _, err := removeWindowsCodexRequirementsOwnedChanges(rewritten, nil, opts); err == nil ||
		!strings.Contains(err.Error(), "cannot edit without rewriting") {
		t.Fatalf("removal error = %v, want uneditable refusal", err)
	}
}
