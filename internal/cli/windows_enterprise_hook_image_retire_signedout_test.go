// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

// The machine files a 1.0.10 install keeps naming its launch folder while an
// enrolled account is signed out (rel-1-0-10 GAP-0856, run 2 on dc-ent-win).
const (
	signedOutClaudeSelector  = `C:\Program Files\ClaudeCode\managed-settings.d\.defenseclaw-managed-runtime-selector.state`
	signedOutCopilotSelector = `C:\ProgramData\Cisco\DefenseClaw-HookRuntime\copilot\.defenseclaw-managed-runtime-selector.state`
	signedOutCodexSelector   = `C:\ProgramData\OpenAI\Codex\.defenseclaw-managed-runtime-selector.state`
	signedOutCodexRequire    = `C:\ProgramData\OpenAI\Codex\requirements.toml`
	signedOutCodexOwnership  = `C:\ProgramData\Cisco\DefenseClaw\install\codex-requirements-ownership.json`
	signedOutMachinePolicy   = `C:\ProgramData\Cisco\DefenseClaw-HookRuntime\machine-policy.json`
	signedOutAccountSID      = "S-1-5-21-1111111111-2222222222-3333333333-1002"
)

// signedOutHost is the host of GAP-0856: which machine files still name the
// launch folder, and which writer takes each one off it.
type signedOutHost struct {
	still map[string]bool
	calls []string
}

func (h *signedOutHost) named(folder string) map[string][]string {
	var files []string
	for _, file := range []string{signedOutClaudeSelector, signedOutCopilotSelector, signedOutCodexSelector,
		signedOutCodexRequire, signedOutCodexOwnership, signedOutMachinePolicy} {
		if h.still[file] {
			files = append(files, file)
		}
	}
	if len(files) == 0 {
		return map[string][]string{}
	}
	return map[string][]string{folder: files}
}

func newSignedOutHost() *signedOutHost {
	return &signedOutHost{still: map[string]bool{
		signedOutClaudeSelector: true, signedOutCopilotSelector: true, signedOutCodexSelector: true,
		signedOutCodexRequire: true, signedOutCodexOwnership: true, signedOutMachinePolicy: true,
	}}
}

// signedOutRetireSteps wires the fixture to the host: the Codex reconcile
// takes the Codex files off the folder, the runtime selector step the
// selectors (the signed-out account's entries), the guardian the rest.
func signedOutRetireSteps(t *testing.T, r *retireFixture, h *signedOutHost) windowsHookImageRetireSteps {
	t.Helper()
	folder, _ := winpath.EnterpriseHookImageDigest(r.recorded["hook"])
	steps := r.steps()
	steps.Scan = func() windowsHookImageConfigScan {
		r.scans++
		return windowsHookImageConfigScan{Named: h.named(folder)}
	}
	steps.ReconcileCodex = func() error {
		h.calls = append(h.calls, "codex")
		h.still[signedOutCodexRequire], h.still[signedOutCodexOwnership] = false, false
		return nil
	}
	steps.DeselectSignedOut = func() windowsHookImageDeselection {
		h.calls = append(h.calls, "deselect")
		h.still[signedOutClaudeSelector], h.still[signedOutCopilotSelector], h.still[signedOutCodexSelector] = false, false, false
		return windowsHookImageDeselection{Errors: map[string]string{}, Profiles: []windowsHookImageSignedOutProfile{{
			SID: signedOutAccountSID, Account: `DCLAB\std2`, Connectors: []string{"claudecode", "codex", "copilot"},
		}}}
	}
	steps.RestartGuardian = func() error {
		h.calls = append(h.calls, "guardian")
		h.still[signedOutMachinePolicy] = false
		return nil
	}
	return steps
}

// GAP-0856: an enrolled account signed out, the selectors and the Codex
// requirements naming the launch folder. With the Codex reconcile working
// and the signed-out account's selections dropped, retire ends ok and
// reports the account; the guardian restarts only after both.
func TestHookImageRetireEndsOkWithAnEnrolledProfileSignedOut(t *testing.T) {
	r := newRetireFixture(t)
	h := newSignedOutHost()
	report := retireWindowsHookImages(signedOutRetireSteps(t, r, h))
	if !report.OK || report.Reason != "" || len(report.StillNamed) != 0 || report.Error != "" {
		t.Fatalf("retire = %+v; it must end ok once every machine file is rewritten", report)
	}
	if strings.Join(h.calls, ",") != "codex,deselect,guardian" {
		t.Fatalf("writer order = %v; the Codex reconcile and the selector step must run before the guardian restart", h.calls)
	}
	if len(report.SignedOutProfiles) != 1 || report.SignedOutProfiles[0].SID != signedOutAccountSID ||
		strings.Join(report.SignedOutProfiles[0].Connectors, ",") != "claudecode,codex,copilot" {
		t.Fatalf("signed_out_profiles = %+v; the signed-out account must be reported", report.SignedOutProfiles)
	}
	notes := strings.Join(report.Notes, "\n")
	if !strings.Contains(notes, "signed_out: "+`DCLAB\std2`+" ("+signedOutAccountSID+")") || !strings.Contains(notes, "until it signs in") {
		t.Fatalf("notes = %q; the signed-out account must be named with what happens at its sign-in", notes)
	}
	for _, file := range []string{signedOutClaudeSelector, signedOutCodexRequire, signedOutMachinePolicy} {
		if !strings.Contains(strings.Join(report.Rewritten, "\n"), file) {
			t.Fatalf("rewritten = %v; want %s", report.Rewritten, file)
		}
	}
}

// The rule stays: while a machine file names a launch folder, retire is
// pending, also with the account signed out. Its output names each file and
// the error that kept it, and the next step: no older Setup, fix the cause,
// retire again, recover with this release's Setup /ensure.
func TestHookImageRetirePendingNamesEachMachineFileAndItsCause(t *testing.T) {
	r := newRetireFixture(t)
	h := newSignedOutHost()
	steps := signedOutRetireSteps(t, r, h)
	const authDir = "DEFENSECLAW_HOOK_GUARDIAN_AUTH_DIR must be an exact absolute protected path"
	steps.ReconcileCodex = func() error { return errors.New(authDir) }
	steps.DeselectSignedOut = func() windowsHookImageDeselection {
		h.still[signedOutClaudeSelector], h.still[signedOutCodexSelector] = false, false
		return windowsHookImageDeselection{Errors: map[string]string{
			strings.ToLower(signedOutCopilotSelector): "the session of " + signedOutAccountSID + " could not be told: access denied",
		}}
	}
	steps.RestartGuardian = func() error { return nil }
	const guardianRow = "last guardian reconcile failed for opencode@DCLAB\\std1 (S-1-5-21-1-2-3-4): access denied"
	steps.GuardianFailures = func() []string { return []string{guardianRow} }
	report := retireWindowsHookImages(steps)
	if report.OK || report.Reason != windowsHookImageRetirePending {
		t.Fatalf("retire = %+v; a machine file that names a launch folder keeps retire pending", report)
	}
	want := map[string]string{
		signedOutCodexRequire:    "Codex requirements reconcile: " + authDir,
		signedOutCodexOwnership:  "Codex requirements reconcile: " + authDir,
		signedOutCopilotSelector: "the runtime selection of a signed-out account could not be dropped: the session of " + signedOutAccountSID + " could not be told: access denied",
		signedOutMachinePolicy:   "the guardian did not rewrite it within 3m0s: " + guardianRow,
	}
	if len(report.StillNamed) != len(want) {
		t.Fatalf("still_named = %+v; want %d machine files", report.StillNamed, len(want))
	}
	for _, named := range report.StillNamed {
		if named.Account || named.Cause != want[named.File] {
			t.Fatalf("%s: cause %q account %v; want %q", named.File, named.Cause, named.Account, want[named.File])
		}
		if !strings.Contains(report.Error, named.File+" ("+named.Cause+")") {
			t.Fatalf("error %q does not name %s with its cause", report.Error, named.File)
		}
	}
	for _, step := range []string{"Do NOT run an older release's Setup", "run retire again", "/ensure"} {
		if !strings.Contains(report.Error, step) {
			t.Fatalf("error %q lacks the next step %q", report.Error, step)
		}
	}
}

// With only the Codex reconcile failing (the writer seams of 1.0.10 before
// GAP-0856), the pending error names the files and the reconcile error next
// to each, and says not to run the older Setup.
func TestHookImageRetirePendingNamesTheCodexReconcileError(t *testing.T) {
	r := newRetireFixture(t)
	folder, _ := winpath.EnterpriseHookImageDigest(r.recorded["hook"])
	r.named = []map[string][]string{{folder: {signedOutCodexRequire, signedOutCodexSelector}}}
	steps := r.steps()
	steps.ReconcileCodex = func() error {
		return errors.New("DEFENSECLAW_HOOK_GUARDIAN_AUTH_DIR must be an exact absolute protected path")
	}
	report := retireWindowsHookImages(steps)
	if report.OK || report.Reason != windowsHookImageRetirePending {
		t.Fatalf("retire = %+v", report)
	}
	for _, part := range []string{
		signedOutCodexRequire + " (Codex requirements reconcile: DEFENSECLAW_HOOK_GUARDIAN_AUTH_DIR must be an exact absolute protected path)",
		signedOutCodexSelector + " (",
		"Do NOT run an older release's Setup",
		"/ensure",
	} {
		if !strings.Contains(report.Error, part) {
			t.Fatalf("error %q lacks %q", report.Error, part)
		}
	}
}

func TestHookImageMachineFileWriter(t *testing.T) {
	for file, want := range map[string]string{
		signedOutClaudeSelector:  "selector",
		signedOutCopilotSelector: "selector",
		signedOutCodexSelector:   "selector",
		signedOutCodexRequire:    "codex",
		signedOutCodexOwnership:  "codex",
		`C:\ProgramData\OpenAI\Codex\.defenseclaw-managed-hooks.state.committed`: "codex",
		signedOutMachinePolicy: "guardian",
		`C:\ProgramData\Cisco\DefenseClaw-HookRuntime\hermes\enrollment.json`: "guardian",
	} {
		if got := windowsHookImageMachineFileWriter(file); got != want {
			t.Errorf("%s: writer %q, want %q", file, got, want)
		}
	}
}
