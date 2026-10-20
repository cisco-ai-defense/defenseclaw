// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"strings"
	"testing"
)

// livePolicyNote returns the static verify note about vendor settings
// DefenseClaw cannot see locally.
func livePolicyNote(t *testing.T, state State) string {
	t.Helper()
	for _, detail := range state.Details {
		if strings.Contains(detail, "not visible locally") {
			return detail
		}
	}
	t.Fatalf("no note about settings that are not visible locally: %q", state.Details)
	return ""
}

func windowsPolicyOptions() Options {
	return Options{
		GOOS:                "windows",
		HookBinary:          `C:\Program Files\Cisco\DefenseClaw\bin\defenseclaw-hook.exe`,
		WindowsProgramFiles: `C:\Program Files`,
		WindowsProgramData:  `C:\ProgramData`,
	}
}

// GAP-0010: a managed Windows host always refuses `enterprise policy verify
// --live`, so the static note there must not recommend it. It names the
// proof that works: a tool call in the user's own session, then the
// record read with audit export from an elevated prompt. Linux and macOS
// keep the --live advice.
func TestStaticVerifyLiveNoteIsOSAware(t *testing.T) {
	withCodexHigherSources(t, nil)
	for _, goos := range []string{"linux", "darwin", "windows"} {
		t.Run("codex/"+goos, func(t *testing.T) {
			opts := testOptions(t)
			opts.GOOS = goos
			if goos == "windows" {
				opts = windowsPolicyOptions()
			}
			policy := opts.PolicyFor(codexConnector)
			rendered, _, err := renderCodex(opts, nil, policy)
			if err != nil {
				t.Fatal(err)
			}
			state := newCodexState(opts, policy, "requirements.toml")
			if err := inspectCodex(opts, rendered, policy, &state); err != nil {
				t.Fatal(err)
			}
			checkLiveNote(t, goos, livePolicyNote(t, state), "codex")
		})
	}
	for _, goos := range []string{"linux", "darwin", "windows"} {
		t.Run("claudecode/"+goos, func(t *testing.T) {
			got := liveProofNote(Options{GOOS: goos}, claudeConnector, "Claude Code", "hooks")
			checkLiveNote(t, goos, got, "claudecode")
		})
	}
}

func checkLiveNote(t *testing.T, goos, note, connectorName string) {
	t.Helper()
	if goos == "windows" {
		for _, want := range []string{"from the user's own session", "elevated", "audit export --connector " + connectorName + " -o <file>"} {
			if !strings.Contains(note, want) {
				t.Fatalf("windows note missing %q: %s", want, note)
			}
		}
		if strings.Contains(note, "verify --live --connector") {
			t.Fatalf("windows note recommends --live, which a managed Windows host refuses: %s", note)
		}
		return
	}
	if want := "`enterprise policy verify --live --connector " + connectorName + " --user <user>`"; !strings.Contains(note, want) {
		t.Fatalf("%s note must keep %q: %s", goos, want, note)
	}
}
