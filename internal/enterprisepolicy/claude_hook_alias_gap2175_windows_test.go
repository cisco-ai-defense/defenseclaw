// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisepolicy

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// GAP-2175: an administrator who puts DefenseClaw's whole Claude Code hook
// matrix in HKLM\SOFTWARE\Policies\ClaudeCode\Settings with the hook named by
// its 8.3 short alias (C:\PROGRA~1\...\DEFENS~1.EXE) passed Setup /ensure,
// but verify returned 1603 and status cov=False (machine_policy_not_covered):
// verify, status and the guardian matched the command to the hook binary by
// spelling only, while enrolment matched it by file identity.

const gap2175HKLM = `HKLM\SOFTWARE\Policies\ClaudeCode\Settings`

// gap2175Hooks lays out a stand-in for an installed hook image folder whose
// long names get 8.3 short names, plus a junction to that folder and a hard
// link to the hook in the (writable) temp root.
type gap2175Hooks struct {
	hook, otherAlias, alias, viaJunction, hardLink string
}

func gap2175Layout(t *testing.T) gap2175Hooks {
	t.Helper()
	root := t.TempDir()
	dir := filepath.Join(root, "DefenseClaw Program Files", "hooks", "e1132b0123456789")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	hook := filepath.Join(dir, "defenseclaw-hook.exe")
	other := filepath.Join(dir, "defenseclaw-other.exe")
	for _, path := range []string{hook, other} {
		if err := os.WriteFile(path, []byte(filepath.Base(path)), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	junction := filepath.Join(root, "linked")
	if out, err := exec.Command("cmd.exe", "/d", "/c", "mklink", "/J", junction, dir).CombinedOutput(); err != nil {
		t.Fatalf("mklink /J: %v: %s", err, out)
	}
	hardLink := filepath.Join(root, "defenseclaw-hook.exe")
	if err := os.Link(hook, hardLink); err != nil {
		t.Fatal(err)
	}
	return gap2175Hooks{
		hook:        hook,
		alias:       gap2175ShortPath(t, hook),
		otherAlias:  gap2175ShortPath(t, other),
		viaJunction: filepath.Join(junction, filepath.Base(hook)),
		hardLink:    hardLink,
	}
}

func gap2175ShortPath(t *testing.T, path string) string {
	t.Helper()
	pointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	buffer := make([]uint16, windows.MAX_LONG_PATH)
	n, err := windows.GetShortPathName(pointer, &buffer[0], uint32(len(buffer)))
	if err != nil || n == 0 || int(n) >= len(buffer) {
		t.Fatalf("GetShortPathName(%s): %v", path, err)
	}
	short := windows.UTF16ToString(buffer[:n])
	if !strings.Contains(short, "~") || strings.EqualFold(short, path) {
		t.Skipf("the volume of %s makes no 8.3 short names", path)
	}
	return short
}

// gap2175Matrix is the full matrix the HKLM export renders, with every
// handler's command spelled as command.
func gap2175Matrix(t *testing.T, opts Options, command string) string {
	t.Helper()
	spelled := opts
	spelled.HookBinary = command
	rendered, err := renderClaudeHigherPrecedence(spelled, spelled.PolicyFor(claudeConnector))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(rendered), strings.ReplaceAll(command, `\`, `\\`)) {
		t.Fatalf("fixture: the matrix does not name %s: %s", command, rendered)
	}
	return string(rendered)
}

func TestGAP2175ClaudeHKLMMatrixByShortAliasCountsAsCovered(t *testing.T) {
	hooks := gap2175Layout(t)
	// Verify reads only the stand-in machine folders here; the HKLM source
	// is the test's (withHigherSources). No protected folder is made, so a
	// Limited token runs it too.
	root := t.TempDir()
	opts := Options{
		GOOS:                "windows",
		HookBinary:          hooks.hook,
		WindowsProgramFiles: filepath.Join(root, "ProgramFiles"),
		WindowsProgramData:  filepath.Join(root, "ProgramData"),
		StateDir:            filepath.Join(root, "state", "machine-policy"),
		SkipTrustChecks:     true,
	}
	groups, err := connector.ManagedHookGroupsForOS(claudeConnector, opts.agentVersion(claudeConnector), "windows")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, command string
		covered       bool
	}{
		{"long path", hooks.hook, true},
		{"8.3 alias of the hook", hooks.alias, true},
		{"8.3 alias of another executable", hooks.otherAlias, false},
		{"path through a junction", hooks.viaJunction, false},
		{"hard link in another folder", hooks.hardLink, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			matrix := gap2175Matrix(t, opts, tc.command)
			doc, err := decodeOrderedObject([]byte(matrix))
			if err != nil {
				t.Fatal(err)
			}
			raw, _ := doc.get("hooks")
			owned, foreign, missing := countClaudeHooks(opts, raw, groups)
			if tc.covered && (len(missing) != 0 || foreign != 0 || owned != len(groups)) {
				t.Fatalf("coverage of %s: owned=%d foreign=%d missing=%v, want all %d events owned", tc.command, owned, foreign, missing, len(groups))
			}
			if !tc.covered && (len(missing) != len(groups) || owned != 0) {
				t.Fatalf("coverage of %s: owned=%d missing=%d, want none of %d owned", tc.command, owned, len(missing), len(groups))
			}

			withHigherSources(t, higherSource(t, gap2175HKLM, matrix))
			state, err := claudeTarget{}.Verify(opts)
			if err != nil {
				t.Fatal(err)
			}
			notCovered := hasConflict(state, "does not include DefenseClaw's hooks")
			if tc.covered && (notCovered || len(state.HigherPrecedence) != 0 || !hasDetail(state, gap2175HKLM+" embeds DefenseClaw's hook matrix")) {
				t.Fatalf("verify of an HKLM matrix naming %s: higher=%v conflicts=%q", tc.command, state.HigherPrecedence, state.Conflicts)
			}
			if !tc.covered && (!notCovered || len(state.HigherPrecedence) != 1) {
				t.Fatalf("verify must refuse an HKLM matrix naming %s: higher=%v conflicts=%q", tc.command, state.HigherPrecedence, state.Conflicts)
			}
		})
	}
}

func TestGAP2175GuardianOwnsTheShortAliasHandlerOnly(t *testing.T) {
	hooks := gap2175Layout(t)
	request := GuardRequest{Connector: ConnectorClaudeCode, GOOS: "windows", HookBinary: hooks.hook}
	handler := func(command string) map[string]any {
		return map[string]any{
			"type":    "command",
			"command": command,
			"args":    []any{"hook", "--connector", "claudecode", "--enterprise-managed"},
			"timeout": float64(30),
		}
	}
	for _, tc := range []struct {
		name, command string
		owned         bool
	}{
		{"long path", hooks.hook, true},
		{"8.3 alias of the hook", hooks.alias, true},
		{"8.3 alias of another executable", hooks.otherAlias, false},
		{"path through a junction", hooks.viaJunction, false},
		{"hard link in another folder", hooks.hardLink, false},
	} {
		if got := request.ownedHandler(handler(tc.command)); got != tc.owned {
			t.Errorf("%s: ownedHandler(%s) = %v, want %v", tc.name, tc.command, got, tc.owned)
		}
		opts := Options{GOOS: "windows", HookBinary: hooks.hook}
		if got := claudeHandlerIsOwned(opts, handler(tc.command)); got != tc.owned {
			t.Errorf("%s: claudeHandlerIsOwned(%s) = %v, want %v", tc.name, tc.command, got, tc.owned)
		}
	}
}
