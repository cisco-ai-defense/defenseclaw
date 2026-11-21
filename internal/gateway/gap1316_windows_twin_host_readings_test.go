// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// gap1316Home is a home with the DefenseClaw config and an .ssh folder, and
// a project folder in it, as the GAP-1150 rows use.
func gap1316Home(t *testing.T) (home, project string) {
	t.Helper()
	root := t.TempDir()
	home = filepath.Join(root, "alice")
	project = filepath.Join(home, "project")
	for _, dir := range []string{filepath.Join(home, ".defenseclaw"), filepath.Join(home, ".ssh"), project} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(home, ".defenseclaw", "config.yaml"), []byte("x: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	return home, project
}

func gap1316Appends(n int) string {
	parts := make([]string, n)
	for i := range parts {
		parts[i] = fmt.Sprintf("type nul >> a%d.txt", i)
	}
	return strings.Join(parts, "; ")
}

// TestGAP1316WindowsReadingTwinLeavesTheCallsScriptReadingsOut pins the cost
// fix of rel-1-0-10:GAP-1316. A Codex shell call on the Windows gateway that
// moves to a folder (Set-Location <home>, then relative appends) is placed in
// no dialect, and its PowerShell reading is the extra GAP-1150 reading
// (windowsReadingTwinRequests). That twin made the same script readings as the
// call (the statement list after the move and each statement, read as
// PowerShell in the hook's folder) and judged each a second time: 1.20-1.24x
// rel per hook call on dc-s7-win. The twin now leaves out the readings the
// call judges itself, and a reading the twin makes in turn keeps its own.
func TestGAP1316WindowsReadingTwinLeavesTheCallsScriptReadingsOut(t *testing.T) {
	home, project := gap1316Home(t)
	plain := "Set-Location " + home + "; " + gap1316Appends(12)
	input := actionfacts.Input{Tool: "shell", Command: plain, CWD: project, ActiveHome: home}
	hint, reading := selectWindowsShellDialectReading("shell", plain, input)
	if hint != "" || reading == nil {
		t.Fatalf("the selection placed the call in %q: it no longer pins an unplaced call", hint)
	}
	request := trustedActionRequest{Input: input, LegacyText: plain, windowsDialectReadings: true, windowsPowerShellReading: reading}
	facts := actionfacts.Analyze(request.Input)
	twins, _ := windowsReadingTwinRequests(request, facts)
	if len(twins) != 1 || twins[0].Input.Command != plain || twins[0].Input.DialectHint != actionfacts.DialectPowerShell {
		t.Fatalf("got %d twins, want the PowerShell reading of the whole call (GAP-1150)", len(twins))
	}
	twin := twins[0]
	own, _ := hostScriptTwinRequests(request, facts)
	twinFacts := actionfacts.Analyze(twin.Input)
	same, _ := hostScriptTwinRequests(twin, twinFacts)
	if len(own) < 13 || len(same) != len(own) {
		t.Fatalf("the call makes %d script readings and its twin %d: the fixture no longer pins the repeated readings", len(own), len(same))
	}
	judged := &judgedHostReadings{}
	judged.note(own)
	twin.windowsTwinHosts = &windowsTwinHostReadings{call: judged, input: twin.Input}
	if left, _ := hostScriptTwinRequests(twin, twinFacts); len(left) != 0 {
		t.Fatalf("the twin still makes %d of the call's own script readings", len(left))
	}
	for name, other := range map[string]func(trustedActionRequest) trustedActionRequest{
		"a statement of the twin": func(r trustedActionRequest) trustedActionRequest { r.simpleCommandPass = true; return r },
		"another input":           func(r trustedActionRequest) trustedActionRequest { r.Input.CWD = home; return r },
		"not a reading twin":      func(r trustedActionRequest) trustedActionRequest { r.readingTwin = false; return r },
	} {
		changed := other(twin)
		if kept, _ := hostScriptTwinRequests(changed, actionfacts.Analyze(changed.Input)); len(kept) == 0 {
			t.Fatalf("%s left out the call's script readings", name)
		}
	}
}

// TestGAP1316WindowsReadingTwinAnswersAreUnchanged judges the GAP-1150 rows
// and the GAP-1316 row on the Codex and Copilot shell routes, in every tier,
// with the twin leaving the call's script readings out and with the twin
// judging them again: every answer is the same. On native Windows the
// authorized_keys row still blocks, and the writes of the DefenseClaw config
// are proven state writes: tamper.detector_state_write in every tier, with
// the GAP-0747 owner tiering (2026-11-15T15:20Z) a HIGH alert in default,
// permissive and managed default and a block in strict and managed strict
// (gap1173WantFor).
func TestGAP1316WindowsReadingTwinAnswersAreUnchanged(t *testing.T) {
	prevHost := windowsHookHost
	windowsHookHost = func() bool { return true }
	t.Cleanup(func() { windowsHookHost = prevHost; windowsTwinsKeepHostReadings = false })
	home, project := gap1316Home(t)
	missing := filepath.Join(filepath.VolumeName(home)+string(filepath.Separator), "nonexistent-gap1316")
	rel := filepath.Join(".defenseclaw", "config.yaml")
	write := "type nul >> " + rel
	move := "Set-Location " + home + "; "
	// kind: "write" is a proven state write, "block" blocks in every tier,
	// "" is not judged here beyond the twin equality.
	rows := []struct {
		id, command, kind string
	}{
		{"w-plain-12", move + gap1316Appends(12), ""},
		{"set-location-home-only", move + write, "write"},
		{"cert-form", move + "cd " + missing + "; " + write, "write"},
		{"push-location", move + "Push-Location " + missing + "; " + write, "write"},
		{"add-content", move + "cd " + missing + "; Add-Content -Path " + rel + " -Value x; " + gap1316Appends(2), "write"},
		{"keys", move + "Add-Content " + filepath.Join(home, ".ssh", "authorized_keys") + " x; " + gap1316Appends(2), "block"},
		{"launcher", move + `powershell -NoProfile -Command "type nul >> ` + rel + `"; ` + gap1316Appends(1), "write"},
		{"benign-append", "cd " + missing + "; type nul >> notes.txt", ""},
		{"benign-project", "Set-Location " + project + "; cd " + missing + "; " + gap1316Appends(3), ""},
		{"benign-read", move + "cd " + missing + "; Get-Content " + rel, ""},
	}
	answer := func(p gap0437Pack, route, command string, keep bool) map[string]any {
		windowsTwinsKeepHostReadings = keep
		a := gap0437Server(t, p, strings.SplitN(route, "-", 2)[0], "action")
		out := gap1150Post(t, a, route, project, command, home, p.managed)
		delete(out, "evaluation_id")
		delete(out, "agent_identity_id")
		return out
	}
	for _, p := range gap0437Packs {
		for _, route := range []string{"codex", "codex-shell_command", "copilot"} {
			for _, r := range rows {
				left := answer(p, route, r.command, false)
				kept := answer(p, route, r.command, true)
				if !reflect.DeepEqual(left, kept) {
					t.Errorf("%s %s %s: answer %v, want %v as with the twin's own script readings", p.name, route, r.id, left, kept)
				}
				if runtime.GOOS != "windows" || r.kind == "" || (p.managed && route == "copilot") {
					continue
				}
				action, _ := left["action"].(string)
				var rules []string
				ids, _ := left["rule_ids"].([]any)
				for _, id := range ids {
					rules = append(rules, fmt.Sprint(id))
				}
				switch want := gap1173WantFor("write", p.name, action, rules); {
				case r.kind == "block" && action != "block":
					t.Errorf("%s %s %s: action %q rules %v, want block", p.name, route, r.id, action, rules)
				case r.kind == "write" && (action != want || !slices.Contains(rules, gap0747StateRule)):
					t.Errorf("%s %s %s: action %q rules %v, want %q with %s", p.name, route, r.id, action, rules, want, gap0747StateRule)
				}
			}
		}
	}
}
