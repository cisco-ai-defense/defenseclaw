// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// TestPowerShellRedirectBeforeExtractionKeepsItsProof (rel-1-0-10:GAP-0946):
// a redirect that opens before the tar extraction of its call or of a later
// statement (fixture rows gap/p0-round_GAP-1536/012 and 013) is judged once,
// with that proof, in the Claude Code PowerShell reading as in agy's
// run_command, inside and outside the home, as on Linux. A partial reading
// still receives the GAP-0988 unknown floor; the open-before proof does not
// prove the rest of that call. The PowerShell
// path fact spells the redirect C:/dir/file where the shell operand is
// C:\dir\file; judged again under that spelling it lost the proof, so the
// PowerShell reading warned or blocked and agy, where only its PowerShell
// reading saw the second spelling, was "weaker" (CI TEMP on its own volume).
//
// The negative controls are the same fixture commands with a write the
// proof must still hold, in every pack: the key file written after the
// extraction, a redirect after the extraction into the folder it extracts
// into (inside the home), and an append through a link the command makes
// earlier to the key file.
func TestPowerShellRedirectBeforeExtractionKeepsItsProof(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("the PowerShell reading of a Windows host")
	}
	fixture := map[string]string{}
	for _, c := range shapeParityCases(t) {
		if c.id == "gap/p0-round_GAP-1536/012" || c.id == "gap/p0-round_GAP-1536/013" {
			fixture[c.id], _ = c.args["command"].(string)
		}
	}
	if len(fixture) != 2 || fixture["gap/p0-round_GAP-1536/012"] == "" || fixture["gap/p0-round_GAP-1536/013"] == "" {
		t.Fatalf("fixture rows: %v", fixture)
	}
	root := t.TempDir()
	home := filepath.Join(root, "home")
	outside := filepath.Join(root, "work")
	inside := filepath.Join(home, "proj")
	for _, dir := range []string{filepath.Join(home, ".ssh"), outside, inside} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("USERPROFILE", home)
	t.Setenv("HOME", home)
	keys := filepath.Join(home, ".ssh", hookpaths.AuthorizedKeysFiles[0])
	extract := fixture["gap/p0-round_GAP-1536/013"][strings.LastIndex(fixture["gap/p0-round_GAP-1536/013"], ";")+1:]
	extract = strings.TrimSpace(extract)
	type row struct {
		id, command string
		block       bool
		dirs        []string
	}
	rows := []row{
		{"gap/p0-round_GAP-1536/012", fixture["gap/p0-round_GAP-1536/012"], false, []string{outside, inside}},
		{"gap/p0-round_GAP-1536/013", fixture["gap/p0-round_GAP-1536/013"], false, []string{outside, inside}},
		{"control/key-write-after-extraction", extract + "; cat x > " + keys, true, []string{outside, inside}},
		{"control/redirect-into-scope-after-extraction", extract + "; echo hi > out.txt", true, []string{inside}},
		{"control/append-through-earlier-link-posix", "ln -s " + keys + " k; " + extract + "; echo x >> k", true, []string{outside, inside}},
		{"control/append-through-earlier-link-powershell", "New-Item -ItemType SymbolicLink -Path k -Target " + keys + "; " + extract + "; echo x >> k", true, []string{outside, inside}},
	}
	shapeParityTiers(t, func(t *testing.T, p gap0437Pack) {
		handlers := map[string]http.HandlerFunc{}
		for _, conn := range []string{"claudecode", "antigravity"} {
			srv := gap0437Server(t, p, conn, "action")
			installToolCallCorpusProfileConnector(t, conn, p.pack)
			handlers[conn] = srv.handleAgentHook(conn)
		}
		for _, r := range rows {
			args := map[string]any{"command": r.command}
			for _, cwd := range r.dirs {
				where := "outside the home"
				if strings.HasPrefix(cwd, home) {
					where = "inside the home"
				}
				claude := shapeParityHook(t, handlers["claudecode"], shapeParityCall{name: "claudecode/PowerShell", conn: "claudecode",
					event: "PreToolUse", body: shapeParityEnvelope("PreToolUse", cwd, "PowerShell", args)}, p.managed)
				for _, call := range shapeParityNative("Bash", args, cwd) {
					agy := shapeParityHook(t, handlers[call.conn], call, p.managed)
					switch {
					case r.block && (claude != "block" || agy != "block"):
						t.Errorf("%s %s %s: Claude Code PowerShell %s, %s %s, want block", p.name, r.id, where, claude, call.name, agy)
					case !r.block:
						want := "alert"
						if p.managed || strings.Contains(p.name, "strict") {
							want = "block"
						}
						if claude != want || agy != want {
							t.Errorf("%s %s %s: Claude Code PowerShell %s, %s %s, want %s (partial reading floor)", p.name, r.id, where, claude, call.name, agy, want)
						}
					}
				}
			}
		}
	})
}
