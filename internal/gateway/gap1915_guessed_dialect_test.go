// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"runtime"
	"slices"
	"strings"
	"testing"
	"unicode/utf16"
)

func gap1915SQ(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

func gap1915Encoded(script string) string {
	u := utf16.Encode([]rune(script))
	b := make([]byte, 0, 2*len(u))
	for _, r := range u {
		b = append(b, byte(r), byte(r>>8))
	}
	enc := base64.StdEncoding.EncodeToString(b)
	var parts []string
	for len(enc) > 12 {
		parts = append(parts, enc[:12])
		enc = enc[12:]
	}
	return `powershell -NoProfile -EncodedCommand "` + strings.Join(append(parts, enc), "\t") + `"`
}

// gap1915Shapes builds the GAP-1915 shapes for one target file: POSIX text on a
// Windows host with no dialect hint (find -exec sh -c, a dot-sourced
// here-string; an echo redirection and an Out-File -Append) and an encoded
// PowerShell script whose output stream is redirected twice.
func gap1915Shapes(target string) map[string]string {
	echo := `powershell.exe -NoProfile -Command ` + gap1915SQ(`echo x >> `+target)
	outFile := `powershell.exe -NoProfile -Command ` + gap1915SQ(gap1915SQ(`x`)+` | Out-File -FilePath `+target+` -Append`)
	return map[string]string{
		"find-exec echo":     `find . -maxdepth 0 -exec sh -c ` + gap1915SQ(echo) + ` \;`,
		"find-exec Out-File": `find . -maxdepth 0 -exec sh -c ` + gap1915SQ(outFile) + ` \;`,
		"dot-stdin echo":     `. /dev/stdin <<< ` + gap1915SQ(echo),
		"dot-stdin Out-File": `. /dev/stdin <<< ` + gap1915SQ(outFile),
		"encoded 1>&2 >>":    gap1915Encoded(`powershell -Command 'echo k' 1>&2 >> ` + target),
	}
}

// TestGAP1915GuessedDialectShapesKeepTheT21aRaise (rel-1-0-10:GAP-1915): the
// PowerShell parser swap (pwsh-a) gave back the raise T21a had on these shapes
// (inspect-oc, hook-codex and llm: no dialect hint, so PowerShell is guessed):
// alert in default (block for authorized_keys), block in strict,
// effect.protected_target_restricted. Red
// at c953fc9fe2 (allow), green at the fix. The twins on a project file stay
// allowed with no effect finding.
func TestGAP1915GuessedDialectShapesKeepTheT21aRaise(t *testing.T) {
	previous := windowsHookHost
	windowsHookHost = func() bool { return true }
	t.Cleanup(func() { windowsHookHost = previous })
	const home = `C:\Users\alice`
	sameHostHomeForTest = home
	t.Cleanup(func() { sameHostHomeForTest = "" })
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	inspect := func(server *APIServer, command string) (string, []string) {
		t.Helper()
		body, err := json.Marshal(map[string]any{"tool": "exec", "connector": "openclaw",
			"args": map[string]any{"command": command, "workdir": home + `\proj`}})
		if err != nil {
			t.Fatal(err)
		}
		recorder := httptest.NewRecorder()
		server.handleInspectTool(recorder, httptest.NewRequest(http.MethodPost, "/api/v1/inspect/tool", bytes.NewReader(body)))
		var verdict ToolInspectVerdict
		if recorder.Code != http.StatusOK || json.Unmarshal(recorder.Body.Bytes(), &verdict) != nil {
			t.Fatalf("%s: status %d body %s", command, recorder.Code, recorder.Body.String())
		}
		return verdict.Action, verdict.Findings
	}
	for _, pack := range gap0437Packs[:2] { // default, strict
		server := gap0437Server(t, pack, "openclaw", "action")
		setLiveEffectsLane(t, "on")
		for _, target := range []string{home + `\.defenseclaw\config.yaml`, home + `\.defenseclaw\audit.db`, home + `\.ssh\authorized_keys`} {
			// default alerts on a DefenseClaw state file and blocks an
			// authorized_keys write, as T21a did; strict blocks both.
			want := "block"
			if pack.name == "default" && strings.Contains(target, ".defenseclaw") {
				want = "alert"
			}
			for name, command := range gap1915Shapes(target) {
				got, findings := inspect(server, command)
				// an authorized_keys write may carry the persistence rule instead.
				restricted := slices.ContainsFunc(findings, func(f string) bool { return strings.HasPrefix(f, "effect.protected_target_restricted") })
				// On a Windows host the 1.0.10 state reader reads these
				// shapes itself, and the effect finding folds into its
				// finding, which names the set (DET111 ruling A).
				if runtime.GOOS == "windows" && slices.ContainsFunc(findings, func(f string) bool { return strings.HasPrefix(f, "tamper.detector_state_write") }) {
					restricted = true
				}
				if got != want || (!restricted && !strings.Contains(target, ".ssh")) {
					t.Errorf("%s %s -> %s: %s %v, want %s with effect.protected_target_restricted", pack.name, name, target, got, findings, want)
				}
			}
		}
		for name, command := range gap1915Shapes(home + `\proj\notes.txt`) {
			got, findings := inspect(server, command)
			var ids []string
			for _, f := range findings {
				if strings.HasPrefix(f, "effect.") {
					ids = append(ids, f)
				}
			}
			if got != "allow" || len(ids) != 0 {
				t.Errorf("%s %s on a project file: %s %v, want allow with no effect finding", pack.name, name, got, ids)
			}
		}
	}
}
