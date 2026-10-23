// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// releasedAdapterOpens are the fail-open answers of the released per-user
// Windows adapters (testdata/released-hooks, rendered from each tag for an
// observe Cursor and a per-user Copilot: open).
var releasedAdapterOpens = map[string][]string{
	"cursor-hook.ps1":  {`[Console]::Out.Write('{"continue":true}')`, "$exitCode = 0"},
	"copilot-hook.ps1": {copilotAdapterOpenFailure},
}

func TestPerUserCopilotAdapterLegacyOpenRendersFailureDeny(t *testing.T) {
	scripts, err := renderHookScripts("127.0.0.1:18970", "open", ".token", []string{"copilot-hook.ps1"}, false, "copilot", true, "", "", false, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, script := range scripts {
		if script.name == "copilot-hook.ps1" {
			body := string(script.body)
			if strings.Contains(body, "Copilot hook adapter failed open") || !strings.Contains(body, `"permissionDecision":"deny"`) {
				t.Fatal("legacy per-user open reached Copilot adapter failure handling")
			}
			return
		}
	}
	t.Fatal("Copilot adapter was not rendered")
}

// The Windows Cursor and Copilot adapters answer for themselves when the
// hook launcher is missing or times out, which an upgrade causes while it
// swaps defenseclaw-hook.exe and the new hook waits for the install. The
// released per-user adapters then let the call run: Cursor's printed
// {"continue":true} (every 0.8.10 render, and 1.0.x observe), Copilot's
// printed nothing. A refresh to closed gives them their closed answers, CRLF
// files too, and a refresh that keeps the operator's open leaves them as
// they are.
func TestRefreshClosesTheReleasedWindowsAdapters(t *testing.T) {
	for _, release := range []string{"0.8.10", "1.0.0", "1.0.3"} {
		for adapter, opens := range releasedAdapterOpens {
			body, err := os.ReadFile(filepath.Join("testdata", "released-hooks", release, adapter))
			if os.IsNotExist(err) && release == "0.8.10" && adapter == "copilot-hook.ps1" {
				continue // 0.8.10 had no Copilot adapter.
			}
			if err != nil {
				t.Fatal(err)
			}
			for _, eol := range []string{"\n", "\r\n"} {
				for _, mode := range []string{"closed", "open"} {
					t.Run(release+"/"+adapter+"/"+mode+"/"+map[string]string{"\n": "lf", "\r\n": "crlf"}[eol], func(t *testing.T) {
						hookDir := t.TempDir()
						path := filepath.Join(hookDir, adapter)
						before := []byte(strings.ReplaceAll(string(body), "\n", eol))
						for _, open := range opens {
							if !bytes.Contains(before, []byte(open)) {
								t.Fatalf("precondition: the %s %s has no %q", release, adapter, open)
							}
						}
						if err := os.WriteFile(path, before, 0o600); err != nil {
							t.Fatal(err)
						}
						result, err := RefreshHookFailModes(hookDir, func(string) string { return mode })
						if err != nil {
							t.Fatal(err)
						}
						after, err := os.ReadFile(path)
						if err != nil {
							t.Fatal(err)
						}
						if mode == "open" {
							if !bytes.Equal(after, before) || len(result.Scripts) != 0 {
								t.Fatalf("a refresh to the operator's open changed the adapter (%v)", result.Scripts)
							}
							return
						}
						for _, open := range opens {
							if bytes.Contains(after, []byte(open)) {
								t.Fatalf("the refreshed %s %s still has %q", release, adapter, open)
							}
						}
						closed := copilotAdapterClosedFailure
						if adapter == "cursor-hook.ps1" {
							closed = `[Console]::Out.Write('` + cursorAdapterClosedResponse + `')`
							if !bytes.Contains(after, []byte("$exitCode = 2"+eol)) {
								t.Fatalf("the refreshed %s Cursor adapter does not exit 2 on a failure:\n%s", release, after)
							}
						}
						if !bytes.Contains(after, []byte(closed)) {
							t.Fatalf("the refreshed %s %s has no closed answer:\n%s", release, adapter, after)
						}
						if eol == "\r\n" && bytes.Contains(bytes.ReplaceAll(after, []byte("\r\n"), nil), []byte("\n")) {
							t.Fatal("the refresh wrote a bare LF into a CRLF adapter")
						}
						if len(result.Scripts) != 1 || result.Scripts[0] != adapter {
							t.Fatalf("refresh reported %v", result.Scripts)
						}
					})
				}
			}
		}
	}
}

// This release's adapters render the same closed answers the refresh writes,
// so a refreshed open render is the closed render, and a refresh leaves a
// closed render alone.
func TestRefreshOfThisReleasesOpenAdapterIsItsClosedRender(t *testing.T) {
	render := func(t *testing.T, adapter, mode string) []byte {
		t.Helper()
		tmpl, err := hookFS.ReadFile("hooks/" + adapter)
		if err != nil {
			t.Fatal(err)
		}
		body, err := renderTemplate(string(tmpl), templateData{
			FailMode:             mode,
			SecureClient:         mode == "open",
			HookBinaryPS:         `C:\Users\dc-user\AppData\Local\DefenseClaw\bin\defenseclaw-hook.exe`,
			HookTimeoutMS:        windowsHookAdapterTimeoutMS,
			CopilotHookTimeoutMS: copilotWindowsHookAdapterTimeoutMS,
		})
		if err != nil {
			t.Fatal(err)
		}
		return []byte(body)
	}
	for _, adapter := range []string{"cursor-hook.ps1", "copilot-hook.ps1"} {
		t.Run(adapter, func(t *testing.T) {
			open, closed := render(t, adapter, "open"), render(t, adapter, "closed")
			if adapter == "copilot-hook.ps1" {
				if !bytes.Contains(open, []byte(copilotAdapterOpenFailure)) || bytes.Contains(open, []byte(copilotAdapterClosedFailure)) {
					t.Fatalf("the open Copilot adapter does not fail open:\n%s", open)
				}
				if !bytes.Contains(closed, []byte(copilotAdapterClosedFailure)) || bytes.Contains(closed, []byte(copilotAdapterOpenFailure)) {
					t.Fatalf("the closed Copilot adapter does not deny on a failure:\n%s", closed)
				}
			}
			for _, start := range [][]byte{open, closed} {
				hookDir := t.TempDir()
				path := filepath.Join(hookDir, adapter)
				if err := os.WriteFile(path, start, 0o600); err != nil {
					t.Fatal(err)
				}
				if _, err := RefreshHookFailModes(hookDir, func(string) string { return "closed" }); err != nil {
					t.Fatal(err)
				}
				if after, _ := os.ReadFile(path); !bytes.Equal(after, closed) {
					t.Fatalf("refreshed adapter differs from the closed render:\n%s", after)
				}
			}
		})
	}
}
