// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// patchToolSpaces are the characters the patch tool trims from the ends of a
// patch and of its first and last line: every Unicode space (measured with the
// tool itself: the ASCII spaces, a lone carriage return, U+0085, U+00A0,
// U+1680, U+2000 to U+200A, U+2028, U+2029, U+202F, U+205F and U+3000).
func patchToolSpaces() []struct{ name, text string } {
	spaces := []struct{ name, text string }{
		{"space", " "}, {"tab", "\t"}, {"vertical tab", "\v"}, {"form feed", "\f"},
		{"lone CR", "\r"}, {"NEL", "\u0085"}, {"NBSP", "\u00a0"}, {"ogham space", "\u1680"},
		{"line separator", "\u2028"}, {"paragraph separator", "\u2029"},
		{"narrow NBSP", "\u202f"}, {"medium math space", "\u205f"}, {"ideographic space", "\u3000"},
	}
	for r := rune(0x2000); r <= 0x200a; r++ {
		spaces = append(spaces, struct{ name, text string }{fmt.Sprintf("U+%04X", r), string(r)})
	}
	return spaces
}

type patchEdgeSpelling struct {
	name        string
	prefix      string
	beginMarker string
	endMarker   string
	suffix      string
}

// patchEdgeSpellings pads one patch at its edges and at its first and last
// line the way the patch tool accepts.
func patchEdgeSpellings(space string) []patchEdgeSpelling {
	return []patchEdgeSpelling{
		{name: "trailing", suffix: space},
		{name: "leading", prefix: space},
		{name: "both", prefix: space, suffix: space},
		{name: "begin line", beginMarker: space},
		{name: "end line", endMarker: space},
	}
}

func (s patchEdgeSpelling) patch(target, text string) string {
	return s.prefix + "*** Begin Patch" + s.beginMarker + "\n*** Add File: " + target + "\n+" + text +
		"\n" + s.endMarker + "*** End Patch" + s.suffix
}

const patchEdgeLoaderRule = "persistence.global_ld_preload_install"

func patchEdgeBody(t *testing.T, route, project, patch string) string {
	t.Helper()
	switch route {
	case "typed":
		return (nativeWriteCall{"codex", "apply_patch", func(string) map[string]any { return map[string]any{"command": patch} }}).body(t, project, project)
	case "shell codex":
		return string(mustJSON(t, map[string]any{
			"hook_event_name": "PreToolUse", "session_id": "edge-space-codex", "turn_id": "t1", "cwd": project,
			"tool_name": "exec_command", "tool_use_id": "u1",
			"tool_input": map[string]any{"cmd": "apply_patch <<\x27PATCH\x27\n" + patch + "\nPATCH\n", "workdir": project},
		}))
	default:
		return string(mustJSON(t, map[string]any{
			"hook_event_name": "PreToolUse", "session_id": "edge-space-claude", "cwd": project,
			"tool_name": "Bash", "tool_use_id": "u1", "permission_mode": "default",
			"tool_input": map[string]any{"command": "apply_patch <<\x27PATCH\x27\n" + patch + "\nPATCH\n"},
		}))
	}
}

// patchEdgeShellReadsSpace reports whether a shell command that holds the
// space is read at all: the shell reader takes a command with a vertical tab,
// a form feed or U+0085 anywhere in its text as unreadable, whatever it runs
// (analyze.go validatePatchToolCommandText), so the shell routes are asserted
// for the other spaces.
func patchEdgeShellReadsSpace(route, space string) bool {
	if route == "typed" {
		return true
	}
	switch space {
	case "\v", "\f", "\u0085":
		return false
	}
	return true
}

func patchEdgeConnector(route string) string {
	if route == "shell claudecode" {
		return "claudecode"
	}
	return "codex"
}

// TestPatchEnvelopeEdgeWhiteSpaceKeepsContentRuleVerdict pins that a patch
// padded at its edges with any space the patch tool trims is judged by the
// content rules like the plain patch, whatever the profile and route: the
// loader-preload file, a link to it and a loader line in a profile fragment are
// blocked, an ordinary file stays allowed.
func TestPatchEnvelopeEdgeWhiteSpaceKeepsContentRuleVerdict(t *testing.T) {
	home, project := hermesPatchHome(t)
	link := filepath.Join(project, "linked-preload")
	if err := os.Symlink("/etc/ld.so.preload", link); err != nil {
		t.Fatal(err)
	}
	const lib = "/usr/local/lib/liblogger.so"
	targets := []struct {
		name, path, text string
		protected        bool
	}{
		{"direct", "/etc/ld.so.preload", lib, true},
		{"link", link, lib, true},
		{"profile fragment", "/etc/profile.d/logger.sh", "export LD_PRELOAD=" + lib, true},
		{"ordinary", filepath.Join(project, "notes.txt"), "hello", false},
	}
	for _, route := range []string{"typed", "shell codex", "shell claudecode"} {
		for _, space := range patchToolSpaces() {
			if !patchEdgeShellReadsSpace(route, space.text) {
				continue
			}
			// The full set of spaces runs in the default tier; the
			// permissive and strict tiers run the three spaces that
			// were allowed before.
			packs := []string{""}
			switch space.text {
			case "\r", "\u00a0", "\u202f":
				packs = []string{"", "permissive", "strict"}
			}
			for _, spelling := range patchEdgeSpellings(space.text) {
				for _, target := range targets {
					for _, pack := range packs {
						t.Run(fmt.Sprintf("%s/%s/%s/%s/%s", route, space.name, spelling.name, target.name, pack), func(t *testing.T) {
							body := patchEdgeBody(t, route, project, spelling.patch(target.path, target.text))
							connector := patchEdgeConnector(route)
							got := overLimitHostHookInPack(t, connector, pack, home, body,
								hookpaths.ResolveConnector(connector, "", "preToolUse", []byte(body)))
							action := overLimitHookAction(t, got)
							if target.protected && (action != "block" || !strings.Contains(got, patchEdgeLoaderRule)) {
								t.Errorf("protected patch action=%s, want a %s block: %.350s", action, patchEdgeLoaderRule, got)
							}
							if !target.protected && pack != "strict" && action == "block" {
								t.Errorf("ordinary patch blocked: %.350s", got)
							}
						})
					}
				}
			}
		}
	}
}

// TestPatchEnvelopeEdgeWhiteSpaceIsBlockedWhenManaged is the managed-default
// twin: a managed install blocks the padded loader-preload patch on the typed
// and the shell route, and does not block the padded ordinary file.
func TestPatchEnvelopeEdgeWhiteSpaceIsBlockedWhenManaged(t *testing.T) {
	home, project := hermesPatchHome(t)
	for _, route := range []string{"typed", "shell codex"} {
		for _, space := range patchToolSpaces() {
			switch space.text {
			case "\r", "\u00a0", "\u202f", "\u0085", "\u3000":
			default:
				continue
			}
			if !patchEdgeShellReadsSpace(route, space.text) {
				continue
			}
			for _, spelling := range patchEdgeSpellings(space.text) {
				for _, protected := range []bool{true, false} {
					t.Run(fmt.Sprintf("%s/%s/%s/protected %t", route, space.name, spelling.name, protected), func(t *testing.T) {
						path, text := "/etc/ld.so.preload", "/usr/local/lib/liblogger.so"
						if !protected {
							path, text = filepath.Join(project, "notes.txt"), "hello"
						}
						body := patchEdgeBody(t, route, project, spelling.patch(path, text))
						store, logger := testStoreAndLogger(t)
						cfg := config.DefaultConfig()
						cfg.DataDir = t.TempDir()
						cfg.DeploymentMode = managed.DeploymentModeManagedEnterprise
						cfg.Enterprise.Profile = managed.ProfileStandalone
						cfg.Guardrail.Mode, cfg.Guardrail.HookFailMode, cfg.Guardrail.Connector = "action", "closed", "codex"
						api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth(), store: store, logger: logger}
						req := httptest.NewRequest(http.MethodPost, "/api/v1/codex/hook", strings.NewReader(body))
						req.Header.Set("Content-Type", "application/json")
						req.Header.Set(hookpaths.Header, hookpaths.ResolveConnector("codex", "", "preToolUse", []byte(body)))
						setTestCodexHookBinding(req, "PreToolUse", defaultTestCodexHookContract)
						req = req.WithContext(withManagedHookPeer(req.Context(), managedHookPeer{Home: home}))
						recorder := httptest.NewRecorder()
						api.handleAgentHook("codex").ServeHTTP(recorder, req)
						action := overLimitHookAction(t, recorder.Body.String())
						if protected && action != "block" {
							t.Errorf("managed protected patch action=%s: %.350s", action, recorder.Body.String())
						}
						if !protected && action == "block" {
							t.Errorf("managed ordinary patch blocked: %.350s", recorder.Body.String())
						}
					})
				}
			}
		}
	}
}
