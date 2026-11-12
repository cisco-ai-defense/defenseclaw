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

// patchEdgeSpaces are one representative of each class of space the old
// parser left unread and the patch tool trims: a lone carriage return, a
// no-break space and a space of the U+2000 range. The exhaustive list of
// tool-trimmed spaces runs in the actionfacts unit test
// (TestPatchEnvelopeEdgeSpacesAreTheSpacesTheToolTrims).
var patchEdgeSpaces = []struct{ name, text string }{
	{"lone CR", "\r"},
	{"NBSP", "\u00a0"},
	{"em space", "\u2003"},
}

type patchEdgeSpelling struct {
	name        string
	beginMarker string
	suffix      string
}

// patchEdgeSpellings pads one patch after its End marker and after its Begin
// marker, the two places the tool trims.
func patchEdgeSpellings(space string) []patchEdgeSpelling {
	return []patchEdgeSpelling{
		{name: "trailing", suffix: space},
		{name: "begin line", beginMarker: space},
	}
}

func (s patchEdgeSpelling) patch(target, text string) string {
	return "*** Begin Patch" + s.beginMarker + "\n*** Add File: " + target + "\n+" + text +
		"\n*** End Patch" + s.suffix
}

const patchEdgeLoaderRule = "persistence.global_ld_preload_install"

// patchEdgeBody builds the Codex hook body of a patch on the typed route or
// the shell route (an apply_patch here-document).
func patchEdgeBody(t *testing.T, route, project, patch string) string {
	t.Helper()
	if route == "typed" {
		return (nativeWriteCall{"codex", "apply_patch", func(string) map[string]any { return map[string]any{"command": patch} }}).body(t, project, project)
	}
	return string(mustJSON(t, map[string]any{
		"hook_event_name": "PreToolUse", "session_id": "edge-space-codex", "turn_id": "t1", "cwd": project,
		"tool_name": "exec_command", "tool_use_id": "u1",
		"tool_input": map[string]any{"cmd": "apply_patch <<\x27PATCH\x27\n" + patch + "\nPATCH\n", "workdir": project},
	}))
}

// TestPatchEnvelopeEdgeWhiteSpaceKeepsContentRuleVerdict pins that a patch
// padded at its edges with a space the patch tool trims is judged by the
// content rules like the plain patch, in the default and the strict profile,
// on the typed and the shell route: the loader-preload file and a link to it
// are blocked, an ordinary file stays allowed.
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
		{"ordinary", filepath.Join(project, "notes.txt"), "hello", false},
	}
	for _, route := range []string{"typed", "shell"} {
		for _, space := range patchEdgeSpaces {
			for _, spelling := range patchEdgeSpellings(space.text) {
				for _, target := range targets {
					for _, pack := range []string{"", "strict"} {
						t.Run(fmt.Sprintf("%s/%s/%s/%s/%s", route, space.name, spelling.name, target.name, pack), func(t *testing.T) {
							body := patchEdgeBody(t, route, project, spelling.patch(target.path, target.text))
							got := overLimitHostHookInPack(t, "codex", pack, home, body,
								hookpaths.ResolveConnector("codex", "", "preToolUse", []byte(body)))
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
	spelling := patchEdgeSpellings(patchEdgeSpaces[0].text)[0]
	store, logger := testStoreAndLogger(t)
	cfg := config.DefaultConfig()
	cfg.DataDir = t.TempDir()
	cfg.DeploymentMode = managed.DeploymentModeManagedEnterprise
	cfg.Enterprise.Profile = managed.ProfileStandalone
	cfg.Guardrail.Mode, cfg.Guardrail.HookFailMode, cfg.Guardrail.Connector = "action", "closed", "codex"
	api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth(), store: store, logger: logger}
	for _, route := range []string{"typed", "shell"} {
		for _, protected := range []bool{true, false} {
			t.Run(fmt.Sprintf("%s/protected %t", route, protected), func(t *testing.T) {
				path, text := "/etc/ld.so.preload", "/usr/local/lib/liblogger.so"
				if !protected {
					path, text = filepath.Join(project, "notes.txt"), "hello"
				}
				body := patchEdgeBody(t, route, project, spelling.patch(path, text))
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
