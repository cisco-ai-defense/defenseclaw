// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// linkedCodexGateway is how the gateway meets the caller's project: a
// per-user gateway reads it; a managed POSIX gateway may read it (a project
// it can stat) or not (ProtectHome).
type linkedCodexGateway struct {
	name    string
	managed bool
	hide    bool
}

var linkedCodexGateways = []linkedCodexGateway{
	{"per-user", false, false},
	{"managed", true, false},
	{"managed ProtectHome", true, true},
}

// linkedCodexProject drives the Codex hook handler for a project the agent
// reaches through a symlink (GAP-1493): real is the physical project,
// link a symlink to it, sub a symlink to its subdirectory. Each body is
// resolved as the hook client does (its evidence header) before the
// request; behind ProtectHome the home is closed for the gateway's request.
type linkedCodexProject struct {
	t       *testing.T
	api     *APIServer
	gw      linkedCodexGateway
	handler http.HandlerFunc
	home    string
	real    string
	link    string
	sub     string
}

func newLinkedCodexProject(t *testing.T, gw linkedCodexGateway, mode string) *linkedCodexProject {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("POSIX symlinked working directories")
	}
	if gw.hide && os.Geteuid() == 0 {
		t.Skip("root reads a closed home")
	}
	home := filepath.Join(t.TempDir(), "home")
	real := filepath.Join(home, "real-project")
	if err := os.MkdirAll(filepath.Join(real, "inner"), 0o700); err != nil {
		t.Fatal(err)
	}
	link, sub := filepath.Join(home, "linked"), filepath.Join(home, "linked-inner")
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err := os.Symlink(filepath.Join(real, "inner"), sub); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(home, 0o700) })
	api := instructionProtectionTestAPI(t, "codex", mode, "HIGH")
	api.scannerCfg.DataDir = t.TempDir()
	return &linkedCodexProject{t: t, api: api, gw: gw, handler: api.handleUnifiedConnectorHook("codex"), home: home, real: real, link: link, sub: sub}
}

func (p *linkedCodexProject) post(event, cwd string, extra map[string]interface{}) (string, []string) {
	p.t.Helper()
	body := map[string]interface{}{"hook_event_name": event, "session_id": "linked", "cwd": cwd}
	for key, value := range extra {
		body[key] = value
	}
	raw := mustJSON(p.t, body)
	evidence := hookpaths.ResolveConnector("codex", "", event, raw)
	if evidence == "" {
		p.t.Fatalf("the hook sent no evidence for %s", event)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/codex/hook", bytes.NewReader(raw))
	req.Header.Set("X-DefenseClaw-Hook-Event", event)
	req.Header.Set("X-DefenseClaw-Hook-Contract", p.api.hookProfileForConnector("codex").ContractID)
	req.Header.Set(hookpaths.Header, evidence)
	ctx := withAuthenticatedHookConnector(context.Background(), "codex")
	if p.gw.managed {
		ctx = withManagedHookPeer(ctx, managedHookPeer{UID: os.Getuid(), Home: p.home})
	}
	if p.gw.hide {
		if err := os.Chmod(p.home, 0); err != nil {
			p.t.Fatal(err)
		}
		defer func() { _ = os.Chmod(p.home, 0o700) }()
		if _, err := os.Lstat(filepath.Join(p.real, "x")); err == nil || os.IsNotExist(err) {
			p.t.Skip("the home stays readable")
		}
	}
	rec := httptest.NewRecorder()
	p.handler(rec, req.WithContext(ctx))
	if rec.Code != http.StatusOK {
		p.t.Fatalf("%s status %d: %s", event, rec.Code, rec.Body.String())
	}
	var out map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		p.t.Fatalf("%s answer: %v", event, err)
	}
	action, _ := out["action"].(string)
	var findings []string
	if list, ok := out["findings"].([]interface{}); ok {
		for _, item := range list {
			if text, ok := item.(string); ok {
				findings = append(findings, text)
			}
		}
	}
	return action, findings
}

func (p *linkedCodexProject) start(cwd string) {
	p.t.Helper()
	p.post("SessionStart", cwd, map[string]interface{}{"source": "startup"})
}

func (p *linkedCodexProject) bash(cwd, command string) (string, []string) {
	p.t.Helper()
	return p.post("PreToolUse", cwd, map[string]interface{}{"tool_name": "Bash", "tool_input": map[string]interface{}{"command": command}})
}

func (p *linkedCodexProject) patch(cwd, patch string) (string, []string) {
	p.t.Helper()
	return p.post("PreToolUse", cwd, map[string]interface{}{"tool_name": "apply_patch", "tool_input": map[string]interface{}{"command": patch}})
}

// linkedWrites are the write forms of the AGENTS.md at the root of the
// project, in each spelling, from each working directory.
func linkedWrites(p *linkedCodexProject) []struct {
	name string
	run  func() (string, []string)
} {
	physical, linked := filepath.Join(p.real, "AGENTS.md"), filepath.Join(p.link, "AGENTS.md")
	return []struct {
		name string
		run  func() (string, []string)
	}{
		{"physical absolute from the link", func() (string, []string) { return p.bash(p.link, "printf x >> "+physical) }},
		{"link absolute from the link", func() (string, []string) { return p.bash(p.link, "printf x >> "+linked) }},
		{"relative from the link", func() (string, []string) { return p.bash(p.link, "printf x >> AGENTS.md") }},
		{"physical absolute from the physical directory", func() (string, []string) { return p.bash(p.real, "printf x >> "+physical) }},
		{"link absolute from the physical directory", func() (string, []string) { return p.bash(p.real, "printf x >> "+linked) }},
		{"relative from the physical directory", func() (string, []string) { return p.bash(p.real, "printf x >> AGENTS.md") }},
		{"relative patch from the link", func() (string, []string) { return p.patch(p.link, sightingUpdatePatch) }},
		{"physical patch from the link", func() (string, []string) {
			return p.patch(p.link, "*** Begin Patch\n*** Update File: "+physical+"\n@@\n-x\n+new\n*** End Patch")
		}},
		{"parent from the linked subdirectory", func() (string, []string) { return p.bash(p.sub, "printf x >> ../AGENTS.md") }},
	}
}

// Protected-target corpus (GAP-1493, P1). A Codex session started in a
// symlinked spelling of its project (or in the physical directory, writing
// through the link) keeps the AGENTS.md it started with protected in action:
// the hook client's startup snapshot names the link spelling, the gateway
// places the session in the physical directory, and both are matched by
// directory identity. Every write form, in either spelling and from either
// working directory, blocks COG-AGENTS-MD on a per-user gateway, a managed
// gateway, and a managed gateway behind ProtectHome. Observe audits only.
func TestInstructionSymlinkedCodexStartupFileStaysProtected(t *testing.T) {
	for _, gw := range linkedCodexGateways {
		for _, startLink := range []bool{true, false} {
			probe := newLinkedCodexProject(t, gw, "action")
			for _, w := range linkedWrites(probe) {
				if gw.hide && w.name == "parent from the linked subdirectory" {
					// Behind ProtectHome the hook client names the lexical
					// parent of a symlinked cwd (GAP-1501, preexisting).
					continue
				}
				t.Run(fmt.Sprintf("%s, start in link %v, %s", gw.name, startLink, w.name), func(t *testing.T) {
					p := newLinkedCodexProject(t, gw, "action")
					writeActiveAgentTestFile(t, p.real, "AGENTS.md")
					startDir := p.real
					if startLink {
						startDir = p.link
					}
					p.start(startDir)
					for _, candidate := range linkedWrites(p) {
						if candidate.name != w.name {
							continue
						}
						if action, findings := candidate.run(); action != guardrailActionBlock || !findingStringHasRuleID(findings, "COG-AGENTS-MD") {
							t.Fatalf("a write to the AGENTS.md the session started with ran: action=%q findings=%v", action, findings)
						}
					}
				})
			}
		}
		t.Run(gw.name+", observe audits only", func(t *testing.T) {
			p := newLinkedCodexProject(t, gw, "observe")
			writeActiveAgentTestFile(t, p.real, "AGENTS.md")
			p.start(p.link)
			if action, findings := p.bash(p.link, "printf x >> "+filepath.Join(p.real, "AGENTS.md")); action == guardrailActionBlock {
				t.Fatalf("observe blocked: %v", findings)
			}
		})
	}
}

// Benign corpus (GAP-1493). The AGENTS.md a Codex session creates in a
// project it reaches through a symlink is its own: creating it and editing
// it in either spelling, from either working directory, never meets an
// instruction rule in action, nor does an ordinary file write.
func TestInstructionBenignSymlinkedCodexSessionCreatedFile(t *testing.T) {
	for _, gw := range linkedCodexGateways {
		for _, startLink := range []bool{true, false} {
			t.Run(fmt.Sprintf("%s, start in link %v", gw.name, startLink), func(t *testing.T) {
				p := newLinkedCodexProject(t, gw, "action")
				startDir := p.real
				if startLink {
					startDir = p.link
				}
				p.start(startDir)
				if action, findings := p.patch(startDir, sightingAddPatch); cogBlocked(action, false, findings) {
					t.Fatalf("creating AGENTS.md was blocked: %v", findings)
				}
				writeActiveAgentTestFile(t, p.real, "AGENTS.md")
				for _, w := range linkedWrites(p) {
					if action, findings := w.run(); cogBlocked(action, false, findings) {
						t.Fatalf("%s of the session's own AGENTS.md was blocked: %v", w.name, findings)
					}
				}
				if action, findings := p.bash(p.link, "printf x >> notes.txt"); cogBlocked(action, false, findings) {
					t.Fatalf("an ordinary write was blocked: %v", findings)
				}
			})
		}
	}
}

// startupClientCWD takes the hook client's absolute directory whenever it
// spells another directory than the gateway's (GAP-1508: no identity match
// is needed, the snapshot is keyed by the spelling the client read), and
// the gateway's otherwise.
func TestStartupClientCWDTakesTheClientSpelling(t *testing.T) {
	real := filepath.Join(t.TempDir(), "real")
	link := filepath.Join(filepath.Dir(real), "link")
	cases := []struct {
		name, client, want string
	}{
		{"link", link, link},
		{"unclean link", link + string(filepath.Separator), link},
		{"other directory", filepath.Join(filepath.Dir(real), "other"), filepath.Join(filepath.Dir(real), "other")},
		{"same directory", real, real},
		{"relative", "link", real},
		{"none", "", real},
		{"NUL", link + "\x00x", real},
	}
	for _, c := range cases {
		facts := map[string]string{}
		if c.client != "" {
			facts[hookpaths.CWDKey] = c.client
		}
		if got := startupClientCWD(real, facts); got != c.want {
			t.Errorf("%s: startupClientCWD = %q, want %q", c.name, got, c.want)
		}
	}
}
