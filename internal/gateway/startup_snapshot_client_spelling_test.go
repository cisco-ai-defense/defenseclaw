// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// r105StartWithout starts p's session in cwd with the hook client's
// SessionStart evidence minus keys, as when they do not fit the header
// (GAP-1508): the startup snapshot and the client cwd stay, the directory
// identities are gone.
func r105StartWithout(t *testing.T, p *linkedCodexProject, cwd string, keys ...string) {
	t.Helper()
	raw := mustJSON(t, map[string]interface{}{"hook_event_name": "SessionStart", "session_id": "linked", "cwd": cwd, "source": "startup"})
	facts, ok := hookpaths.Decode(hookpaths.ResolveConnector("codex", "", "SessionStart", raw))
	if !ok {
		t.Fatal("no SessionStart evidence")
	}
	for _, key := range keys {
		delete(facts, key)
	}
	encoded, err := json.Marshal(facts)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/codex/hook", bytes.NewReader(raw))
	req.Header.Set("X-DefenseClaw-Hook-Event", "SessionStart")
	req.Header.Set("X-DefenseClaw-Hook-Contract", p.api.hookProfileForConnector("codex").ContractID)
	req.Header.Set(hookpaths.Header, base64.RawURLEncoding.EncodeToString(encoded))
	ctx := withManagedHookPeer(withAuthenticatedHookConnector(context.Background(), "codex"), managedHookPeer{UID: os.Getuid(), Home: p.home})
	if p.gw.hide {
		if err := os.Chmod(p.home, 0); err != nil {
			t.Fatal(err)
		}
		defer func() { _ = os.Chmod(p.home, 0o700) }()
	}
	rec := httptest.NewRecorder()
	p.handler(rec, req.WithContext(ctx))
	if rec.Code != http.StatusOK {
		t.Fatalf("SessionStart status %d: %s", rec.Code, rec.Body.String())
	}
}

// GAP-1508 (P1). A managed Codex session starts in a symlinked spelling of
// a project with a pre-existing AGENTS.md, and its SessionStart evidence
// lost the directory identities (header overflow). The gateway never records
// the physical directory as empty from that: the snapshot keeps the client's
// directories with the files it found, a gateway that can stat them adds
// their identities itself, and every write to the AGENTS.md the session
// started with blocks in action, from both working directories, also behind
// ProtectHome (the ../ case there is GAP-1501, routed to classifier).
func TestR105GAP1508HeaderOverflowKeepsTheSymlinkedStartupFile(t *testing.T) {
	for _, gw := range linkedCodexGateways[1:] {
		probe := newLinkedCodexProject(t, gw, "action")
		for _, w := range linkedWrites(probe) {
			if w.name == "parent from the linked subdirectory" {
				// The client names the lexical parent of a symlinked cwd
				// and, without its directory sighting, the physical parent
				// keeps the call-time proof (GAP-1501, classifier seam).
				continue
			}
			t.Run(gw.name+", "+w.name, func(t *testing.T) {
				p := newLinkedCodexProject(t, gw, "action")
				writeActiveAgentTestFile(t, p.real, "AGENTS.md")
				r105StartWithout(t, p, p.link, hookpaths.ReachedInstructionsKey)
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
}

// Benign corpus (GAP-1508 with GAP-1514): the same overflowed start, on a
// managed gateway that can stat the project, leaves the AGENTS.md the
// session creates its own in every edit form from both spellings.
func TestR105GAP1508BenignHeaderOverflowSessionCreatedFile(t *testing.T) {
	p := newLinkedCodexProject(t, linkedCodexGateways[1], "action")
	r105StartWithout(t, p, p.link, hookpaths.ReachedInstructionsKey)
	if action, findings := p.patch(p.link, sightingAddPatch); cogBlocked(action, false, findings) {
		t.Fatalf("creating AGENTS.md was blocked: %v", findings)
	}
	writeActiveAgentTestFile(t, p.real, "AGENTS.md")
	for _, w := range linkedWrites(p) {
		if action, findings := w.run(); cogBlocked(action, false, findings) {
			t.Fatalf("%s of the session's own AGENTS.md was blocked: %v", w.name, findings)
		}
	}
}
