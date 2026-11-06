// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

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
)

// gap0055ServePack answers call as serve does, with rulePack ("" is the
// default pack, "strict" the strict one).
func (f b36ManagedHookFixture) gap0055ServePack(call *hookCall, rulePack string) (string, string) {
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = call.connector
	cfg.Guardrail.RulePack = rulePack
	api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth()}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/hook", strings.NewReader(string(call.payload)))
	if call.managed && call.header != "" {
		req.Header.Set(hookpaths.Header, call.header)
	}
	if call.connector == "codex" {
		setTestCodexHookBinding(req, "PreToolUse", defaultTestCodexHookContract)
	}
	if call.managed {
		req = req.WithContext(withManagedHookPeer(req.Context(), managedHookPeer{Home: f.home}))
	}
	recorder := httptest.NewRecorder()
	api.handleAgentHook(call.connector).ServeHTTP(recorder, req)
	body := recorder.Body.String()
	switch {
	case strings.HasPrefix(body, `{"action":"block"`):
		return "block", body
	case strings.HasPrefix(body, `{"action":"allow"`):
		return "allow", body
	}
	return fmt.Sprintf("status %d body %.200s", recorder.Code, body), body
}

// TestGAP0055SuppliedArchiveModeIsPossibleGrade is gas-ux-r1 GAP-0055 round
// 4 (ROOTCAUSE-CROSS-1 Rule G): an archive call whose arguments come from an
// argument supplier and that shows a list or test mode (xargs unzip -v) may
// still extract through the supplied words, so a later write it could
// redirect is a Possible hit. The default pack allows it with a visible
// alert-only finding; the strict pack blocks it. A later write whose target
// is Named (the project's link to authorized_keys) blocks in both packs, and
// a supplied call that shows no mode (xargs unzip) keeps its block. Both
// connectors, managed and per-user.
func TestGAP0055SuppliedArchiveModeIsPossibleGrade(t *testing.T) {
	f := newB36ManagedHookFixture(t)
	if err := os.WriteFile(filepath.Join(f.project, "a.txt"), []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(f.project, "build"), 0o700); err != nil {
		t.Fatal(err)
	}
	rows := []struct {
		name, command    string
		balanced, strict string
		possible         bool
	}{
		{"possible", `ls *.zip | xargs unzip -v; cp a.txt build/`, "allow", "block", true},
		{"possible-n1-and", `ls *.zip | xargs -n1 unzip -v && cp a.txt build/`, "allow", "block", true},
		{"possible-replace", `ls *.zip | xargs -I{} unzip -v {}; cp a.txt build/`, "allow", "block", true},
		{"possible-sudo", `ls *.zip | xargs sudo unzip -v; cp a.txt build/`, "allow", "block", true},
		{"named-copy", `ls *.zip | xargs unzip -v; cp a.txt keylink`, "block", "block", false},
		{"named-redirect", `ls *.zip | xargs unzip -v; echo hi > keylink`, "block", "block", false},
		{"named-after-possible-and-unseen", `ls *.zip | xargs unzip -v; ls *.zip | xargs unzip; cp a.txt build/`, "block", "block", false},
		{"unseen", `ls *.zip | xargs unzip; cp a.txt build/`, "block", "block", false},
		{"unseen-overwrite", `ls *.zip | xargs unzip -o; cp a.txt build/`, "block", "block", false},
		{"direct-version", `unzip -v; cp a.txt build/`, "allow", "", false},
	}
	if err := os.Chmod(f.homes, 0o700); err != nil {
		t.Fatal(err)
	}
	var calls []*hookCall
	for _, row := range rows {
		payload := f.payload(t, row.command)
		calls = append(calls, everyMode(row.name, payload, hookpaths.Resolve(payload))...)
	}
	defer os.Chmod(f.homes, 0o700)
	for _, pack := range []string{"", "strict"} {
		for _, managed := range []bool{false, true} {
			mode := os.FileMode(0o700)
			if managed {
				mode = 0
			}
			if err := os.Chmod(f.homes, mode); err != nil {
				t.Fatal(err)
			}
			for i, call := range calls {
				if call.managed != managed {
					continue
				}
				row := rows[i/4]
				want := row.balanced
				if pack == "strict" {
					want = row.strict
				}
				verdict, body := f.gap0055ServePack(call, pack)
				if strings.HasPrefix(body, `{"action":"alert"`) {
					verdict = "allow" // alert: allowed with a visible warning
				}
				if want != "" && verdict != want {
					t.Errorf("%s pack=%q: verdict %s, want %s; body %.400s", call.name, pack, verdict, want, body)
				}
				if row.possible && pack == "" && !strings.Contains(body, "supplied arguments") {
					t.Errorf("%s pack=%q: no visible Possible finding; body %.300s", call.name, pack, body)
				}
			}
		}
	}
}
