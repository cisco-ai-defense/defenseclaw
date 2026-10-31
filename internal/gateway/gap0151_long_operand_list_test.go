// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// answerAs sends the hook request as a managed gateway behind ProtectHome
// (managed) or as a per-user gateway that reads the home itself, and
// returns "allow", "block" or a description of any other answer, with the
// answer body.
func (f b36ManagedHookFixture) answerAs(t *testing.T, connector string, payload []byte, header string, managed bool) (string, string) {
	t.Helper()
	mode := os.FileMode(0o700)
	if managed {
		mode = 0
	}
	if err := os.Chmod(f.homes, mode); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(f.homes, 0o700)
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = connector
	api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth()}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/hook", strings.NewReader(string(payload)))
	if managed && header != "" {
		req.Header.Set(hookpaths.Header, header)
	}
	if connector == "codex" {
		setTestCodexHookBinding(req, "PreToolUse", defaultTestCodexHookContract)
	}
	if managed {
		req = req.WithContext(withManagedHookPeer(req.Context(), managedHookPeer{Home: f.home}))
	}
	recorder := httptest.NewRecorder()
	api.handleAgentHook(connector).ServeHTTP(recorder, req)
	body := recorder.Body.String()
	switch {
	case strings.HasPrefix(body, `{"action":"block"`):
		return "block", body
	case strings.HasPrefix(body, `{"action":"allow"`):
		return "allow", body
	}
	return fmt.Sprintf("status %d body %.200s", recorder.Code, body), body
}

// postAs is the verdict of answerAs.
func (f b36ManagedHookFixture) postAs(t *testing.T, connector string, payload []byte, header string, managed bool) string {
	t.Helper()
	verdict, _ := f.answerAs(t, connector, payload, header, managed)
	return verdict
}

// gap0151Operands is N benign touch operands with the protected keys path
// first, in the middle or last, or not at all ("none", the benign twin).
func gap0151Operands(n int, position, protected string) string {
	words := make([]string, 0, n+1)
	for i := 0; i < n; i++ {
		words = append(words, fmt.Sprintf("h%04d", i))
	}
	switch position {
	case "first":
		words = append([]string{protected}, words...)
	case "middle":
		words = append(words[:n/2], append([]string{protected}, words[n/2:]...)...)
	case "last":
		words = append(words, protected)
	}
	return strings.Join(words, " ")
}

// TestGAP0151LongOperandListKeepsProtectedTarget is rel-1-0-6 GAP-0151: a
// managed touch of more operands than ActionFacts reads (256) that names the
// protected keys file was allowed, because no path fact named the operands
// and the hook client's concrete reading saw none either, while a per-user
// gateway blocks it with its whole-command decision. The client now sends
// that decision, ahead of every operand, so the managed answer matches the
// per-user one at every size and position, for both connectors. Benign
// twins of the same length stay allowed.
func TestGAP0151LongOperandListKeepsProtectedTarget(t *testing.T) {
	f := newB36ManagedHookFixture(t)
	for _, n := range []int{100, 500, 511, 512, 513, 600, 2000} {
		for _, position := range []string{"none", "first", "middle", "last"} {
			for _, protected := range []string{"~/.ssh/authorized_keys", f.keys} {
				if position == "none" && protected != f.keys {
					continue
				}
				command := "cd ordinary && touch " + gap0151Operands(n, position, protected)
				payload := f.payload(t, command)
				header := f.clientHeader(t, payload)
				targets, ok := hookpaths.Decode(header)
				if !ok {
					t.Fatalf("n=%d %s: client header does not decode", n, position)
				}
				want := "block"
				if position == "none" {
					want = "allow"
				}
				if decided := targets[hookpaths.ActionDecisionKey] == hookpaths.ProtectedTargetDecision; decided != (want == "block") {
					t.Errorf("n=%d %s %s: client protected-target fact = %v, want %v", n, position, protected, decided, want == "block")
				}
				for _, connector := range []string{"claudecode", "codex"} {
					for _, managed := range []bool{true, false} {
						if got := f.postAs(t, connector, payload, header, managed); got != want {
							t.Errorf("n=%d %s %s %s managed=%v: verdict %s, want %s", n, position, protected, connector, managed, got, want)
						}
					}
				}
			}
		}
	}
}

// TestGAP0151DecisionSurvivesFullMap fills the bounded map past its entry
// and byte bounds with benign redirects before the protected touch: the
// protected-target fact is still in the map, so the managed answer names
// the protected write, not only the omitted operands.
func TestGAP0151DecisionSurvivesFullMap(t *testing.T) {
	f := newB36ManagedHookFixture(t)
	var filler strings.Builder
	filler.WriteString("echo hi")
	for i := 0; i < 600; i++ {
		fmt.Fprintf(&filler, " > ordinary/filler%03d", i)
	}
	for _, tail := range []string{
		" && touch " + gap0151Operands(600, "last", "~/.ssh/authorized_keys"),
		" && touch " + gap0151Operands(300, "first", f.keys),
	} {
		payload := f.payload(t, filler.String()+tail)
		header := f.clientHeader(t, payload)
		targets, ok := hookpaths.Decode(header)
		if !ok || targets[hookpaths.TruncatedKey] != "1" {
			t.Fatal("client header is not a full bounded map")
		}
		if targets[hookpaths.ActionDecisionKey] != hookpaths.ProtectedTargetDecision {
			t.Errorf("full map lost the protected-target fact")
		}
		for _, connector := range []string{"claudecode", "codex"} {
			if got := f.post(t, connector, payload, header); got != "block" {
				t.Errorf("%s: verdict %s, want block", connector, got)
			}
		}
	}
}
