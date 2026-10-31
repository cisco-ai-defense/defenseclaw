// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// hookCall is one hook request of a table, sent as a managed gateway behind
// ProtectHome (managed) or as a per-user gateway that reads the home, and
// its answer: "allow", "block" or a description, and the body.
type hookCall struct {
	name      string
	connector string
	payload   []byte
	header    string
	managed   bool
	verdict   string
	body      string
}

// eachConcurrently runs work for every index on all processors.
func eachConcurrently(n int, work func(int)) {
	var wg sync.WaitGroup
	slots := make(chan struct{}, runtime.GOMAXPROCS(0))
	for i := range n {
		wg.Add(1)
		slots <- struct{}{}
		go func() {
			defer func() { <-slots; wg.Done() }()
			work(i)
		}()
	}
	wg.Wait()
}

// clientHeaders computes the real hook client's header of every payload,
// as the user, concurrently.
func (f b36ManagedHookFixture) clientHeaders(t *testing.T, payloads [][]byte) []string {
	t.Helper()
	if err := os.Chmod(f.homes, 0o700); err != nil {
		t.Fatal(err)
	}
	headers := make([]string, len(payloads))
	eachConcurrently(len(payloads), func(i int) { headers[i] = hookpaths.Resolve(payloads[i]) })
	return headers
}

// answerAll answers every call: the per-user calls with the home readable,
// then the managed calls with it unsearchable, each group concurrently, so
// a large table costs about its rows divided by the processors.
func (f b36ManagedHookFixture) answerAll(t *testing.T, calls []*hookCall) {
	t.Helper()
	defer os.Chmod(f.homes, 0o700)
	for _, managed := range []bool{false, true} {
		mode := os.FileMode(0o700)
		if managed {
			mode = 0
		}
		if err := os.Chmod(f.homes, mode); err != nil {
			t.Fatal(err)
		}
		var group []*hookCall
		for _, call := range calls {
			if call.managed == managed {
				group = append(group, call)
			}
		}
		eachConcurrently(len(group), func(i int) { group[i].verdict, group[i].body = f.serve(group[i]) })
	}
}

// serve answers one call; the caller sets the home mode for its group.
func (f b36ManagedHookFixture) serve(call *hookCall) (string, string) {
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = call.connector
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

// everyMode is the call for both connectors, managed and per-user.
func everyMode(name string, payload []byte, header string) []*hookCall {
	var calls []*hookCall
	for _, connector := range []string{"claudecode", "codex"} {
		for _, managed := range []bool{true, false} {
			calls = append(calls, &hookCall{name: fmt.Sprintf("%s %s managed=%v", name, connector, managed),
				connector: connector, payload: payload, header: header, managed: managed})
		}
	}
	return calls
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
// per-user one at every size and position, for both connectors; 255 and
// 256 benign operands put the keys path just past the argv bound while the
// analysis is only partial. Benign twins of the same length stay allowed.
// The rows run concurrently. A race build (the CI gateway shards, about 20
// times slower) runs one size of each reading: within the bounds, just past
// the argv bound, and past the analysis limits; every position, twin,
// spelling, connector and mode stays.
func TestGAP0151LongOperandListKeepsProtectedTarget(t *testing.T) {
	f := newB36ManagedHookFixture(t)
	type row struct {
		name, command string
		protected     bool
	}
	sizes := []int{100, 255, 256, 500, 511, 512, 513, 600, 2000}
	if hookAnswerRaceBuild {
		sizes = []int{100, 256, 513}
	}
	var rows []row
	for _, n := range sizes {
		for _, position := range []string{"none", "first", "middle", "last"} {
			for _, protected := range []string{"~/.ssh/authorized_keys", f.keys} {
				if position == "none" && protected != f.keys {
					continue
				}
				rows = append(rows, row{fmt.Sprintf("n=%d %s %s", n, position, protected),
					"cd ordinary && touch " + gap0151Operands(n, position, protected), position != "none"})
			}
		}
	}
	payloads := make([][]byte, len(rows))
	for i, r := range rows {
		payloads[i] = f.payload(t, r.command)
	}
	headers := f.clientHeaders(t, payloads)
	var calls []*hookCall
	for i, r := range rows {
		targets, ok := hookpaths.Decode(headers[i])
		if !ok {
			t.Fatalf("%s: client header does not decode", r.name)
		}
		if decided := targets[hookpaths.ActionDecisionKey] == hookpaths.ProtectedTargetDecision; decided != r.protected {
			t.Errorf("%s: client protected-target fact = %v, want %v", r.name, decided, r.protected)
		}
		calls = append(calls, everyMode(r.name, payloads[i], headers[i])...)
	}
	f.answerAll(t, calls)
	for i, call := range calls {
		want := "allow"
		if rows[i/4].protected {
			want = "block"
		}
		if call.verdict != want {
			t.Errorf("%s: verdict %s, want %s", call.name, call.verdict, want)
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
