// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// substrate-1 GAP-0257: a refused request records as refused only what the
// refusal is attributed to, so the text sent next to the refused turn (a
// benign co-turn, a tool result) goes on when the client sends it back.
// Uses only what 1257d7f5be had (fail-before there).

// A refused turn with a benign co-turn and a tool result in the same
// request: later only the refused turn is removed.
func TestGAP0257OnlyTheRefusedTurnIsRedacted(t *testing.T) {
	covAllowPrivate(t)
	const coTurn, toolOut = "please continue", "the tool says all is fine"
	for _, managed := range []bool{false, true} {
		covSetManaged(t, managed)
		for _, w := range f14Wires() {
			for _, stream := range []bool{false, true} {
				t.Run(fmt.Sprintf("managed=%v/%s/stream=%v", managed, w.name, stream), func(t *testing.T) {
					rg := newF14Rig(t, w.provider, "action")
					c := f14Caller{session: "blame", owner: true}
					first := []f14Item{{"user", "hello"}, {"tool", toolOut}, {"user", coTurn}, {"user", "please " + covMarker}}
					if fwd, _ := rg.post(t, w, c, first, stream); fwd {
						t.Fatal("the marker as the current turn was not refused")
					}
					next := append(append([]f14Item{}, first...), f14Item{"assistant", "[DefenseClaw] blocked"}, f14Item{"user", "a harmless sentence"})
					fwd, rec := rg.post(t, w, c, next, stream)
					if !fwd {
						t.Fatalf("the benign turn after a refused one was refused (status %d): %s", rec.Code, rec.Body)
					}
					body := rg.lastBody()
					if bytes.Contains(body, []byte(covMarker)) {
						t.Errorf("the refused text reached the upstream: %s", body)
					}
					for _, keep := range []string{coTurn, toolOut, "a harmless sentence"} {
						if !bytes.Contains(body, []byte(keep)) {
							t.Errorf("%q sent next to the refused turn was removed: %s", keep, body)
						}
					}
					if n := strings.Count(string(body), "Removed by DefenseClaw policy"); n != 1 {
						t.Errorf("%d placeholders, want 1 (the refused turn): %s", n, body)
					}
				})
			}
		}
	}
}

// A refusal no current turn is blamed for alone (here the system text)
// cannot be attributed: the current scope is recorded refused, as before
// (fail safe), so the co-turn is removed later.
func TestGAP0257UnattributedRefusalRecordsTheCurrentScope(t *testing.T) {
	covAllowPrivate(t)
	rg := newF14Rig(t, "openai", "action")
	post := func(body map[string]any) bool {
		t.Helper()
		before := rg.hits()
		req := httptest.NewRequest(http.MethodPost, "/v1/responses", bytes.NewReader(covJSON(t, body)))
		req = req.WithContext(ContextWithSessionID(req.Context(), "unattributed"))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-DC-Target-URL", rg.capt.URL)
		req.Header.Set("X-AI-Auth", "Bearer test-key")
		req.Header.Set("X-DC-Auth", "Bearer "+f14GatewayToken)
		req.RemoteAddr = "127.0.0.1:12345"
		rg.proxy.handlePassthrough(httptest.NewRecorder(), req)
		return rg.hits() > before
	}
	user := func(s string) map[string]any {
		return map[string]any{"type": "message", "role": "user", "content": []any{map[string]any{"type": "input_text", "text": s}}}
	}
	if post(map[string]any{"model": "dc-test-model", "instructions": covMarker, "input": []any{user("please continue")}}) {
		t.Fatal("the marker in the instructions was not refused")
	}
	if !post(map[string]any{"model": "dc-test-model", "instructions": "be brief", "input": []any{user("please continue"),
		map[string]any{"type": "message", "role": "assistant", "content": []any{map[string]any{"type": "output_text", "text": "[DefenseClaw] blocked"}}},
		user("a harmless sentence")}}) {
		t.Fatal("the benign turn was refused")
	}
	if body := rg.lastBody(); bytes.Contains(body, []byte("please continue")) || !bytes.Contains(body, []byte("Removed by DefenseClaw policy")) {
		t.Errorf("an unattributed refusal did not record its current turn refused: %s", body)
	}
}
