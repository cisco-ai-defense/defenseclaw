// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

const (
	openCodeGatewayBlock   = `{"action":"block","mode":"action","severity":"CRITICAL","reason":"matched: TEST-MARKER","hook_output":{"decision":"deny","reason":"matched: TEST-MARKER"}}`
	openCodeGatewayConfirm = `{"action":"alert","raw_action":"confirm","mode":"action","severity":"HIGH","reason":"matched: TEST-CONFIRM-MARKER"}`
)

// OpenCode shows a plugin block as the tool's error and hands it to the
// model, so the error says DefenseClaw blocked the call under policy and that
// it did not run; a bare rule reason read like tool output and the model
// reported success. A confirm (human-in-the-loop) verdict, which this bridge
// cannot ask about, shows a visible notice instead of running silently.
func TestOpenCodePluginBlockAndConfirmAreVisible(t *testing.T) {
	server := openCodeStubGateway(t, openCodeGatewayBlock, openCodeGatewayConfirm)
	lines := runOpenCodePluginHarness(t, openCodePluginTestData(t, server), 2)
	if len(lines) != 3 {
		t.Fatalf("harness output = %q", lines)
	}
	if want := "block:DefenseClaw blocked this tool call under policy, so it did not run: matched: TEST-MARKER"; lines[0] != want {
		t.Fatalf("block = %q, want %q", lines[0], want)
	}
	if lines[1] != "allow" {
		t.Fatalf("a confirm verdict still runs the call here: %q", lines[1])
	}
	var toasts []struct {
		Message string `json:"message"`
		Variant string `json:"variant"`
	}
	if err := json.Unmarshal([]byte(strings.TrimPrefix(lines[2], "toasts:")), &toasts); err != nil {
		t.Fatalf("toasts %q: %v", lines[2], err)
	}
	// The block is also shown as an error notice: some OpenCode versions show
	// a failed tool with no text.
	if len(toasts) != 2 || toasts[0].Variant != "error" ||
		toasts[0].Message != strings.TrimPrefix(lines[0], "block:") {
		t.Fatalf("block notice = %+v", toasts)
	}
	if toasts[1].Variant != "warning" ||
		!strings.HasPrefix(toasts[1].Message, "DefenseClaw flagged this tool call for review (HIGH): matched: TEST-CONFIRM-MARKER.") {
		t.Fatalf("confirm notice = %+v", toasts)
	}
}

// A reason that already starts with DefenseClaw (fail-closed and credential
// failures) is shown as is.
func TestOpenCodePluginKeepsDefenseClawReasons(t *testing.T) {
	server := openCodeStubGateway(t, `{"action":"block","mode":"action","hook_output":{"decision":"deny","reason":"DefenseClaw blocked the command under policy."}}`)
	lines := runOpenCodePluginHarness(t, openCodePluginTestData(t, server), 1)
	if len(lines) != 2 || lines[0] != "block:DefenseClaw blocked the command under policy." ||
		lines[1] != `toasts:[{"message":"DefenseClaw blocked the command under policy.","variant":"error"}]` {
		t.Fatalf("harness output = %q", lines)
	}
}

// The Secure Client render keeps its pinned behavior.
func TestOpenCodePluginSecureClientRenderKeepsItsText(t *testing.T) {
	server := openCodeStubGateway(t, openCodeGatewayBlock, openCodeGatewayConfirm)
	data := openCodePluginTestData(t, server)
	data.Managed = true
	lines := runOpenCodePluginAssetHarness(t, secureClientPluginAssets["opencode-plugin.js"], data, 2)
	if len(lines) != 3 || lines[0] != "block:matched: TEST-MARKER" || lines[1] != "allow" || lines[2] != "toasts:[]" {
		t.Fatalf("harness output = %q", lines)
	}
}

// GAP-0535: a gateway that is taking all the hook calls it can answers 429
// with Retry-After before it evaluates the call. The plugin waits and sends
// the call again instead of failing it closed.
func TestOpenCodePluginRetriesBusyGateway(t *testing.T) {
	var busy atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(string(body), `"tool.execute.before"`) && !busy.Swap(true) {
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = io.WriteString(w, `{"error":"rate_limited"}`)
			return
		}
		_, _ = io.WriteString(w, `{"action":"allow","mode":"action"}`)
	}))
	t.Cleanup(server.Close)
	lines := runOpenCodePluginHarness(t, openCodePluginTestData(t, server), 1)
	if len(lines) == 0 || lines[0] != "allow" {
		t.Fatalf("busy gateway: harness output = %q, want one retry and an allow", lines)
	}
}
