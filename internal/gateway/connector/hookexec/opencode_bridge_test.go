// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// openCodeBridgeAnswer decodes the single JSON line the managed OpenCode
// plugin reads.
func openCodeBridgeAnswer(t *testing.T, stdout string) map[string]any {
	t.Helper()
	lines := strings.Split(strings.TrimSpace(stdout), "\n")
	if len(lines) != 1 {
		t.Fatalf("want exactly one JSON line, got %q", stdout)
	}
	var answer map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &answer); err != nil {
		t.Fatalf("answer is not JSON: %q: %v", stdout, err)
	}
	return answer
}

func openCodeBridgeDecision(t *testing.T, stdout string) (string, string) {
	t.Helper()
	output, _ := openCodeBridgeAnswer(t, stdout)["hook_output"].(map[string]any)
	decision, _ := output["decision"].(string)
	reason, _ := output["reason"].(string)
	return decision, reason
}

// The managed OpenCode plugin delegates each event to the hook binary; the
// binary forwards the plugin's payload unchanged and hands back the whole
// gateway answer so the plugin applies hook_output and mode itself.
func TestOpenCodeBridgeEchoesTheGatewayAnswer(t *testing.T) {
	payload := `{"hook_event_name":"tool.execute.before","tool_name":"bash","tool_input":{"command":"ls"},"arguments_authoritative":true}`
	for _, tc := range []struct {
		name     string
		body     string
		decision string
	}{
		{"allow", `{"action":"allow","mode":"action","hook_output":{"decision":"allow"}}`, "allow"},
		{"deny", "{\n  \"action\": \"block\",\n  \"mode\": \"action\",\n  \"hook_output\": {\"decision\": \"deny\", \"reason\": \"policy marker\"}\n}", "deny"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result := run(t, "opencode", ok(tc.body), func(opts *Options) {
				opts.Event = "tool.execute.before"
				opts.FailMode = "closed"
				opts.Stdin = strings.NewReader(payload)
			})
			if result.code != 0 {
				t.Fatalf("a gateway answer exits 0, got %d; stderr=%s", result.code, result.stderr)
			}
			if got := result.rt.gotReq.URL.Path; got != "/api/v1/opencode/hook" {
				t.Fatalf("endpoint = %s", got)
			}
			if got := result.rt.gotReq.Header.Get("X-DefenseClaw-Client"); got != "opencode-plugin/1.0" {
				t.Fatalf("client header = %q", got)
			}
			if string(result.rt.gotBody) != payload {
				t.Fatalf("payload must be forwarded unchanged:\n%s", result.rt.gotBody)
			}
			answer := openCodeBridgeAnswer(t, result.stdout)
			if answer["mode"] != "action" {
				t.Fatalf("mode must reach the plugin: %v", answer)
			}
			if decision, _ := openCodeBridgeDecision(t, result.stdout); decision != tc.decision {
				t.Fatalf("decision = %q, want %q", decision, tc.decision)
			}
		})
	}
}

// Every local, transport and response failure of the managed runtime is a
// hook_output denial with a non-zero exit, never an empty allow.
func TestOpenCodeBridgeFailuresDeny(t *testing.T) {
	managed := func(opts *Options) {
		opts.Event = "tool.execute.before"
		opts.ManagedEnterprise = true
		opts.StrictAvailability = true
		opts.FailMode = "closed"
		opts.Stdin = strings.NewReader(`{"hook_event_name":"tool.execute.before"}`)
	}
	for _, tc := range []struct {
		name   string
		rt     *stubRT
		mutate func(*Options)
		reason string
	}{
		{"unreachable", &stubRT{err: errors.New("dial refused")}, managed, failedClosed},
		{"server error", &stubRT{status: 503, body: "busy"}, managed, failedClosed},
		{"auth refused", &stubRT{status: 403, body: "{}"}, managed, failedClosed},
		{"not json", ok("not json"), managed, failedClosed},
		{"oversized", ok(`{}`), func(opts *Options) {
			managed(opts)
			opts.MaxBody = 8
		}, tooLarge},
		{"runtime invalid", ok(`{}`), func(opts *Options) {
			managed(opts)
			opts.ManagedRuntimeFailure = "enterprise_managed_runtime_state_invalid"
		}, failedClosed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result := run(t, "opencode", tc.rt, tc.mutate)
			if result.code == 0 {
				t.Fatalf("a failure must not exit 0; stdout=%s", result.stdout)
			}
			decision, reason := openCodeBridgeDecision(t, result.stdout)
			if decision != "deny" || reason != tc.reason {
				t.Fatalf("decision=%q reason=%q, want deny %q", decision, reason, tc.reason)
			}
		})
	}
}

// A foreign-plugin guard denial reaches the user with its reason (which
// file, which allowlist key) and never contacts the gateway.
func TestOpenCodeBridgeForeignPluginBlockCarriesItsReason(t *testing.T) {
	reason := ForeignHookBlockedReasonPrefix + " The project file /repo/.opencode/plugins/rewrite.js is not approved (digest sha256:ab)."
	rt := ok(`{"action":"allow"}`)
	result := run(t, "opencode", rt, func(opts *Options) {
		opts.Event = "tool.execute.before"
		opts.ManagedEnterprise = true
		opts.ManagedRuntimeFailure = reason
		opts.Stdin = strings.NewReader(`{"hook_event_name":"tool.execute.before"}`)
	})
	if rt.requests != 0 {
		t.Fatal("a guard denial must not reach the gateway")
	}
	if result.code == 0 {
		t.Fatal("a guard denial must not exit 0")
	}
	if decision, got := openCodeBridgeDecision(t, result.stdout); decision != "deny" || got != reason {
		t.Fatalf("decision=%q reason=%q", decision, got)
	}
}
