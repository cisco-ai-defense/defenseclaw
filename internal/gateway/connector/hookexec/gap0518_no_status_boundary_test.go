// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"strings"
	"testing"
	"time"
)

func TestGAP0518NoStatusKeepsToolCallClosed(t *testing.T) {
	shortAnswerBudget(t, 300*time.Millisecond)
	addr := hungGateway(t)
	client, err := NewPerUserGatewayHTTPClient(2*time.Second, addr)
	if err != nil {
		t.Fatal(err)
	}
	for _, command := range []string{
		"cp a.txt .ssh/authorized_keys",
		"echo marker >> .ssh/authorized_keys",
	} {
		t.Run(command, func(t *testing.T) {
			result, _ := runAgainstGateway(t, "claudecode", addr, func(opts *Options) {
				opts.HTTPClient = client
				opts.FailMode = "open"
				opts.OutageFailModeNow = func() string { return "open" }
				opts.Stdin = strings.NewReader(`{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":` + mustJSONString(command) + `}}`)
			})
			if !claudeBlocked(result) {
				t.Fatalf("no-status call was allowed: code=%d stdout=%q stderr=%q", result.code, result.stdout, result.stderr)
			}
		})
	}
}
