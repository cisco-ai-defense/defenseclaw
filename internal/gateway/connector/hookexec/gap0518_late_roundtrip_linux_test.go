// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package hookexec

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestGAP0518LongOrdinaryCallFollowsOutageTierAtDeadline(t *testing.T) {
	shortAnswerBudget(t, 300*time.Millisecond)
	cwd := t.TempDir()
	names := make([]string, 2000)
	for i := range names {
		names[i] = fmt.Sprintf("leaf%d.txt", i)
	}
	command := "mkdir -p " + strings.Join(names, " ")
	body := `{"hook_event_name":"PreToolUse","tool_name":"Bash","cwd":` +
		mustJSONString(cwd) + `,"tool_input":{"command":` + mustJSONString(command) + `}}`
	addr := hungGateway(t)
	for _, tc := range []struct {
		name, mode string
		allow      bool
	}{
		{"default", "open", true},
		{"strict", "closed", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result, _ := runAgainstGateway(t, "claudecode", addr, func(opts *Options) {
				opts.FailMode = tc.mode
				opts.OutageFailModeNow = func() string { return tc.mode }
				opts.Stdin = strings.NewReader(body)
			})
			if tc.allow {
				if blocked(result) || !strings.Contains(result.stdout+result.stderr, "DefenseClaw") {
					t.Fatalf("ordinary late call: code=%d stdout=%q stderr=%q", result.code, result.stdout, result.stderr)
				}
			} else if !blocked(result) {
				t.Fatalf("strict late call: code=%d stdout=%q stderr=%q", result.code, result.stdout, result.stderr)
			}
		})
	}
}
