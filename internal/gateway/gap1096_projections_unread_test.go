// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// TestGAP1096ProjectionsReportUnread: substrateMCPProjectionsRead reports
// unread only a part the structured reading reads: a cut command, path or
// url value (at the top level or in an input envelope), a dropped level of
// such a value. Padding the reading does not read (a note, a payload,
// unread members, containers under unread keys) loses nothing.
func TestGAP1096ProjectionsReportUnread(t *testing.T) {
	long := strings.Repeat("w ", 40000)
	members := func(n int, extra string) string {
		parts := make([]string, 0, n+1)
		for i := range n {
			parts = append(parts, fmt.Sprintf(`"a%04d":"x"`, i))
		}
		if extra != "" {
			parts = append(parts, extra)
		}
		return `{` + strings.Join(parts, ",") + `}`
	}
	nest := func(levels int, leaf string) string {
		return strings.Repeat(`{"n":`, levels) + leaf + strings.Repeat(`}`, levels)
	}
	for _, tc := range []struct {
		name   string
		args   string
		unread bool
	}{
		{"long note", `{"path":"/n/a.txt","note":"` + long + `"}`, false},
		{"long payload", `{"path":"/n/a.txt","content":"` + long + `"}`, false},
		{"long command", `{"command":"echo ` + long + `"}`, true},
		{"long nested url", `{"input":{"url":"https://example.com/` + long + `"}}`, true},
		{"many unread members", members(2000, ""), false},
		{"read field under an unread key past the windows", members(2000, `"zz":{"path":"/n/a.txt"}`), false},
		{"long command in an envelope", `{"input":{"command":"echo ` + long + `"}}`, true},
		{"deep unread level", `{"path":"/n/a.txt","x":` + nest(20, `"v"`) + `}`, false},
		{"deep argv level", `{"argv":` + strings.Repeat("[", 20) + `"v"` + strings.Repeat("]", 20) + `}`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if !json.Valid([]byte(tc.args)) {
				t.Fatal("test arguments are not JSON")
			}
			out, unread := substrateMCPProjectionsRead(json.RawMessage(tc.args), substrateMCPMaxProjections)
			if len(out) == 0 {
				t.Fatal("no projection")
			}
			if unread != tc.unread {
				t.Fatalf("unread=%v, want %v", unread, tc.unread)
			}
		})
	}
}
