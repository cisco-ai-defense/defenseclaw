// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// gap1096LimitShapes are argument objects on both sides of every bound of the
// argument reading, in ASCII and in bytes that decode longer than written.
func gap1096LimitShapes() map[string]string {
	members := func(n int) string {
		m := make([]string, n)
		for i := range m {
			m[i] = fmt.Sprintf(`"k%d":1`, i)
		}
		return "{" + strings.Join(m, ",") + "}"
	}
	nested := func(n int) string { return strings.Repeat(`[`, n) + `1` + strings.Repeat(`]`, n) }
	return map[string]string{
		"small":          `{"path":"/notes/a.txt","content":"hello"}`,
		"empty":          `{}`,
		"string-4k":      `{"a":"` + strings.Repeat("A", maxScalarBytes) + `"}`,
		"string-64k":     `{"a":"` + strings.Repeat("A", maxCommandBytes) + `"}`,
		"string-64k+1":   `{"a":"` + strings.Repeat("A", maxCommandBytes+1) + `"}`,
		"key-4k":         `{"` + strings.Repeat("K", maxScalarBytes) + `":1}`,
		"key-4k+1":       `{"` + strings.Repeat("K", maxScalarBytes+1) + `":1}`,
		"key-escapes":    `{"` + strings.Repeat(`\n`, maxScalarBytes) + `":1}`,
		"key-invalid":    "{\"" + strings.Repeat("\xff", 1400) + "\":1}",
		"key-multibyte":  `{"` + strings.Repeat("é", 2049) + `":1}`,
		"members-512":    members(maxJSONMembers),
		"members-513":    members(maxJSONMembers + 1),
		"array-513":      `{"a":[` + strings.TrimSuffix(strings.Repeat("1,", maxJSONMembers), ",") + `]}`,
		"commas-in-text": `{"a":"` + strings.Repeat(",[{", 1000) + `"}`,
		"depth-16":       nested(maxJSONDepth),
		"depth-17":       nested(maxJSONDepth + 1),
		"depth-17-empty": strings.Repeat(`[`, maxJSONDepth+1) + strings.Repeat(`]`, maxJSONDepth+1),
		"quote-escape":   `{"a":"x\"` + strings.Repeat("A", maxScalarBytes) + `"}`,
		"unterminated":   `{"a":"` + strings.Repeat("A", 100),
		"invalid":        `{"a":1,,}`,
	}
}

// TestGAP1096ArgsLimitIssueScanMatchesDecode (substrate-1:GAP-1096): the
// byte scan that lets ArgsLimitIssue skip the decode never hides a bound the
// decode finds.
func TestGAP1096ArgsLimitIssueScanMatchesDecode(t *testing.T) {
	for name, raw := range gap1096LimitShapes() {
		got, want := ArgsLimitIssue(json.RawMessage(raw)), argsLimitIssueDecoded(json.RawMessage(raw))
		if len(raw) > maxArgsJSONBytes {
			want = IssueInputLimit
		}
		if got != want {
			t.Errorf("%s: ArgsLimitIssue=%q, decode=%q", name, got, want)
		}
	}
	for _, name := range []string{"string-64k+1", "key-4k+1", "members-513", "array-513", "depth-17"} {
		if ArgsLimitIssue(json.RawMessage(gap1096LimitShapes()[name])) == "" {
			t.Errorf("%s: no issue, want a bound", name)
		}
	}
}

// TestGAP1096ArgsLimitIssueSmallCallsAllocateNothing: the hook routes ask
// ArgsLimitIssue of every MCP and app tool call; a call inside the bounds
// costs one scan and no allocation.
func TestGAP1096ArgsLimitIssueSmallCallsAllocateNothing(t *testing.T) {
	raw := json.RawMessage(`{"path":"/notes/a.txt","content":"` + strings.Repeat("hello ", 600) + `","tags":["a","b"],"n":{"m":1}}`)
	if allocs := testing.AllocsPerRun(100, func() {
		if ArgsLimitIssue(raw) != "" {
			t.Fatal("benign call over a bound")
		}
	}); allocs != 0 {
		t.Fatalf("ArgsLimitIssue allocs=%v on a benign call, want 0", allocs)
	}
}
