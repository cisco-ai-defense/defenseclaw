// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// A managed gateway cannot open the user home, so the hook client is the only
// reader of the scripts a command runs. A body the client could not read
// because its path passes more links than the system opens is told to the
// gateway in the evidence, whichever way the command names it; a body it
// read, or a command with none, tells nothing (rel-1-0-9:GAP-0950).
func TestClientEvidenceTellsAScriptBodyBehindMoreLinksThanTheSystemOpens(t *testing.T) {
	limit := SystemLinkLimit()
	for _, links := range []int{1, limit, limit + 1, limit + 8} {
		for _, spelling := range []string{"cwd-in-chain", "path-operand"} {
			t.Run(fmt.Sprintf("%d links %s", links, spelling), func(t *testing.T) {
				base := linkFreeTempDir(t)
				t.Setenv("HOME", base)
				t.Setenv("USERPROFILE", base)
				live := filepath.Join(base, "live")
				if err := os.Mkdir(live, 0o700); err != nil {
					t.Fatal(err)
				}
				for name, body := range map[string]string{
					"writer.sh": "echo marker >> alias\n",
					"safe.sh":   "echo ordinary > report.txt\n",
				} {
					if err := os.WriteFile(filepath.Join(live, name), []byte(body), 0o600); err != nil {
						t.Fatal(err)
					}
				}
				// Relative links, each to the next, as the system reads them below a folder.
				for i := links; i >= 1; i-- {
					to := "live"
					if i < links {
						to = fmt.Sprintf("hop%03d", i+1)
					}
					if err := os.Symlink(to, filepath.Join(base, fmt.Sprintf("hop%03d", i))); err != nil {
						t.Skipf("symlink unavailable: %v", err)
					}
				}
				for _, script := range []string{"writer.sh", "safe.sh"} {
					cwd, command := filepath.Join(base, "hop001"), "source "+script
					if spelling == "path-operand" {
						cwd, command = base, "source hop001/"+script
					}
					payload, _ := json.Marshal(map[string]any{
						"hook_event_name": "PreToolUse", "cwd": cwd,
						"tool_name": "Bash", "tool_input": map[string]any{"command": command},
					})
					targets, ok := Decode(ResolveConnector("claudecode", "", "PreToolUse", payload))
					if !ok {
						t.Fatalf("%s: evidence does not decode", command)
					}
					budget, linkBound := ClientShareBodyUnread(targets)
					if want := links > limit; linkBound != want || budget {
						t.Errorf("%s behind %d links (limit %d): link bound told %v, budget told %v, want link bound %v",
							command, links, limit, linkBound, budget, want)
					}
				}
			})
		}
	}
}

func TestClientEvidenceOfACommandWithNoScriptTellsNoUnreadBody(t *testing.T) {
	base := linkFreeTempDir(t)
	t.Setenv("HOME", base)
	t.Setenv("USERPROFILE", base)
	payload, _ := json.Marshal(map[string]any{
		"hook_event_name": "PreToolUse", "cwd": base,
		"tool_name": "Bash", "tool_input": map[string]any{"command": "echo ordinary > report.txt"},
	})
	targets, ok := Decode(ResolveConnector("claudecode", "", "PreToolUse", payload))
	if !ok {
		t.Fatal("evidence does not decode")
	}
	if _, present := targets[ShareBodyUnreadKey]; present {
		t.Errorf("an ordinary redirect carries the unread-body fact: %v", targets)
	}
}

func TestShareBodyUnreadFactIsValidatedAndMergedByCause(t *testing.T) {
	for _, value := range []string{"budget", "links", "budget,links"} {
		encoded, _ := json.Marshal(map[string]string{ShareBodyUnreadKey: value})
		if _, ok := Decode(base64.RawURLEncoding.EncodeToString(encoded)); !ok {
			t.Errorf("fact %q is refused", value)
		}
	}
	encoded, _ := json.Marshal(map[string]string{ShareBodyUnreadKey: "anything"})
	if _, ok := Decode(base64.RawURLEncoding.EncodeToString(encoded)); ok {
		t.Error("an unknown cause is accepted")
	}
	for _, c := range []struct{ a, b, want string }{
		{"", "links", "links"}, {"links", "links", "links"}, {"budget", "links", "budget,links"}, {"budget,links", "budget", "budget,links"},
	} {
		if got := mergeShareBodyUnread(c.a, c.b); got != c.want {
			t.Errorf("merge(%q, %q) = %q, want %q", c.a, c.b, got, c.want)
		}
	}
}
