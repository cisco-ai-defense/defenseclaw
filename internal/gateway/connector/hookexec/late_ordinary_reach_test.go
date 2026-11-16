// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package hookexec

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestLateOrdinaryCallProtectedReach: in the open tier a late call from a
// verified gateway is still denied when it reaches a protected file through a
// link hop (a link to the keys path after the keys were moved), or through a
// grep file option whose value looks like an option; an ordinary hard link
// and an ordinary link open with the warning, and the strict tier stays closed.
func TestLateOrdinaryCallProtectedReach(t *testing.T) {
	project := lateOrdinaryProject(t)
	keys := filepath.Join(filepath.Dir(project), ".ssh", "authorized_keys")
	moved := filepath.Join(project, "moved")
	for path, text := range map[string]string{moved: "# decoy\n", filepath.Join(project, "plain-copy.txt"): "x\n"} {
		if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Remove(keys); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(moved, keys); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(moved, filepath.Join(project, "movedlink")); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"-e", "--regexp"} {
		if err := os.Symlink(keys, filepath.Join(project, name)); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Link(filepath.Join(project, "plain-copy.txt"), filepath.Join(project, "plain-second-name")); err != nil {
		t.Fatal(err)
	}
	shortAnswerBudget(t, 400*time.Millisecond)
	addr := hungGateway(t)
	client, err := NewPerUserGatewayHTTPClient(2*time.Second, addr)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, command, mode string
		blocks              bool
	}{
		{"write through the link hop", "echo x > keylink", "open", true},
		{"read through the link hop", "cat keylink", "open", true},
		{"link to the place the keys were moved to", "cat movedlink", "open", true},
		{"short file option, option-shaped link", "grep -f -e x plain.txt", "open", true},
		{"long file option, option-shaped link", "grep --file --regexp x plain.txt", "open", true},
		{"file option and a direct link", "grep -f keylink plain.txt", "open", true},
		{"ordinary hard link", "cat plain-second-name", "open", false},
		{"ordinary link", "cat l", "open", false},
		{"file option and a plain file", "grep -f plain.txt plain.txt", "open", false},
		{"ordinary hard link, strict tier", "cat plain-second-name", "closed", true},
	} {
		for _, connector := range []string{"claudecode", "codex"} {
			t.Run(connector+"/"+tc.name, func(t *testing.T) {
				result, _ := runAgainstGateway(t, connector, addr, func(opts *Options) {
					opts.HTTPClient = client
					opts.FailMode = "open"
					opts.OutageFailModeNow = func() string { return tc.mode }
					opts.Stdin = strings.NewReader(lateOrdinaryPayload(t, project, tc.command))
				})
				if got := blocked(result); got != tc.blocks {
					t.Errorf("blocks=%v, want %v: code=%d stdout=%.200q stderr=%.200q", got, tc.blocks, result.code, result.stdout, result.stderr)
				}
				if !tc.blocks && !strings.Contains(result.stdout+result.stderr, "did not answer in time") {
					t.Error("missing visible warning")
				}
			})
		}
	}
}
