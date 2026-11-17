// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"encoding/json"
	"strings"
	"testing"

	"mvdan.cc/sh/v3/syntax"
)

// TestAttachedTargetDirectoryWithNoFolderNamesNoDestination: an attached
// target-directory option with an empty value (--target-directory= as the
// last word) names no folder: GNU cp, mv, install and ln refuse it, and the
// reader of the attached folder returns no destination. The empty word it cut
// out of the option has no parts, and a word with no parts panics in every
// reader that asks for its position (the GAP-0055 race sweep found it,
// rel-1-0-10:GAP-1149 round 2). Behind a wrapper the same holds; a folder that
// is given is still read.
func TestAttachedTargetDirectoryWithNoFolderNamesNoDestination(t *testing.T) {
	cwd, home := t.TempDir(), t.TempDir()
	for _, command := range []string{
		"cp --target-directory=", "cp a --target-directory=", "gcp a --target-directory=",
		"mv a --target-directory=", "install a --target-directory=", "ln --target-directory=",
		"ln -s a --target-directory=", "busybox cp a --target-directory=", "xargs cp --target-directory=",
		"env A=1 cp a --target-directory=",
	} {
		t.Run(command, func(t *testing.T) {
			if got := gap1149AttachedDestinations(t, command, home); len(got) != 0 {
				t.Fatalf("%d attached destinations, want none", len(got))
			}
			func() {
				defer func() {
					if recovered := recover(); recovered != nil {
						t.Fatalf("panic: %v", recovered)
					}
				}()
				actionPosixTargetMention(command, cwd, home, 0, false, nil)
				payload, err := json.Marshal(map[string]any{"session_id": "gap1149", "hook_event_name": "PreToolUse", "cwd": cwd,
					"tool_name": "Bash", "tool_input": map[string]any{"command": command}})
				if err != nil {
					t.Fatal(err)
				}
				Resolve(payload)
			}()
		})
	}
	for _, command := range []string{"cp a --target-directory=b", "busybox cp a -tb", "env A=1 cp a -ftb"} {
		if got := gap1149AttachedDestinations(t, command, home); len(got) != 1 {
			t.Fatalf("%q: %d attached destinations, want one", command, len(got))
		}
	}
}

func gap1149AttachedDestinations(t *testing.T, command, home string) []*syntax.Word {
	t.Helper()
	file, err := syntax.NewParser().Parse(strings.NewReader(command), "")
	if err != nil {
		t.Fatal(err)
	}
	var call *syntax.CallExpr
	syntax.Walk(file, func(node syntax.Node) bool {
		if found, ok := node.(*syntax.CallExpr); ok && call == nil {
			call = found
		}
		return call == nil
	})
	if call == nil {
		t.Fatalf("%q: no call", command)
	}
	return actionAttachedCopyDestinations(call, home)
}
