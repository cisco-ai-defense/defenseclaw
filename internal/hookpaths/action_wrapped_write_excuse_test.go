// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// TestWrappedProtectedWriteIsNotExcused: a protected write behind every
// wrapper shape the excused mention scan meets keeps its protected-target
// finding and is never excused as a read (ActionMentionsNoWriteRole false),
// so no tier downgrades it: default and permissive block as rel does, and
// strict and managed never downgrade (rel-1-0-10:GAP-0910, GAP-0925; the
// rows of review s7-d4t2rev; a shell named at run time, GAP-0975).
func TestWrappedProtectedWriteIsNotExcused(t *testing.T) {
	home := t.TempDir()
	cwd := filepath.Join(home, "project")
	if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(cwd, 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(home, ".ssh", "authorized_keys")
	writes := []string{"cp new.pub " + target, "tee -a " + target + " < new.pub"}
	prefixes := []string{
		"", "chroot / ", "chroot --userspec=1000:1000 / ", "nsenter -t 1 -m ", "nsenter --target=1 --mount -- ",
		"nsenter -a -t 1 ", "nsenter --all --target 1 ", "unbuffer ", "unbuffer -p ", "taskset 0x1 ", "taskset -c 0-1 ",
		"taskset -a -c 1 ", "flock /tmp/l ", "flock -x /tmp/l ", "flock -w 5 /tmp/l ", "flock -xn /tmp/l ",
		"flock --timeout=5 /tmp/l ", "sudo flock /tmp/l ", "taskset 0x1 flock /tmp/l nice ", "chroot / taskset 0x1 ",
		"xargs -0 ",
	}
	shellForms := []string{"flock /tmp/l -c '%s'", "flock -x /tmp/l --command '%s'", "flock /tmp/l sh -c '%s'",
		"sudo flock /tmp/l -c '%s'", "taskset 0x1 flock -n /tmp/l -c '%s'",
		// A shell named at run time runs its -c text as code (rel-1-0-10:GAP-0975).
		"\"$SHELL\" -c '%s'", "time \"$SHELL\" -c '%s'", "time -p \"$SHELL\" -c '%s'",
		"FOO=$BAR \"$SHELL\" -c '%s'", "$BASH -lc '%s'", "\"$SHELL\" --norc -ec '%s'"}
	for _, write := range writes {
		commands := make([]string, 0, len(prefixes)+len(shellForms))
		for _, prefix := range prefixes {
			commands = append(commands, prefix+write)
		}
		for _, form := range shellForms {
			commands = append(commands, strings.Replace(form, "%s", write, 1))
		}
		for _, command := range commands {
			if got := ActionCommandDecisionWithDialectAndGlobFacts(command, cwd, home, actionfacts.DialectPOSIX, nil); got != "protected-target" {
				t.Errorf("%q: decision %q, want protected-target", command, got)
			}
			if ActionMentionsNoWriteRole(command, cwd, home, actionfacts.DialectPOSIX, nil) {
				t.Errorf("%q: the protected write is excused as a read", command)
			}
		}
		// A program named at run time without a -c option hands the text to
		// something the scan cannot know: its operands stay data of unknown
		// role (rel-1-0-10:GAP-0018), also when an option cluster has no c.
		for _, form := range []string{"$T send '%s'", "\"$TOOL\" -v '%s'", "\"$TOOL\" -- -c '%s'"} {
			command := strings.Replace(form, "%s", write, 1)
			if !ActionMentionsNoWriteRole(command, cwd, home, actionfacts.DialectPOSIX, nil) {
				t.Errorf("%q: a run-time program without -c is no longer data of unknown role", command)
			}
		}
	}
}
