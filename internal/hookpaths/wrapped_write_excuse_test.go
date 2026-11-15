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

// A write to the authorized_keys file behind any wrapper that runs a command
// is a protected target the excused mention scan never excuses as a read
// (ActionMentionsNoWriteRole), so it keeps its block in the per-user default
// and permissive packs: the wrappers the shared reader looks through
// (rel-1-0-10:GAP-0910) and those it cannot follow to a program word, a
// shell string (flock FILE -c TEXT) or an option it does not read
// (nsenter -a, rel-1-0-10:GAP-0925).
func TestWrappedProtectedWriteIsNeverExcusedAsARead(t *testing.T) {
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
	wrappers := []string{
		"", "chroot / ", "chroot --userspec=1000:1000 / ", "nsenter -t 1 -m ", "nsenter --target=1 --mount -- ",
		"nsenter -a -t 1 ", "unbuffer ", "unbuffer -p ", "taskset 0x1 ", "taskset -c 0-1 ", "taskset -a -c 1 ",
		"flock /tmp/l ", "flock -x /tmp/l ", "flock -w 5 /tmp/l ", "flock -xn /tmp/l ", "flock --timeout=5 /tmp/l ",
		"sudo flock /tmp/l ", "taskset 0x1 flock /tmp/l nice ", "chroot / taskset 0x1 ", "xargs -0 ",
	}
	for _, write := range writes {
		commands := []string{}
		for _, wrapper := range wrappers {
			commands = append(commands, wrapper+write)
		}
		for _, form := range []string{"flock /tmp/l -c '%s'", "flock -x /tmp/l --command '%s'", "flock /tmp/l sh -c '%s'"} {
			commands = append(commands, strings.Replace(form, "%s", write, 1))
		}
		for _, command := range commands {
			if got := ActionCommandDecisionWithDialectAndGlobFacts(command, cwd, home, actionfacts.DialectPOSIX, nil); got != "protected-target" {
				t.Errorf("%q: decision %q, want protected-target", command, got)
			}
			if ActionMentionsNoWriteRole(command, cwd, home, actionfacts.DialectPOSIX, nil) {
				t.Errorf("%q: the write is excused as a read", command)
			}
		}
	}
}
