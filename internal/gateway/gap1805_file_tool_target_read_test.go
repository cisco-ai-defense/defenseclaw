// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

// rel-1-0-10:GAP-1805 (RV-1804): fileToolWriteThroughLinkToState, the check
// of a file-tool write (no shell command) through a link into the state,
// dropped a target that did not resolve. A target whose own folder read does
// not answer in time is now not proved free of the state there either, as in
// linkedActiveStateWrite (GAP-1804). Idle targets keep their answers: a link
// into the state is refused, an ordinary file and a hard link (the hard-link
// check's) are not this check's.
func TestGAP1805FileToolTargetReadUnansweredIsRefused(t *testing.T) {
	root := t.TempDir()
	home, cwd := filepath.Join(root, "home"), filepath.Join(root, "project")
	for _, dir := range []string{filepath.Join(home, ".defenseclaw"), cwd} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	config := filepath.Join(home, ".defenseclaw", "config.yaml")
	plain := filepath.Join(cwd, "notes.txt")
	for _, file := range []string{config, plain} {
		if err := os.WriteFile(file, []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	alias := filepath.Join(cwd, "cfg-alias")
	if err := os.Link(config, alias); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(cwd, "cfg-link")
	testenv.Symlink(t, config, link)
	restore := overrideNetworkSharesIdle(t, func(string) string { return "" }, func(string) {})
	t.Cleanup(restore)
	for _, row := range []struct {
		name   string
		target string
		hold   bool
		want   bool
	}{
		{"idle link into the state", link, false, true},
		{"idle ordinary file", plain, false, false},
		{"idle hard link", alias, false, false},
		{"ordinary file, own folder read unanswered", plain, true, true},
		{"hard link, own folder read unanswered", alias, true, true},
	} {
		t.Run(row.name, func(t *testing.T) {
			candidate := actionfacts.PathFact{Access: actionfacts.PathAccessWrite, CommandID: 1,
				Value: row.target, Normalized: row.target, Resolved: row.target}
			facts := actionfacts.Facts{ActiveHome: home,
				Commands: []actionfacts.CommandFact{{ID: 1, Program: "write_file", Effect: actionfacts.EffectExecute,
					Operations: []actionfacts.OperationKind{actionfacts.OperationWrite}}},
				Paths: []actionfacts.PathFact{candidate}}
			var holding atomic.Bool
			var held atomic.Int32
			release := holdKnownFolderReadsIdle(t, func(folder string) bool {
				if holding.Load() && folder == cwd {
					held.Add(1)
					return true
				}
				return false
			}, 20*time.Millisecond)
			defer release()
			// The idle read makes the project folder a known one, read
			// again (stillPlain) by the next walk.
			if _, ok := hookpaths.ResolveWriteTarget(filepath.Join(cwd, "primer")); !ok {
				t.Fatal("idle primer not resolved")
			}
			holding.Store(row.hold)
			got := fileToolWriteThroughLinkToState(facts, trustedActionRequest{})
			holding.Store(false)
			if row.hold && held.Load() == 0 {
				t.Fatal("the target folder read was never held (vacuous)")
			}
			if got != row.want {
				t.Errorf("fileToolWriteThroughLinkToState(%s) = %v, want %v", row.target, got, row.want)
			}
		})
	}
}
