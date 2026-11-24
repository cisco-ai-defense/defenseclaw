// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// rel-1-0-10:GAP-1804 (P3 of RV-1789): the gateway state-write checks refuse
// a write target whose own folder read does not answer in time, and keep
// their answer for an idle local target and for a target on a network share
// that does not answer (a file there cannot be a hard link to local state).
func TestGAP1804GatewayTargetReadUnansweredIsRefused(t *testing.T) {
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
	var share atomic.Bool
	end := make(chan struct{})
	t.Cleanup(func() { close(end) })
	restore := overrideNetworkSharesIdle(t, func(path string) string {
		if share.Load() && (path == cwd || strings.HasPrefix(path, cwd+string(filepath.Separator))) {
			return cwd
		}
		return ""
	}, func(string) {
		if share.Load() {
			<-end
		}
	})
	t.Cleanup(restore)
	projected := actionfacts.Facts{ActiveHome: home}
	command := actionfacts.CommandFact{Program: "cp"}
	for _, row := range []struct {
		name         string
		target       string
		hold, remote bool
		// want is the answer of provenStateCandidateMatches and of
		// linkedActiveStateWrite (which judges only a target a link
		// places elsewhere: an idle hard link is the other check's).
		want [2]bool
	}{
		{"idle local hard link", alias, false, false, [2]bool{true, false}},
		{"idle local ordinary file", plain, false, false, [2]bool{false, false}},
		{"local hard link, own folder read unanswered", alias, true, false, [2]bool{true, true}},
		{"local ordinary file, own folder read unanswered", plain, true, false, [2]bool{true, true}},
		{"hard link on a share that does not answer", alias, false, true, [2]bool{false, false}},
	} {
		for i, check := range []struct {
			name string
			run  func(actionfacts.PathFact) bool
		}{
			{"provenStateCandidateMatches", func(c actionfacts.PathFact) bool {
				return provenStateCandidateMatches(projected, command, c, trustedActionRequest{}, func() bool { return false })
			}},
			{"linkedActiveStateWrite", func(c actionfacts.PathFact) bool {
				return linkedActiveStateWrite(projected, command, c, hookpaths.Links{}, trustedActionRequest{}, cwd, true)
			}},
		} {
			t.Run(row.name+"/"+check.name, func(t *testing.T) {
				candidate := actionfacts.PathFact{Access: actionfacts.PathAccessWrite, Value: row.target, Normalized: row.target, Resolved: row.target}
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
				share.Store(row.remote)
				defer share.Store(false)
				holding.Store(row.hold)
				got := check.run(candidate)
				holding.Store(false)
				if row.hold && held.Load() == 0 {
					t.Fatal("the target folder read was never held (vacuous)")
				}
				if got != row.want[i] {
					t.Errorf("%s(%s) = %v, want %v", check.name, row.target, got, row.want[i])
				}
			})
		}
	}
}
