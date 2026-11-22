// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package effectrules

import (
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"

	"github.com/defenseclaw/defenseclaw/internal/effects"
	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
	"github.com/defenseclaw/defenseclaw/internal/guardrail/semanticpb"
)

// FileID is the identity of one existing regular file: its device (volume
// serial on Windows), its inode (file index) and its hard-link count. Two
// names with the same Dev and Ino are one file, so a write through either
// changes the other (DET111 D3, rel-1-0-10:GAP-1288/1289/1317/1318).
type FileID struct {
	Dev, Ino uint64
	Links    uint64
}

// IdentityFunc reads the FileID of an existing regular file, following
// symbolic links. ok is false for a path that does not exist, is not a
// regular file, or cannot be read.
type IdentityFunc func(path string) (FileID, bool)

// maxIdentityStats bounds the target stats of one Project call: a call with
// more path targets leaves the rest to the name reading, counted, and hits
// bounded.Paths on the call's Truncated (Env.Truncated). S2 cap registry name
// effectrules.maxIdentityStats (unit bounded.Paths); it is registered where
// det111/s2-bounds merges (bounded.Register, with effectrules in the
// registry's reader packages).
const maxIdentityStats = 64

var identityStats, identityHits, identityOverBudget atomic.Int64

// IdentityCounts reports the classifier's identity reads since start: target
// stats, targets found to be a hard link of a protected member, and targets
// left unread because a call passed maxIdentityStats (shadow report counters).
func IdentityCounts() (stats, hits, overBudget int64) {
	return identityStats.Load(), identityHits.Load(), identityOverBudget.Load()
}

// identityCache is the identity reading of one Project call: one stat per
// resolved target, and the member identities read once, only when a target
// has a second hard link.
type identityCache struct {
	fn      IdentityFunc
	sets    map[string]protectedSet
	budget  int
	trunc   *bounded.Truncated     // the call's; nil: counted only
	members map[[2]uint64][]string // (dev, ino) -> sets; nil until needed
}

func newIdentityCache(fn IdentityFunc, sets map[string]protectedSet, trunc *bounded.Truncated) *identityCache {
	if fn == nil {
		fn = DiskIdentity
	}
	return &identityCache{fn: fn, sets: sets, budget: maxIdentityStats, trunc: trunc}
}

func (c *identityCache) memberSets(id FileID) []string {
	if c.members == nil {
		c.members = map[[2]uint64][]string{}
		for _, name := range AllSets {
			for _, f := range c.sets[name].files {
				if m, ok := c.fn(f); ok {
					k := [2]uint64{m.Dev, m.Ino}
					c.members[k] = appendOnce(c.members[k], name)
				}
			}
		}
	}
	return c.members[[2]uint64{id.Dev, id.Ino}]
}

func appendOnce(list []string, s string) []string {
	for _, v := range list {
		if v == s {
			return list
		}
	}
	return append(list, s)
}

// hardLinkSets returns the sets one of whose member files is the same file as
// the target, and whether that answer is certain. A placed path whose
// resolved name holds a member's inode is known (every component was walked
// by the stat). A glob is read only as its literal placed word, the name the
// shell passes when nothing matches (key[9]); it is maybe (R-NAME). Nothing
// is walked: no directory is listed and no pattern is expanded on disk.
func (c *identityCache) hardLinkSets(t effects.Target, rsv resolver) ([]string, bool) {
	var p string
	known := false
	switch {
	case t.Glob != "":
		p = t.Lexical
	case t.Path != "":
		// A placed word with a pattern character may be the shell's
		// unmatched-glob literal (cp x key[9] writes key9 when that exists):
		// maybe, not known.
		p, known = t.Path, !strings.ContainsAny(t.Spelling, "*?[")
		if r, ok := rsv(t.Path); ok && r != "" {
			p = r
		}
	}
	if p == "" || !absoluteAny(p) {
		return nil, false
	}
	if c.budget <= 0 {
		identityOverBudget.Add(1)
		if c.trunc != nil {
			c.trunc.Hit(bounded.Paths)
		}
		return nil, false
	}
	c.budget--
	identityStats.Add(1)
	id, ok := c.fn(p)
	if !ok || id.Links < 2 {
		return nil, false
	}
	sets := c.memberSets(id)
	if len(sets) > 0 {
		identityHits.Add(1)
	}
	return sets, known
}

func absoluteAny(p string) bool {
	return strings.HasPrefix(p, "/") || strings.HasPrefix(p, `\\`) ||
		(len(p) > 2 && p[1] == ':' && (p[2] == '\\' || p[2] == '/'))
}

// addIdentityMatches raises the target's grade for every set a hard link
// reaches: known with basis "inode", maybe with basis "inode_glob".
func addIdentityMatches(pt *semanticpb.EffectTarget, sets []string, known bool) {
	state, basis := string(gradeUnknown), "inode_glob"
	if known {
		state, basis = string(gradeKnown), "inode"
	}
	for _, name := range sets {
		found := false
		for _, m := range pt.Protected {
			if m.Set != name {
				continue
			}
			found = true
			if matchRank(m.State) < matchRank(state) {
				m.State, m.Reason = state, basis
			}
		}
		if !found {
			pt.Protected = append(pt.Protected, &semanticpb.ProtectedMatch{Set: name, State: state, Reason: basis})
		}
	}
}

func matchRank(s string) int {
	switch setGrade(s) {
	case gradeKnown:
		return 2
	case gradeUnknown:
		return 1
	}
	return 0
}

// HardLinkFixture is an in-memory IdentityFunc for tests: File adds a single
// link file, Link gives several paths one inode. Paths match exactly.
type HardLinkFixture struct {
	ids  map[string]FileID
	next uint64
	// Calls counts Identity reads (a test of the one-stat bound).
	Calls int
}

// NewHardLinkFixture returns an empty fixture.
func NewHardLinkFixture() *HardLinkFixture {
	return &HardLinkFixture{ids: map[string]FileID{}}
}

// File records each path as its own file with one link.
func (f *HardLinkFixture) File(paths ...string) *HardLinkFixture {
	for _, p := range paths {
		f.next++
		f.ids[p] = FileID{Dev: 1, Ino: f.next, Links: 1}
	}
	return f
}

// Link records the paths as hard links of one file.
func (f *HardLinkFixture) Link(paths ...string) *HardLinkFixture {
	f.next++
	for _, p := range paths {
		f.ids[p] = FileID{Dev: 1, Ino: f.next, Links: uint64(len(paths))}
	}
	return f
}

// Identity implements IdentityFunc.
func (f *HardLinkFixture) Identity(path string) (FileID, bool) {
	f.Calls++
	id, ok := f.ids[path]
	return id, ok
}

// WriteHardLinkHome lays out a home on disk for identity tests (the disk
// twin of HardLinkFixture): each member, relative to home, becomes a one-line
// file, then each link name (relative to home) a hard link of its member.
// linked is false, with no error, when the file system makes no hard links
// (the caller skips).
func WriteHardLinkHome(home string, members []string, links map[string]string) (linked bool, err error) {
	for _, m := range members {
		p := filepath.Join(home, filepath.FromSlash(m))
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			return false, err
		}
		if err := os.WriteFile(p, []byte("k\n"), 0o600); err != nil {
			return false, err
		}
	}
	for name, member := range links {
		p := filepath.Join(home, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			return false, err
		}
		if os.Link(filepath.Join(home, filepath.FromSlash(member)), p) != nil {
			return false, nil
		}
	}
	return true, nil
}
