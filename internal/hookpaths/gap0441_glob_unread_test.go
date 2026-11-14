// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// gap0441Rows are the review rows of rel-1-0-10:GAP-0441, built from the
// GAP-1445 alias rows (gap0398AliasRows): C1 the rows that name
// keyd*/authorized_keys (A0, A3, A4, A5) with that pattern replaced by the
// GAP-0270 shape S7's x-*/*.txt over folder; C2 the last row (A6), whose
// final component keyd* becomes x-*/n*.
func gap0441Rows(t *testing.T, cwd, folder string) (c1 []string, c2 string) {
	t.Helper()
	s7 := strings.Fields(gap0270ReadShapes(folder)[7])[3]
	rows := gap0398AliasRows(t, cwd)
	for _, row := range rows {
		if strings.Contains(row, "keyd*/authorized_keys") && !strings.Contains(row, "authorized_keys2") &&
			!strings.Contains(row, "$PWD") && !strings.Contains(row, cwd) {
			c1 = append(c1, strings.ReplaceAll(row, "keyd*/authorized_keys", s7))
		}
	}
	last := rows[len(rows)-1]
	if !strings.HasSuffix(last, "keyd*") || len(c1) != 4 {
		t.Fatalf("GAP-1445 rows changed: %d C1 rows, last row ends %q", len(c1), last[len(last)-5:])
	}
	return c1, strings.TrimSuffix(last, "keyd*") + strings.TrimSuffix(s7, "*.txt") + "n*"
}

// rel-1-0-10:GAP-0441 (review round 2 P1-1, probes C1, C2 and L1): past a
// walk bound, a name the walk did not read is never decided from the
// pattern text. An away folder of n subfolders matched by one wildcard
// holds, in subfolder k, a link of an ordinary name: to authorized_keys
// for C1, to the .ssh folder for C2. k takes every position, so the read
// order of the walk cannot hide a result. With the read bound lowered, a
// link the walk read is a protected target; one it did not read is
// TRUNCATED (TargetMemo.GlobTruncated, the pack's unknown tier); none is a
// plain allow.
func TestGAP0441UnreadNameIsTruncatedNeverTextDecided(t *testing.T) {
	gap0398POSIX(t)
	const subfolders, reads = 8, 4
	defer UseGlobWalkBoundsForTests(reads, 1<<18)()
	home, cwd := globAliasFixture(t)
	ssh := filepath.Join(home, ".ssh")
	away := t.TempDir()
	for k := range subfolders {
		if err := os.Mkdir(filepath.Join(away, fmt.Sprintf("x-%02d", k)), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	c1, c2 := gap0441Rows(t, cwd, away)
	tally := map[string]int{}
	for k := range subfolders {
		sub := filepath.Join(away, fmt.Sprintf("x-%02d", k))
		links := map[string]string{filepath.Join(sub, "n.txt"): filepath.Join(ssh, "authorized_keys"), filepath.Join(sub, "nd"): ssh}
		for link, target := range links {
			if err := os.Symlink(target, link); err != nil {
				t.Fatal(err)
			}
		}
		for i, command := range append(append([]string(nil), c1...), c2) {
			id := fmt.Sprintf("C1 row %d", i)
			if i == len(c1) {
				id = "C2"
			}
			got := globHeldDecision(command, cwd, home, nil)
			switch got {
			case "protected-target", globHeld:
				tally[id+" "+got]++
			default:
				t.Errorf("%s, link in subfolder %d: decision %q, want protected-target or TRUNCATED", id, k, got)
			}
		}
		for link := range links {
			if err := os.Remove(link); err != nil {
				t.Fatal(err)
			}
		}
	}
	var keys []string
	for key := range tally {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		t.Logf("%s: %d of %d positions", key, tally[key], subfolders)
	}
	// Both outcomes occur: the walk reads the first subfolders and not the
	// last, so the test checks the unread branch, not only the read one.
	if tally["C1 row 0 "+globHeld] == 0 || tally["C1 row 0 protected-target"] == 0 {
		t.Fatalf("C1 row 0 tally %v: the bound did not split the positions", tally)
	}
}

// The same rows at the real bounds (64 directory reads): 70 subfolders,
// the link in each in turn. The walk reads the folder in directory order,
// so which positions fall past the 64th read depends on the file system;
// every position is a protected target or TRUNCATED, and both occur.
func TestGAP0441UnreadNamePastRealBound(t *testing.T) {
	gap0398POSIX(t)
	home, cwd := globAliasFixture(t)
	away := t.TempDir()
	for k := range 70 {
		if err := os.Mkdir(filepath.Join(away, fmt.Sprintf("x-%02d", k)), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	c1, _ := gap0441Rows(t, cwd, away)
	tally := map[string]int{}
	for k := range 70 {
		link := filepath.Join(away, fmt.Sprintf("x-%02d", k), "n.txt")
		if err := os.Symlink(filepath.Join(home, ".ssh", "authorized_keys"), link); err != nil {
			t.Fatal(err)
		}
		for i, command := range c1 {
			got := globHeldDecision(command, cwd, home, nil)
			if got != "protected-target" && got != globHeld {
				t.Errorf("C1 row %d, link in subfolder %d: decision %q, want protected-target or TRUNCATED", i, k, got)
			}
			tally[got]++
		}
		if err := os.Remove(link); err != nil {
			t.Fatal(err)
		}
	}
	if tally[globHeld] == 0 || tally["protected-target"] == 0 {
		t.Fatalf("tally %v: the 64-read bound did not split the 70 positions", tally)
	}
}

// rel-1-0-10:GAP-0442 (review round 2 P2-1, probe H2): in a hidden view the
// client's answer comes first. The client walked as the user and proved a
// match ("1") through a link of an ordinary name in an away folder; this
// process then sees the home as missing and cannot read the away folder.
// The call is a protected target, as on rel, with the home hidden (H1),
// missing (H2) or hidden with the folder gone (H4).
func TestGAP0442HiddenViewClientMatchHolds(t *testing.T) {
	gap0398POSIX(t)
	if os.Geteuid() == 0 {
		t.Skip("root reads every folder")
	}
	homes, home, cwd := globFactsFixture(t, false)
	away := t.TempDir()
	if err := os.Symlink(filepath.Join(home, ".ssh", "authorized_keys"), filepath.Join(away, "n.txt")); err != nil {
		t.Fatal(err)
	}
	pattern := strings.Fields(gap0270ReadShapes(away)[0])[1]
	pattern = strings.TrimSuffix(pattern, "x-*.log") + "n*.txt"
	var rows []string
	for _, row := range globAliasProtectedCommands(cwd) {
		if strings.Contains(row, "keyd*/authorized_keys") && !strings.Contains(row, "authorized_keys2") &&
			!strings.Contains(row, "$PWD") && !strings.Contains(row, cwd) && !strings.HasPrefix(row, "cd ") {
			rows = append(rows, strings.ReplaceAll(row, "keyd*/authorized_keys", pattern))
		}
	}
	if len(rows) != 4 {
		t.Fatalf("GAP-1445 rows changed: %d rows", len(rows))
	}
	t.Cleanup(func() {
		_ = os.Rename(homes+".gone", homes)
		_ = os.Rename(away+".gone", away)
		_ = os.Chmod(homes, 0o700)
		_ = os.Chmod(away, 0o700)
	})
	for i, command := range rows {
		facts := clientGlobFactsFor(t, command, cwd)
		proved := false
		for key, value := range facts {
			proved = proved || strings.HasPrefix(key, GlobFactPrefix) && value == "1"
		}
		if !proved {
			t.Fatalf("row %d: the client proved no match", i)
		}
		views := []struct {
			name         string
			hide, unhide func() error
		}{
			{"H1 home and folder not accessible",
				func() error { return chmodAll(0, homes, away) }, func() error { return chmodAll(0o700, homes, away) }},
			{"H2 home missing, folder not accessible",
				func() error { return firstErr(os.Rename(homes, homes+".gone"), os.Chmod(away, 0)) },
				func() error { return firstErr(os.Rename(homes+".gone", homes), os.Chmod(away, 0o700)) }},
			{"H4 home not accessible, folder missing",
				func() error { return firstErr(os.Chmod(homes, 0), os.Rename(away, away+".gone")) },
				func() error { return firstErr(os.Chmod(homes, 0o700), os.Rename(away+".gone", away)) }},
		}
		for _, view := range views {
			if err := view.hide(); err != nil {
				t.Fatal(err)
			}
			got := ActionCommandDecisionWithGlobFacts(command, cwd, home, facts)
			if err := view.unhide(); err != nil {
				t.Fatal(err)
			}
			if got != "protected-target" {
				t.Errorf("row %d, %s: decision %q, want protected-target", i, view.name, got)
			}
		}
	}
}

func chmodAll(mode os.FileMode, paths ...string) error {
	for _, path := range paths {
		if err := os.Chmod(path, mode); err != nil {
			return err
		}
	}
	return nil
}

func firstErr(errs ...error) error {
	for _, err := range errs {
		if err != nil {
			return err
		}
	}
	return nil
}
