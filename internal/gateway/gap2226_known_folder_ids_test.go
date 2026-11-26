// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"math/rand/v2"
	"path"
	"slices"
	"strings"
	"testing"
)

// gap2226KnownStats counts the rare branches gap2226KnownFoldersReference
// took, so the comparison below is known to read them.
type gap2226KnownStats struct{ capped, followed, cdpath, replaced int }

// gap2226KeepCleanReference is newGuestPlacementPlan's keepClean as it was
// before guestKeepFolder.
func gap2226KeepCleanReference(list []string, dir, home string) []string {
	first := len(list) < maxSandboxGuestCandidateDirs || guestDirFirst(dir, home)
	if !first || slices.Contains(list, dir) {
		return list
	}
	if len(list) < maxSandboxGuestCandidateDirs {
		return append(list, dir)
	}
	for at := len(list) - 1; at > 0; at-- {
		if !guestDirFirst(list[at], home) {
			list[at] = dir
			return list
		}
	}
	return list
}

// gap2226KnownFolderPrograms are scripts for the comparison: random mixes
// of static, dynamic, absolute, ~ and relative cds, pushd/popd, cd -, loops,
// functions, groups, subshells, CDPATH settings and followed values, and
// the long cd chains of the cost shapes.
func gap2226KnownFolderPrograms() []string {
	r := rand.New(rand.NewPCG(2226, 2249))
	pool := []string{"cd a", "cd b", "cd ..", "cd ../..", "cd ~/.ssh", "cd ~", "cd", "cd /tmp/x", "cd /", "pushd p", "popd",
		"cd -", "$CMD", "eval $X", "f", "g", "g(){ cd q; }", "f(){ cd ~/.defenseclaw && ls; }", "for i in 1 2; do cd l; done",
		"export CDPATH=.", "CDPATH=/tmp:~", "ls", "touch f", "cd ../.claude", `cd "$D"`, `D=~/.claude`, "cd ./c/d", "cd .cache",
		"cd src/..", "echo m > config.yaml", "{ cd grp; }", "(cd sub)", "cd s && ls", "while true; do cd w; break; done", "cd p0", "cd .x",
		"h1(){ cd a; }", "h2(){ cd b; }", "h3(){ cd a; cd b; }", "h5(){ h1; cd b; }", "h1", "h2", "h3", "h5"}
	seps := []string{"; ", "\n", " && ", " || "}
	var out []string
	for range 300 {
		var b strings.Builder
		for i := range 2 + r.IntN(30) {
			if i > 0 {
				b.WriteString(seps[r.IntN(len(seps))])
			}
			b.WriteString(pool[r.IntN(len(pool))])
		}
		out = append(out, b.String())
	}
	chain := func(head, line string, n int) string {
		var b strings.Builder
		b.WriteString(head)
		for i := range n {
			fmt.Fprintf(&b, line, i)
		}
		return b.String() + "ls"
	}
	return append(out,
		chain("cd .cache\n$CMD\n", "cd d%d\n", 300),
		chain("cd .cache\nbash <<< 'true'\n", "cd /tmp/rk%d && ls\n", 60),
		chain("export CDPATH=.\n", "cd s%d\n", 80),
		chain("D=~/.claude; cd \"$D\"\n", "cd d%d; cd ..\n", 70),
		chain("f(){ cd ~/.ssh; }\n", "cd x%d\nf\n", 40),
		chain("$CMD\n", "pushd e%[1]d; cd .h%[1]d\n", 50),
		// Each round knows one more folder earlier through a function
		// called before its body: the walk stops at its fourth round.
		"ls; h2; h1(){ cd a; }; h3(){ cd a; cd b; }; h2(){ cd b; }; cd a; h3; h5(){ h1; cd b; }; cd b; cd ..")
}

// TestGAP2226KnownFolderIDsAreReference pins guestKnownFolders, its folders
// ids of a folder tree, to the walk on strings it replaced: the same grown
// targets in the same order and the same place for every folder of dirs and
// of the targets, over random scripts and the cost shapes' cd chains, short,
// nearly full and full lists, with and without followed values, with the
// guest's folder in the lists or not and an absolute or relative home
// (rel-1-0-10:GAP-2226).
func TestGAP2226KnownFolderIDsAreReference(t *testing.T) {
	var plain []string
	for i := range maxSandboxGuestCandidateDirs {
		plain = append(plain, fmt.Sprintf("/home/alice/p%d", i))
	}
	lists := [][2][]string{
		{{"/home/alice/.cache"}, {"/home/alice/.cache"}},
		{{"/home/alice", "/tmp"}, {"/home/alice/.cache", "/home/alice/.ssh"}},
		{plain, plain[:maxSandboxGuestCandidateDirs-1]},
		{plain, append([]string{"/home/alice/.cache"}, plain[1:]...)},
		{{"/"}, {"/home/alice/a/b", "/"}},
	}
	followeds := []map[string]int{nil, {"/home/alice/.claude": 3, "/home/alice/p1": 1, "/home/alice/.cache/a": 2, "/home/alice/.cache": 1}}
	stats := &gap2226KnownStats{}
	compared := 0
	for _, command := range gap2226KnownFolderPrograms() {
		for _, home := range []string{"/home/alice", "home"} {
			keep := func(list []string, dir string) []string {
				if len(list) == maxSandboxGuestCandidateDirs && guestDirFirst(dir, home) && !slices.Contains(list, dir) {
					stats.replaced++
				}
				return gap2226KeepCleanReference(list, dir, home)
			}
			calls, cdpath := guestScriptCalls(command, home)
			for _, list := range lists {
				for _, followed := range followeds {
					for _, cwd := range []string{"/home/alice/.cache", "/home/alice", "/tmp/elsewhere", "rel"} {
						dirs, targets := list[0], list[1]
						wantGrown, wantKnown := gap2226KnownFoldersReference(calls, slices.Clone(dirs), slices.Clone(targets), followed, cwd, home, cdpath, keep, newGuestCDMemo(home), stats)
						gotGrown, gotKnown := guestKnownFolders(calls, slices.Clone(dirs), slices.Clone(targets), followed, cwd, home, cdpath, newGuestCDMemo(home))
						if !slices.Equal(gotGrown, wantGrown) {
							t.Fatalf("%.80q home %q cwd %q: grown targets\n got %q\nwant %q", command, home, cwd, gotGrown, wantGrown)
						}
						for _, dir := range slices.Concat(dirs, wantGrown) {
							want, wantOK := wantKnown[dir]
							got, gotOK := gotKnown[dir]
							if got != want || gotOK != wantOK {
								t.Fatalf("%.80q home %q cwd %q: %s known from %d (%v), want %d (%v)", command, home, cwd, dir, got, gotOK, want, wantOK)
							}
						}
						compared++
					}
				}
			}
		}
	}
	if stats.capped == 0 || stats.followed == 0 || stats.cdpath == 0 || stats.replaced == 0 {
		t.Fatalf("a branch of the walk was never taken (%+v): the comparison reads less than it says", *stats)
	}
	t.Logf("%d walks compared; branches %+v", compared, *stats)
}

// guestCDJoinClean is guestCDJoin for bases that are each clean
// (path.Clean's answer), as the walks' own folder lists are. A plain name
// (cd d5) joined to a clean folder is that folder, a slash and the name,
// path.Join's answer without its clean, and the targets are clean too: a
// long call joins each of its cds to up to 128 folders, and cleaning each
// join rescanned folders that grow with the chain (rel-1-0-10:GAP-2226,
// GAP-2249).
func guestCDJoinClean(operand string, bases []string, home string) []string {
	if !guestCDPlainOperand(operand) {
		return guestCDJoin(operand, bases, home)
	}
	// The targets are cut from one string: an 8 KB cd chain joins each of
	// its 1,100 cds to up to 128 folders, and a string each was most of
	// guestKnownFolders' allocations (rel-1-0-10:GAP-2249).
	size, count := 0, 0
	for _, base := range bases {
		switch {
		case base == "/":
			size, count = size+1+len(operand), count+1
		case path.IsAbs(base):
			size, count = size+len(base)+1+len(operand), count+1
		}
	}
	if count == 0 {
		return nil
	}
	var joined strings.Builder
	joined.Grow(size)
	for _, base := range bases {
		if base == "/" || path.IsAbs(base) {
			if base != "/" {
				joined.WriteString(base)
			}
			joined.WriteByte('/')
			joined.WriteString(operand)
		}
	}
	all := joined.String()
	targets := make([]string, 0, count)
	for _, base := range bases {
		size := 0
		switch {
		case base == "/":
			size = 1 + len(operand)
		case path.IsAbs(base):
			size = len(base) + 1 + len(operand)
		}
		if size != 0 {
			targets = append(targets, all[:size])
			all = all[size:]
		}
	}
	return targets
}

// gap2226KnownFoldersReference is guestKnownFolders as it was before its
// folder ids (t6/fix-guestperf-m 2e3e486302), its folders strings, with
// stats counting the rare branches it took.
func gap2226KnownFoldersReference(calls []guestScriptCall, dirs, targets []string, followed map[string]int, cwd, home string, cdpath int,
	keep func([]string, string) []string, cdMemo *guestCDMemo, stats *gap2226KnownStats) ([]string, map[string]int) {
	type move struct {
		operand string
		at      int
	}
	var moves []move
	dynamic := -1
	for at, call := range calls {
		if call.dynamic && dynamic < 0 {
			dynamic = call.start
		}
		if reading := cdMemo.reading(call.text); reading.moves {
			moves = append(moves, move{reading.operand, at})
		}
	}
	// known is made at about the size it reaches: a relative cd is joined
	// to at most every listed folder, an absolute or ~ one names one. An
	// 8 KB cd chain grew it to 140,000 folders a split at a time
	// (rel-1-0-10:GAP-2249).
	listed := slices.Concat(dirs, targets)
	size := len(listed)
	for _, move := range moves {
		if path.IsAbs(move.operand) || move.operand == "~" || strings.HasPrefix(move.operand, "~/") {
			size++
		} else {
			size += len(dirs) + maxSandboxGuestCandidateDirs
		}
	}
	known := make(map[string]int, min(size, guestKnownFoldersSizeMax))
	// dirs and targets are clean (newGuestPlacementPlan's keep cleans each),
	// so every target guestCDJoinClean makes from them is clean, and keep
	// takes it as it is.
	for _, dir := range listed {
		if cdpath < 0 || dir == path.Clean(cwd) {
			known[dir] = -1
		}
	}
	grown := targets
	var bases []string
	reached := map[string]int{}
	// joins holds, per move, the bases it was joined to in the last round
	// that changed them, and the targets of that join. A move whose bases
	// are the same in a later round reaches the same targets, and each of
	// them is already known from call.first or earlier (a folder's place
	// only moves earlier), so it is not joined or looked up again: the
	// round that only confirms the walk redid every join of an 8 KB cd
	// chain (rel-1-0-10:GAP-2249).
	type moveJoin struct{ bases, targets []string }
	joins := make([]moveJoin, len(moves))
	for round := 0; ; round++ {
		if round == 4 {
			stats.capped++
			for _, dir := range slices.Concat(listed, grown) {
				known[dir] = -1
			}
			return grown, known
		}
		changed := false
		grown = slices.Clone(targets)
		clear(reached)
		var pool []string
		for at, move := range moves {
			call := calls[move.at]
			bases = bases[:0]
			for _, list := range [2][]string{dirs, grown} {
				for _, dir := range list {
					if since, ok := known[dir]; ok && since <= call.at {
						bases = append(bases, dir)
					}
				}
			}
			join := &joins[at]
			same := round > 0 && slices.Equal(join.bases, bases)
			if !same {
				start := len(pool)
				pool = append(pool, bases...)
				join.bases, join.targets = pool[start:len(pool):len(pool)], guestCDJoinClean(move.operand, bases, home)
			}
			for _, target := range join.targets {
				// reached is read only against followed, which counts no
				// folder when the split followed no value.
				if len(followed) != 0 {
					reached[target]++
				}
				grown = keep(grown, target)
				if same {
					continue
				}
				if since, ok := known[target]; !ok || call.first < since {
					known[target] = call.first
					changed = true
				}
			}
			if call.at < cdpath || !guestCDPathLooksUp(move.operand) {
				continue
			}
			for _, dir := range slices.Concat(listed, grown) {
				if since, ok := known[dir]; guestCDPathMayReach(dir, move.operand) && (!ok || call.first < since) {
					known[dir] = call.first
					stats.cdpath++
					changed = true
				}
			}
		}
		for _, dir := range slices.Concat(listed, grown) {
			since, ok := known[dir]
			switch {
			case !ok:
				known[dir] = -1
				changed = true
			case followed[dir] > reached[dir] && since > dynamic:
				stats.followed++
				known[dir] = dynamic
				changed = true
			}
		}
		if !changed {
			return grown, known
		}
	}
}
