// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"math/rand/v2"
	"path"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
	"mvdan.cc/sh/v3/syntax"
)

// gap2249CDTargetsReference is guestCDTargets as it was before the walk's
// folder tree: the operand joined to each base string (guestCDJoinClean).
func gap2249CDTargetsReference(text string, bases []string, home string) []string {
	operand, ok := guestCDOperand(text, home)
	if !ok {
		return nil
	}
	return guestCDJoinClean(operand, bases, home)
}

// gap2249OwnShellWalkReference is guestOwnShellWalkText as it was before
// the walk's folder tree (t6/fix-guestperf dcdeb7eb06), its folders strings
// and its readings every (text, folder) pair, for
// TestGAP2249OwnShellWalkFolderTreeIsReference.
func gap2249OwnShellWalkReference(command, cwd, home string) (map[guestShellReading]bool, map[string]bool) {
	file, err := syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse(strings.NewReader(command), "")
	if err != nil || !path.IsAbs(cwd) {
		return nil, nil
	}
	cdpath := strings.Contains(command, "CDPATH")
	// Functions whose body changes the folder; a call of one leaves it unknown.
	moving := map[string]bool{}
	syntax.Walk(file, func(node syntax.Node) bool {
		if decl, ok := node.(*syntax.FuncDecl); ok && decl.Name != nil && guestNodeChangesDirectory(decl.Body, home, nil) {
			moving[decl.Name.Value] = true
		}
		return true
	})
	text := func(node syntax.Node) string {
		start, end := int(node.Pos().Offset()), int(node.End().Offset())
		if start < 0 || end > len(command) || start >= end {
			return ""
		}
		return command[start:end]
	}
	// seen is join's, cleared for each join: a fresh map for each statement
	// was most of the walk's allocations on a long call (rel-1-0-10:GAP-2226).
	// Every folder the walk holds is clean: the call's folder cleaned, then
	// only targets guestCDTargets joins to clean folders. So join keeps the
	// absolute ones as they are; cleaning each again rescanned folders that
	// grow with a cd chain (GAP-2249).
	seen := map[string]bool{}
	join := func(sets ...[]string) []string {
		var out []string
		clear(seen)
		for _, set := range sets {
			for _, dir := range set {
				if path.IsAbs(dir) && !seen[dir] {
					seen[dir] = true
					out = append(out, dir)
				}
			}
		}
		if len(out) > maxSandboxGuestOwnShellFolders {
			// The folders that may hold protected files first (guestDirFirst),
			// each part in its own order, up to the bound: the stable sort
			// that did it asked guestDirFirst n log n times a join
			// (rel-1-0-10:GAP-2249).
			kept := make([]string, 0, maxSandboxGuestOwnShellFolders)
			for _, first := range [2]bool{true, false} {
				for _, dir := range out {
					if len(kept) == maxSandboxGuestOwnShellFolders {
						break
					}
					if guestDirFirst(dir, home) == first {
						kept = append(kept, dir)
					}
				}
			}
			out = kept
		}
		return out
	}
	unread := false
	var readings map[guestShellReading]bool
	placed := map[string]bool{}
	// mark keys every simple command of node (one statement, run from the
	// folders in) with each of those folders, once a command before it may
	// have moved the shell, and notes in placed whether the walk placed it.
	mark := func(node syntax.Node, in []string) {
		syntax.Walk(node, func(inner syntax.Node) bool {
			stmt, ok := inner.(*syntax.Stmt)
			if !ok {
				return true
			}
			if call, isCall := stmt.Cmd.(*syntax.CallExpr); !isCall || len(call.Args) == 0 {
				return true
			}
			span := text(stmt)
			if span == "" {
				return true
			}
			if inner != node || len(in) == 0 {
				placed[span] = false
			} else if _, seen := placed[span]; !seen {
				placed[span] = true
			}
			if unread && len(in) != 0 {
				if readings == nil {
					readings = map[guestShellReading]bool{}
				}
				for _, dir := range in {
					readings[guestShellReading{span, dir}] = true
				}
			}
			return true
		})
	}
	// step runs one statement from the folders in: the folders the shell
	// stands in where it succeeded and where it failed.
	var step func(*syntax.Stmt, []string) (succeeded, failed []string)
	step = func(stmt *syntax.Stmt, in []string) (succeeded, failed []string) {
		if pair, ok := stmt.Cmd.(*syntax.BinaryCmd); ok && !stmt.Background && len(stmt.Redirs) == 0 {
			switch {
			case pair.Op == syntax.AndStmt:
				leftOK, leftFailed := step(pair.X, in)
				rightOK, rightFailed := step(pair.Y, leftOK)
				return rightOK, join(leftFailed, rightFailed)
			case pair.Op == syntax.OrStmt && guestStmtLeaves(pair.Y, home):
				leftOK, _ := step(pair.X, in)
				return leftOK, nil
			}
		}
		mark(stmt, in)
		defer func() { unread = unread || guestNodeRunsUnreadCommand(stmt, home) }()
		if stmt.Background {
			return in, in // an & list runs in a subshell
		}
		switch cmd := stmt.Cmd.(type) {
		case *syntax.CallExpr:
			if len(cmd.Args) == 0 {
				return in, in
			}
			program, static := hookpaths.StaticWord(cmd.Args[0], home)
			switch {
			case !static:
			case moving[program] || program == "popd":
				return nil, nil
			case program == "cd" || program == "pushd":
				if cdpath || len(cmd.Assigns) != 0 {
					return nil, nil
				}
				moved := gap2249CDTargetsReference(text(stmt), in, home)
				if len(moved) == 0 {
					return nil, nil
				}
				return join(moved), in
			}
			return in, in
		case *syntax.Subshell, *syntax.FuncDecl:
			return in, in
		}
		if guestNodeChangesDirectory(stmt.Cmd, home, moving) {
			return nil, nil
		}
		return in, in
	}
	current := []string{path.Clean(cwd)}
	for _, stmt := range file.Stmts {
		succeeded, failed := step(stmt, current)
		current = join(succeeded, failed)
	}
	return readings, placed
}

// gap2249WalkShapes are the cost shapes of the walk (rel-1-0-10:GAP-2249,
// GAP-2226): 8 KB cd chains and fans after $CMD or a here-string.
func gap2249WalkShapes() []string {
	fill := func(prefix, format, tail string) string {
		var b strings.Builder
		b.WriteString(prefix)
		for i := 0; ; i++ {
			u := fmt.Sprintf(format, i)
			if b.Len()+len(u)+len(tail) > 8192 {
				break
			}
			b.WriteString(u)
		}
		b.WriteString(tail)
		return b.String()
	}
	lines := func(n int, format string) string {
		var b strings.Builder
		for i := range n {
			fmt.Fprintf(&b, format, i)
		}
		return b.String()
	}
	pairs64 := lines(64, "cd /tmp/rk4r%d && ls\n")
	return []string{
		fill("cd .cache\n$CMD\n", "cd d%d\n", "ls"),
		fill("cd .cache\n$CMD\n", "cd s%d; $C\n", "ls"),
		fill("cd .cache\nbash <<< 'true'\n$CMD\n"+lines(7, "cd s%d\n"), "touch f%d\n", "ls"),
		"cd .cache\n$CMD\n" + lines(7, "cd s%d\n") + lines(118, "touch f%d\n") + "ls",
		fill("cd .cache\n$CMD\n", "cd /tmp/rk4w%d && ls\n", "ls"),
		fill("cd .cache\n$CMD\n"+pairs64, "touch f%d\n", "ls"),
		fill("cd .cache\n$CMD\n", "cd ../d%d\n", "ls"),
		fill("cd .cache\n$CMD\n", "cd d%d/e\n", "ls"),
		fill("$CMD\n", "cd ~/d%d || cd d%d\n", "ls"),
		fill("cd .cache\n$CMD\n", "cd d%d && cd ..\n", "ls"),
	}
}

// gap2249WalkScript is a random script of the statements the walk reads:
// static cds of every operand form (plain, hidden, .., a/b, absolute, ~,
// ~/x, a bare cd, cd -, a dynamic one, pushd, popd), unread commands ($CMD,
// eval, source), && and || lists, cd X || exit, subshells, functions, & and
// key-shaped readings, enough cds that may fail to pass the folder bound.
func gap2249WalkScript(r *rand.Rand) string {
	cds := []string{"cd d%d", "cd .ssh", "cd .cache", "cd ..", "cd ../x%d", "cd a/b%d", "cd ./c", "cd /tmp/t%d", "cd /", "cd ~",
		"cd ~/.claude", "cd ~/w%d", "cd", "cd -", "cd \"$D\"", "pushd p%d", "popd", "cd -- q%d", "builtin cd b%d", "cd .", "cd ~x",
		"cd /home/alice/.ssh", "cd ../../..", "cd e%d/", "cd //f%d"}
	other := []string{"$CMD", "eval \"$X\"", "source s.sh", "ls", "touch f%d", "echo k >> authorized_keys", "cat id_ed25519",
		"(cd /tmp/z; ls)", "f() { cd y; }", "f", "true && cd g%d", "cd h%d || exit", "cd i%d || cd j%d", "ls &", "{ cd k%d; }",
		"echo m > config.yaml", "x=1 cd l%d"}
	var b strings.Builder
	n := 4 + r.IntN(40)
	for i := range n {
		var line string
		if r.IntN(3) != 0 {
			line = cds[r.IntN(len(cds))]
		} else {
			line = other[r.IntN(len(other))]
		}
		if strings.Contains(line, "%d") {
			line = strings.ReplaceAll(line, "%d", fmt.Sprint(i%9))
		}
		b.WriteString(line)
		switch r.IntN(6) {
		case 0:
			b.WriteString(" && ")
		case 1:
			b.WriteString("; ")
		default:
			b.WriteString("\n")
		}
	}
	b.WriteString("ls")
	return b.String()
}

// TestGAP2249OwnShellWalkFolderTreeIsReference pins the walk's folder tree
// (guestFolderTree) to the string walk it replaced: the same (text, folder)
// readings, the same placed texts, and has answering exactly those pairs,
// on the cost shapes, the own-shell tests' scripts and 3,000 random scripts
// in three folders under three homes (rel-1-0-10:GAP-2249).
func TestGAP2249OwnShellWalkFolderTreeIsReference(t *testing.T) {
	scripts := gap2249WalkShapes()
	scripts = append(scripts,
		"cd .cache\nbash <<< 'true'\n$CMD\ncd s0\ncd s1\ncd s2\ncd s3\ncd s4\ntouch f0\nls",
		"$CMD\ncd ../.ssh || exit\necho k >> authorized_keys",
		"cd a && $CMD && cd b; ls; ls",
		"(cd ~/.defenseclaw || cd /tmp); $CMD; echo m > config.yaml; cd ~/.defenseclaw && ls",
		"cd .cache; bash <<< true; $CMD; cd s0; cd s1; cd s2; cd s3; cd s4; cd s5; cd s6; cd ../.ssh; echo k >> authorized_keys",
	)
	r := rand.New(rand.NewPCG(2249, 0))
	for range 3000 {
		scripts = append(scripts, gap2249WalkScript(r))
	}
	homes := []string{"/home/alice", "rel", ""}
	cwds := []string{"/home/alice", "/home/alice/.cache", "/"}
	compared, pairs := 0, 0
	for at, script := range scripts {
		home := homes[at%len(homes)]
		cwd := cwds[(at/len(homes))%len(cwds)]
		want, wantPlaced := gap2249OwnShellWalkReference(script, cwd, home)
		readings, placed := guestOwnShellWalkText(script, cwd, home)
		got := readings.pairs()
		if fmt.Sprint(placed) != fmt.Sprint(wantPlaced) {
			t.Fatalf("%q in %q, home %q: placed %v, want %v", script, cwd, home, placed, wantPlaced)
		}
		if len(got) != len(want) {
			t.Fatalf("%q in %q, home %q: %d readings, want %d", script, cwd, home, len(got), len(want))
		}
		// has answers every pair read, and on its neighbours (the folder's
		// parent, the folder with a trailing slash, another text, probe
		// folders) exactly what the reference read.
		var texts []string
		for pair := range want {
			texts = append(texts, pair.text)
		}
		texts = append(texts, "ls", "nope")
		probes := []string{"/", "/nope", cwd, path.Join(cwd, "x"), "rel", ""}
		check := func(text, dir string) {
			if readings.has(text, dir) != want[guestShellReading{text, dir}] {
				t.Fatalf("%q in %q, home %q: has(%q, %q) = %v", script, cwd, home, text, dir, !want[guestShellReading{text, dir}])
			}
		}
		at := 0
		for pair := range want {
			if !got[pair] {
				t.Fatalf("%q in %q, home %q: missing reading %q", script, cwd, home, pair)
			}
			check(pair.text, pair.dir)
			check(pair.text, pair.dir+"/")
			check(pair.text, path.Dir(pair.dir))
			check(texts[at%len(texts)], pair.dir)
			at++
		}
		for _, text := range texts[max(0, len(texts)-64):] {
			for _, dir := range probes {
				check(text, dir)
			}
		}
		compared++
		pairs += len(want)
	}
	if pairs < 1_000_000 {
		t.Fatalf("only %d readings compared over %d scripts", pairs, compared)
	}
	t.Logf("%d scripts, %d readings identical", compared, pairs)
}

// TestGAP2249FolderTreeLookup pins the folder tree's strings and lookup: a
// folder's string is the path it was made from, lookup finds exactly the
// folders made, and two folders whose strings share a 64-bit hash are told
// apart by their names.
func TestGAP2249FolderTreeLookup(t *testing.T) {
	tree := newGuestFolderTree()
	dirs := []string{"/", "/a", "/a/b", "/a/b/.c", "/x y/z", "/a/...", "/home/alice/.cache/s0/s1"}
	ids := map[string]int32{}
	for _, dir := range dirs {
		ids[dir] = tree.folder(dir)
	}
	ids["/a/b/d"] = tree.child(ids["/a/b"], "d")
	ids["/e"] = tree.child(0, "e")
	for dir, id := range ids {
		if got := tree.path(id); got != dir {
			t.Errorf("path(%d) = %q, want %q", id, got, dir)
		}
		if got, ok := tree.lookup(dir); !ok || got != id {
			t.Errorf("lookup(%q) = %d, %v, want %d", dir, got, ok, id)
		}
	}
	for _, dir := range []string{"/b", "/a/b/", "a/b", "", "//a", "/a//b", "/a/b/.c/d", "/home/bob"} {
		if id, ok := tree.lookup(dir); ok {
			t.Errorf("lookup(%q) = %d, want none", dir, id)
		}
	}
	// A collision: a second folder filed under the hash of the first.
	other := tree.child(0, "zz")
	hash := tree.hashes[ids["/a"]]
	tree.more = map[uint64][]int32{hash: {other}}
	tree.byHash[hash] = other
	if got, ok := tree.lookup("/a"); ok {
		t.Errorf("lookup(/a) under a shared hash = %d, want none (only /zz is filed there first)", got)
	}
	tree.more[hash] = append(tree.more[hash], ids["/a"])
	if got, ok := tree.lookup("/a"); !ok || got != ids["/a"] {
		t.Errorf("lookup(/a) past a shared hash = %d, %v, want %d", got, ok, ids["/a"])
	}
	if got, ok := tree.lookup("/zz"); !ok || got != other {
		t.Errorf("lookup(/zz) = %d, %v, want %d", got, ok, other)
	}
	tree.done()
	if got, ok := tree.lookup("/a/b/d"); !ok || got != ids["/a/b/d"] {
		t.Errorf("lookup after done = %d, %v", got, ok)
	}
}
