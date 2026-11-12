// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

// hookPathRawReads are the file system reads that wait for a network share
// as long as the system's connect timeout. A hook call names its paths, so
// a read of one must go through the bounded readers of network_path.go.
var hookPathRawReads = map[string][]string{
	// A root (os.OpenRoot) reads every path below it; only pathOpenRoot
	// opens one.
	"os":           {"Stat", "Lstat", "Open", "OpenFile", "ReadFile", "ReadDir", "Readlink", "OpenRoot", "OpenInRoot", "DirFS"},
	"ioutil":       {"ReadFile", "ReadDir"},
	"filepath":     {"EvalSymlinks", "WalkDir", "Walk", "Glob"},
	"pathidentity": {"StatPinned"},
}

// hookPathRawHandles open a path through the Windows API. A function may
// call one only after it read the same path through the bounded readers or
// asked networkPathUnanswered.
var hookPathRawHandles = map[string][]string{
	"windows": {"CreateFile", "GetLongPathName", "GetNamedSecurityInfo"},
	"syscall": {"CreateFile"},
}

// rel-1-0-6:GAP-0482: the target scans read below a network share only
// once the share answered (GAP-0127), but the gateway's command-target
// proofs and some scans read paths directly, so a redirect to a share that
// does not answer held its hook for the 21 s connect timeout. Every read
// of a path a hook call names, in this package and in those proofs, goes
// through the bounded readers; only a fixed system path is read directly.
func TestHookPathReadsAreShareBounded(t *testing.T) {
	var files []string
	for _, pattern := range []string{"*.go", "../gateway/semantic_*.go", "../gateway/trusted_action_*.go"} {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			t.Fatal(err)
		}
		for _, name := range matches {
			if strings.HasSuffix(name, "_test.go") || strings.HasPrefix(filepath.Base(name), "network_path") {
				continue
			}
			files = append(files, name)
		}
	}
	if len(files) < 50 {
		t.Fatalf("read %d files; the scan no longer finds the hook path sources", len(files))
	}
	var found []string
	fset := token.NewFileSet()
	for _, name := range files {
		file, err := parser.ParseFile(fset, name, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		for _, decl := range file.Decls {
			found = append(found, hookPathUnboundedReads(fset, decl)...)
		}
	}
	sort.Strings(found)
	if len(found) != 0 {
		t.Fatalf("hook path reads that bypass the network share bound (use pathStat, pathLstat, pathWalkDir, ... here, hookpaths.Stat or hookpaths.Lstat in the gateway):\n%s", strings.Join(found, "\n"))
	}
}

func fixedLocalPath(value string) bool {
	return strings.HasPrefix(value, "/") && !strings.HasPrefix(value, "//") && !strings.Contains(value, `\`)
}

// The guard itself sees a root opened under a named path, a reader of one,
// and a literal UNC path, and passes the bounded readers and a fixed local
// system path.
func TestHookPathReadGuardSeesRootsAndUNCLiterals(t *testing.T) {
	source := `package p
func a(cwd string) { root, _ := os.OpenRoot(cwd); root.Close() }
func b(cwd string) { _, _ = os.OpenInRoot(cwd, "x") }
func c(cwd string) { _ = os.DirFS(cwd) }
func d() { _, _ = os.Stat("//host/share/x") }
func e() { _, _ = os.Lstat("\\\\host\\share\\x") }
func f() { _, _ = ioutil.ReadFile("x") }
func ok(cwd string) { root, _ := pathOpenRoot(cwd); root.Close(); _, _ = os.ReadDir("/etc/profile.d") }
`
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "guard.go", source, parser.SkipObjectResolution)
	if err != nil {
		t.Fatal(err)
	}
	var found []string
	for _, decl := range file.Decls {
		found = append(found, hookPathUnboundedReads(fset, decl)...)
	}
	want := []string{"os.OpenRoot", "os.OpenInRoot", "os.DirFS", "os.Stat", "os.Lstat", "ioutil.ReadFile"}
	if len(found) != len(want) {
		t.Fatalf("guard found %d reads, want %d (%v):\n%s", len(found), len(want), want, strings.Join(found, "\n"))
	}
	for i, name := range want {
		if !strings.HasSuffix(found[i], ": "+name) {
			t.Fatalf("guard finding %d = %q, want %s", i, found[i], name)
		}
	}
}

// rel-1-0-6:GAP-0482 (review 1): the source, make and script readings read
// their file under the cwd through a root, which is opened below a share
// only once the share answered.
func TestIndirectSourceOnAShareThatDoesNotAnswerIsBounded(t *testing.T) {
	cwd := t.TempDir()
	if err := os.WriteFile(filepath.Join(cwd, "ordinary.sh"), []byte("echo ordinary\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	release := make(chan struct{})
	defer close(release)
	probes := fakeNetworkShare(t, cwd, 75*time.Millisecond, 50*time.Millisecond, func(string) { <-release })
	start := time.Now()
	content, ok := readIndirectSource("ordinary.sh", cwd)
	if took := time.Since(start); took > time.Second {
		t.Fatalf("the indirect read held the call %v", took)
	}
	if ok || content != "" || probes.Load() != 1 {
		t.Fatalf("indirect read below a share that does not answer: content %q, ok %v, %d probes; want unread after one probe", content, ok, probes.Load())
	}
}

func TestIndirectSourceOnAShareThatAnswersIsRead(t *testing.T) {
	cwd := t.TempDir()
	if err := os.WriteFile(filepath.Join(cwd, "ordinary.sh"), []byte("echo ordinary\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	probes := fakeNetworkShare(t, cwd, 100*time.Millisecond, 50*time.Millisecond, func(string) {})
	if content, ok := readIndirectSource("ordinary.sh", cwd); !ok || content != "echo ordinary\n" || probes.Load() != 1 {
		t.Fatalf("indirect read below a share that answers: content %q, ok %v, %d probes", content, ok, probes.Load())
	}
}

// rel-1-0-6:GAP-0482 (review 1): a hook call that names many fresh shares
// that do not answer waits for them one answer wait in all, not one per
// share, and reads every one of them as the first: unknown.
func TestOneHookCallWaitsForItsSharesOneAnswerWaitInAll(t *testing.T) {
	const shares = 8
	release := make(chan struct{})
	defer close(release)
	probes := fakeNetworkShare(t, "/dead0.example/share", 750*time.Millisecond, 5*time.Second, func(string) { <-release })
	networkShareRootOf = func(path string) string {
		for i := range shares {
			root := fmt.Sprintf("/dead%d.example/share", i)
			if strings.HasPrefix(filepath.ToSlash(path), root+"/") {
				return root
			}
		}
		return ""
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	var commands []string
	for i := range shares {
		commands = append(commands, fmt.Sprintf("echo ordinary > /dead%d.example/share/notes.txt", i))
	}
	payload, err := json.Marshal(map[string]any{
		"tool_name": "Bash", "cwd": home,
		"tool_input": map[string]string{"command": strings.Join(commands, "; ")},
	})
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	got := Resolve(payload)
	if took := time.Since(start); took > 2*time.Second {
		t.Fatalf("one hook call spent %v on %d shares that do not answer (%d probes); want one 750ms answer wait in all", took, shares, probes.Load())
	}
	targets, ok := Decode(got)
	if !ok {
		t.Fatalf("Resolve = %q", got)
	}
	first, listed := targets["/dead0.example/share/notes.txt"]
	for i := range shares {
		target := fmt.Sprintf("/dead%d.example/share/notes.txt", i)
		if value, present := targets[target]; present != listed || value != first {
			t.Fatalf("share %d read as %q (listed %v), the first as %q (listed %v): %s", i, value, present, first, listed, got)
		}
	}
}

// The benign twin: shares that answer are each read, however many.
func TestOneHookCallReadsEveryShareThatAnswers(t *testing.T) {
	const shares = 8
	var roots []string
	for range shares {
		roots = append(roots, t.TempDir())
	}
	probes := fakeNetworkShare(t, roots[0], 750*time.Millisecond, 5*time.Second, func(string) {})
	networkShareRootOf = func(path string) string {
		for _, root := range roots {
			if strings.HasPrefix(path, root+string(filepath.Separator)) {
				return root
			}
		}
		return ""
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	var commands []string
	for _, root := range roots {
		commands = append(commands, "echo ordinary > "+filepath.ToSlash(filepath.Join(root, "notes.txt")))
	}
	payload, err := json.Marshal(map[string]any{
		"tool_name": "Bash", "cwd": home,
		"tool_input": map[string]string{"command": strings.Join(commands, "; ")},
	})
	if err != nil {
		t.Fatal(err)
	}
	targets, ok := Decode(Resolve(payload))
	if !ok {
		t.Fatal("Resolve gave no target map")
	}
	for _, root := range roots {
		target := filepath.Join(root, "notes.txt")
		if targets[target] != target {
			t.Fatalf("a share that answers was not read: %s -> %q in %v", target, targets[target], targets)
		}
	}
	if got := probes.Load(); got != shares {
		t.Fatalf("%d probes, want one per share (%d)", got, shares)
	}
}

func hookPathUnboundedReads(fset *token.FileSet, decl ast.Decl) []string {
	fixed := map[*ast.SelectorExpr]bool{}
	gated := false
	ast.Inspect(decl, func(node ast.Node) bool {
		switch node := node.(type) {
		case *ast.CallExpr:
			// A fixed system path (/etc/profile.d) names no share; a
			// literal UNC path (//host/share, \\host\share) does.
			if selector, ok := node.Fun.(*ast.SelectorExpr); ok && len(node.Args) > 0 {
				if literal, ok := node.Args[0].(*ast.BasicLit); ok && literal.Kind == token.STRING {
					if value, err := strconv.Unquote(literal.Value); err == nil && fixedLocalPath(value) {
						fixed[selector] = true
					}
				}
			}
		case *ast.Ident:
			switch node.Name {
			case "networkPathUnanswered", "pathStat", "pathLstat":
				gated = true
			}
		}
		return true
	})
	var found []string
	ast.Inspect(decl, func(node ast.Node) bool {
		selector, ok := node.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		pkg, ok := selector.X.(*ast.Ident)
		if !ok {
			return true
		}
		where := fset.Position(selector.Pos()).String() + ": " + pkg.Name + "." + selector.Sel.Name
		for _, name := range hookPathRawReads[pkg.Name] {
			if selector.Sel.Name == name && !fixed[selector] {
				found = append(found, where)
			}
		}
		for _, name := range hookPathRawHandles[pkg.Name] {
			if selector.Sel.Name == name && !gated {
				found = append(found, where+" (no bounded read of the path first)")
			}
		}
		return true
	})
	return found
}

// The readers the gateway proofs use answer a share that does not answer
// within the bound, with an error that NotExist reports: the verdict a
// proof reached when its unbounded read failed with ERROR_BAD_NETPATH at
// the end of the connect timeout. A share that answers is read as before.
func TestHookPathReadersBoundAShareThatDoesNotAnswer(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	probes := fakeNetworkShare(t, "/dead.example", 100*time.Millisecond, 50*time.Millisecond, func(string) { <-release })
	for _, read := range []struct {
		name string
		read func(string) (os.FileInfo, error)
	}{{"Lstat", Lstat}, {"Stat", Stat}} {
		start := time.Now()
		info, err := read.read("/dead.example/share/w4.txt")
		if took := time.Since(start); took > time.Second {
			t.Fatalf("%s held the call %v", read.name, took)
		}
		if info != nil || err == nil || !NotExist(err) || os.IsNotExist(err) {
			t.Fatalf("%s = %v, %v; want the share's error, which NotExist reports", read.name, info, err)
		}
	}
	if got := probes.Load(); got != 1 {
		t.Fatalf("the share was asked %d times, want once", got)
	}
	missing := filepath.Join(t.TempDir(), "missing")
	if _, err := Lstat(missing); !NotExist(err) {
		t.Fatalf("Lstat(local missing) = %v, want not exist", err)
	}
	if _, err := Stat(t.TempDir()); err != nil || NotExist(nil) {
		t.Fatalf("Stat(local dir) = %v", err)
	}
}

func TestHookPathReadersReadAShareThatAnswers(t *testing.T) {
	share := t.TempDir()
	fakeNetworkShare(t, share, 100*time.Millisecond, 50*time.Millisecond, func(string) {})
	file := filepath.Join(share, "w4.txt")
	if err := os.WriteFile(file, []byte("hi\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, read := range []func(string) (os.FileInfo, error){Lstat, Stat} {
		if info, err := read(file); err != nil || !info.Mode().IsRegular() {
			t.Fatalf("read of a file on a share that answers = %v, %v", info, err)
		}
	}
	walked := 0
	if err := pathWalkDir(share, func(string, os.DirEntry, error) error { walked++; return nil }); err != nil || walked != 2 {
		t.Fatalf("walk of a share that answers: %d entries, %v", walked, err)
	}
}

// The copy-source link check (cp -r) reads its source below a share only
// after the share answered, and records a source on a share that does not
// answer as the missing source the unbounded read reported.
func TestCopySourceOnAShareThatDoesNotAnswerIsBounded(t *testing.T) {
	share := t.TempDir()
	release := make(chan struct{})
	defer close(release)
	probes := fakeNetworkShare(t, share, 100*time.Millisecond, 50*time.Millisecond, func(string) { <-release })
	cwd := t.TempDir()
	source := filepath.Join(share, "src")
	facts := map[string]string{}
	start := time.Now()
	linked := cpDiskSymlink([]string{"-r", source, "out"}, []bool{true, true, true}, cwd, cwd, facts, true)
	if took := time.Since(start); took > time.Second {
		t.Fatalf("the copy-source check held the call %v", took)
	}
	if probes.Load() == 0 {
		t.Fatal("the copy-source check read below the share without asking it")
	}
	if linked || facts[SourceLinkFactPrefix+source] != "0" {
		t.Fatalf("copy from a share that does not answer: linked %v, facts %v; want the missing-source verdict", linked, facts)
	}
	// The local twin is read as before.
	local := filepath.Join(cwd, "src")
	if err := os.Mkdir(local, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(cwd, "elsewhere"), filepath.Join(local, "link")); err != nil {
		t.Skip("no symbolic links here:", err)
	}
	if !cpDiskSymlink([]string{"-r", local, "out"}, []bool{true, true, true}, cwd, cwd, map[string]string{}, true) {
		t.Fatal("a local source tree that holds a link no longer reads as one")
	}
}
