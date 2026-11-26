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

	"github.com/defenseclaw/defenseclaw/internal/testenv"
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
	"pathidentity": {"StatPinned", "LstatPinned", "HoldUnlinked"},
}

// hookPathRawHandles open a path through the Windows API. A function may
// call one only inside a read of readGated or readGatedValue, which hands
// it the path the share gate read under the hold of its last component and
// discards the answer when the hold saw it change. Asking the share gate
// or a stat first and then opening the name again is a second lookup of the
// name after the share decision; it is no gate (rel-1-0-10:GAP-1264).
var hookPathRawHandles = map[string][]string{
	"windows": {"CreateFile", "GetLongPathName", "GetNamedSecurityInfo", "FindFirstFile"},
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

// rel-1-0-10:GAP-1264 (CHK-RF-WINPATH-R2 F1): the share gate's own readers
// (network_path*.go), which TestHookPathReadsAreShareBounded leaves out,
// read only the path the gate read. A raw read there is either the read a
// readGated or readGatedValue call makes (the function it is handed), or a
// read of gate.read, the path the share walk resolved; the share walk itself
// (shareGateOwnReads) is the gate. pathReadDirLimit asked the gate and then
// opened the name again (os.Open(name)), a second lookup after the share
// decision that this test now refuses.
func TestShareGateReadersReadTheGatedPath(t *testing.T) {
	files, err := filepath.Glob("network_path*.go")
	if err != nil {
		t.Fatal(err)
	}
	var sources []string
	for _, name := range files {
		if !strings.HasSuffix(name, "_test.go") {
			sources = append(sources, name)
		}
	}
	if len(sources) < 4 {
		t.Fatalf("read %d share gate sources (%v); the scan no longer finds network_path.go", len(sources), sources)
	}
	var found []string
	fset := token.NewFileSet()
	for _, name := range sources {
		file, err := parser.ParseFile(fset, name, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		for _, decl := range file.Decls {
			found = append(found, shareGateNameReads(fset, decl)...)
		}
	}
	sort.Strings(found)
	if len(found) != 0 {
		t.Fatalf("share gate readers that read a name, not the path the gate read (hand the read to readGated, or read gate.read):\n%s", strings.Join(found, "\n"))
	}
}

// shareGateOwnReads are the declarations of network_path*.go that are the
// share gate: they read the name to make the share decision, or hold what
// the decision read.
var shareGateOwnReads = map[string]string{
	"readGated":         "holds the gated path for the read it is handed",
	"walkShareLinks":    "the share walk: reads each component once",
	"probeNetworkShare": "asks a share root (on this machine) whether it answers",
	"walkLstat":         "the share walk's read of one component",
	"openDirectory":     "the read pathOpenDirectory hands to readGated",
}

// shareGateNameReads lists the raw reads of decl that read neither inside
// the read handed to readGated or readGatedValue nor gate.read.
func shareGateNameReads(fset *token.FileSet, decl ast.Decl) []string {
	switch decl := decl.(type) {
	case *ast.FuncDecl:
		if _, ok := shareGateOwnReads[decl.Name.Name]; ok {
			return nil
		}
	case *ast.GenDecl:
		// A var block: each value is looked at alone.
		var found []string
		for _, spec := range decl.Specs {
			value, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for i, name := range value.Names {
				if _, ok := shareGateOwnReads[name.Name]; ok || i >= len(value.Values) {
					continue
				}
				found = append(found, shareGateNameReadsIn(fset, value.Values[i])...)
			}
		}
		return found
	}
	return shareGateNameReadsIn(fset, decl)
}

func shareGateNameReadsIn(fset *token.FileSet, root ast.Node) []string {
	type span struct{ from, to token.Pos }
	var handed []span
	gatedPath := map[*ast.SelectorExpr]bool{}
	readsGateRead := func(node ast.Node) bool {
		found := false
		ast.Inspect(node, func(node ast.Node) bool {
			if selector, ok := node.(*ast.SelectorExpr); ok && selector.Sel.Name == "read" {
				if ident, ok := selector.X.(*ast.Ident); ok && ident.Name == "gate" {
					found = true
				}
			}
			return !found
		})
		return found
	}
	ast.Inspect(root, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		if ident, ok := call.Fun.(*ast.Ident); ok && (ident.Name == "readGated" || ident.Name == "readGatedValue") && len(call.Args) >= 3 {
			handed = append(handed, span{call.Args[2].Pos(), call.Args[2].End()})
		}
		if selector, ok := call.Fun.(*ast.SelectorExpr); ok && len(call.Args) > 0 && readsGateRead(call.Args[0]) {
			gatedPath[selector] = true
		}
		return true
	})
	var found []string
	ast.Inspect(root, func(node ast.Node) bool {
		selector, ok := node.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		pkg, ok := selector.X.(*ast.Ident)
		if !ok {
			return true
		}
		raw := false
		for _, name := range append(append([]string(nil), hookPathRawReads[pkg.Name]...), hookPathRawHandles[pkg.Name]...) {
			raw = raw || selector.Sel.Name == name
		}
		if !raw || gatedPath[selector] {
			return true
		}
		for _, s := range handed {
			if selector.Pos() >= s.from && selector.End() <= s.to {
				return true
			}
		}
		found = append(found, fset.Position(selector.Pos()).String()+": "+pkg.Name+"."+selector.Sel.Name)
		return true
	})
	return found
}

// rel-1-0-10:GAP-1074: the agent hook config guard, the promoted-artifact
// reader and the codex trusted-source proofs read a path a hook call names
// (a Write or Edit target, a cp destination, a git pathspec or -C folder, a
// script the command runs). Each read goes through the share-gated readers
// (the guard through its seam, which must call them), so a share on another
// machine is never contacted; a bounded regular-file read goes through
// hookpaths.ReadRegularFileBounded. On native Windows
// the guard's direct os.Lstat and filepath.EvalSymlinks of a Write target on
// \\server\share opened an SMB session (210 DNS names in the native run).
func TestGatewayHookPathOperandReadsAreShareBounded(t *testing.T) {
	files := []string{
		"../gateway/agent_hook_config_guard.go", "../gateway/agent_hook_artifact.go",
		"../gateway/fixturefs_seam.go", "../gateway/codex_hook.go",
	}
	// The codex hook also reads its cwd, config and component trees (the
	// agent's own working tree, not operand text); only its proofs of a
	// named operand are held here.
	codexProofs := map[string]bool{
		"trustedFixtureOrGuardrailSourceTarget": true, "trustedObserveWorkspaceSourceTarget": true,
		"codexObserveGitDiffPathspecs": true, "trustedPhysicalWorkspaceRelativePath": true,
	}
	fset := token.NewFileSet()
	var found []string
	seamReaders := 0
	seenProof := map[string]bool{}
	for _, name := range files {
		file, err := parser.ParseFile(fset, name, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		for _, decl := range file.Decls {
			fn, isFunc := decl.(*ast.FuncDecl)
			if strings.HasSuffix(name, "codex_hook.go") {
				if !isFunc || !codexProofs[fn.Name.Name] {
					continue
				}
				seenProof[fn.Name.Name] = true
			}
			found = append(found, hookPathUnboundedReads(fset, decl)...)
			found = append(found, gatewayUngatedOperandReads(fset, decl)...)
			if isFunc && strings.HasSuffix(name, "fixturefs_seam.go") && strings.HasPrefix(fn.Name.Name, "seam") {
				seamReaders++
				if !callsPackage(fn, "hookpaths") {
					found = append(found, fset.Position(fn.Pos()).String()+": "+fn.Name.Name+" does not read through a hookpaths reader")
				}
			}
		}
	}
	for name := range codexProofs {
		if !seenProof[name] {
			t.Errorf("codex proof %s is gone; update the scan", name)
		}
	}
	if seamReaders < 6 {
		t.Fatalf("found %d seam readers; the scan no longer finds the guard seam", seamReaders)
	}
	sort.Strings(found)
	if len(found) != 0 {
		t.Fatalf("gateway reads of a path a hook call names that bypass the share gate (use the seam or hookpaths.Stat, Lstat, LstatPinned, EvalSymlinks, Readlink, Open, ReadFile, ReadRegularFileBounded):\n%s", strings.Join(found, "\n"))
	}
}

// gatewayUngatedOperandReads finds the readers hookPathRawReads does not
// name that the gateway uses on an operand: a pinned lstat and a bounded
// safefile read (hookpaths.LstatPinned and ReadRegularFileBounded read them
// through the share gate). A check before a safefile read is no gate: the
// read would open the name again after it (rel-1-0-10:GAP-1074 review 1).
func gatewayUngatedOperandReads(fset *token.FileSet, decl ast.Decl) []string {
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
		switch {
		case pkg.Name == "pathidentity" && selector.Sel.Name == "LstatPinned":
			found = append(found, where)
		case pkg.Name == "safefile" && strings.HasPrefix(selector.Sel.Name, "Read"):
			found = append(found, where)
		}
		return true
	})
	return found
}

func callsPackage(fn *ast.FuncDecl, pkg string) bool {
	calls := false
	ast.Inspect(fn, func(node ast.Node) bool {
		if selector, ok := node.(*ast.SelectorExpr); ok {
			if ident, ok := selector.X.(*ast.Ident); ok && ident.Name == pkg {
				calls = true
			}
		}
		return true
	})
	return calls
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
	// One wait in all takes 2.0 s here under -race on an idle host; a wait
	// for each share takes shares x 750 ms = 6 s at least. A window of 2 s sat on
	// the idle time itself and failed at 2.03 s (GAP-0538). The window is
	// 4 s, stretched with the host's slowdown, and kept under the 6 s that
	// waiting for each share takes, so it still tells the two apart.
	limit := min(max(4*time.Second, testenv.Scale(2*time.Second, testenv.HostSlowdown())), (shares-1)*750*time.Millisecond)
	if took := time.Since(start); took > limit {
		t.Fatalf("one hook call spent %v on %d shares that do not answer (%d probes); want one 750ms answer wait in all (window %v)", took, shares, probes.Load(), limit)
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
			case "readGated", "readGatedValue":
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
