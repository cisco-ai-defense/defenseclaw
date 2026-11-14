// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/hookguard"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

const hookImageTestBin = `C:\Program Files\Cisco\DefenseClaw\bin`

// fakeHookImageNode is one file or folder of fakeHookImageFS.
type fakeHookImageNode struct {
	dir, link bool
	data      string
	mod       time.Time
}

// fakeHookImageFS is an in-memory Windows tree (case-insensitive) with the
// failure points stage and prune must handle.
type fakeHookImageFS struct {
	nodes      map[string]*fakeHookImageNode
	names      map[string]string // lower -> spelled path
	random     int
	renameErr  map[string]error // by lower source path
	renameBusy map[string]int   // refusals (fs.ErrPermission) left, by lower source path
	removeErr  map[string]error
	placeErr   error
	replaced   []string
	placed     []string
	corruptOut map[string]string // a write to this path yields these bytes
}

func newFakeHookImageFS() *fakeHookImageFS {
	return &fakeHookImageFS{nodes: map[string]*fakeHookImageNode{}, names: map[string]string{}}
}

func (f *fakeHookImageFS) put(path string, node *fakeHookImageNode) {
	f.nodes[strings.ToLower(path)] = node
	f.names[strings.ToLower(path)] = path
}

func (f *fakeHookImageFS) file(path, data string) { f.put(path, &fakeHookImageNode{data: data}) }
func (f *fakeHookImageFS) dir(path string)        { f.put(path, &fakeHookImageNode{dir: true}) }

func (f *fakeHookImageFS) get(path string) (*fakeHookImageNode, bool) {
	node, ok := f.nodes[strings.ToLower(path)]
	return node, ok
}

type fakeHookImageInfo struct {
	name string
	node *fakeHookImageNode
}

func (i fakeHookImageInfo) Name() string { return i.name }
func (i fakeHookImageInfo) Size() int64  { return int64(len(i.node.data)) }
func (i fakeHookImageInfo) Mode() fs.FileMode {
	mode := fs.FileMode(0)
	if i.node.dir {
		mode |= fs.ModeDir
	}
	if i.node.link {
		mode |= fs.ModeSymlink
	}
	return mode
}
func (i fakeHookImageInfo) ModTime() time.Time { return i.node.mod }
func (i fakeHookImageInfo) IsDir() bool        { return i.node.dir }
func (i fakeHookImageInfo) Sys() any           { return nil }

func baseOf(path string) string {
	return path[strings.LastIndex(path, `\`)+1:]
}

func (f *fakeHookImageFS) Lstat(path string) (fs.FileInfo, error) {
	node, ok := f.get(path)
	if !ok {
		return nil, fs.ErrNotExist
	}
	return fakeHookImageInfo{name: baseOf(path), node: node}, nil
}

func (f *fakeHookImageFS) ReadDir(path string) ([]fs.DirEntry, error) {
	prefix := strings.ToLower(strings.TrimRight(path, `\`)) + `\`
	var entries []fs.DirEntry
	for key, node := range f.nodes {
		rest, ok := strings.CutPrefix(key, prefix)
		if !ok || strings.Contains(rest, `\`) {
			continue
		}
		entries = append(entries, fs.FileInfoToDirEntry(fakeHookImageInfo{name: baseOf(f.names[key]), node: node}))
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	return entries, nil
}

func fakeSHA(data string) string {
	sum := sha256.Sum256([]byte(data))
	return hex.EncodeToString(sum[:])
}

func (f *fakeHookImageFS) SHA256(path string) (string, error) {
	node, ok := f.get(path)
	if !ok {
		return "", fs.ErrNotExist
	}
	if node.dir {
		return "", errors.New("is a folder")
	}
	return fakeSHA(node.data), nil
}

// FileSHA256 lets the real winpath resolver read this tree.
func (f *fakeHookImageFS) FileSHA256(path string) (string, error) { return f.SHA256(path) }

func (f *fakeHookImageFS) MkdirProtected(path string) error {
	if _, ok := f.get(path); ok {
		return fs.ErrExist
	}
	f.dir(path)
	return nil
}

func (f *fakeHookImageFS) write(source, destination string) error {
	node, ok := f.get(source)
	if !ok {
		return fs.ErrNotExist
	}
	data := node.data
	if corrupt, ok := f.corruptOut[strings.ToLower(destination)]; ok {
		data = corrupt
	}
	f.file(destination, data)
	return nil
}

func (f *fakeHookImageFS) PlaceImage(source, destination string) error {
	if f.placeErr != nil {
		return f.placeErr
	}
	if _, ok := f.get(destination); ok {
		return fs.ErrExist
	}
	f.placed = append(f.placed, destination)
	return f.write(source, destination)
}

func (f *fakeHookImageFS) ReplaceImage(source, destination string) error {
	f.replaced = append(f.replaced, destination)
	f.file(destination+".backup."+strings.Repeat("a", 32), "old bytes")
	return f.write(source, destination)
}

func (f *fakeHookImageFS) Rename(from, to string) error {
	if f.renameBusy[strings.ToLower(from)] > 0 {
		f.renameBusy[strings.ToLower(from)]--
		return fmt.Errorf("rename %s: %w", from, fs.ErrPermission)
	}
	if err := f.renameErr[strings.ToLower(from)]; err != nil {
		return err
	}
	if _, ok := f.get(to); ok {
		return fs.ErrExist
	}
	fromKey := strings.ToLower(from)
	moved := map[string]*fakeHookImageNode{}
	for key, node := range f.nodes {
		if key == fromKey || strings.HasPrefix(key, fromKey+`\`) {
			moved[key] = node
		}
	}
	if len(moved) == 0 {
		return fs.ErrNotExist
	}
	for key, node := range moved {
		spelled := to + f.names[key][len(from):]
		delete(f.nodes, key)
		delete(f.names, key)
		f.put(spelled, node)
	}
	return nil
}

func (f *fakeHookImageFS) RemoveAll(path string) error {
	if err := f.removeErr[strings.ToLower(path)]; err != nil {
		return err
	}
	key := strings.ToLower(path)
	for k := range f.nodes {
		if k == key || strings.HasPrefix(k, key+`\`) {
			delete(f.nodes, k)
			delete(f.names, k)
		}
	}
	return nil
}

func (f *fakeHookImageFS) RandomHex(n int) (string, error) {
	f.random++
	return fmt.Sprintf("%0*x", 2*n, f.random), nil
}

// fakeHookImageStarter answers --version-json, --version and the managed
// Claude Code self test like the real images, per image name (the self test
// is "selftest"), unless told otherwise.
type fakeHookImageStarter struct {
	runs         []string
	starts       []windowsHookImageStart
	answer       map[string]string
	stderr       map[string]string
	exit         map[string]int
	fail         map[string]error
	build        windowsHookImageBuild
	unrestricted string // TokenProblem when the filtered token is unavailable
}

func fakeHookImageStartKey(req windowsHookImageStart) string {
	for _, arg := range req.Args {
		if arg == "--enterprise-managed" {
			return "selftest"
		}
	}
	return baseOf(req.Path)
}

func (s *fakeHookImageStarter) Start(req windowsHookImageStart) (windowsHookImageStartResult, error) {
	key := fakeHookImageStartKey(req)
	s.runs = append(s.runs, key+" "+strings.Join(req.Args, " "))
	s.starts = append(s.starts, req)
	result := windowsHookImageStartResult{Restricted: s.unrestricted == "", TokenProblem: s.unrestricted}
	if req.Timeout != windowsHookImageStartTimeout {
		return result, fmt.Errorf("timeout %s", req.Timeout)
	}
	if err := s.fail[key]; err != nil {
		return result, err
	}
	result.ExitCode = s.exit[key]
	result.Stderr = []byte(s.stderr[key])
	if answer, ok := s.answer[key]; ok {
		result.Stdout = []byte(answer)
		return result, nil
	}
	switch key {
	case winpath.EnterpriseHookImageName:
		result.Stdout = []byte(fmt.Sprintf(`{"schema_version":1,"name":"defenseclaw-hook","version":%q,"commit":%q,"built":"2026-11-13T00:00:00Z"}`+"\n", s.build.Version, s.build.Commit))
	case winpath.EnterpriseHookGuardImageName:
		result.Stdout = []byte(fmt.Sprintf("defenseclaw-hook-guard version %s (commit=%s, built=2026-11-13T00:00:00Z)\n", s.build.Version, s.build.Commit))
	case "selftest":
		result.Stdout = []byte(`{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"DefenseClaw is being updated"}}` + "\n")
	default:
		return result, errors.New("unknown image")
	}
	return result, nil
}

var hookImageTestBuild = windowsHookImageBuild{Version: "1.0.10", Commit: "abc1234"}

// installRelease puts a release's transition images in bin, as Setup's
// payload step (and its early hook publish) does.
func installRelease(f *fakeHookImageFS, release string) (hookSHA, guardSHA string) {
	f.dir(hookImageTestBin)
	f.file(hookImageTestBin+`\defenseclaw-hook.exe`, "hook "+release)
	f.file(hookImageTestBin+`\defenseclaw-hook-guard.exe`, "guard "+release)
	return fakeSHA("hook " + release), fakeSHA("guard " + release)
}

func stageRelease(t *testing.T, f *fakeHookImageFS, hookSHA, guardSHA string) windowsHookImageStageReport {
	t.Helper()
	return stageWindowsHookImage(f, &fakeHookImageStarter{build: hookImageTestBuild}, windowsHookImageStageRequest{
		Bin: hookImageTestBin, HookSHA256: hookSHA, GuardSHA256: guardSHA, Build: hookImageTestBuild,
	})
}

func launchDir(sha string) string {
	dir, err := winpath.EnterpriseHookImageDir(hookImageTestBin, sha)
	if err != nil {
		panic(err)
	}
	return dir
}

// The 1.0.9 layout (configs name bin\defenseclaw-hook.exe, no bin\hooks)
// through the first managed upgrade, a repeated ensure, a repair of a changed
// launch image, a second upgrade and its prune.
func TestHookImageUpgradeFromTheFixedPathLayout(t *testing.T) {
	f := newFakeHookImageFS()
	installRelease(f, "1.0.9")
	before := winpath.ResolveEnterpriseHookLaunchSetWith(f, hookImageTestBin)
	if before.State != winpath.EnterpriseHookImageLegacyLayout || before.Hook != hookImageTestBin+`\defenseclaw-hook.exe` {
		t.Fatalf("1.0.9 layout resolves %+v; writers must keep naming the fixed path", before)
	}

	// First managed upgrade: Setup installs 1.0.10 at the transition path,
	// then stages its launch folder.
	hook10, guard10 := installRelease(f, "1.0.10")
	report := stageRelease(t, f, hook10, guard10)
	if !report.OK || !report.CreatedFolder || !report.Changed ||
		report.Hook != launchDir(hook10)+`\defenseclaw-hook.exe` || report.Guard != launchDir(hook10)+`\defenseclaw-hook-guard.exe` {
		t.Fatalf("first upgrade stage = %+v", report)
	}
	after := winpath.ResolveEnterpriseHookImageWith(f, hookImageTestBin)
	if after.State != winpath.EnterpriseHookImageStaged || after.Hook != report.Hook || after.Guard != report.Guard {
		t.Fatalf("after the first upgrade writers resolve %+v; they must name the launch set %s", after, report.Hook)
	}
	// The old configs name the fixed path: same install, not current (R2
	// rewrite, R3 ownership).
	if !sameWindowsManagedHookImage(before.Hook, after.Hook) || before.Hook == after.Hook {
		t.Fatal("the fixed path and the launch image must be one install's family but not equal")
	}

	// A repeated ensure of the same release changes nothing.
	again := stageRelease(t, f, hook10, guard10)
	if !again.OK || again.Changed || again.CreatedFolder {
		t.Fatalf("repeated ensure = %+v; it must keep the exact folder", again)
	}

	// Repair: a changed launch image is put back by the guardian's swap.
	f.file(report.Hook, "tampered")
	repaired := stageRelease(t, f, hook10, guard10)
	if !repaired.OK || !repaired.Changed || len(f.replaced) != 1 || f.replaced[0] != report.Hook {
		t.Fatalf("repair = %+v, replaced %v", repaired, f.replaced)
	}
	if sum, _ := f.SHA256(report.Hook); sum != hook10 {
		t.Fatal("repair left a changed launch image")
	}

	// Second upgrade: a new folder; the 1.0.10 folder is never touched.
	hook11, guard11 := installRelease(f, "1.0.11")
	second := stageRelease(t, f, hook11, guard11)
	if !second.OK || !second.CreatedFolder {
		t.Fatalf("second upgrade stage = %+v", second)
	}
	if sum, _ := f.SHA256(report.Hook); sum != hook10 {
		t.Fatal("the second upgrade changed the image older sessions start")
	}
	if got := winpath.ResolveEnterpriseHookImageWith(f, hookImageTestBin); got.Hook != second.Hook {
		t.Fatalf("after the second upgrade writers resolve %s, want %s", got.Hook, second.Hook)
	}

	// A third release; its prune keeps the current and the replaced one.
	hook12, guard12 := installRelease(f, "1.0.12")
	third := stageRelease(t, f, hook12, guard12)
	if !third.OK {
		t.Fatalf("third stage = %+v", third)
	}
	d11, _ := winpath.EnterpriseHookImageDigest(hook11)
	pruned := pruneOldUnnamed(f, hookImageTestBin, []string{d11})
	if !pruned.OK || len(pruned.Removed) != 1 || pruned.Removed[0] != launchDir(hook10) || len(pruned.Kept) != 2 || len(pruned.InUse) != 0 {
		t.Fatalf("prune = %+v", pruned)
	}
	if _, ok := f.get(launchDir(hook11)); !ok {
		t.Fatal("prune removed the folder of the replaced release")
	}
	if _, ok := f.get(launchDir(hook12)); !ok {
		t.Fatal("prune removed the current folder")
	}
}

func TestHookImageStageFailsClosed(t *testing.T) {
	cases := map[string]struct {
		mutate  func(f *fakeHookImageFS, s *fakeHookImageStarter, req *windowsHookImageStageRequest)
		reason  string
		keepOld bool
	}{
		"hook does not start": {
			mutate: func(_ *fakeHookImageFS, s *fakeHookImageStarter, _ *windowsHookImageStageRequest) {
				s.fail = map[string]error{winpath.EnterpriseHookImageName: errors.New("This program is blocked by group policy")}
			},
			reason: windowsHookImageStartFailed,
		},
		"hook reports another build": {
			mutate: func(_ *fakeHookImageFS, s *fakeHookImageStarter, _ *windowsHookImageStageRequest) {
				s.answer = map[string]string{winpath.EnterpriseHookImageName: `{"schema_version":1,"name":"defenseclaw-hook","version":"1.0.9","commit":"old"}`}
			},
			reason: windowsHookImageStartFailed,
		},
		"hook prints no document": {
			mutate: func(_ *fakeHookImageFS, s *fakeHookImageStarter, _ *windowsHookImageStageRequest) {
				s.answer = map[string]string{winpath.EnterpriseHookImageName: "usage: defenseclaw-hook ..."}
			},
			reason: windowsHookImageStartFailed,
		},
		"hook prints two documents": {
			mutate: func(_ *fakeHookImageFS, s *fakeHookImageStarter, _ *windowsHookImageStageRequest) {
				doc := `{"schema_version":1,"name":"defenseclaw-hook","version":"1.0.10","commit":"abc1234"}`
				s.answer = map[string]string{winpath.EnterpriseHookImageName: doc + doc}
			},
			reason: windowsHookImageStartFailed,
		},
		"guard does not start": {
			mutate: func(_ *fakeHookImageFS, s *fakeHookImageStarter, _ *windowsHookImageStageRequest) {
				s.fail = map[string]error{winpath.EnterpriseHookGuardImageName: errors.New("exit status 0xc0000135")}
			},
			reason: windowsHookImageStartFailed,
		},
		"guard reports another build": {
			mutate: func(_ *fakeHookImageFS, s *fakeHookImageStarter, _ *windowsHookImageStageRequest) {
				s.answer = map[string]string{winpath.EnterpriseHookGuardImageName: "defenseclaw-hook-guard version 1.0.10 (commit=other, built=x)"}
			},
			reason: windowsHookImageStartFailed,
		},
		"transition hook is not the installed one": {
			mutate: func(f *fakeHookImageFS, _ *fakeHookImageStarter, _ *windowsHookImageStageRequest) {
				f.file(hookImageTestBin+`\defenseclaw-hook.exe`, "someone else's hook")
			},
			reason: windowsHookImageDigestMismatch,
		},
		"transition guard is not the installed one": {
			mutate: func(f *fakeHookImageFS, _ *fakeHookImageStarter, _ *windowsHookImageStageRequest) {
				f.file(hookImageTestBin+`\defenseclaw-hook-guard.exe`, "other guard")
			},
			reason: windowsHookImageDigestMismatch,
		},
		"guard named but missing": {
			mutate: func(f *fakeHookImageFS, _ *fakeHookImageStarter, _ *windowsHookImageStageRequest) {
				_ = f.RemoveAll(hookImageTestBin + `\defenseclaw-hook-guard.exe`)
			},
			reason: windowsHookImageDigestMismatch,
		},
		"bad digest argument": {
			mutate: func(_ *fakeHookImageFS, _ *fakeHookImageStarter, req *windowsHookImageStageRequest) {
				req.HookSHA256 = "1234"
			},
			reason: windowsHookImageStageFailed,
		},
		"no build identity": {
			mutate: func(_ *fakeHookImageFS, _ *fakeHookImageStarter, req *windowsHookImageStageRequest) {
				req.Build = windowsHookImageBuild{}
			},
			reason: windowsHookImageStageFailed,
		},
		"copy has other bytes": {
			mutate: func(f *fakeHookImageFS, _ *fakeHookImageStarter, _ *windowsHookImageStageRequest) {
				staging := hookImageTestBin + `\hooks\.staging-` + fmt.Sprintf("%032x", f.random+1)
				f.corruptOut = map[string]string{strings.ToLower(staging + `\defenseclaw-hook.exe`): "short"}
			},
			reason: windowsHookImageStageFailed,
		},
		"hooks is a link": {
			mutate: func(f *fakeHookImageFS, _ *fakeHookImageStarter, _ *windowsHookImageStageRequest) {
				f.put(hookImageTestBin+`\hooks`, &fakeHookImageNode{dir: true, link: true})
			},
			reason: windowsHookImageStageFailed,
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFakeHookImageFS()
			oldHook, oldGuard := installRelease(f, "1.0.10-prior")
			if prior := stageRelease(t, f, oldHook, oldGuard); !prior.OK {
				t.Fatalf("prior stage = %+v", prior)
			}
			hookSHA, guardSHA := installRelease(f, "1.0.10")
			starter := &fakeHookImageStarter{build: hookImageTestBuild}
			req := windowsHookImageStageRequest{Bin: hookImageTestBin, HookSHA256: hookSHA, GuardSHA256: guardSHA, Build: hookImageTestBuild}
			tc.mutate(f, starter, &req)
			report := stageWindowsHookImage(f, starter, req)
			if report.OK || report.Reason != tc.reason || report.Error == "" {
				t.Fatalf("report = %+v; want ok=false reason %s", report, tc.reason)
			}
			// The image the configs name now is kept, whatever failed.
			if sum, _ := f.SHA256(launchDir(oldHook) + `\defenseclaw-hook.exe`); sum != oldHook {
				t.Fatal("a failed stage changed the prior release's launch image")
			}
			for key := range f.nodes {
				if strings.Contains(key, ".staging-") {
					t.Fatalf("a failed stage left %s", key)
				}
			}
		})
	}
}

func TestHookImageStageWithoutGuardAndLeftovers(t *testing.T) {
	f := newFakeHookImageFS()
	f.dir(hookImageTestBin)
	f.file(hookImageTestBin+`\defenseclaw-hook.exe`, "hook only")
	f.dir(hookImageTestBin + `\hooks`)
	stale := hookImageTestBin + `\hooks\.staging-` + strings.Repeat("e", 32)
	f.dir(stale)
	f.file(stale+`\defenseclaw-hook.exe`, "half")
	starter := &fakeHookImageStarter{build: hookImageTestBuild}
	report := stageWindowsHookImage(f, starter, windowsHookImageStageRequest{Bin: hookImageTestBin, HookSHA256: fakeSHA("hook only"), Build: hookImageTestBuild})
	if !report.OK || report.Guard != "" || !report.CreatedFolder {
		t.Fatalf("stage = %+v", report)
	}
	// Without a guard the self test runs the hook itself (the writer registers
	// it unwrapped then).
	if len(starter.runs) != 2 || starter.runs[0] != "defenseclaw-hook.exe --version-json" ||
		starter.runs[1] != "selftest hook --connector claudecode --enterprise-managed" ||
		starter.starts[1].Path != report.Hook {
		t.Fatalf("start checks = %v", starter.runs)
	}
	if _, ok := f.get(stale); ok {
		t.Fatal("stage kept a staging folder an interrupted stage left")
	}
	// A missing image in an existing folder is placed again.
	_ = f.RemoveAll(report.Hook)
	again := stageWindowsHookImage(f, starter, windowsHookImageStageRequest{Bin: hookImageTestBin, HookSHA256: fakeSHA("hook only"), Build: hookImageTestBuild})
	if !again.OK || !again.Changed || len(f.placed) != 2 {
		t.Fatalf("restage = %+v placed %v", again, f.placed)
	}
	// A folder at an image's name is refused, never replaced.
	_ = f.RemoveAll(report.Hook)
	f.dir(report.Hook)
	if refused := stageWindowsHookImage(f, starter, windowsHookImageStageRequest{Bin: hookImageTestBin, HookSHA256: fakeSHA("hook only"), Build: hookImageTestBuild}); refused.OK || refused.Reason != windowsHookImageStageFailed {
		t.Fatalf("folder at the image name = %+v", refused)
	}
}

func TestHookImagePrune(t *testing.T) {
	f := newFakeHookImageFS()
	current, _ := installRelease(f, "current")
	if r := stageRelease(t, f, current, fakeSHA("guard current")); !r.OK {
		t.Fatalf("stage = %+v", r)
	}
	root := hookImageTestBin + `\hooks`
	kept := strings.Repeat("1", 16)
	old := strings.Repeat("2", 16)
	busy := strings.Repeat("3", 16)
	for _, name := range []string{kept, old, busy} {
		f.dir(root + `\` + name)
		f.file(root+`\`+name+`\defenseclaw-hook.exe`, "hook "+name)
	}
	staging := root + `\.staging-` + strings.Repeat("4", 32)
	f.dir(staging)
	f.file(root+`\notes.txt`, "admin file")
	f.dir(root + `\` + strings.Repeat("5", 16) + "x")
	f.put(root+`\`+strings.Repeat("6", 16), &fakeHookImageNode{dir: true, link: true})
	f.renameErr = map[string]error{strings.ToLower(root + `\` + busy): errors.New("The process cannot access the file because it is being used by another process.")}

	report := pruneOldUnnamed(f, hookImageTestBin, []string{strings.ToUpper(kept)})
	if !report.OK {
		t.Fatalf("prune = %+v", report)
	}
	wantRemoved := []string{root + `\.staging-` + strings.Repeat("4", 32), root + `\` + old}
	sort.Strings(report.Removed)
	if strings.Join(report.Removed, "|") != strings.Join(wantRemoved, "|") {
		t.Fatalf("removed %v, want %v", report.Removed, wantRemoved)
	}
	if len(report.InUse) != 1 || report.InUse[0].Folder != root+`\`+busy {
		t.Fatalf("in use %+v", report.InUse)
	}
	if _, ok := f.get(root + `\` + busy + `\defenseclaw-hook.exe`); !ok {
		t.Fatal("prune took part of a folder a session runs")
	}
	currentName, _ := winpath.EnterpriseHookImageDigest(current)
	for _, name := range []string{kept, currentName} {
		if _, ok := f.get(root + `\` + name + `\defenseclaw-hook.exe`); !ok {
			t.Fatalf("prune removed kept folder %s", name)
		}
	}
	for _, left := range []string{root + `\notes.txt`, root + `\` + strings.Repeat("5", 16) + "x", root + `\` + strings.Repeat("6", 16)} {
		if _, ok := f.get(left); !ok {
			t.Fatalf("prune touched %s, which is not a launch or staging folder", left)
		}
	}
	if len(report.Notes) != 3 {
		t.Fatalf("notes %v", report.Notes)
	}

	// A launch folder renamed aside whose removal fails is out of service
	// and named; the next prune removes the staging folder.
	f.renameErr = nil
	f.removeErr = map[string]error{}
	victim := root + `\` + busy
	f.removeErr[strings.ToLower(root+`\.staging-`+fmt.Sprintf("%032x", f.random+1))] = errors.New("access denied")
	again := pruneOldUnnamed(f, hookImageTestBin, []string{kept})
	if !again.OK || len(again.Removed) != 1 || again.Removed[0] != victim || len(again.Notes) == 0 {
		t.Fatalf("second prune = %+v", again)
	}
	f.removeErr = nil
	third := pruneOldUnnamed(f, hookImageTestBin, []string{kept})
	if !third.OK || len(third.Removed) != 1 || !strings.Contains(third.Removed[0], ".staging-") {
		t.Fatalf("third prune = %+v", third)
	}
}

func TestHookImagePruneRefusals(t *testing.T) {
	f := newFakeHookImageFS()
	if r := pruneOldUnnamed(f, hookImageTestBin, nil); !r.OK || len(r.Removed) != 0 {
		t.Fatalf("no hooks folder = %+v", r)
	}
	f.dir(hookImageTestBin + `\hooks`)
	f.dir(hookImageTestBin + `\hooks\` + strings.Repeat("7", 16))
	// Without a readable transition image the current folder is unknown:
	// nothing is removed.
	if r := pruneOldUnnamed(f, hookImageTestBin, nil); r.OK || r.Error == "" {
		t.Fatalf("unknown current = %+v", r)
	}
	if _, ok := f.get(hookImageTestBin + `\hooks\` + strings.Repeat("7", 16)); !ok {
		t.Fatal("prune removed a folder while the current one was unknown")
	}
	installRelease(f, "x")
	if r := pruneOldUnnamed(f, hookImageTestBin, []string{"../etc"}); r.OK || !strings.Contains(r.Error, "--keep") {
		t.Fatalf("bad keep = %+v", r)
	}
}

func TestSameWindowsManagedHookImage(t *testing.T) {
	fixed := hookImageTestBin + `\defenseclaw-hook.exe`
	launch := hookImageTestBin + `\hooks\0123456789abcdef\defenseclaw-hook.exe`
	if !sameWindowsManagedHookImage(fixed, launch) || !sameWindowsManagedHookImage("", "") {
		t.Fatal("one install's images (and two empty journal fields) must match")
	}
	if sameWindowsManagedHookImage(launch, `C:\Program Files\Other\bin\hooks\0123456789abcdef\defenseclaw-hook.exe`) ||
		sameWindowsManagedHookImage(launch, hookImageTestBin+`\hooks\0123456789abcdef\defenseclaw-hook-guard.exe`) ||
		sameWindowsManagedHookImage(fixed, "") {
		t.Fatal("another install, another image kind or an empty path must not match")
	}
}

func TestWindowsHookImageVerifyProblem(t *testing.T) {
	if p := windowsHookImageVerifyProblem(winpath.EnterpriseHookImage{State: winpath.EnterpriseHookImageStaged}); p != "" {
		t.Fatalf("staged problem %q", p)
	}
	for _, image := range []winpath.EnterpriseHookImage{
		{State: winpath.EnterpriseHookImageLegacyLayout, Bin: hookImageTestBin, Hook: hookImageTestBin + `\defenseclaw-hook.exe`},
		{State: winpath.EnterpriseHookImageNotStaged, Bin: hookImageTestBin, Hook: hookImageTestBin + `\defenseclaw-hook.exe`, Problem: "no launch folder"},
	} {
		if p := windowsHookImageVerifyProblem(image); !strings.Contains(p, image.Hook) {
			t.Fatalf("%s problem %q does not name the image agents start", image.State, p)
		}
	}
}

// The start check runs the hook, the guard and then the managed Claude Code
// command the writer registers, all from the new folder (review P2-1).
func TestHookImageStartCheckRunsTheManagedClaudeCommandFromTheNewFolder(t *testing.T) {
	f := newFakeHookImageFS()
	hookSHA, guardSHA := installRelease(f, "1.0.10")
	starter := &fakeHookImageStarter{build: hookImageTestBuild}
	report := stageWindowsHookImage(f, starter, windowsHookImageStageRequest{
		Bin: hookImageTestBin, HookSHA256: hookSHA, GuardSHA256: guardSHA, Build: hookImageTestBuild,
	})
	if !report.OK || len(report.Notes) != 0 {
		t.Fatalf("stage = %+v", report)
	}
	if len(starter.starts) != 3 {
		t.Fatalf("starts = %v", starter.runs)
	}
	self := starter.starts[2]
	if !strings.EqualFold(baseOf(self.Path), "cmd.exe") || string(self.Stdin) != string(windowsHookImageSelfTestInput) {
		t.Fatalf("self test = %+v", self)
	}
	joined := strings.Join(self.Args, " ")
	for _, want := range []string{report.Guard, report.Hook, "--enterprise-managed", "--event PreToolUse"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("self test args %q do not name %q", joined, want)
		}
	}
	command, args, ok := connector.ClaudeCodeManagedGuardInvocation("PreToolUse", report.Hook, windowsHookImageSelfTestArgs)
	if !ok || command != self.Path || strings.Join(args, "\x00") != strings.Join(self.Args, "\x00") {
		t.Fatal("the self test is not the command the managed Claude Code writer registers")
	}
	var input map[string]any
	if err := json.Unmarshal(self.Stdin, &input); err != nil || input["hook_event_name"] != "PreToolUse" || input["tool_name"] != "Read" {
		t.Fatalf("self test input %s: %v", self.Stdin, err)
	}
}

func TestHookImageSelfTestAnswers(t *testing.T) {
	cases := map[string]struct {
		stdout, stderr string
		exit           int
		fail           error
		pass           bool
	}{
		"closed deny with JSON":        {stdout: `{"hookSpecificOutput":{"permissionDecision":"deny"}}`, pass: true},
		"block with a reason":          {stderr: "DefenseClaw blocked this tool call: the gateway is being updated", exit: 2, pass: true},
		"allow with no output":         {pass: true},
		"guard missing (cmd fallback)": {stderr: "DefenseClaw could not start its Claude Code hook guard. Run the DefenseClaw installer again to repair it.", exit: 2},
		"hook missing":                 {stderr: hookguard.MissingMessage, exit: 2},
		"hook cannot start":            {stderr: hookguard.CannotStartMessage, exit: 2},
		"hook crashed":                 {exit: 1, stderr: "panic"},
		"wrapped error status":         {exit: hookguard.WrappedExitBase + 3},
		"cmd cannot find the program":  {exit: 9009},
		"malformed answer":             {stdout: "not json"},
		"two answers":                  {stdout: `{"a":1}{"b":2}`},
		"silent block":                 {exit: 2},
		"did not start":                {fail: errors.New("access denied by policy")},
		"timeout":                      {fail: errors.New("no answer within 1m0s")},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFakeHookImageFS()
			hookSHA, guardSHA := installRelease(f, "1.0.10")
			starter := &fakeHookImageStarter{
				build:  hookImageTestBuild,
				answer: map[string]string{"selftest": tc.stdout},
				stderr: map[string]string{"selftest": tc.stderr},
				exit:   map[string]int{"selftest": tc.exit},
				fail:   map[string]error{"selftest": tc.fail},
			}
			report := stageWindowsHookImage(f, starter, windowsHookImageStageRequest{
				Bin: hookImageTestBin, HookSHA256: hookSHA, GuardSHA256: guardSHA, Build: hookImageTestBuild,
			})
			if report.OK != tc.pass {
				t.Fatalf("report = %+v; want ok %v", report, tc.pass)
			}
			if !tc.pass && (report.Reason != windowsHookImageStartFailed || !strings.Contains(report.Error, "managed Claude Code hook command")) {
				t.Fatalf("report = %+v; want hook_image_start_failed naming the managed command", report)
			}
		})
	}
}

func TestHookImageStartCheckNotesTheInstallerToken(t *testing.T) {
	f := newFakeHookImageFS()
	hookSHA, guardSHA := installRelease(f, "1.0.10")
	starter := &fakeHookImageStarter{build: hookImageTestBuild, unrestricted: "create the filtered token: Access is denied."}
	report := stageWindowsHookImage(f, starter, windowsHookImageStageRequest{
		Bin: hookImageTestBin, HookSHA256: hookSHA, GuardSHA256: guardSHA, Build: hookImageTestBuild,
	})
	if !report.OK || len(report.Notes) != 1 ||
		report.Notes[0] != "start check ran with the installer token: create the filtered token: Access is denied." {
		t.Fatalf("stage = %+v; want one installer-token note", report)
	}
}

func TestHookImageVersionStartThatFailsIsRefused(t *testing.T) {
	f := newFakeHookImageFS()
	hookSHA, guardSHA := installRelease(f, "1.0.10")
	starter := &fakeHookImageStarter{build: hookImageTestBuild, exit: map[string]int{winpath.EnterpriseHookImageName: 1}}
	report := stageWindowsHookImage(f, starter, windowsHookImageStageRequest{
		Bin: hookImageTestBin, HookSHA256: hookSHA, GuardSHA256: guardSHA, Build: hookImageTestBuild,
	})
	if report.OK || report.Reason != windowsHookImageStartFailed || !strings.Contains(report.Error, "ended with status 1") {
		t.Fatalf("stage = %+v", report)
	}
}

// The publish rename is retried while a handle in the new folder refuses it
// (an antivirus scan), then reported as hook_image_publish_busy (review P2-2).
func TestHookImagePublishRetriesABusyRename(t *testing.T) {
	var slept []time.Duration
	restore := windowsHookImageSleep
	windowsHookImageSleep = func(d time.Duration) { slept = append(slept, d) }
	t.Cleanup(func() { windowsHookImageSleep = restore })
	staging := func(f *fakeHookImageFS) string {
		return strings.ToLower(hookImageTestBin + `\hooks\.staging-` + fmt.Sprintf("%032x", f.random+1))
	}

	f := newFakeHookImageFS()
	hookSHA, guardSHA := installRelease(f, "1.0.10")
	f.renameBusy = map[string]int{staging(f): 3}
	report := stageRelease(t, f, hookSHA, guardSHA)
	if !report.OK || !report.CreatedFolder {
		t.Fatalf("busy then free = %+v", report)
	}
	if want := []time.Duration{100 * time.Millisecond, 200 * time.Millisecond, 400 * time.Millisecond}; fmt.Sprint(slept) != fmt.Sprint(want) {
		t.Fatalf("waits = %v, want %v", slept, want)
	}

	slept = nil
	f = newFakeHookImageFS()
	hookSHA, guardSHA = installRelease(f, "1.0.10")
	f.renameBusy = map[string]int{staging(f): 100}
	report = stageRelease(t, f, hookSHA, guardSHA)
	if report.OK || report.Reason != windowsHookImagePublishBusy || !strings.Contains(report.Error, "still refused after 10 tries") {
		t.Fatalf("always busy = %+v", report)
	}
	want := []time.Duration{100 * time.Millisecond, 200 * time.Millisecond, 400 * time.Millisecond, 800 * time.Millisecond,
		1600 * time.Millisecond, 2 * time.Second, 2 * time.Second, 2 * time.Second, 2 * time.Second}
	if fmt.Sprint(slept) != fmt.Sprint(want) {
		t.Fatalf("waits = %v, want %v", slept, want)
	}
	for key := range f.nodes {
		if strings.Contains(key, ".staging-") {
			t.Fatalf("a busy publish left %s", key)
		}
	}

	// Any other refusal is not retried.
	slept = nil
	f = newFakeHookImageFS()
	hookSHA, guardSHA = installRelease(f, "1.0.10")
	f.renameErr = map[string]error{staging(f): errors.New("the file name is too long")}
	report = stageRelease(t, f, hookSHA, guardSHA)
	if report.OK || report.Reason != windowsHookImageStageFailed || len(slept) != 0 {
		t.Fatalf("other error = %+v, waits %v", report, slept)
	}
}

// A stage removes only staging folders older than an hour: a younger one may
// be another run's folder in flight (review P3-6).
func TestHookImageStageLeavesAYoungStagingFolder(t *testing.T) {
	now := time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)
	restore := windowsHookImageNow
	windowsHookImageNow = func() time.Time { return now }
	t.Cleanup(func() { windowsHookImageNow = restore })
	f := newFakeHookImageFS()
	hookSHA, guardSHA := installRelease(f, "1.0.10")
	f.dir(hookImageTestBin + `\hooks`)
	young := hookImageTestBin + `\hooks\.staging-` + strings.Repeat("b", 32)
	old := hookImageTestBin + `\hooks\.staging-` + strings.Repeat("c", 32)
	f.put(young, &fakeHookImageNode{dir: true, mod: now.Add(-10 * time.Minute)})
	f.put(old, &fakeHookImageNode{dir: true, mod: now.Add(-2 * time.Hour)})
	if report := stageRelease(t, f, hookSHA, guardSHA); !report.OK {
		t.Fatalf("stage = %+v", report)
	}
	if _, ok := f.get(young); !ok {
		t.Fatal("a stage removed a staging folder another run may still write")
	}
	if _, ok := f.get(old); ok {
		t.Fatal("a stage kept an hour-old staging folder")
	}
}

func TestHookImageStageReportHasNoCreatedRoot(t *testing.T) {
	encoded, err := json.Marshal(windowsHookImageStageReport{SchemaVersion: 1})
	if err != nil || strings.Contains(string(encoded), "created_root") {
		t.Fatalf("report %s, %v", encoded, err)
	}
}
