// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/claudedesktop"
	"github.com/defenseclaw/defenseclaw/internal/codesig"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

const desktopEnginePlist = `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>com.anthropic.claude-code</string>
<key>CFBundleShortVersionString</key>
<string>%s</string>
</dict></plist>`

// desktopEngineFixture lays out Claude Desktop's macOS engine build of
// version under home and returns its executable.
func desktopEngineFixture(t *testing.T, home, version, plistVersion string) string {
	t.Helper()
	bundle := filepath.Join(home, "Library", "Application Support", "Claude", "claude-code", version, "5af865b9901c", "claude.app")
	exe := filepath.Join(bundle, "Contents", "MacOS", "claude")
	if err := os.MkdirAll(filepath.Dir(exe), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(exe, []byte("engine"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bundle, "Contents", "Info.plist"), []byte(strings.Replace(desktopEnginePlist, "%s", plistVersion, 1)), 0o644); err != nil {
		t.Fatal(err)
	}
	return exe
}

type fakeDesktopVerify struct {
	calls  int
	path   string
	want   codesig.Darwin
	opts   codesig.DarwinOptions
	result codesig.Result
}

func stubDesktopVerify(t *testing.T, result codesig.Result) *fakeDesktopVerify {
	t.Helper()
	fake := &fakeDesktopVerify{result: result}
	oldGID := claudeDesktopAccountGID
	claudeDesktopAccountGID = func(uid int) (uint32, bool) { return 20, uid == 501 }
	t.Cleanup(func() { claudeDesktopAccountGID = oldGID })
	old := verifyClaudeDesktopEngine
	verifyClaudeDesktopEngine = func(_ context.Context, path string, want codesig.Darwin, opts codesig.DarwinOptions) codesig.Result {
		fake.calls++
		fake.path, fake.want, fake.opts = path, want, opts
		return fake.result
	}
	t.Cleanup(func() { verifyClaudeDesktopEngine = old })
	return fake
}

func TestClaudeDesktopEngineBuildRecognizesOnlyTheEngineFolderOfTheAccount(t *testing.T) {
	home := t.TempDir()
	exe := desktopEngineFixture(t, home, "2.1.309", "2.1.309")
	engine, ok := claudeDesktopEngineBuild("darwin", home, exe)
	if !ok || engine.version != "2.1.309" || engine.executable != exe ||
		engine.bundle != filepath.Dir(filepath.Dir(filepath.Dir(exe))) || filepath.Base(engine.plist) != "Info.plist" {
		t.Fatalf("claudeDesktopEngineBuild = %+v, %v", engine, ok)
	}
	if _, ok := claudeDesktopEngineBuild("darwin", t.TempDir(), exe); ok {
		t.Fatal("an engine in another account's home was recognized")
	}
	if _, ok := claudeDesktopEngineBuild("linux", home, exe); ok {
		t.Fatal("a macOS engine folder was recognized on Linux")
	}
	if _, ok := claudeDesktopEngineBuild("darwin", home, filepath.Join(home, ".local", "share", "claude", "versions", "2.1.309")); ok {
		t.Fatal("the native installer's build was taken for Claude Desktop's")
	}
	other := filepath.Join(home, "Library", "Application Support", "Claude", "claude-code", "2.1.309", "5af865b9901c", "claude.app", "Contents", "Resources", "claude")
	if _, ok := claudeDesktopEngineBuild("darwin", home, other); ok {
		t.Fatal("another executable of the bundle was recognized")
	}
	bad := filepath.Join(home, "Library", "Application Support", "Claude", "claude-code", "latest", "claude.app", "Contents", "MacOS", "claude")
	if _, ok := claudeDesktopEngineBuild("darwin", home, bad); ok {
		t.Fatal("a folder that is not a version was recognized")
	}
	if _, ok := claudeDesktopEngineBuild("darwin", home, exe+" (deleted)"); ok {
		t.Fatal("a replaced build was recognized")
	}
	linux := filepath.Join(home, ".config", "Claude", "claude-code", "2.1.309", "claude")
	if err := os.MkdirAll(filepath.Dir(linux), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(linux, []byte("engine"), 0o755); err != nil {
		t.Fatal(err)
	}
	if engine, ok := claudeDesktopEngineBuild("linux", home, linux); !ok || engine.version != "2.1.309" || engine.bundle != "" {
		t.Fatalf("Linux engine = %+v, %v", engine, ok)
	}
}

func TestClaudeDesktopEngineCoverageTrustsTheSignatureNotTheFolder(t *testing.T) {
	home := t.TempDir()
	exe := desktopEngineFixture(t, home, "2.1.309", "2.1.309")
	engine, ok := claudeDesktopEngineBuild("darwin", home, exe)
	if !ok {
		t.Fatal("engine not recognized")
	}
	fake := stubDesktopVerify(t, codesig.Result{Verified: true})
	if got := claudeDesktopEngineCoverage(context.Background(), engine, 501); got != (claudeDesktopVerdict{}) {
		t.Fatalf("signed 2.1.309 engine = %+v, want covered", got)
	}
	if fake.calls != 1 || fake.path != engine.bundle || fake.want != codesig.ClaudeCodeDarwin || fake.opts.UID != 501 || fake.opts.GID != 20 ||
		strings.Join(fake.opts.Pin, "|") != engine.executable+"|"+engine.plist {
		t.Fatalf("signature check = %+v", fake)
	}
	fake.result = codesig.Result{Reason: "code object is not signed at all"}
	if got := claudeDesktopEngineCoverage(context.Background(), engine, 501); got.reason != reasonClaudeDesktopUnsigned || got.detail != "code object is not signed at all" {
		t.Fatalf("unsigned engine = %+v", got)
	}
}

func TestClaudeDesktopEngineCoverageBindsTheVersionToTheSignedPlist(t *testing.T) {
	home := t.TempDir()
	fake := stubDesktopVerify(t, codesig.Result{Verified: true})
	exe := desktopEngineFixture(t, home, "2.1.309", "2.1.154")
	engine, _ := claudeDesktopEngineBuild("darwin", home, exe)
	got := claudeDesktopEngineCoverage(context.Background(), engine, 501)
	if got.reason != reasonClaudeDesktopVersionMismatch || !strings.Contains(got.detail, "names 2.1.154") || fake.calls != 0 {
		t.Fatalf("renamed version folder = %+v (signature checks %d)", got, fake.calls)
	}
}

// The engine follows the version Claude Desktop ships: a release newer than
// every tested one resolves the newest contract (reported untested by the
// enumerator), and one below every contract stays unverified.
func TestClaudeDesktopEngineCoverageFollowsTheShippedVersion(t *testing.T) {
	stubDesktopVerify(t, codesig.Result{Verified: true})
	for version, want := range map[string]string{
		"2.1.309": "",
		"2.9.0":   "",
		"2.0.77":  "claude_version_unverified",
	} {
		home := t.TempDir()
		engine, ok := claudeDesktopEngineBuild("darwin", home, desktopEngineFixture(t, home, version, version))
		if !ok {
			t.Fatalf("%s: engine not recognized", version)
		}
		if got := claudeDesktopEngineCoverage(context.Background(), engine, 501); got.reason != want {
			t.Fatalf("%s: coverage = %+v, want %q", version, got, want)
		}
	}
	if resolution := connector.ResolveHookContract("claudecode", "2.1.309"); resolution.Status != connector.HookCompatibilityKnown {
		t.Fatalf("2.1.309 resolves %+v, want a known contract", resolution)
	}
}

func TestClaudeDesktopVerdictIsCheckedOncePerRun(t *testing.T) {
	home := t.TempDir()
	fake := stubDesktopVerify(t, codesig.Result{Verified: true})
	engine, _ := claudeDesktopEngineBuild("darwin", home, desktopEngineFixture(t, home, "2.1.309", "2.1.309"))
	l := &lifecycle{}
	for range 3 {
		if got := l.claudeDesktopVerdictFor(context.Background(), engine, 501); got.reason != "" {
			t.Fatalf("verdict = %+v", got)
		}
	}
	if fake.calls != 1 {
		t.Fatalf("signature checks = %d, want 1", fake.calls)
	}
}

func TestManagedClaudeDesktopLinuxEngineIsReportedUserWritable(t *testing.T) {
	h := newTestHost(t, "linux")
	h.env.ReportLaunchCoverage = func(context.Context, managed.LaunchCoverageReport) error { return nil }
	const uid = 711338
	home := t.TempDir()
	h.runner.replies = map[string]fakeReply{
		"getent passwd 711338": {result: CommandResult{Stdout: []byte("bob:x:711338:711338::" + home + ":/bin/bash\n")}},
	}
	engine := filepath.Join(home, ".config", "Claude", "claude-code", "2.1.309", "claude")
	if err := os.MkdirAll(filepath.Dir(engine), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(engine, []byte("engine"), 0o755); err != nil {
		t.Fatal(err)
	}
	result := enterprisestatus.New(ActionVerify, managed.ProfileStandalone, "linux", "1.0.8")
	result.CoverageComplete, result.SecurityComplete = true, true
	l := lifecycle{env: h.env, result: result, opts: Options{Action: ActionVerify}}
	l.describePluginLaunchSession(context.Background(), agentSession{PID: 7140, UID: uid, Agent: "claude",
		Args: []string{"claude"}, ArgsKnown: true, Executable: engine}, "claudecode")
	if result.CoverageComplete || len(result.Warnings) != 1 ||
		!strings.Contains(result.Warnings[0].Message, "Linux builds carry no vendor code signature") {
		t.Fatalf("Linux Claude Desktop engine = %+v", result)
	}
}

// An unknown session account never runs codesign (as root or otherwise).
func TestClaudeDesktopEngineCoverageNeedsTheSessionAccount(t *testing.T) {
	home := t.TempDir()
	fake := stubDesktopVerify(t, codesig.Result{Verified: true})
	engine, _ := claudeDesktopEngineBuild("darwin", home, desktopEngineFixture(t, home, "2.1.309", "2.1.309"))
	for _, uid := range []int{-1, 0, 777} { // 777: no passwd entry in the stub
		got := claudeDesktopEngineCoverage(context.Background(), engine, uid)
		if got.reason != reasonClaudeDesktopUnsigned || got.detail != "session account unknown" {
			t.Fatalf("uid %d: coverage = %+v", uid, got)
		}
	}
	if fake.calls != 0 {
		t.Fatalf("codesign ran %d times for an unknown account", fake.calls)
	}
}

// Every data root of macOS and Linux (first party and third-party inference,
// internal/claudedesktop) holds a recognized engine build; on macOS the
// third-party build is trusted by its signature like the first-party one
// (cowork-1-0-8 GAP-0024).
func TestClaudeDesktopEngineBuildRecognizesEveryDataRoot(t *testing.T) {
	for _, goos := range []string{"darwin", "linux"} {
		for _, root := range claudedesktop.Roots(goos) {
			home := t.TempDir()
			data := root.Pattern(claudedesktop.FoldersForHome(goos, home))
			exe := filepath.Join(data, "claude-code", "2.1.317", "claude")
			if goos == "darwin" {
				exe = filepath.Join(data, "claude-code", "2.1.317", "91184d3d9ba3", "claude.app", "Contents", "MacOS", "claude")
			}
			// The running executable must exist (claudeRunningExecutable
			// resolves it).
			if err := os.MkdirAll(filepath.Dir(exe), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(exe, []byte("engine"), 0o755); err != nil {
				t.Fatal(err)
			}
			engine, ok := claudeDesktopEngineBuild(goos, home, exe)
			if !ok || engine.version != "2.1.317" {
				t.Fatalf("%s %s engine = %+v, %v", goos, root.Path, engine, ok)
			}
			if goos != "darwin" {
				continue
			}
			if engine.executable != exe || engine.plist != filepath.Join(data, "claude-code", "2.1.317", "91184d3d9ba3", "claude.app", "Contents", "Info.plist") {
				t.Fatalf("%s engine = %+v", root.Path, engine)
			}
			if err := os.WriteFile(engine.plist, []byte(strings.Replace(desktopEnginePlist, "%s", "2.1.317", 1)), 0o644); err != nil {
				t.Fatal(err)
			}
			fake := stubDesktopVerify(t, codesig.Result{Verified: true})
			if got := claudeDesktopEngineCoverage(context.Background(), engine, 501); got != (claudeDesktopVerdict{}) || fake.calls != 1 || fake.want != codesig.ClaudeCodeDarwin {
				t.Fatalf("%s signed engine = %+v (checks %+v)", root.Path, got, fake)
			}
			fake.result = codesig.Result{Reason: "code object is not signed at all"}
			if got := claudeDesktopEngineCoverage(context.Background(), engine, 501); got.reason != reasonClaudeDesktopUnsigned {
				t.Fatalf("%s unsigned engine = %+v, want refused by signature", root.Path, got)
			}
		}
	}
	home := t.TempDir()
	vm := filepath.Join(home, "Library", "Application Support", "Claude-3p", "claude-code-vm", "2.1.317", "claude")
	if err := os.MkdirAll(filepath.Dir(vm), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(vm, []byte("elf"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, ok := claudeDesktopEngineBuild("darwin", home, vm); ok {
		t.Fatal("the Cowork VM's Linux engine copy was taken for a macOS engine build")
	}
}
