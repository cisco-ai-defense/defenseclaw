// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package workspace

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"unsafe"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
	"golang.org/x/sys/windows"
)

func hostStageFixture(t *testing.T) StageOptions {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	home := filepath.Join(root, "synthetic-home")
	project, data := filepath.Join(home, "project with spaces"), filepath.Join(root, "private-data")
	if err := os.MkdirAll(project, 0o700); err != nil {
		t.Fatal(err)
	}
	if created, err := safefile.CreatePrivateDirectory(data); err != nil || !created {
		t.Fatalf("create exact new private fixture directory: %v, %t", err, created)
	}
	return StageOptions{Name: "owned-stage", Project: project, DataDir: data, Home: home, MaxBytes: 8 << 20}
}

func writeHostStageFixture(t *testing.T, project, rel, content string) {
	t.Helper()
	path := filepath.Join(project, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func assertNoHostStageResidue(t *testing.T, opts StageOptions) {
	t.Helper()
	entries, err := os.ReadDir(opts.DataDir)
	if err != nil || len(entries) != 0 {
		t.Fatalf("host stage residue after refusal/close: entries=%v, error=%v", entries, err)
	}
}

type hostStageDetectorFunc func(string, []byte) (string, bool)

func (f hostStageDetectorFunc) DetectSecret(rel string, content []byte) (string, bool) {
	return f(rel, content)
}

func TestHostStageWindowsPlainFrozenBytesOriginalPolicyAndCleanup(t *testing.T) {
	opts := hostStageFixture(t)
	writeHostStageFixture(t, opts.Project, "main.txt", "fixed safe initial bytes")
	writeHostStageFixture(t, opts.Project, ".env", "fixed operator-unmasked fixture")
	writeHostStageFixture(t, opts.Project, ".env.blocked", "fixed held fixture")
	writeHostStageFixture(t, opts.Project, "private.txt", "fixed synthetic secret marker")
	opts.Unmask = []string{filepath.Join(opts.Project, ".env")}
	opts.UnmaskAsked = slices.Clone(opts.Unmask)
	changedOriginal := false
	opts.Detector = hostStageDetectorFunc(func(rel string, content []byte) (string, bool) {
		if rel == "main.txt" && !changedOriginal {
			changedOriginal = true
			writeHostStageFixture(t, opts.Project, "main.txt", "different original bytes after private capture")
		}
		return "fixed-fixture", bytes.Contains(content, []byte("synthetic secret marker"))
	})
	stage, err := PrepareHostStage(context.Background(), opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := stage.Close(); err != nil {
			t.Error(err)
		}
	})
	path, err := stage.TreePath()
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(path, "main.txt"))
	if err != nil || string(got) != "fixed safe initial bytes" || !changedOriginal {
		t.Fatalf("sanitizer reread the changed live source: %q, %v", got, err)
	}
	if _, err := os.Stat(filepath.Join(path, ".env")); err != nil {
		t.Fatalf("absolute original-source unmask was rebound to capture path: %v", err)
	}
	for _, name := range []string{".env.blocked", "private.txt"} {
		if _, err := os.Stat(filepath.Join(path, name)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("held file %s was retained: %v", name, err)
		}
	}
	summary := stage.Summary()
	if !samePath(summary.Project, opts.Project) || !strings.HasPrefix(summary.SourceIdentity, "windows:") ||
		summary.Kind != CopyPlain || !slices.Contains(summary.HeldBack, "private.txt") {
		t.Fatalf("original source identity/policy summary changed: %+v", summary)
	}
	summary.HeldBack[0] = "caller changed copy"
	if slices.Contains(stage.Summary().HeldBack, "caller changed copy") {
		t.Fatal("summary leaked mutable policy facts")
	}
	artifact := filepath.Dir(filepath.Dir(path))
	if _, err := os.Stat(filepath.Join(artifact, "capture")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("raw secret-bearing capture was retained: %v", err)
	}
	artifactHandle, err := os.Open(artifact)
	if err != nil {
		t.Fatal(err)
	}
	aclErr := safefile.ValidatePrivateHandle(windows.Handle(artifactHandle.Fd()))
	closeErr := artifactHandle.Close()
	if err := errors.Join(aclErr, closeErr); err != nil {
		t.Fatalf("artifact does not have the required private DACL: %v", err)
	}
	if err := stage.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := stage.TreePath(); err == nil {
		t.Fatal("closed host artifact returned a usable path")
	}
	assertNoHostStageResidue(t, opts)
}

func TestHostStageWindowsGitSanitizationAndHistoryWithholding(t *testing.T) {
	opts := hostStageFixture(t)
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("native host staging requires installed git >=2.29")
	}
	for _, args := range [][]string{{"init", "--quiet", "--template=", "."}, {"config", "core.autocrlf", "false"}} {
		fixedGit(t, opts.Project, args...)
	}
	writeHostStageFixture(t, opts.Project, "main.txt", "fixed committed safe bytes")
	writeHostStageFixture(t, opts.Project, ".env", "fixed committed secret fixture")
	fixedGit(t, opts.Project, "add", "--all")
	fixedGit(t, opts.Project, "commit", "--quiet", "-m", "fixed fixture")
	secretOID := fixedGit(t, opts.Project, "rev-parse", "HEAD:.env")
	// Neither the hostile hook nor credential-bearing remote is copied as-is.
	writeHostStageFixture(t, opts.Project, ".git/hooks/post-checkout", "fixed nonexecutable fixture")
	fixedGit(t, opts.Project, "config", "remote.origin.url", "https://fixed-user:fixed-password@example.invalid/project.git")
	// Only preparation runs with PATH empty. Native Git below independently
	// checks the emitted guest object store after the original PATH is restored.
	oldPath := os.Getenv("PATH")
	t.Setenv("PATH", "")
	stage, err := PrepareHostStage(context.Background(), opts)
	t.Setenv("PATH", oldPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := stage.Close(); err != nil {
			t.Error(err)
		}
	}()
	path, err := stage.TreePath()
	if err != nil {
		t.Fatal(err)
	}
	if stage.Summary().Kind != CopyGit || stage.Summary().Head == "" || stage.Summary().Baseline == "" {
		t.Fatal("git history/baseline was silently flattened")
	}
	if got := stage.Summary().Remotes["origin"]; got != "https://example.invalid/project.git" {
		t.Fatalf("remote credentials were not sanitized: %q", got)
	}
	if _, err := os.Stat(filepath.Join(path, ".env")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("tracked secret remains in worktree: %v", err)
	}
	gitPath, release := fixedGitFixturePath(t, path)
	defer release()
	// First prove the actual emitted path works through an identity-checked
	// spelling, then read an independent guest-only copy with no host store.
	if got, err := fixedGitResult(gitPath, "show", "HEAD:main.txt"); err != nil || string(got) != "fixed committed safe bytes" {
		t.Fatalf("native Git positive control could not read staged history: %q %v", got, err)
	}
	gitPath = fixedGuestOnlyFixture(t, path)
	if got, err := fixedGitResult(gitPath, "show", "HEAD:main.txt"); err != nil || string(got) != "fixed committed safe bytes" {
		t.Fatalf("native Git guest-only pack lacks public HEAD blob: %q %v", got, err)
	}
	if got, err := fixedGitResult(gitPath, "show", stage.Summary().Baseline+":main.txt"); err != nil || string(got) != "fixed committed safe bytes" {
		t.Fatalf("native Git could not read guest baseline blob: %q %v", got, err)
	}
	if _, err := fixedGitResult(gitPath, "show", "HEAD:.env"); err == nil {
		t.Fatal("held secret blob remains readable in shipped history")
	}
	if _, err := fixedGitResult(gitPath, "cat-file", "-e", secretOID); err == nil {
		t.Fatal("guest-only pack exposes withheld historic object by OID")
	}
	if _, err := os.Stat(filepath.Join(path, ".git", "hooks", "post-checkout")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("source git hook was copied: %v", err)
	}
}

// Git for Windows does not preserve the volume-GUID spelling through its
// internal cwd normalization. This compatibility oracle alone uses a DOS path
// obtained from, compared with, and pinned against the exact held fixture.
// It grants no production path authority and performs no namespace mutation.
func fixedGitFixturePath(t *testing.T, path string) (string, func()) {
	t.Helper()
	held, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = held.Close() })
	want, err := windowsHostStageIdentity(held)
	if err != nil {
		t.Fatal(err)
	}
	display, err := windowsHostStageFinalPath(held, 0)
	if err != nil || !strings.HasPrefix(display, `\\?\`) {
		t.Fatalf("resolve exact native Git fixture DOS spelling: %v", err)
	}
	display = strings.TrimPrefix(display, `\\?\`)
	pin, err := openWindowsHostStagePin(display)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pin.close)
	got, err := windowsHostStageIdentity(pin.leaf())
	if err != nil || got != want {
		t.Fatalf("native Git fixture spelling changed identity: %v", err)
	}
	return display, func() { pin.close(); _ = held.Close() }
}

func TestHostStageWindowsRefusesReparseStreamsHardlinksAndWriter(t *testing.T) {
	for _, kind := range []string{"junction", "symlink", "named stream", "hardlink", "open writer", "reserved name", "trailing dot"} {
		t.Run(kind, func(t *testing.T) {
			opts := hostStageFixture(t)
			writeHostStageFixture(t, opts.Project, "safe.txt", "fixed safe fixture")
			outside := filepath.Join(filepath.Dir(opts.Home), "outside-canary")
			if err := os.Mkdir(outside, 0o700); err != nil {
				t.Fatal(err)
			}
			canary := filepath.Join(outside, "canary.txt")
			if err := os.WriteFile(canary, []byte("fixed outside canary"), 0o600); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "junction":
				link := filepath.Join(opts.Project, "redirect")
				if output, err := exec.Command("cmd.exe", "/D", "/C", "mklink", "/J", link, outside).CombinedOutput(); err != nil {
					t.Fatalf("create exact owned junction fixture: %v: %s", err, output)
				}
				t.Cleanup(func() { _ = os.Remove(link) })
			case "symlink":
				if err := os.Symlink(canary, filepath.Join(opts.Project, "redirect.txt")); err != nil {
					t.Skipf("native symlink fixture unavailable (junction is separately mandatory): %v", err)
				}
			case "named stream":
				if err := os.WriteFile(filepath.Join(opts.Project, "safe.txt:private"), []byte("fixed stream canary"), 0o600); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(canary, filepath.Join(opts.Project, "hardlink.txt")); err != nil {
					t.Fatal(err)
				}
			case "open writer":
				file, err := os.OpenFile(filepath.Join(opts.Project, "safe.txt"), os.O_WRONLY, 0)
				if err != nil {
					t.Fatal(err)
				}
				defer file.Close()
			case "reserved name", "trailing dot":
				name := "NUL.txt"
				if kind == "trailing dot" {
					name = "ambiguous."
				}
				// The extended namespace creates an actual NTFS entry with a
				// name ordinary Win32 APIs would interpret or normalize.
				ptr, err := windows.UTF16PtrFromString(`\\?\` + filepath.Join(opts.Project, name))
				if err != nil {
					t.Fatal(err)
				}
				handle, err := windows.CreateFile(ptr, windows.GENERIC_WRITE, 0, nil, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL, 0)
				if err != nil {
					t.Fatal(err)
				}
				_ = windows.CloseHandle(handle)
				t.Cleanup(func() {
					if err := windows.DeleteFile(ptr); err != nil {
						t.Errorf("remove exact owned ambiguous-name fixture: %v", err)
					}
				})
			}
			stage, err := PrepareHostStage(context.Background(), opts)
			if err == nil {
				_ = stage.Close()
				t.Fatal("unsafe native Windows source was accepted")
			}
			want := map[string]string{"junction": "reparse", "symlink": "reparse", "named stream": "named data streams",
				"hardlink": "hardlinked", "open writer": "concurrent writers", "reserved name": "entry name", "trailing dot": "entry name"}[kind]
			if !strings.Contains(err.Error(), want) {
				t.Fatalf("refused for an unrelated reason; want %q: %v", want, err)
			}
			if got, err := os.ReadFile(canary); err != nil || string(got) != "fixed outside canary" {
				t.Fatal("host-stage refusal changed the outside canary")
			}
			assertNoHostStageResidue(t, opts)
		})
	}
}

func TestHostStageWindowsRefusesOriginalProtectedRootsBeforeCapture(t *testing.T) {
	for _, kind := range []string{"protected", "home", "credential tree", "source junction", "guest layout"} {
		t.Run(kind, func(t *testing.T) {
			opts := hostStageFixture(t)
			switch kind {
			case "protected":
				opts.Protected = []string{strings.ToUpper(opts.Project)}
			case "home":
				opts.Project = opts.Home
			case "credential tree":
				opts.Project = filepath.Join(opts.Home, ".claude")
				if err := os.Mkdir(opts.Project, 0o700); err != nil {
					t.Fatal(err)
				}
			case "source junction":
				link := filepath.Join(opts.Home, "source-redirect")
				if output, err := exec.Command("cmd.exe", "/D", "/C", "mklink", "/J", link, opts.Project).CombinedOutput(); err != nil {
					t.Fatalf("create exact owned source junction: %v: %s", err, output)
				}
				t.Cleanup(func() { _ = os.Remove(link) })
				opts.Project = link
			case "guest layout":
				opts.RemoteRoot = "/sandbox/work"
			}
			if stage, err := PrepareHostStage(context.Background(), opts); err == nil {
				_ = stage.Close()
				t.Fatal("unsafe original source/layout was accepted")
			}
			assertNoHostStageResidue(t, opts)
		})
	}
}

func TestHostStageWindowsNamesCaseSemanticsAndLimits(t *testing.T) {
	for _, name := range []string{"NUL", "con.txt", "COM1", "LPT9.log", "a:stream", "trailing.", "trailing ", `..\outside`, "bad\x00name"} {
		if err := validateWindowsHostStageName(name); err == nil {
			t.Fatalf("ambiguous/reserved native Windows name accepted: %q", name)
		}
	}
	for _, kind := range []string{"case-sensitive", "size", "entries", "cancelled"} {
		t.Run(kind, func(t *testing.T) {
			opts := hostStageFixture(t)
			writeHostStageFixture(t, opts.Project, "safe.txt", "fixed safe fixture")
			ctx := context.Background()
			switch kind {
			case "case-sensitive":
				// NTFS can change this flag only on an empty directory.
				if err := os.Remove(filepath.Join(opts.Project, "safe.txt")); err != nil {
					t.Fatal(err)
				}
				ptr, err := windows.UTF16PtrFromString(opts.Project)
				if err != nil {
					t.Fatal(err)
				}
				handle, err := windows.CreateFile(ptr, windows.FILE_WRITE_ATTRIBUTES|windows.FILE_READ_ATTRIBUTES,
					windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING,
					windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
				if err != nil {
					t.Fatal(err)
				}
				flags := uint32(windows.FILE_CS_FLAG_CASE_SENSITIVE_DIR)
				err = windows.SetFileInformationByHandle(handle, windows.FileCaseSensitiveInfo, (*byte)(unsafe.Pointer(&flags)), uint32(unsafe.Sizeof(flags)))
				_ = windows.CloseHandle(handle)
				if err != nil {
					t.Skipf("native case-sensitive fixture unavailable: %v", err)
				}
				writeHostStageFixture(t, opts.Project, "CASE.txt", "fixed case A")
				writeHostStageFixture(t, opts.Project, "case.txt", "fixed case B")
				entries, err := os.ReadDir(opts.Project)
				if err != nil || len(entries) != 2 {
					t.Fatalf("case-collision fixture did not create two distinct native entries: %v, %v", entries, err)
				}
			case "size":
				opts.MaxBytes = 2
			case "entries":
				opts.MaxWalkEntries = 1
				writeHostStageFixture(t, opts.Project, "second.txt", "fixed safe fixture")
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			stage, err := PrepareHostStage(ctx, opts)
			if err == nil {
				_ = stage.Close()
				t.Fatal("native staging boundary/limit was accepted")
			}
			if kind == "cancelled" {
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("cancellation cause changed: %v", err)
				}
			} else if want := map[string]string{"case-sensitive": "case-sensitive", "size": "complete Windows source capture", "entries": "entry limit"}[kind]; !strings.Contains(err.Error(), want) {
				t.Fatalf("boundary refused for an unrelated reason; want %q: %v", want, err)
			}
			assertNoHostStageResidue(t, opts)
		})
	}
	if platformSupported() {
		t.Fatal("host staging enabled unsupported mount/POSIX guest workflows")
	}
	opts := hostStageFixture(t)
	if _, err := Stage(context.Background(), opts); !errors.Is(err, ErrUnsupportedPlatform) {
		t.Fatalf("legacy Stage activated Windows/POSIX guest behavior: %v", err)
	}
	assertNoHostStageResidue(t, opts)
}

func TestHostStageWindowsRefusesExternalGitMetadata(t *testing.T) {
	for _, kind := range []string{"gitfile", "commondir", "alternates", "includes", "partial clone", "external attributes", "filter"} {
		t.Run(kind, func(t *testing.T) {
			opts := hostStageFixture(t)
			if kind == "gitfile" {
				writeHostStageFixture(t, opts.Project, ".git", "gitdir: ../external.git\n")
			} else {
				if err := (gitCmd{dir: opts.Project}).run(context.Background(), "init", "--quiet", "--template=", "."); err != nil {
					t.Fatal(err)
				}
				switch kind {
				case "commondir":
					writeHostStageFixture(t, opts.Project, ".git/commondir", "../external.git\n")
				case "alternates":
					writeHostStageFixture(t, opts.Project, ".git/objects/info/alternates", "../external-objects\n")
				case "includes":
					writeHostStageFixture(t, opts.Project, ".git/config", "[include]\n path = ../external-config\n")
				case "partial clone":
					writeHostStageFixture(t, opts.Project, ".git/config", "[extensions]\n partialClone = origin\n")
				case "external attributes":
					writeHostStageFixture(t, opts.Project, ".git/config", "[core]\n attributesFile = ../external-attributes\n")
				case "filter":
					writeHostStageFixture(t, opts.Project, ".git/config", "[filter \"fixed\"]\n clean = fixed-unused-fixture\n")
				}
			}
			if stage, err := PrepareHostStage(context.Background(), opts); err == nil {
				_ = stage.Close()
				t.Fatal("external git metadata was accepted")
			}
			assertNoHostStageResidue(t, opts)
		})
	}
}

func TestHostStageWindowsPrivateACLRefusalPreservesExistingParent(t *testing.T) {
	opts := hostStageFixture(t)
	writeHostStageFixture(t, opts.Project, "safe.txt", "fixed safe fixture")
	owner, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	// This exact fresh fixture contains no credentials. Its deliberately
	// nonprivate DACL must be refused without repairing it or other paths.
	descriptor, err := windows.SecurityDescriptorFromString("O:" + owner.User.Sid.String() + "D:P(A;OICI;FA;;;" + owner.User.Sid.String() + ")(A;OICI;FA;;;SY)(A;OICI;GR;;;BU)")
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(opts.DataDir, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		t.Fatal(err)
	}
	readDescriptor := func() string {
		t.Helper()
		sd, err := windows.GetNamedSecurityInfo(opts.DataDir, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.OWNER_SECURITY_INFORMATION)
		if err != nil {
			t.Fatal(err)
		}
		return sd.String()
	}
	before := readDescriptor()
	if stage, err := PrepareHostStage(context.Background(), opts); err == nil {
		_ = stage.Close()
		t.Fatal("unsafe existing output DACL accepted")
	}
	if readDescriptor() != before {
		t.Fatal("staging refusal repaired an existing directory DACL")
	}
	assertNoHostStageResidue(t, opts)
}

func TestHostStageWindowsOwnedArtifactLockAndIdentity(t *testing.T) {
	opts := hostStageFixture(t)
	writeHostStageFixture(t, opts.Project, "safe.txt", "fixed safe fixture")
	stage, err := PrepareHostStage(context.Background(), opts)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := stage.Close(); err != nil {
			t.Error(err)
		}
	}()
	path, err := stage.TreePath()
	if err != nil {
		t.Fatal(err)
	}
	artifact := filepath.Dir(filepath.Dir(path))
	if err := os.Rename(artifact, artifact+"-moved"); err == nil {
		t.Fatal("owned host artifact lost its pinned directory identity")
	}
	file, err := os.OpenFile(filepath.Join(artifact, "owner.lock"), os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if err := windows.LockFileEx(windows.Handle(file.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY,
		0, 1, 0, new(windows.Overlapped)); err == nil {
		_ = windows.UnlockFileEx(windows.Handle(file.Fd()), 0, 1, 0, new(windows.Overlapped))
		t.Fatal("second owner acquired the live artifact byte-range lock")
	}
}

func TestHostStageWindowsCleanupRefusesMissingOrReplacedIdentity(t *testing.T) {
	for _, replace := range []bool{false, true} {
		t.Run(map[bool]string{false: "renamed", true: "replaced"}[replace], func(t *testing.T) {
			opts := hostStageFixture(t)
			parent, err := openWindowsHostStagePin(opts.DataDir)
			if err != nil {
				t.Fatal(err)
			}
			defer parent.close()
			create := func(name, content string) string {
				t.Helper()
				file, err := createWindowsHostStageDirectory(parent.leaf(), name)
				if err != nil {
					t.Fatal(err)
				}
				defer file.Close()
				identity, err := windowsHostStageIdentity(file)
				if err != nil {
					t.Fatal(err)
				}
				path, err := windowsHostStageFinalPath(file, hostStageVolumeGUID)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(path, "fixed-canary.txt"), []byte(content), 0o600); err != nil {
					t.Fatal(err)
				}
				return identity
			}
			originalID := create("owned", "fixed original canary")
			if err := os.Rename(filepath.Join(opts.DataDir, "owned"), filepath.Join(opts.DataDir, "moved")); err != nil {
				t.Fatal(err)
			}
			replacementID := ""
			if replace {
				replacementID = create("owned", "fixed replacement canary")
			}
			budget := 100
			err = removeWindowsHostStageChild(context.Background(), parent.leaf(), "owned", originalID, 0, &budget)
			want := "no longer at its expected name"
			if replace {
				want = "differs from its owned Windows file identity"
			}
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("cleanup did not refuse changed identity (%s): %v", want, err)
			}
			for name, content := range map[string]string{"moved": "fixed original canary", "owned": "fixed replacement canary"} {
				if name == "owned" && !replace {
					continue
				}
				got, err := os.ReadFile(filepath.Join(opts.DataDir, name, "fixed-canary.txt"))
				if err != nil || string(got) != content {
					t.Fatalf("refusal changed %s canary: %q, %v", name, got, err)
				}
			}
			for name, id := range map[string]string{"moved": originalID, "owned": replacementID} {
				if id == "" {
					continue
				}
				budget := 100
				if err := removeWindowsHostStageChild(context.Background(), parent.leaf(), name, id, 0, &budget); err != nil {
					t.Fatal(err)
				}
			}
			assertNoHostStageResidue(t, opts)
		})
	}
}

func TestHostStageWindowsCreatedPinAllowsVerifiedGoRoot(t *testing.T) {
	opts := hostStageFixture(t)
	parent, err := openWindowsHostStagePin(opts.DataDir)
	if err != nil {
		t.Fatal(err)
	}
	defer parent.close()
	const name = "owned-root-compatible"
	file, err := createWindowsHostStageDirectory(parent.leaf(), name)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	id, err := windowsHostStageCreatedIdentity(file, filepath.Join(opts.DataDir, name))
	if err != nil {
		t.Fatal(err)
	}
	path, err := windowsHostStageFinalPath(file, hostStageVolumeGUID)
	if err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		t.Fatalf("read-only creation pin conflicts with Go Root: %v", err)
	}
	if err := validateWindowsHostStagePrivateRoot(root, id); err != nil {
		_ = root.Close()
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(opts.DataDir, name), filepath.Join(opts.DataDir, name+"-moved")); err == nil {
		_ = root.Close()
		t.Fatal("creation pin lost no-delete-sharing custody")
	}
	_ = root.Close()
	_ = file.Close()
	budget := 100
	if err := removeWindowsHostStageChild(context.Background(), parent.leaf(), name, id, 0, &budget); err != nil {
		t.Fatal(err)
	}
	assertNoHostStageResidue(t, opts)
}

func TestHostStageWindowsInitialIdentityFailureReportsEmptyResidue(t *testing.T) {
	opts := hostStageFixture(t)
	parent, err := openWindowsHostStagePin(opts.DataDir)
	if err != nil {
		t.Fatal(err)
	}
	defer parent.close()
	const name = "owned-identity-failure"
	file, err := createWindowsHostStageDirectory(parent.leaf(), name)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(opts.DataDir, name)
	// Closing the handle forces a real FileIdInfo error without altering the
	// newly created empty directory or injecting a fake success value.
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := windowsHostStageCreatedIdentity(file, path); err == nil || !errors.Is(err, windows.ERROR_INVALID_HANDLE) ||
		!strings.Contains(err.Error(), "retained empty private directory "+strconv.Quote(path)) {
		t.Fatalf("identity failure omitted exact retained residue/cause: %v", err)
	}
	entries, err := os.ReadDir(path)
	if err != nil || len(entries) != 0 {
		t.Fatalf("empty residue missing or changed: %v, %v", entries, err)
	}
	if err := safefile.ValidatePrivateDirectory(path); err != nil {
		t.Fatal(err)
	}
	// This test fixture may be removed only after recovering its actual ID
	// from a fresh held-parent open. Production refusal performs no retry.
	recovery, err := openWindowsHostStageChild(parent.leaf(), name, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE)
	if err != nil {
		t.Fatal(err)
	}
	id, err := windowsHostStageIdentity(recovery)
	_ = recovery.Close()
	if err != nil {
		t.Fatal(err)
	}
	budget := 100
	if err := removeWindowsHostStageChild(context.Background(), parent.leaf(), name, id, 0, &budget); err != nil {
		t.Fatal(err)
	}
	assertNoHostStageResidue(t, opts)
}
