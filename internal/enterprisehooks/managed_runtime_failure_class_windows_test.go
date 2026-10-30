// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func TestWindowsManagedRuntimeFailureClassOf(t *testing.T) {
	plain := errors.New("enterprise hooks: something failed")
	for _, tc := range []struct {
		name string
		err  error
		want WindowsManagedRuntimeFailureClass
	}{
		{name: "nil", want: WindowsManagedRuntimeFailureNone},
		{name: "untagged", err: plain, want: WindowsManagedRuntimeFailureBoundary},
		{name: "drift", err: windowsManagedRuntimeDriftError(plain), want: WindowsManagedRuntimeFailureDrift},
		{name: "boundary", err: windowsManagedRuntimeBoundaryError(plain), want: WindowsManagedRuntimeFailureBoundary},
		{
			name: "unregistered",
			err:  fmt.Errorf("%w: connector codex SID S-1-5-21-1 is absent", ErrWindowsManagedSIDUnregistered),
			want: WindowsManagedRuntimeFailureUnregistered,
		},
		{
			name: "boundary wins over drift",
			err:  windowsManagedRuntimeBoundaryError(windowsManagedRuntimeDriftError(plain)),
			want: WindowsManagedRuntimeFailureBoundary,
		},
		{
			name: "drift never downgrades a boundary",
			err:  windowsManagedRuntimeDriftError(windowsManagedRuntimeBoundaryError(plain)),
			want: WindowsManagedRuntimeFailureBoundary,
		},
		{
			// Reason text inside a target-owned path is not a class.
			name: "drift text without the tag",
			err:  fmt.Errorf("open C:\\Users\\x\\%s: failed", WindowsManagedRuntimeDriftReason),
			want: WindowsManagedRuntimeFailureBoundary,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := WindowsManagedRuntimeFailureClassOf(tc.err); got != tc.want {
				t.Fatalf("class = %q, want %q (err=%v)", got, tc.want, tc.err)
			}
		})
	}
}

// Untyped resolver errors become drift only on typed evidence.
func TestClassifyWindowsManagedHookRuntimeErrorNeedsTypedDriftEvidence(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want WindowsManagedRuntimeFailureClass
	}{
		{name: "access denied", err: &os.PathError{Op: "open", Path: "x", Err: windows.ERROR_ACCESS_DENIED}, want: WindowsManagedRuntimeFailureDrift},
		{name: "sharing violation", err: fmt.Errorf("read: %w", windows.ERROR_SHARING_VIOLATION), want: WindowsManagedRuntimeFailureDrift},
		{name: "lock violation", err: fmt.Errorf("lock: %w", windows.ERROR_LOCK_VIOLATION), want: WindowsManagedRuntimeFailureDrift},
		{name: "lock timeout", err: fmt.Errorf("lock: %w", context.DeadlineExceeded), want: WindowsManagedRuntimeFailureDrift},
		{name: "selector kept changing", err: ErrWindowsManagedRuntimeGenerationConflict, want: WindowsManagedRuntimeFailureDrift},
		{name: "hard link", err: fmt.Errorf("enterprise hooks: %w (x has 2 links)", errWindowsManagedHardlink), want: WindowsManagedRuntimeFailureBoundary},
		{
			name: "hard link with a denied handle",
			err:  errors.Join(fmt.Errorf("%w", errWindowsManagedHardlink), windows.ERROR_ACCESS_DENIED),
			want: WindowsManagedRuntimeFailureBoundary,
		},
		{name: "untyped", err: errors.New("enterprise hooks: symlinks, junctions, and reparse points are not allowed: x"), want: WindowsManagedRuntimeFailureBoundary},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := WindowsManagedRuntimeFailureClassOf(classifyWindowsManagedHookRuntimeError(tc.err)); got != tc.want {
				t.Fatalf("class = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestStricterWindowsManagedFailMode(t *testing.T) {
	for _, tc := range []struct {
		modes []string
		want  string
	}{
		{modes: nil, want: ""},
		{modes: []string{"", ""}, want: ""},
		{modes: []string{"open", ""}, want: "open"},
		{modes: []string{"", "closed"}, want: "closed"},
		{modes: []string{"open", "closed"}, want: "closed"},
		{modes: []string{"closed", "open"}, want: "closed"},
		{modes: []string{"bogus", "open"}, want: "open"},
	} {
		if got := stricterWindowsManagedFailMode(tc.modes...); got != tc.want {
			t.Fatalf("stricter(%q) = %q, want %q", tc.modes, got, tc.want)
		}
	}
}

func stubWindowsManagedRuntimeFailureSeams(
	t *testing.T,
	longPath func(string) (string, bool),
	probe func(WindowsManagedRuntimeGenerationResolveOptions) error,
	generationMode string,
) {
	t.Helper()
	oldLongPath := windowsManagedHookLongPath
	oldProbe := windowsManagedRuntimeBoundaryProbe
	oldMode := windowsManagedRuntimeGenerationFailMode
	if longPath != nil {
		windowsManagedHookLongPath = longPath
	}
	if probe != nil {
		windowsManagedRuntimeBoundaryProbe = probe
	}
	windowsManagedRuntimeGenerationFailMode = func(string, *windows.SID) string { return generationMode }
	t.Cleanup(func() {
		windowsManagedHookLongPath = oldLongPath
		windowsManagedRuntimeBoundaryProbe = oldProbe
		windowsManagedRuntimeGenerationFailMode = oldMode
	})
}

// A short-path invocation of the policy executable is drift under the
// authenticated mode; any other executable is a boundary.
func TestWindowsManagedHookExecutableMismatchClassifiesShortPath(t *testing.T) {
	const policy = `C:\Program Files\Cisco\DefenseClaw\bin\defenseclaw-hook.exe`
	const short = `C:\PROGRA~1\Cisco\DEFENS~1\bin\DEFENS~1.EXE`
	stubWindowsManagedRuntimeFailureSeams(t,
		func(path string) (string, bool) {
			if path == short {
				return policy, true
			}
			return path, true
		},
		nil,
		"closed",
	)
	sid, err := windows.StringToSid("S-1-5-21-1000-1000-1000-1001")
	if err != nil {
		t.Fatal(err)
	}

	var result WindowsManagedHookRuntime
	err = windowsManagedHookExecutableMismatch(&result, "claudecode", sid, "", short, policy)
	if WindowsManagedRuntimeFailureClassOf(err) != WindowsManagedRuntimeFailureDrift || result.FailMode != "closed" {
		t.Fatalf("short-path invocation: class=%q failMode=%q err=%v", WindowsManagedRuntimeFailureClassOf(err), result.FailMode, err)
	}

	result = WindowsManagedHookRuntime{}
	err = windowsManagedHookExecutableMismatch(&result, "claudecode", sid, "", `C:\Users\x\evil\defenseclaw-hook.exe`, policy)
	if WindowsManagedRuntimeFailureClassOf(err) != WindowsManagedRuntimeFailureBoundary || result.FailMode != "" {
		t.Fatalf("foreign executable: class=%q failMode=%q", WindowsManagedRuntimeFailureClassOf(err), result.FailMode)
	}

	stubWindowsManagedRuntimeFailureSeams(t, func(string) (string, bool) { return "", false }, nil, "")
	if err := windowsManagedHookExecutableMismatch(&result, "claudecode", sid, "", short, policy); WindowsManagedRuntimeFailureClassOf(err) != WindowsManagedRuntimeFailureBoundary {
		t.Fatalf("unexpandable path was not a boundary: %v", err)
	}
}

func TestWindowsShortPathExpandsToLongPath(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "a long directory name for 8dot3")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	pointer, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		t.Fatal(err)
	}
	buffer := make([]uint16, windows.MAX_LONG_PATH)
	n, err := windows.GetShortPathName(pointer, &buffer[0], uint32(len(buffer)))
	if err != nil || n == 0 {
		t.Skipf("short names unavailable: %v", err)
	}
	short := windows.UTF16ToString(buffer[:n])
	long, ok := windowsLongPathName(short)
	if !ok || !sameWindowsEnterprisePath(long, dir) {
		t.Fatalf("long path of %q = %q, %t; want %q", short, long, ok, dir)
	}
}

// A generation failure is a boundary on any probe finding and drift under the
// authenticated mode otherwise. The unregistered sentinel passes through.
func TestClassifyWindowsManagedRuntimeGenerationFailure(t *testing.T) {
	opts := WindowsManagedRuntimeGenerationResolveOptions{
		Connector:      "codex",
		TargetSID:      "S-1-5-21-1000-1000-1000-1001",
		DataDir:        `C:\Users\x\.defenseclaw`,
		HookExecutable: `C:\Program Files\Cisco\DefenseClaw\bin\defenseclaw-hook.exe`,
	}
	cause := errors.New("enterprise hooks: managed runtime generation directory is untrusted: owner SID mismatch")

	for _, tc := range []struct {
		name           string
		finding        error
		policyMode     string
		generationMode string
		wantClass      WindowsManagedRuntimeFailureClass
		wantMode       string
	}{
		{name: "acl drift under open generation", generationMode: "open", wantClass: WindowsManagedRuntimeFailureDrift, wantMode: "open"},
		{name: "acl drift under closed generation", generationMode: "closed", wantClass: WindowsManagedRuntimeFailureDrift, wantMode: "closed"},
		{name: "drift with no recoverable mode", wantClass: WindowsManagedRuntimeFailureDrift, wantMode: ""},
		{name: "closed policy beats open generation", policyMode: "closed", generationMode: "open", wantClass: WindowsManagedRuntimeFailureDrift, wantMode: "closed"},
		{name: "reparse finding", finding: errors.New("enterprise hooks: reparse point in path: x"), generationMode: "open", wantClass: WindowsManagedRuntimeFailureBoundary},
		{name: "foreign writer on hook executable", finding: errors.New("enterprise hooks: managed hook executable trust check failed"), generationMode: "open", wantClass: WindowsManagedRuntimeFailureBoundary},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stubWindowsManagedRuntimeFailureSeams(t, nil,
				func(WindowsManagedRuntimeGenerationResolveOptions) error { return tc.finding },
				tc.generationMode,
			)
			var result WindowsManagedHookRuntime
			err := classifyWindowsManagedRuntimeGenerationFailure(&result, opts, tc.policyMode, cause)
			if got := WindowsManagedRuntimeFailureClassOf(err); got != tc.wantClass {
				t.Fatalf("class = %q, want %q (err=%v)", got, tc.wantClass, err)
			}
			if tc.wantClass == WindowsManagedRuntimeFailureDrift && result.FailMode != tc.wantMode {
				t.Fatalf("fail mode = %q, want %q", result.FailMode, tc.wantMode)
			}
			if !strings.Contains(err.Error(), cause.Error()) {
				t.Fatalf("classified error lost its cause: %v", err)
			}
		})
	}

	stubWindowsManagedRuntimeFailureSeams(t, nil,
		func(WindowsManagedRuntimeGenerationResolveOptions) error {
			t.Fatal("unregistered failure must not be probed")
			return nil
		},
		"open",
	)
	unregistered := fmt.Errorf("%w: not enrolled", ErrWindowsManagedSIDUnregistered)
	var result WindowsManagedHookRuntime
	if err := classifyWindowsManagedRuntimeGenerationFailure(&result, opts, "", unregistered); WindowsManagedRuntimeFailureClassOf(err) != WindowsManagedRuntimeFailureUnregistered {
		t.Fatalf("unregistered class = %q", WindowsManagedRuntimeFailureClassOf(err))
	}
	hardlink := fmt.Errorf("enterprise hooks: %w", errWindowsManagedHardlink)
	if err := classifyWindowsManagedRuntimeGenerationFailure(&result, opts, "", hardlink); WindowsManagedRuntimeFailureClassOf(err) != WindowsManagedRuntimeFailureBoundary {
		t.Fatalf("hard link class = %q", WindowsManagedRuntimeFailureClassOf(err))
	}
}

// The object-type probe finds a wrong type and a missing runtime directory,
// and treats a missing optional file as no finding.
func TestWindowsManagedRuntimeObjectTypeFinding(t *testing.T) {
	root := t.TempDir()
	file := filepath.Join(root, "bundle.json")
	if err := os.WriteFile(file, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := windowsManagedRuntimeObjectTypeFinding(root, true, false); err != nil {
		t.Fatalf("directory: %v", err)
	}
	if err := windowsManagedRuntimeObjectTypeFinding(file, false, true); err != nil {
		t.Fatalf("regular file: %v", err)
	}
	if err := windowsManagedRuntimeObjectTypeFinding(file, true, false); err == nil {
		t.Fatal("file accepted as a directory")
	}
	if err := windowsManagedRuntimeObjectTypeFinding(root, false, true); err == nil {
		t.Fatal("directory accepted as a file")
	}
	if err := windowsManagedRuntimeObjectTypeFinding(filepath.Join(root, "missing"), true, false); err == nil {
		t.Fatal("missing runtime directory was not a finding")
	}
	if err := windowsManagedRuntimeObjectTypeFinding(filepath.Join(root, "missing.json"), false, true); err != nil {
		t.Fatalf("missing optional file: %v", err)
	}
	link := filepath.Join(root, "second-link.json")
	if err := os.Link(file, link); err == nil {
		if err := windowsManagedRuntimeObjectTypeFinding(file, false, true); !errors.Is(err, errWindowsManagedHardlink) {
			t.Fatalf("hard-linked file finding = %v", err)
		}
	}
}

// A bundle whose bytes do not match the selector digest is forged content: a
// boundary, never a source of the configured fail mode.
func TestReadWindowsManagedRuntimeAuthenticatedBundleRejectsForgedBytes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "runtime.json")
	if err := os.WriteFile(path, []byte(`{"fail_mode":"open"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	entry := windowsManagedRuntimeSelectorTarget{BundleSHA256: windowsManagedRuntimeSHA256([]byte("other bytes"))}
	if _, err := readWindowsManagedRuntimeAuthenticatedBundle(entry, path); !errors.Is(err, errWindowsManagedRuntimeBundleForged) {
		t.Fatalf("forged bundle error = %v", err)
	}
}
