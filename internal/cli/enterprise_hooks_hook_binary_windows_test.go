//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// GAP-0935, GAP-0680: the guardian keeps a copy of the recorded hook binary
// and puts a missing (quarantined), empty or different binary back from it;
// a copy of another release is never restored.
func TestKeepWindowsManagedFileCopyRestoresADamagedHookBinary(t *testing.T) {
	requireAdministratorTestToken(t, "the product restore writes the hook binary with the install file descriptor (an Administrators owner); the guardian runs it as SYSTEM, so the product writer, not the fixture, needs an administrator token")
	root := t.TempDir()
	target := filepath.Join(root, "bin", "defenseclaw-hook.exe")
	copyPath := filepath.Join(root, "hook-guardian", "payload", "defenseclaw-hook.exe")
	if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte("hook release"), 0o600); err != nil {
		t.Fatal(err)
	}
	want, err := windowsFileSHA256Hex(target)
	if err != nil {
		t.Fatal(err)
	}
	if damage, err := keepWindowsManagedFileCopy(target, copyPath, want, true); err != nil || damage != "" {
		t.Fatalf("keep copy: restored %q, %v", damage, err)
	}
	for _, c := range []struct {
		name, state string
		damage      func() error
	}{
		{"missing", "missing", func() error { return os.Remove(target) }},
		{"empty", "empty", func() error { return os.WriteFile(target, nil, 0o600) }},
		{"hash mismatch", "hash mismatch", func() error { return os.WriteFile(target, []byte("other"), 0o600) }},
	} {
		if err := c.damage(); err != nil {
			t.Fatal(err)
		}
		if damage, err := keepWindowsManagedFileCopy(target, copyPath, want, false); err != nil || !strings.Contains(damage, c.state) {
			t.Fatalf("%s: restored %q, %v", c.name, damage, err)
		}
		if body, err := os.ReadFile(target); err != nil || string(body) != "hook release" {
			t.Fatalf("%s: restored %q, %v", c.name, body, err)
		}
	}
	if damage, err := keepWindowsManagedFileCopy(target, copyPath, want, false); err != nil || damage != "" {
		t.Fatalf("healthy binary: restored %q, %v", damage, err)
	}
	if err := os.Remove(target); err != nil {
		t.Fatal(err)
	}
	damage, err := keepWindowsManagedFileCopy(target, copyPath, "0000", true)
	if err == nil || damage != "" {
		t.Fatalf("a copy of another release was restored: %q, %v", damage, err)
	}
	// Only Setup carries a payload to restore the binary from, and it is not
	// installed on the computer: the error runs it from its folder and says
	// where it comes from (cowork-1-0-8 GAP-0095).
	if message := err.Error(); !strings.Contains(message, windowsEnterpriseSetupCommand("/repair", "JSON=1")) ||
		!strings.Contains(message, managed.WindowsSetupSource) || strings.Contains(message, "Setup /repair") {
		t.Fatalf("no-copy error = %q", message)
	}
}

// GAP-0934, GAP-0937: the copy an upgrade kept of the ACP guard an editor
// still ran goes as soon as nothing runs it; other files stay.
func TestRemoveWindowsReplacementCopiesRemovesOnlyUnusedCopies(t *testing.T) {
	dir := t.TempDir()
	unused := filepath.Join(dir, "defenseclaw-acp.exe.backup.b93b18a784c74be1bdd7803057d577bd")
	held := filepath.Join(dir, "defenseclaw-hook.exe.backup.d9a400178cdb4634a2599baba406ffd5")
	other := filepath.Join(dir, "defenseclaw-acp.exe.backup.notacopy")
	for _, path := range []string{unused, held, other} {
		if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// A running program holds its image open without delete sharing.
	name, err := windows.UTF16PtrFromString(held)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := windows.CreateFile(name, windows.GENERIC_READ, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(handle)
	removed := removeWindowsReplacementCopies(dir)
	if len(removed) != 1 || removed[0] != unused {
		t.Fatalf("removed %q", removed)
	}
	for _, path := range []string{held, other} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
	}
}

// GAP-0656: while a hook call runs the binary, Windows refuses to replace
// its last name, so the guardian's MoveFileEx restore failed until no hook
// ran. The one-step swap keeps the running program under a backup name,
// puts the new file in place, and a start right after runs the new one. The
// backup goes at a later guardian check, once no program runs it.
func TestCopyWindowsManagedFileSwapsARunningProgram(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "defenseclaw-hook.exe")
	source := filepath.Join(dir, "source.exe")
	writeWindowsSystemProgram(t, "PING.EXE", target, nil)
	writeWindowsSystemProgram(t, "HOSTNAME.EXE", source, nil)
	running := exec.Command(target, "-n", "30", "127.0.0.1")
	if err := running.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = running.Process.Kill(); _, _ = running.Process.Wait() }()
	time.Sleep(200 * time.Millisecond)
	if err := copyWindowsManagedFile(source, target, "", true, true); err != nil {
		t.Fatalf("replace the running program: %v", err)
	}
	want, err := windowsFileSHA256Hex(source)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := windowsFileSHA256Hex(target); err != nil || got != want {
		t.Fatalf("target is %s (%v), want the new program %s", got, err, want)
	}
	if damage, err := windowsHookBinaryStructuralDamage(target); err != nil || damage != "" {
		t.Fatalf("new target: %q, %v", damage, err)
	}
	if out, err := exec.Command(target).Output(); err != nil || len(strings.TrimSpace(string(out))) == 0 {
		t.Fatalf("start after the swap: %q, %v", out, err)
	}
	backups, err := filepath.Glob(target + ".backup.*")
	if err != nil || len(backups) != 1 || !windowsReplacementCopyPattern.MatchString(filepath.Base(backups[0])) {
		t.Fatalf("backup of the running program: %q, %v", backups, err)
	}
	// The swap does not delete the old file in the instant after its
	// rename, and the after-reconcile sweep leaves a backup the swap made
	// a moment ago.
	if removed := removeWindowsReplacementCopies(dir); len(removed) != 0 {
		t.Fatalf("removed a backup the swap made a moment ago: %q", removed)
	}
	restoreAge := setWindowsImageBackupMinAgeForTest(0)
	defer restoreAge()
	if removed := removeDueWindowsImageBackups(); len(removed) != 0 {
		t.Fatalf("removed the image a program still runs: %q", removed)
	}
	if removed := removeWindowsReplacementCopies(dir); len(removed) != 0 {
		t.Fatalf("removed the image a program still runs: %q", removed)
	}
	_ = running.Process.Kill()
	_, _ = running.Process.Wait()
	deadline := time.Now().Add(5 * time.Second)
	for {
		removed := removeDueWindowsImageBackups()
		if len(removed) == 1 && strings.EqualFold(removed[0], backups[0]) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the backup stayed after the program ended: %q", removed)
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err := copyWindowsManagedFile(target, filepath.Join(dir, "missing.exe"), "", true, true); err != nil {
		t.Fatalf("a missing destination is still created: %v", err)
	}
	if left, _ := filepath.Glob(filepath.Join(dir, "*.backup.*")); len(left) != 0 {
		t.Fatalf("leftover backups: %q", left)
	}
}

// GAP-0656 review M1: agents start the hook while the guardian restores it.
// Every start must succeed while restores alternate two builds of a program,
// as in the review's probe: with the transacted safefile rename (g655 round
// c) 6,316 of 7,193 starts failed with "Access is denied" or 6838. The
// count can be raised natively with -g656-image-swaps.
func TestCopyWindowsManagedFileSwapsUnderConcurrentLaunches(t *testing.T) {
	swaps := *windowsImageSwapLaunchSwaps
	if swaps <= 0 {
		swaps = 300
		if testing.Short() {
			swaps = 60
		}
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "defenseclaw-hook.exe")
	builds := []string{filepath.Join(dir, "build-a.exe"), filepath.Join(dir, "build-b.exe")}
	writeWindowsSystemProgram(t, "PING.EXE", builds[0], nil)
	writeWindowsSystemProgram(t, "PING.EXE", builds[1], []byte("defenseclaw-g656-overlay"))
	writeWindowsSystemProgram(t, "PING.EXE", target, nil)
	failures, starts, restoreErrs := runWindowsImageSwapLaunches(t, target, builds, swaps, 8, 10*time.Millisecond)
	t.Logf("swaps=%d starts=%d failed starts=%d restore errors=%d", swaps, starts, len(failures), restoreErrs)
	if restoreErrs != 0 {
		t.Fatalf("%d of %d restores failed", restoreErrs, swaps)
	}
	if starts < int64(swaps) {
		t.Fatalf("only %d starts ran beside %d restores", starts, swaps)
	}
	if len(failures) != 0 {
		t.Fatalf("%d of %d hook starts failed during the restores, first: %v", len(failures), starts, failures[:min(len(failures), 5)])
	}
	want, err := windowsFileSHA256Hex(builds[(swaps-1)%2])
	if err != nil {
		t.Fatal(err)
	}
	if got, err := windowsFileSHA256Hex(target); err != nil || got != want {
		t.Fatalf("target is %s (%v), want the last build %s", got, err, want)
	}
	if damage, err := windowsHookBinaryStructuralDamage(target); err != nil || damage != "" {
		t.Fatalf("restored target: %q, %v", damage, err)
	}
	if left, _ := filepath.Glob(target + ".restore-*"); len(left) != 0 {
		t.Fatalf("staging copies left: %q", left)
	}
	restoreAge := setWindowsImageBackupMinAgeForTest(0)
	defer restoreAge()
	deadline := time.Now().Add(10 * time.Second)
	for {
		_ = removeDueWindowsImageBackups()
		left, _ := filepath.Glob(target + ".backup.*")
		if len(left) == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d backups stayed after every start ended", len(left))
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// GAP-0656 review S1 (GAP-0369): on a volume or behind a filter driver that
// refuses the backup hard link, the restore replaces the hook the older way
// and the guardian says so once, instead of failing every check.
func TestCopyWindowsManagedFileFallsBackWhenHardLinksAreRefused(t *testing.T) {
	for _, code := range windowsImageSwapLinkRefusedCodes {
		dir := t.TempDir()
		target := filepath.Join(dir, "defenseclaw-hook.exe")
		source := filepath.Join(dir, "source.exe")
		if err := os.WriteFile(target, []byte("old"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(source, []byte("new"), 0o600); err != nil {
			t.Fatal(err)
		}
		previous := windowsImageSwapLink
		windowsImageSwapLink = func(string, string) error { return code }
		err := copyWindowsManagedFile(source, target, "", true, true)
		windowsImageSwapLink = previous
		if err != nil {
			t.Fatalf("code %d: restore failed: %v", code, err)
		}
		if body, err := os.ReadFile(target); err != nil || string(body) != "new" {
			t.Fatalf("code %d: target %q, %v", code, body, err)
		}
		var log strings.Builder
		reportWindowsImageSwapLinkRefusal(&log, target)
		reportWindowsImageSwapLinkRefusal(&log, target)
		if strings.Count(log.String(), "without the one-step swap") != 1 {
			t.Fatalf("code %d: notice %q", code, log.String())
		}
		windowsImageSwapLinkRefusalLogged = ""
		if left, _ := filepath.Glob(filepath.Join(dir, "*.*-*")); len(left) != 0 {
			t.Fatalf("code %d: leftovers %q", code, left)
		}
	}
	// Any other link failure still fails the restore with nothing changed.
	dir := t.TempDir()
	target := filepath.Join(dir, "defenseclaw-hook.exe")
	source := filepath.Join(dir, "source.exe")
	_ = os.WriteFile(target, []byte("old"), 0o600)
	_ = os.WriteFile(source, []byte("new"), 0o600)
	previous := windowsImageSwapLink
	windowsImageSwapLink = func(string, string) error { return windows.ERROR_ACCESS_DENIED }
	err := copyWindowsManagedFile(source, target, "", true, true)
	windowsImageSwapLink = previous
	if err == nil {
		t.Fatal("an access-denied link was taken for a refused volume")
	}
	if body, _ := os.ReadFile(target); string(body) != "old" {
		t.Fatalf("target changed: %q", body)
	}
}

// The rename step fails with nothing changed: the backup link goes again.
func TestSwapWindowsProgramImageRemovesItsBackupWhenTheRenameFails(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "defenseclaw-hook.exe")
	source := filepath.Join(dir, "source.exe")
	_ = os.WriteFile(target, []byte("old"), 0o600)
	_ = os.WriteFile(source, []byte("new"), 0o600)
	previous := windowsImageSwapRename
	windowsImageSwapRename = func(string, string) error { return windows.ERROR_SHARING_VIOLATION }
	_, err := swapWindowsProgramImage(source, target)
	windowsImageSwapRename = previous
	if err == nil {
		t.Fatal("swap reported success")
	}
	if left, _ := filepath.Glob(target + ".backup.*"); len(left) != 0 {
		t.Fatalf("backup left: %q", left)
	}
	if damage, err := windowsHookBinaryStructuralDamage(target); err != nil || damage != "" {
		t.Fatalf("target after a failed swap: %q, %v", damage, err)
	}
}

var windowsImageSwapLaunchSwaps = flag.Int("g656-image-swaps", 0, "restores in TestCopyWindowsManagedFileSwapsUnderConcurrentLaunches (0: 300, or 60 with -short)")

func setWindowsImageBackupMinAgeForTest(age time.Duration) (restore func()) {
	previous := windowsImageBackupMinAge
	windowsImageBackupMinAge = age
	return func() { windowsImageBackupMinAge = previous }
}

func writeWindowsSystemProgram(t *testing.T, name, to string, overlay []byte) {
	t.Helper()
	system := os.Getenv("SystemRoot")
	if system == "" {
		system = `C:\Windows`
	}
	body, err := os.ReadFile(filepath.Join(system, "System32", name))
	if err != nil {
		t.Skipf("system program unavailable: %v", err)
	}
	if err := os.WriteFile(to, append(body, overlay...), 0o700); err != nil {
		t.Fatal(err)
	}
}

// runWindowsImageSwapLaunches starts target from workers goroutines with
// CreateProcess (suspended, then ended), as agents start the hook, while the
// guardian restore alternates builds onto it swaps times, gap apart. It
// returns the failed starts, the number of starts and of failed restores.
func runWindowsImageSwapLaunches(t *testing.T, target string, builds []string, swaps, workers int, gap time.Duration) ([]error, int64, int) {
	t.Helper()
	application, err := windows.UTF16PtrFromString(target)
	if err != nil {
		t.Fatal(err)
	}
	commandLine := `"` + target + `" -n 1 127.0.0.1`
	var starts atomic.Int64
	var mu sync.Mutex
	var failures []error
	stop := make(chan struct{})
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				command, _ := windows.UTF16PtrFromString(commandLine)
				var startup windows.StartupInfo
				startup.Cb = uint32(unsafe.Sizeof(startup))
				var process windows.ProcessInformation
				starts.Add(1)
				if err := windows.CreateProcess(application, command, nil, nil, false,
					windows.CREATE_SUSPENDED|windows.CREATE_NO_WINDOW, nil, nil, &startup, &process); err != nil {
					mu.Lock()
					failures = append(failures, err)
					mu.Unlock()
					continue
				}
				_ = windows.TerminateProcess(process.Process, 0)
				_, _ = windows.WaitForSingleObject(process.Process, 5000)
				_ = windows.CloseHandle(process.Thread)
				_ = windows.CloseHandle(process.Process)
			}
		}()
	}
	restoreErrs := 0
	for i := 0; i < swaps; i++ {
		if err := copyWindowsManagedFile(builds[i%2], target, windowsInstallFileSDDL, true, true); err != nil {
			restoreErrs++
			if restoreErrs <= 3 {
				t.Logf("restore %d: %v", i, err)
			}
		}
		time.Sleep(gap)
	}
	close(stop)
	wg.Wait()
	return failures, starts.Load(), restoreErrs
}
