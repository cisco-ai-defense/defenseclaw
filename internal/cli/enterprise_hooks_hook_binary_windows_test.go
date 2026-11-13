//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bufio"
	"bytes"
	"context"
	"debug/pe"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
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

// GAP-0656 review M2: a standard user who once had Modify on the hook keeps
// a write handle that shares read and delete. The bytes and the single name
// stay right, but every start fails with a sharing violation. The guardian
// moves the name to a fresh object; starts work again while the handle
// still holds the old one.
func TestKeepWindowsManagedFileCopyReplacesAHookHeldOpenForWriting(t *testing.T) {
	requireAdministratorTestToken(t, "the product restore writes the hook binary with the install file descriptor (an Administrators owner)")
	resetWindowsHeldSwapsForTest(t)
	root := t.TempDir()
	target := filepath.Join(root, "bin", "defenseclaw-hook.exe")
	copyPath := filepath.Join(root, "hook-guardian", "payload", "defenseclaw-hook.exe")
	if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
		t.Fatal(err)
	}
	writeWindowsSystemProgram(t, "HOSTNAME.EXE", target, nil)
	want, err := windowsFileSHA256Hex(target)
	if err != nil {
		t.Fatal(err)
	}
	if damage, err := keepWindowsManagedFileCopy(target, copyPath, want, true); err != nil || damage != "" {
		t.Fatalf("keep copy: restored %q, %v", damage, err)
	}
	name, err := windows.UTF16PtrFromString(target)
	if err != nil {
		t.Fatal(err)
	}
	writer, err := windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(writer)
	if _, err := exec.Command(target).Output(); err == nil {
		t.Fatal("a start succeeded while a writer held the hook; the fixture does not reproduce the failure")
	}
	damage, err := keepWindowsManagedFileCopy(target, copyPath, want, false)
	if err != nil || !strings.Contains(damage, "held open by another program") {
		t.Fatalf("restored %q, %v", damage, err)
	}
	if out, err := exec.Command(target).Output(); err != nil || len(strings.TrimSpace(string(out))) == 0 {
		t.Fatalf("start after the restore, writer still open: %q, %v", out, err)
	}
	if got, err := windowsFileSHA256Hex(target); err != nil || got != want {
		t.Fatalf("restored %s (%v), want %s", got, err, want)
	}
	if damage, err := keepWindowsManagedFileCopy(target, copyPath, want, false); err != nil || damage != "" {
		t.Fatalf("the fresh object is reported again: %q, %v", damage, err)
	}
}

// startWindowsExclusiveHolder runs a child process that opens path with no
// sharing and keeps it open until release is called. The child ends by itself
// and prints "alive" if its handle was closed by someone else; it is never
// killed by the test while the fixture is needed. shell names the PowerShell
// to run (the 64-bit PowerShell, or the 32-bit Go holder that
// buildWindowsWow64Holder returns); a missing PowerShell skips the test.
func startWindowsExclusiveHolder(t *testing.T, shell, path string) (release func() string, pid int) {
	t.Helper()
	var cmd *exec.Cmd
	if isWindowsGoHolder(shell) {
		cmd = exec.Command(shell, "exclusive", path)
	} else {
		if _, err := os.Stat(shell); err != nil {
			t.Skipf("PowerShell unavailable: %v", err)
		}
		script := fmt.Sprintf(`$f = [IO.File]::Open('%s', 'Open', 'Read', 'None'); [Console]::Out.WriteLine('ready'); [Console]::Out.Flush(); [void][Console]::In.ReadLine(); [Console]::Out.WriteLine('alive')`, strings.ReplaceAll(path, "'", "''"))
		cmd = exec.Command(shell, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	lines := make(chan string, 4)
	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			lines <- strings.TrimSpace(scanner.Text())
		}
		close(lines)
	}()
	select {
	case line := <-lines:
		if line != "ready" {
			_ = cmd.Process.Kill()
			t.Fatalf("holder said %q", line)
		}
	case <-time.After(30 * time.Second):
		holderNeverReady(t, cmd, &stderr, 30*time.Second)
	}
	done := false
	release = func() string {
		if done {
			return ""
		}
		done = true
		_, _ = io.WriteString(stdin, "\n")
		answer := ""
		select {
		case line := <-lines:
			answer = line
		case <-time.After(20 * time.Second):
		}
		_ = stdin.Close()
		_ = cmd.Wait()
		return answer
	}
	t.Cleanup(func() {
		if !done {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	})
	return release, cmd.Process.Pid
}

// interactiveFactsSystem is the real handle table and the real processes, with
// every process taken for a signed-in user's: the test runs in session 0 or as
// SYSTEM, which the bound (c) rules refuse (they are tested with injected
// facts, and on the host in a real interactive session: the real token and
// session reads are covered only by the live cells). What it proves is the
// Windows calls: listing, duplicating, identifying, closing.
type interactiveFactsSystem struct{ windowsHolderSystem }

func (s interactiveFactsSystem) OpenProcess(pid uint32) (windowsHolderProc, error) {
	proc, err := s.windowsHolderSystem.OpenProcess(pid)
	if err != nil {
		return nil, err
	}
	return interactiveFactsProc{proc}, nil
}

type interactiveFactsProc struct{ windowsHolderProc }

func (p interactiveFactsProc) Facts() windowsHolderProcess {
	facts := p.windowsHolderProc.Facts()
	facts.Session, facts.SID, facts.Protected, facts.FactsErr = 1, "S-1-5-21-1-2-3-1001", false, nil
	return facts
}

func powershellForTest() string {
	return filepath.Join(os.Getenv("SystemRoot"), "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
}

// windowsGoHolderName is the image name of the 32-bit holder that
// buildWindowsWow64Holder compiles.
const windowsGoHolderName = "dc-wow64-holder.exe"

// windowsGoHolderBuildLimit bounds the compile of the 32-bit holder: a cold
// GOARCH=386 build of runtime and syscall takes well under a minute on a
// loaded hosted runner.
const windowsGoHolderBuildLimit = 4 * time.Minute

// windowsGoHolderSource is a holder with the protocol of the PowerShell
// holders, in the one language the CI image always has a 32-bit toolchain for.
// "exclusive" opens the file with no sharing, says ready, blocks in a read on
// its (synchronous) stdin pipe and says alive when that read returns.
// "reacquire" opens it the same way and opens it again whenever a read on its
// handle fails, saying "reopened N". It imports only os, strconv, syscall and
// time, so the cold 32-bit build is small.
const windowsGoHolderSource = `package main

import (
	"os"
	"strconv"
	"syscall"
	"time"
)

func open(path string) (syscall.Handle, error) {
	name, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}
	return syscall.CreateFile(name, syscall.GENERIC_READ, 0, nil, syscall.OPEN_EXISTING, syscall.FILE_ATTRIBUTE_NORMAL, 0)
}

func say(line string) { _, _ = os.Stdout.WriteString(line + "\n") }

func main() {
	if len(os.Args) != 3 {
		os.Exit(2)
	}
	h, err := open(os.Args[2])
	if err != nil {
		_, _ = os.Stderr.WriteString("open: " + err.Error() + "\n")
		os.Exit(1)
	}
	say("ready")
	switch os.Args[1] {
	case "exclusive":
		var b [1]byte
		_, _ = os.Stdin.Read(b[:])
		say("alive")
	case "reacquire":
		reopened := 0
		for i := 0; i < 1200; i++ {
			time.Sleep(100 * time.Millisecond)
			var b [1]byte
			var n uint32
			_, _ = syscall.SetFilePointer(h, 0, nil, 0)
			if syscall.ReadFile(h, b[:], &n, nil) != nil {
				if again, err := open(os.Args[2]); err == nil {
					h = again
					reopened++
					say("reopened " + strconv.Itoa(reopened))
				}
			}
		}
	default:
		os.Exit(2)
	}
}
`

// isWindowsGoHolder says whether shell is the holder program built by
// buildWindowsWow64Holder, not a PowerShell.
func isWindowsGoHolder(shell string) bool {
	return strings.EqualFold(filepath.Base(shell), windowsGoHolderName)
}

// The 32-bit holder is built once per test binary: the compile of the 386
// runtime takes seconds, the holder keeps no state, and every test that needs
// one starts a new process from the same image. The one build keeps its error,
// so a build that failed fails every test that needs the holder with the
// original message (a skip would hide it). The folder is removed by
// removeWindowsWow64Holder when the run ends (isolateTestHost).
var (
	windowsWow64HolderOnce sync.Once
	windowsWow64HolderDir  string
	windowsWow64HolderExe  string
	windowsWow64HolderErr  error
)

// buildWindowsWow64Holder returns the path of the 32-bit holder, compiling it
// on the first call of the test binary. A 32-bit process on 64-bit Windows is
// a WOW64 process whatever its language; the test builds one instead of using
// the SysWOW64 PowerShell, which the hosted runner did not start within a
// bounded wait. The build is bounded, and a failure says which step failed.
// The error is returned from the Once, not raised in it: a Fatalf there would
// end the first test inside the Once and leave the others with no error.
func buildWindowsWow64Holder(t *testing.T) string {
	t.Helper()
	windowsWow64HolderOnce.Do(func() {
		started := time.Now()
		windowsWow64HolderExe, windowsWow64HolderErr = compileWindowsWow64Holder()
		if windowsWow64HolderErr == nil {
			t.Logf("built the 32-bit holder in %s (once for this test binary)", time.Since(started).Round(time.Millisecond))
		}
	})
	if windowsWow64HolderErr != nil {
		t.Fatal(windowsWow64HolderErr)
	}
	return windowsWow64HolderExe
}

// compileWindowsWow64Holder compiles the holder for GOARCH=386 into a folder
// of its own and checks that the result is a 32-bit image.
func compileWindowsWow64Holder() (string, error) {
	goTool, err := exec.LookPath("go")
	if err != nil {
		return "", fmt.Errorf("cannot build the 32-bit holder: there is no go tool on PATH (%v); the test needs a real 32-bit process and compiles one", err)
	}
	dir, err := os.MkdirTemp("", "dc-wow64-holder-")
	if err != nil {
		return "", fmt.Errorf("cannot make the folder for the 32-bit holder: %w", err)
	}
	windowsWow64HolderDir = dir
	src := filepath.Join(dir, "holder.go")
	if err := os.WriteFile(src, []byte(windowsGoHolderSource), 0o600); err != nil {
		return "", fmt.Errorf("cannot write the 32-bit holder source: %w", err)
	}
	exe := filepath.Join(dir, windowsGoHolderName)
	ctx, cancel := context.WithTimeout(context.Background(), windowsGoHolderBuildLimit)
	defer cancel()
	cmd := exec.CommandContext(ctx, goTool, "build", "-trimpath", "-o", exe, src)
	cmd.Dir = dir
	cmd.Env = append(withoutEnv(os.Environ(), "GOOS", "GOARCH", "GOFLAGS", "CGO_ENABLED", "GOWORK"), "GOOS=windows", "GOARCH=386", "CGO_ENABLED=0", "GOWORK=off")
	started := time.Now()
	out, err := cmd.CombinedOutput()
	if err != nil {
		if len(out) > 4000 {
			out = out[len(out)-4000:]
		}
		return "", fmt.Errorf("building the 32-bit holder (%s build, GOARCH=386) failed after %s: %v (build limit %s)\n%s", goTool, time.Since(started).Round(time.Millisecond), err, windowsGoHolderBuildLimit, out)
	}
	image, err := pe.Open(exe)
	if err != nil {
		return "", fmt.Errorf("the built holder is not a Windows image: %w", err)
	}
	defer image.Close()
	if image.Machine != pe.IMAGE_FILE_MACHINE_I386 {
		return "", fmt.Errorf("the built holder is machine 0x%04x, want a 32-bit image (0x%04x)", image.Machine, pe.IMAGE_FILE_MACHINE_I386)
	}
	return exe, nil
}

// removeWindowsWow64Holder removes the folder of the built holder when the
// test run ends. It is a no-op when no test needed the holder.
func removeWindowsWow64Holder() {
	if windowsWow64HolderDir != "" {
		_ = os.RemoveAll(windowsWow64HolderDir)
	}
}

// holderNeverReady ends a holder that did not say ready in time and fails the
// test with what is known: the wait, how the process ended and what it wrote
// to stderr.
func holderNeverReady(t *testing.T, cmd *exec.Cmd, stderr *bytes.Buffer, limit time.Duration) {
	t.Helper()
	_ = cmd.Process.Kill()
	waitErr := cmd.Wait()
	text := strings.TrimSpace(stderr.String())
	if len(text) > 2000 {
		text = text[:2000]
	}
	t.Fatalf("the holder %s (pid %d) did not open the file and say ready within %s (wait: %v, exit code %d, stderr %q)", filepath.Base(cmd.Path), cmd.Process.Pid, limit, waitErr, cmd.ProcessState.ExitCode(), text)
}

// GAP-0755: a handle that shares nothing, held by another process, refuses
// the guardian's own digest read and every start. A swap cannot end it, so the
// guardian closes that handle, on the second check: the next start works on
// the same file, nothing was moved, no process was ended, and one HIGH audit
// row names the holder. A holder that takes the handle again waits out the
// backoff, and a hold in a later streak writes a new row.
func TestKeepWindowsManagedFileCopyEndsAnExclusiveHoldOfAnotherProcess(t *testing.T) {
	endsAnExclusiveHold(t, powershellForTest())
}

// The same with a 32-bit holder (WOW64): the handle values and the calls are
// the same, and the audit row says so. The holder is a GOARCH=386 program the
// test compiles, so it does not depend on the SysWOW64 PowerShell.
func TestKeepWindowsManagedFileCopyEndsAnExclusiveHoldOfAWow64Process(t *testing.T) {
	endsAnExclusiveHold(t, buildWindowsWow64Holder(t))
}

func endsAnExclusiveHold(t *testing.T, shell string) {
	resetWindowsHeldSwapsForTest(t)
	advance := fakeWindowsHeldSwapClock(t)
	var rows []windowsHolderAuditRow
	savedStandalone, savedSys, savedPost := windowsHolderStandalone, windowsHolderSys, windowsHolderAuditPost
	windowsHolderStandalone = func() bool { return true }
	windowsHolderSys = interactiveFactsSystem{windowsNativeHolderSystem{}}
	windowsHolderAuditPost = func(row windowsHolderAuditRow) error { rows = append(rows, row); return nil }
	resetWindowsHolderOutputForTest()
	t.Cleanup(func() {
		windowsHolderStandalone, windowsHolderSys, windowsHolderAuditPost = savedStandalone, savedSys, savedPost
		resetWindowsHolderOutputForTest()
	})
	root := t.TempDir()
	target := filepath.Join(root, "bin", "defenseclaw-hook.exe")
	copyPath := filepath.Join(root, "hook-guardian", "payload", "defenseclaw-hook.exe")
	if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
		t.Fatal(err)
	}
	writeWindowsSystemProgram(t, "HOSTNAME.EXE", target, nil)
	want, err := windowsFileSHA256Hex(target)
	if err != nil {
		t.Fatal(err)
	}
	if damage, err := keepWindowsManagedFileCopy(target, copyPath, want, true); err != nil || damage != "" {
		t.Fatalf("keep copy: restored %q, %v", damage, err)
	}
	before, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	var log strings.Builder
	check := func() {
		t.Helper()
		if damage, err := keepWindowsManagedFileCopy(target, copyPath, want, false); err != nil || damage != "" {
			t.Fatalf("check: restored %q, %v", damage, err)
		}
		reportWindowsHookHolders(&log)
	}
	started := func() bool {
		out, err := exec.Command(target).Output()
		return err == nil && len(strings.TrimSpace(string(out))) > 0
	}
	release, pid := startWindowsExclusiveHolder(t, shell, target)
	if started() {
		t.Fatal("a start succeeded while another process held the hook with no sharing; the fixture does not reproduce the failure")
	}
	if _, err := windowsFileSHA256Hex(target); err == nil {
		t.Fatal("the guardian's digest read succeeded under an exclusive handle; the fixture does not reproduce the failure")
	}
	// Tick 1: the hold is seen, nothing is closed.
	check()
	if started() || len(rows) != 0 {
		t.Fatalf("the first check acted on a hold seen once (rows %d)", len(rows))
	}
	// Tick 2: the same handle, five seconds on. The pass reads the whole
	// handle table of the host, with the holder's blocked pipe handle in it.
	advance(windowsHookBinaryCheckInterval)
	passStart := time.Now()
	check()
	t.Logf("second check (list, probe, close) took %s", time.Since(passStart))
	if time.Since(passStart) > 15*time.Second {
		t.Fatalf("the pass took %s", time.Since(passStart))
	}
	if !started() {
		t.Fatal("a start still fails after the second check")
	}
	if len(rows) != 1 {
		t.Fatalf("audit rows %d, want 1", len(rows))
	}
	row := rows[0]
	t.Logf("row: holder %s pid %d session %d sid %s wow64 %v access 0x%08x; scan %d ms, %d handles listed, %d inspected", row.Holder.Image, row.Holder.PID, row.Holder.Session, row.Holder.SID, row.Holder.Wow64, row.Access, row.ScanMS, row.Listed, row.Probed)
	if row.Holder.PID != uint32(pid) || !row.Closed || !strings.EqualFold(filepath.Base(row.Holder.Image), filepath.Base(shell)) || row.Holder.SID == "" ||
		row.Access&windowsHolderDataAccess == 0 || row.Hook != target || row.Holder.Wow64 != isWindowsGoHolder(shell) {
		t.Fatalf("row %+v", row)
	}
	if !strings.Contains(log.String(), "tamper: closed the handle") || strings.Count(log.String(), "[hook-guardian]") != 1 {
		t.Fatalf("log %q", log.String())
	}
	after, err := os.Stat(target)
	if err != nil || !os.SameFile(before, after) {
		t.Fatalf("the hook file changed (%v)", err)
	}
	if left, _ := filepath.Glob(target + ".backup.*"); len(left) != 0 {
		t.Fatalf("a swap was made: %q", left)
	}
	if answer := release(); answer != "alive" {
		t.Fatalf("the holder process did not survive the close (said %q)", answer)
	}
	// A check on the free hook, then ten quiet minutes: the next hold is a
	// new streak with its own row.
	check()
	advance(11 * time.Minute)
	check()
	second, _ := startWindowsExclusiveHolder(t, shell, target)
	check()
	advance(windowsHookBinaryCheckInterval)
	check()
	if !started() || len(rows) != 2 {
		t.Fatalf("second hold: start works %v, rows %d", started(), len(rows))
	}
	// The same process takes the handle again as soon as it loses it: the
	// close waits out the backoff and writes no new row.
	_ = second()
	check()
	advance(11 * time.Minute) // a new streak
	check()
	stop, reopened := startWindowsReacquiringHolder(t, shell, target)
	check()
	advance(windowsHookBinaryCheckInterval)
	check() // close 1
	if opens := reopened(); opens < 1 {
		t.Fatalf("the holder did not take the handle again (%d re-opens)", opens)
	}
	rowsAfterFirst := len(rows)
	for _, step := range []string{"+5 s", "+10 s", "+15 s", "+20 s"} {
		advance(windowsHookBinaryCheckInterval)
		check()
		t.Logf("%s after the first close: start works %v, re-opens %d, rows %d", step, started(), reopened(), len(rows))
		if len(rows) != rowsAfterFirst {
			t.Fatalf("a close of the same holder in the same streak wrote a row (%d)", len(rows))
		}
	}
	if opens := reopened(); opens < 2 {
		t.Fatalf("the holder was closed %d time(s) in 20 s of backoff steps; the second close is due by then", opens-1)
	}
	stop()
}

// startWindowsReacquiringHolder opens path with no sharing and opens it again
// whenever its handle is gone; reopened is how many times that happened.
func startWindowsReacquiringHolder(t *testing.T, shell, path string) (stop func(), reopened func() int) {
	t.Helper()
	var cmd *exec.Cmd
	if isWindowsGoHolder(shell) {
		cmd = exec.Command(shell, "reacquire", path)
	} else {
		cmd = exec.Command(shell, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", reacquiringHolderScript(path))
	}
	return runWindowsReacquiringHolder(t, cmd)
}

// reacquiringHolderScript is the PowerShell body of the re-opening holder: an
// unbuffered stream, so that every poll is a read on the handle and fails when
// the handle is gone.
func reacquiringHolderScript(path string) string {
	return fmt.Sprintf(`$p = '%s'; $n = 0; $b = New-Object byte[] 1; $f = New-Object IO.FileStream($p, 'Open', 'Read', 'None', 1); [Console]::Out.WriteLine('ready'); [Console]::Out.Flush(); for ($i = 0; $i -lt 1200; $i++) { Start-Sleep -Milliseconds 100; try { [void]$f.Seek(0, 0); [void]$f.Read($b, 0, 1) } catch { try { $f = New-Object IO.FileStream($p, 'Open', 'Read', 'None', 1); $n++; [Console]::Out.WriteLine('reopened ' + $n); [Console]::Out.Flush() } catch {} } }`, strings.ReplaceAll(path, "'", "''"))
}

// runWindowsReacquiringHolder starts cmd and waits for it to say ready; reopened
// is how many times the holder opened the file again.
func runWindowsReacquiringHolder(t *testing.T, cmd *exec.Cmd) (stop func(), reopened func() int) {
	t.Helper()
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	var opens atomic.Int32
	ready := make(chan struct{})
	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			if line := strings.TrimSpace(scanner.Text()); line == "ready" {
				close(ready)
			} else if n, err := strconv.Atoi(strings.TrimPrefix(line, "reopened ")); err == nil {
				opens.Store(int32(n))
			}
		}
	}()
	select {
	case <-ready:
	case <-time.After(30 * time.Second):
		holderNeverReady(t, cmd, &stderr, 30*time.Second)
	}
	stopped := false
	stop = func() {
		if !stopped {
			stopped = true
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	}
	t.Cleanup(stop)
	return stop, func() int {
		time.Sleep(1500 * time.Millisecond) // the holder polls every 100 ms
		return int(opens.Load())
	}
}

// startWindowsRotatingHolder opens path with no sharing and, every 300 ms,
// duplicates that handle to a new value and closes the old one, so the file
// is never free and no handle value lasts two checks. When its handle is
// closed by someone else it says so ("lost n") and opens the file again only
// after allowReopen: a re-open on its own next tick raced the test's start of
// the freed hook (the start failed while the close had worked). state is the
// latest handle value (-1 while it waits to re-open), how many times it
// rotated and how many times it lost the handle.
func startWindowsRotatingHolder(t *testing.T, shell, path string) (stop func(), state func() (handle int64, rotations, lost int), allowReopen func()) {
	t.Helper()
	if _, err := os.Stat(shell); err != nil {
		t.Skipf("PowerShell unavailable: %v", err)
	}
	gate := filepath.Join(t.TempDir(), "reopen")
	script := strings.Join([]string{
		`Add-Type -TypeDefinition @'`,
		`using System; using System.Runtime.InteropServices;`,
		`public static class R {`,
		`  [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] public static extern IntPtr CreateFileW(string p, uint a, uint s, IntPtr c, uint d, uint f, IntPtr t);`,
		`  [DllImport("kernel32.dll", SetLastError=true)] public static extern bool DuplicateHandle(IntPtr sp, IntPtr sh, IntPtr tp, out IntPtr th, uint acc, bool inh, uint opt);`,
		`  [DllImport("kernel32.dll")] public static extern IntPtr GetCurrentProcess();`,
		`  [DllImport("kernel32.dll", SetLastError=true)] public static extern bool CloseHandle(IntPtr h);`,
		`}`,
		`'@`,
		fmt.Sprintf(`$p = '%s'`, strings.ReplaceAll(path, "'", "''")),
		fmt.Sprintf(`$g = '%s'`, strings.ReplaceAll(gate, "'", "''")),
		`$me = [R]::GetCurrentProcess(); $rot = 0; $lost = 0; $keep = @()`,
		`$h = [R]::CreateFileW($p, 2147483648, 0, [IntPtr]::Zero, 3, 128, [IntPtr]::Zero)`,
		`[Console]::Out.WriteLine('ready'); [Console]::Out.Flush()`,
		`for ($i = 0; $i -lt 600; $i++) {`,
		`  Start-Sleep -Milliseconds 300`,
		`  $keep += New-Object System.Threading.ManualResetEvent($false)`, // takes a handle slot, so that values do not just alternate
		`  $n = [IntPtr]::Zero`,
		// -1 is "could not open" (the hook is in use for a moment): try again; it is not a handle to rotate.
		`  if ($h.ToInt64() -eq -1) { $h = [R]::CreateFileW($p, 2147483648, 0, [IntPtr]::Zero, 3, 128, [IntPtr]::Zero) }`,
		`  elseif ([R]::DuplicateHandle($me, $h, $me, [ref]$n, 0, $false, 2)) { [void][R]::CloseHandle($h); $h = $n; $rot++ }`,
		// The handle is gone (closed by the guardian): report it, then wait
		// for the test to let it open the file again.
		`  else { $lost++; [Console]::Out.WriteLine('lost ' + $lost); [Console]::Out.Flush()`,
		`    while (-not (Test-Path -LiteralPath $g)) { Start-Sleep -Milliseconds 50 }`,
		`    Remove-Item -LiteralPath $g -Force`,
		`    $h = [R]::CreateFileW($p, 2147483648, 0, [IntPtr]::Zero, 3, 128, [IntPtr]::Zero) }`,
		`  [Console]::Out.WriteLine('state ' + $h.ToInt64() + ' ' + $rot + ' ' + $lost); [Console]::Out.Flush()`,
		`}`,
	}, "\n")
	encoded := make([]byte, 0, 2*len(script))
	for _, unit := range windows.StringToUTF16(script) {
		encoded = append(encoded, byte(unit), byte(unit>>8))
	}
	cmd := exec.Command(shell, "-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand", base64.StdEncoding.EncodeToString(encoded))
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var all []string
	t.Cleanup(func() {
		mu.Lock()
		defer mu.Unlock()
		if t.Failed() {
			t.Logf("holder said: %q", all)
		}
	})
	var last struct {
		handle        int64
		rotations, lo int
	}
	ready := make(chan struct{})
	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "ready" {
				close(ready)
				continue
			}
			var h int64
			var r, l int
			mu.Lock()
			all = append(all, line)
			mu.Unlock()
			if _, err := fmt.Sscanf(line, "state %d %d %d", &h, &r, &l); err == nil {
				mu.Lock()
				last.handle, last.rotations, last.lo = h, r, l
				mu.Unlock()
			} else if _, err := fmt.Sscanf(line, "lost %d", &l); err == nil {
				mu.Lock()
				last.handle, last.lo = -1, l
				mu.Unlock()
			}
		}
	}()
	select {
	case <-ready:
	case <-time.After(60 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatal("the holder did not open the file")
	}
	stopped := false
	stop = func() {
		if !stopped {
			stopped = true
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	}
	t.Cleanup(stop)
	return stop, func() (int64, int, int) {
			mu.Lock()
			defer mu.Unlock()
			return last.handle, last.rotations, last.lo
		}, func() {
			if err := os.WriteFile(gate, nil, 0o600); err != nil {
				t.Fatal(err)
			}
		}
}

// GAP-0755: a holder that hands its file to a new handle value
// every 300 ms, so that no value lasts two checks and the hook is never free,
// is closed at the second check, and then waits out the backoff. The session
// and the account are injected (interactiveFactsSystem); the calls are real.
func TestKeepWindowsManagedFileCopyEndsAHoldThatRotatesItsHandle(t *testing.T) {
	resetWindowsHeldSwapsForTest(t)
	advance := fakeWindowsHeldSwapClock(t)
	var rows []windowsHolderAuditRow
	savedStandalone, savedSys, savedPost := windowsHolderStandalone, windowsHolderSys, windowsHolderAuditPost
	windowsHolderStandalone = func() bool { return true }
	windowsHolderSys = interactiveFactsSystem{windowsNativeHolderSystem{}}
	windowsHolderAuditPost = func(row windowsHolderAuditRow) error { rows = append(rows, row); return nil }
	resetWindowsHolderOutputForTest()
	t.Cleanup(func() {
		windowsHolderStandalone, windowsHolderSys, windowsHolderAuditPost = savedStandalone, savedSys, savedPost
		resetWindowsHolderOutputForTest()
	})
	root := t.TempDir()
	target := filepath.Join(root, "bin", "defenseclaw-hook.exe")
	copyPath := filepath.Join(root, "hook-guardian", "payload", "defenseclaw-hook.exe")
	if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
		t.Fatal(err)
	}
	writeWindowsSystemProgram(t, "HOSTNAME.EXE", target, nil)
	want, err := windowsFileSHA256Hex(target)
	if err != nil {
		t.Fatal(err)
	}
	if damage, err := keepWindowsManagedFileCopy(target, copyPath, want, true); err != nil || damage != "" {
		t.Fatalf("keep copy: restored %q, %v", damage, err)
	}
	var log strings.Builder
	check := func() {
		t.Helper()
		if damage, err := keepWindowsManagedFileCopy(target, copyPath, want, false); err != nil || damage != "" {
			t.Fatalf("check: restored %q, %v", damage, err)
		}
		reportWindowsHookHolders(&log)
	}
	started := func() bool {
		out, err := exec.Command(target).Output()
		return err == nil && len(strings.TrimSpace(string(out))) > 0
	}
	_, state, allowReopen := startWindowsRotatingHolder(t, powershellForTest(), target)
	if started() {
		t.Fatal("a start succeeded while another process held the hook with no sharing")
	}
	waitFor(t, 30*time.Second, func() bool { _, rot, _ := state(); return rot >= 1 })
	check() // check 1: the hold is seen
	first, rot1, _ := state()
	if started() || len(rows) != 0 {
		t.Fatalf("the first check acted (rows %d)", len(rows))
	}
	time.Sleep(900 * time.Millisecond) // the handle value changes before the next check
	_, _, lostBefore := state()
	advance(windowsHookBinaryCheckInterval)
	check() // check 2: another handle value, the same hold
	second, rot2, _ := state()
	if rot2 < rot1+2 {
		t.Fatalf("the holder rotated its handle %d time(s) between the checks, want at least 2", rot2-rot1)
	}
	t.Logf("handle value %d at check 1, %d at check 2 (%d rotations between)", first, second, rot2-rot1)
	if !started() || len(rows) != 1 || !rows[0].Closed {
		t.Fatalf("second check: start works %v, rows %+v", started(), rows)
	}
	waitFor(t, 10*time.Second, func() bool { _, _, l := state(); return l > lostBefore })
	allowReopen()
	waitFor(t, 10*time.Second, func() bool { h, _, l := state(); return l > lostBefore && h != -1 }) // it holds the file again
	// The next check is inside the backoff (10 s).
	advance(windowsHookBinaryCheckInterval)
	check()
	_, _, lost := state()
	if len(rows) != 1 || strings.Count(log.String(), "tamper: closed the handle") != 1 {
		t.Fatalf("closed again inside the backoff: rows %d, log %q", len(rows), log.String())
	}
	// 10 s after the first close the hold is seen again (the two checks start
	// over after a close), and 15 s after it is closed again.
	time.Sleep(900 * time.Millisecond)
	advance(windowsHookBinaryCheckInterval)
	check()
	if len(rows) != 1 || strings.Count(log.String(), "tamper: closed the handle") != 1 {
		t.Fatalf("closed at the first sight after the backoff: rows %d, log %q", len(rows), log.String())
	}
	time.Sleep(900 * time.Millisecond)
	advance(windowsHookBinaryCheckInterval)
	check()
	waitFor(t, 10*time.Second, func() bool { _, _, l := state(); return l > lost })
	if strings.Count(log.String(), "tamper: closed the handle") != 2 || len(rows) != 1 {
		t.Fatalf("second close after the backoff: rows %d, log %q", len(rows), log.String())
	}
	t.Logf("log: %s", log.String())
}

// GAP-0369: on a volume or behind a filter driver that
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

// GAP-0656: a sharing violation on the start-style open also comes
// from a handle that shares no reading, which any user may hold on the
// hook, and a swap cannot end that hold. The swaps back off for the same
// path, stop at a cap of pending backups, and are logged once.
func resetWindowsHeldSwapsForTest(t *testing.T) {
	t.Helper()
	windowsHeldSwaps = windowsHeldSwapState{}
	t.Cleanup(func() { windowsHeldSwaps = windowsHeldSwapState{} })
	// The cap counts the process-wide pending backups: a test that left some
	// behind (a failed one, a test that never ran the later check) must not
	// refuse the swaps of the tests after it.
	windowsImageBackups.Lock()
	previous := windowsImageBackups.pending
	windowsImageBackups.pending = map[string]windowsImageBackup{}
	windowsImageBackups.Unlock()
	t.Cleanup(func() {
		windowsImageBackups.Lock()
		windowsImageBackups.pending = previous
		windowsImageBackups.Unlock()
	})
}

func fakeWindowsHeldSwapClock(t *testing.T) (advance func(time.Duration)) {
	t.Helper()
	now := time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)
	previous := windowsHeldSwapNow
	windowsHeldSwapNow = func() time.Time { return now }
	t.Cleanup(func() { windowsHeldSwapNow = previous })
	return func(d time.Duration) { now = now.Add(d) }
}

func TestWindowsHeldSwapBacksOffExponentiallyUpToTheMaximum(t *testing.T) {
	resetWindowsHeldSwapsForTest(t)
	advance := fakeWindowsHeldSwapClock(t)
	// Held at every 5 s check: the swaps fall 10, 20, 40, 80, 160, 300, 300 s apart.
	var swaps []time.Duration
	var last time.Duration
	var elapsed time.Duration
	for elapsed = 0; elapsed <= 30*time.Minute; elapsed += 5 * time.Second {
		if allowed, why := windowsHeldSwapAllowed(); allowed {
			if len(swaps) > 0 {
				swaps = append(swaps, elapsed-last)
			} else {
				swaps = append(swaps, 0)
			}
			last = elapsed
		} else if why == "" {
			t.Fatal("a refused swap gave no reason")
		}
		advance(5 * time.Second)
	}
	want := []time.Duration{0, 10 * time.Second, 20 * time.Second, 40 * time.Second, 80 * time.Second, 160 * time.Second, 300 * time.Second, 300 * time.Second}
	if len(swaps) < len(want) {
		t.Fatalf("swaps %v, want at least %v", swaps, want)
	}
	for i, d := range want {
		if swaps[i] != d {
			t.Fatalf("swap gaps %v, want %v", swaps, want)
		}
	}
	// Without a held verdict for the streak's end, the next hold starts again.
	advance(windowsHeldSwapStreakEnd + time.Second)
	if allowed, _ := windowsHeldSwapAllowed(); !allowed {
		t.Fatal("the backoff outlived the streak")
	}
	if allowed, _ := windowsHeldSwapAllowed(); allowed {
		t.Fatal("a second swap in the same instant")
	}
}

func TestWindowsHeldSwapStopsAtTheBackupCapAndLogsOnce(t *testing.T) {
	resetWindowsHeldSwapsForTest(t)
	advance := fakeWindowsHeldSwapClock(t)
	for i := 0; i < windowsHeldSwapBackupCap; i++ {
		deferWindowsImageBackupRemoval(filepath.Join(`C:\bin`, "defenseclaw-hook.exe.backup."+strings.Repeat("a", 31)+string(rune('a'+i))))
	}
	var log strings.Builder
	for i := 0; i < 5; i++ {
		advance(time.Minute)
		allowed, why := windowsHeldSwapAllowed()
		if allowed {
			t.Fatalf("check %d swapped with %d backups pending", i, windowsHeldSwapBackupCap)
		}
		if !strings.Contains(why, "backups of earlier swaps are still held open") {
			t.Fatalf("reason %q", why)
		}
		windowsHeldSwaps.notice = why
		reportWindowsHeldSwapNotice(&log, `C:\bin\defenseclaw-hook.exe`)
	}
	if strings.Count(log.String(), "notice: the hook binary") != 1 || strings.Contains(log.String(), "for writing") {
		t.Fatalf("log %q", log.String())
	}
	// A holder lets go: the pending backup goes and swapping resumes.
	for key := range windowsImageBackups.pending {
		forgetWindowsImageBackup(key)
		break
	}
	if allowed, _ := windowsHeldSwapAllowed(); !allowed {
		t.Fatal("no swap once the backups were below the cap")
	}
}

// Review L8: when the cap stops the very first held verdict of a streak, the
// logged flag still ends with the streak, so a hold ten minutes later says so
// again.
func TestWindowsHeldSwapNoticeIsLoggedAgainAfterAStreakTheCapStopped(t *testing.T) {
	resetWindowsHeldSwapsForTest(t)
	advance := fakeWindowsHeldSwapClock(t)
	for i := 0; i < windowsHeldSwapBackupCap; i++ {
		deferWindowsImageBackupRemoval(filepath.Join(`C:\bin`, "defenseclaw-hook.exe.backup."+strings.Repeat("b", 31)+string(rune('a'+i))))
	}
	target := `C:\bin\defenseclaw-hook.exe`
	var log strings.Builder
	check := func() {
		t.Helper()
		allowed, why := windowsHeldSwapAllowed()
		if allowed {
			t.Fatal("swapped with the backup cap reached")
		}
		windowsHeldSwaps.notice = why
		reportWindowsHeldSwapNotice(&log, target)
	}
	check()
	advance(time.Minute)
	check()
	if got := strings.Count(log.String(), "notice: the hook binary"); got != 1 {
		t.Fatalf("inside the streak, %d notices: %q", got, log.String())
	}
	advance(windowsHeldSwapStreakEnd + time.Second)
	check()
	if got := strings.Count(log.String(), "notice: the hook binary"); got != 2 {
		t.Fatalf("after the streak ended, %d notices: %q", got, log.String())
	}
}

// The guardian swaps a held hook at the first check, then leaves it for the
// backoff: the file ID stays and nothing piles up.
func TestKeepWindowsManagedFileCopyBacksOffFromAHoldItCannotEnd(t *testing.T) {
	requireAdministratorTestToken(t, "the product restore writes the hook binary with the install file descriptor (an Administrators owner)")
	resetWindowsHeldSwapsForTest(t)
	advance := fakeWindowsHeldSwapClock(t)
	root := t.TempDir()
	target := filepath.Join(root, "bin", "defenseclaw-hook.exe")
	copyPath := filepath.Join(root, "hook-guardian", "payload", "defenseclaw-hook.exe")
	if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
		t.Fatal(err)
	}
	writeWindowsSystemProgram(t, "HOSTNAME.EXE", target, nil)
	want, err := windowsFileSHA256Hex(target)
	if err != nil {
		t.Fatal(err)
	}
	if damage, err := keepWindowsManagedFileCopy(target, copyPath, want, true); err != nil || damage != "" {
		t.Fatalf("keep copy: restored %q, %v", damage, err)
	}
	// The injected open check stands for a reader with share mode 0 that
	// reopens whatever object holds the name.
	previous := windowsHookBinaryOpenRefused
	windowsHookBinaryOpenRefused = func(string) bool { return true }
	t.Cleanup(func() { windowsHookBinaryOpenRefused = previous })
	t.Cleanup(func() { removeWindowsReplacementCopies(filepath.Dir(target)) })
	damage, err := keepWindowsManagedFileCopy(target, copyPath, want, false)
	if err != nil || !strings.Contains(damage, "held open by another program") || strings.Contains(damage, "for writing") {
		t.Fatalf("first check: restored %q, %v", damage, err)
	}
	afterFirst, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		advance(time.Second)
		damage, err := keepWindowsManagedFileCopy(target, copyPath, want, false)
		if err != nil || damage != "" {
			t.Fatalf("check %d inside the backoff: restored %q, %v", i, damage, err)
		}
	}
	if now, err := os.Stat(target); err != nil || !os.SameFile(now, afterFirst) {
		t.Fatalf("the hook was swapped again inside the backoff (%v)", err)
	}
	var log strings.Builder
	reportWindowsHeldSwapNotice(&log, target)
	reportWindowsHeldSwapNotice(&log, target)
	if strings.Count(log.String(), "held open by another program") != 1 {
		t.Fatalf("log %q", log.String())
	}
	if left, _ := filepath.Glob(target + ".backup.*"); len(left) != 1 {
		t.Fatalf("backups after one swap: %q", left)
	}
	advance(windowsHeldSwapBackoffBase)
	if damage, err := keepWindowsManagedFileCopy(target, copyPath, want, false); err != nil || damage == "" {
		t.Fatalf("after the backoff: restored %q, %v", damage, err)
	}
	if left, _ := filepath.Glob(target + ".backup.*"); len(left) != 2 {
		t.Fatalf("backups after two swaps: %q", left)
	}
}

// GAP-0656: the older replacement runs after a refused hard link,
// and the "restored without the one-step swap" notice is set only if it
// succeeded. A running hook refuses it; the notice stays empty.
func TestCopyWindowsManagedFileClaimsNoRestoreWhenTheOlderReplacementIsRefused(t *testing.T) {
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
	previous := windowsImageSwapLink
	windowsImageSwapLink = func(string, string) error { return windows.ERROR_NOT_SUPPORTED }
	t.Cleanup(func() { windowsImageSwapLink = previous })
	windowsImageSwapLinkRefusal, windowsImageSwapLinkRefusalLogged = "", ""
	t.Cleanup(func() { windowsImageSwapLinkRefusal, windowsImageSwapLinkRefusalLogged = "", "" })
	if err := copyWindowsManagedFile(source, target, "", true, true); err == nil {
		t.Fatal("the MoveFileEx replacement of a running program succeeded")
	}
	var log strings.Builder
	reportWindowsImageSwapLinkRefusal(&log, target)
	if log.Len() != 0 || windowsImageSwapLinkRefusal != "" {
		t.Fatalf("a restore was claimed although the replacement failed: %q", log.String())
	}
	if left, _ := filepath.Glob(filepath.Join(dir, "*.restore-*")); len(left) != 0 {
		t.Fatalf("temporaries left: %q", left)
	}
}

// GAP-0656: the old program under its backup name takes an
// administrators-only access list, so a user cannot start it from there.
func TestSwapWindowsProgramImageClosesTheBackupToUsers(t *testing.T) {
	requireAdministratorTestToken(t, "the backup keeps the old object's owner")
	dir := t.TempDir()
	target := filepath.Join(dir, "defenseclaw-hook.exe")
	source := filepath.Join(dir, "source.exe")
	_ = os.WriteFile(target, []byte("old"), 0o600)
	_ = os.WriteFile(source, []byte("new"), 0o600)
	backup, err := swapWindowsProgramImage(source, target)
	if err != nil {
		t.Fatal(err)
	}
	descriptor, err := windows.GetNamedSecurityInfo(backup, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	sddl := descriptor.String()
	if strings.Contains(sddl, ";;;BU") || strings.Contains(sddl, ";;;WD") || !strings.Contains(sddl, ";;;BA") {
		t.Fatalf("backup access list %s", sddl)
	}
	if body, _ := os.ReadFile(target); string(body) != "new" {
		t.Fatalf("target %q", body)
	}
	// A failing access-list step does not fail the swap.
	_ = os.WriteFile(source, []byte("newer"), 0o600)
	previous := windowsImageBackupRestrict
	windowsImageBackupRestrict = func(string) error { return windows.ERROR_ACCESS_DENIED }
	t.Cleanup(func() { windowsImageBackupRestrict = previous })
	if _, err := swapWindowsProgramImage(source, target); err != nil {
		t.Fatalf("swap with a failing access-list step: %v", err)
	}
}

// Review L9: a backup name that could not be closed to users is logged, once
// per error, not dropped; a later swap that closes its backup ends the
// suppression.
func TestSwapWindowsProgramImageLogsAFailedBackupAccessListOnce(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "defenseclaw-hook.exe")
	source := filepath.Join(dir, "source.exe")
	_ = os.WriteFile(target, []byte("v0"), 0o600)
	previous := windowsImageBackupRestrict
	t.Cleanup(func() { windowsImageBackupRestrict = previous })
	reset := func() {
		windowsImageBackupRestrictFailure.backup, windowsImageBackupRestrictFailure.err = "", ""
		windowsImageBackupRestrictLogged = ""
	}
	reset()
	t.Cleanup(reset)
	swap := func(body string, restrict func(string) error) string {
		t.Helper()
		windowsImageBackupRestrict = restrict
		if err := os.WriteFile(source, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		backup, err := swapWindowsProgramImage(source, target)
		if err != nil {
			t.Fatalf("swap %s: %v", body, err)
		}
		return backup
	}
	denied := func(string) error { return windows.ERROR_ACCESS_DENIED }
	var log strings.Builder
	first := swap("v1", denied)
	reportWindowsImageBackupRestrictFailure(&log)
	swap("v2", denied)
	reportWindowsImageBackupRestrictFailure(&log)
	reportWindowsImageBackupRestrictFailure(&log)
	text := log.String()
	if strings.Count(text, "could not close the backup") != 1 || !strings.Contains(text, first) || !strings.Contains(text, windows.ERROR_ACCESS_DENIED.Error()) {
		t.Fatalf("two failed swaps logged %q", text)
	}
	// A swap that closes its backup ends the suppression.
	swap("v3", func(string) error { return nil })
	reportWindowsImageBackupRestrictFailure(&log)
	swap("v4", denied)
	reportWindowsImageBackupRestrictFailure(&log)
	if got := strings.Count(log.String(), "could not close the backup"); got != 2 {
		t.Fatalf("after a closed backup, %d notices: %q", got, log.String())
	}
}

// GAP-0755: in each guardian check the hook binary is checked, and restored
// when it is damaged, before the runtime files are looked at, so a user who
// holds many runtime files cannot delay the binary. The real check runs on a
// layout in a temporary folder; the binary lookup and the runtime folder
// lookup are recorders. Moving the runtime pass above the binary check fails
// this test.
func TestKeepWindowsStandaloneHookBinaryChecksTheBinaryBeforeTheRuntimeFiles(t *testing.T) {
	root := t.TempDir()
	roots := winpath.EnterpriseRoots{
		Profile:      managed.ProfileStandalone,
		InstallRoot:  filepath.Join(root, "install"),
		StateRoot:    filepath.Join(root, "state"),
		MetadataPath: filepath.Join(root, "state", "metadata.json"),
	}
	target := filepath.Join(roots.InstallRoot, "bin", "defenseclaw-hook.exe")
	if err := os.MkdirAll(roots.StateRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(roots.MetadataPath, []byte(`{"hashes":{"hook":"0123456789abcdef"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	savedRoots, savedManifest, savedStandalone := windowsManagedLayout.roots, enterpriseHookManifest, windowsHolderStandalone
	savedLstat, savedDir := windowsHookBinaryLstat, windowsHookRuntimeDir
	t.Cleanup(func() {
		windowsManagedLayout.roots, enterpriseHookManifest, windowsHolderStandalone = savedRoots, savedManifest, savedStandalone
		windowsHookBinaryLstat, windowsHookRuntimeDir = savedLstat, savedDir
		resetWindowsHolderOutputForTest()
	})
	windowsManagedLayout.roots = func(string) (winpath.EnterpriseRoots, error) { return roots, nil }
	enterpriseHookManifest = filepath.Join(roots.StateRoot, "targets.yaml")
	windowsHolderStandalone = func() bool { return true }
	var order []string
	windowsHookBinaryLstat = func(path string) (os.FileInfo, error) {
		if path == target {
			order = append(order, "binary")
			return nil, os.ErrPermission
		}
		return os.Lstat(path)
	}
	windowsHookRuntimeDir = func() (string, error) {
		order = append(order, "runtime")
		return "", fmt.Errorf("no runtime folder in this test")
	}
	var log strings.Builder
	keepWindowsStandaloneHookBinaryLocked(&log, false)
	if len(order) < 2 || order[0] != "binary" || order[len(order)-1] != "runtime" {
		t.Fatalf("order of the guardian check: %v, want the binary first and the runtime files after it", order)
	}
	if !strings.Contains(log.String(), "inspect the hook binary") {
		t.Fatalf("the binary check did not report its own result: %q", log.String())
	}
}
