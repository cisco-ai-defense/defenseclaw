// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package openshell_test

import (
	"bytes"
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/openshelltest"
)

// recordingSSH writes an ssh that prints each argument it gets in
// brackets, in dir.
func recordingSSH(t *testing.T, dir string) string {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "ssh")
	if err := os.WriteFile(p, []byte("#!/bin/sh\nfor a in \"$@\"; do printf '[%s]' \"$a\"; done\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestSSHShimRunsTheRealSSHWithSharingOff(t *testing.T) {
	skipOnWindows(t)
	base := realTempDir(t)
	openshell.SetSSHShimBase(t, base)
	bin := filepath.Join(t.TempDir(), "it's bin")
	realSSH := recordingSSH(t, bin)
	shim, err := openshell.NewSSHShim("relative/bin" + string(os.PathListSeparator) + bin + string(os.PathListSeparator) + "/usr/bin")
	if err != nil || shim == nil {
		t.Fatalf("NewSSHShim = %v, %v", shim, err)
	}
	if shim.Real != realSSH || shim.Path != filepath.Join(shim.Dir, "ssh") || filepath.Dir(shim.Dir) != base ||
		!strings.HasPrefix(filepath.Base(shim.Dir), "defenseclaw-ssh-") {
		t.Fatalf("shim = %+v; want one running %s, in a new directory under %s", shim, realSSH, base)
	}
	expectMode(t, shim.Dir, 0o700)
	expectMode(t, shim.Path, 0o700)
	if err := shim.Verify(); err != nil {
		t.Fatal(err)
	}

	// The options come first, then the CLI's own arguments, untouched.
	out, err := exec.Command(shim.Path, "-tt", "-o", "SetEnv=TERM=xterm", "sandbox", "a b", "").Output()
	want := "[-o][ControlMaster=no][-o][ControlPath=none][-o][ControlPersist=no][-tt][-o][SetEnv=TERM=xterm][sandbox][a b][]"
	if err != nil || string(out) != want {
		t.Fatalf("shim ran ssh with %q, %v; want %q", out, err, want)
	}
	if got := openshell.SSHNoSharingOptions(); !slices.Equal(got, []string{"-o", "ControlMaster=no", "-o", "ControlPath=none", "-o", "ControlPersist=no"}) {
		t.Fatalf("SSHNoSharingOptions = %q", got)
	}

	// The variable that makes the shim answer a probe never reaches the CLI.
	env := shim.Environ([]string{"HOME=/h", "PATH=/usr/bin:/bin", "DEFENSECLAW_SSH_SHIM_PROBE=1", "PATH=/last"})
	if strings.Join(env, " ") != "HOME=/h PATH="+shim.Dir+":/last" {
		t.Fatalf("Environ = %q", env)
	}
	if err := shim.Remove(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(shim.Dir); !os.IsNotExist(err) {
		t.Fatalf("Remove left %s: %v", shim.Dir, err)
	}
	if err := shim.Remove(); err != nil {
		t.Fatalf("second Remove = %v", err)
	}
	// A shim DefenseClaw did not make is never deleted.
	if err := (&openshell.SSHShim{Dir: bin}).Remove(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(realSSH); err != nil {
		t.Fatal(err)
	}
}

// The shim runs the ssh a command lookup of PATH finds, never a shim (its
// own or another DefenseClaw process's), a relative entry, a directory
// named ssh or a file that is not executable.
func TestSSHShimFindsTheRealSSH(t *testing.T) {
	skipOnWindows(t)
	openshell.SetSSHShimBase(t, realTempDir(t))
	root := t.TempDir()
	realSSH := recordingSSH(t, filepath.Join(root, "real"))
	recordingSSH(t, filepath.Join(root, "defenseclaw-ssh-123"))
	if err := os.MkdirAll(filepath.Join(root, "dirs", "ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "plain"), 0o700); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(root, "plain", "ssh"), "#!/bin/sh\n", 0o600)
	join := func(dirs ...string) string { return strings.Join(dirs, string(os.PathListSeparator)) }

	first, err := openshell.NewSSHShim(join(filepath.Join(root, "real")))
	if err != nil || first == nil {
		t.Fatalf("NewSSHShim = %v, %v", first, err)
	}
	defer first.Remove()
	// A shim elsewhere, under any name, is recognised by its content.
	other := filepath.Join(root, "other")
	if err := os.MkdirAll(other, 0o700); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(first.Path)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(other, "ssh"), string(data), 0o700)

	path := join(".", "", first.Dir, other, filepath.Join(root, "defenseclaw-ssh-123"), filepath.Join(root, "dirs"), filepath.Join(root, "plain"), filepath.Join(root, "real"))
	s, err := openshell.NewSSHShim(path)
	if err != nil || s == nil || s.Real != realSSH {
		t.Fatalf("NewSSHShim(%s) = %+v, %v; want one running %s", path, s, err, realSSH)
	}
	defer s.Remove()

	// No ssh at all: nothing for the CLI to share connections with.
	if s, err := openshell.NewSSHShim(join(filepath.Join(root, "plain"), first.Dir, "relative")); s != nil || err != nil {
		t.Fatalf("NewSSHShim without an ssh = %+v, %v; want nil, nil", s, err)
	}
	if s, err := openshell.NewSSHShim(""); s != nil || err != nil {
		t.Fatalf("NewSSHShim with no PATH = %+v, %v; want nil, nil", s, err)
	}
}

// The shim runs the real ssh with the PATH it was made for, without the
// shim's directory. A first ssh that is itself a wrapper running "the next
// ssh" on PATH (ssh-ident installed as ~/bin/ssh) used to find the shim
// again, which ran the wrapper again with six more arguments each round,
// until the argument list was too long.
func TestSSHShimRunsSSHWithoutItselfOnPATH(t *testing.T) {
	skipOnWindows(t)
	openshell.SetSSHShimBase(t, realTempDir(t))
	root := t.TempDir()
	wrapperDir, realDir := filepath.Join(root, "home bin"), filepath.Join(root, "usr-bin")
	recordingSSH(t, realDir)
	if err := os.Mkdir(wrapperDir, 0o700); err != nil {
		t.Fatal(err)
	}
	rounds := filepath.Join(root, "rounds")
	q := func(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }
	// Like ssh-ident: skip its own directory, run the first other ssh.
	writeFile(t, filepath.Join(wrapperDir, "ssh"), "#!/bin/sh\n"+
		"echo x >> "+q(rounds)+"\n"+
		"n=0; while read -r _; do n=$((n+1)); done < "+q(rounds)+"\n"+
		"[ \"$n\" -le 3 ] || { echo 'the wrapper looped' >&2; exit 99; }\n"+
		"IFS=:\nfor d in $PATH; do\n"+
		"  [ \"$d\" = "+q(wrapperDir)+" ] && continue\n"+
		"  [ -x \"$d/ssh\" ] && exec \"$d/ssh\" \"$@\"\n"+
		"done\nexit 127\n", 0o700)
	// A shim directory another DefenseClaw process left on PATH is no
	// ssh to run either.
	stale := filepath.Join(root, "defenseclaw-ssh-stale")
	recordingSSH(t, stale)
	pathEnv := strings.Join([]string{stale, wrapperDir, realDir}, string(os.PathListSeparator))

	s, err := openshell.NewSSHShim(pathEnv)
	if err != nil || s == nil || s.Real != filepath.Join(wrapperDir, "ssh") {
		t.Fatalf("NewSSHShim = %+v, %v; want one running the wrapper", s, err)
	}
	defer s.Remove()
	// The CLI finds ssh on the PATH the shim gives it.
	cmd := exec.Command("/bin/sh", "-c", `exec ssh "$@"`, "sh", "-tt", "sandbox")
	cmd.Env = s.Environ([]string{"PATH=" + pathEnv})
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if want := "[-o][ControlMaster=no][-o][ControlPath=none][-o][ControlPersist=no][-tt][sandbox]"; err != nil || string(out) != want {
		t.Fatalf("ssh ran with %q, %v (%s); want %q", out, err, stderr.String(), want)
	}
	if data, err := os.ReadFile(rounds); err != nil || string(data) != "x\n" {
		t.Fatalf("the wrapper ran %q times, %v; want once", data, err)
	}
}

// A temporary directory that another user could swap the shim out of is
// refused, and so is a shim that changed after it was written.
func TestSSHShimRefusesUnsafeDirectories(t *testing.T) {
	skipOnWindows(t)
	skipAsRoot(t)
	bin := filepath.Join(t.TempDir(), "bin")
	recordingSSH(t, bin)
	mk := func(parent string, mode fs.FileMode) string {
		dir, err := os.MkdirTemp(parent, "base-")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(dir, mode); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
		return dir
	}
	root := realTempDir(t)
	for _, tc := range []struct {
		name string
		base string
		want string
	}{
		{"world-writable", mk(root, 0o777), "is writable by other users (mode 0777)"},
		{"group-writable", mk(root, 0o770), "is writable by other users (mode 0770)"},
		{"below a world-writable directory", mk(mk(root, 0o777), 0o700), "is writable by other users (mode 0777)"},
		{"missing", filepath.Join(root, "missing"), "no such file"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			openshell.SetSSHShimBase(t, tc.base)
			s, err := openshell.NewSSHShim(bin)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("NewSSHShim in %s = %+v, %v; want an error containing %q", tc.base, s, err, tc.want)
			}
			if tc.name != "missing" && !strings.Contains(err.Error(), "set TMPDIR to a directory only you can write") {
				t.Fatalf("error %q does not say what to do", err)
			}
			if entries, _ := os.ReadDir(tc.base); len(entries) != 0 {
				t.Fatalf("a refused shim left %v in %s", entries, tc.base)
			}
		})
	}

	// A sticky world-writable directory (as /tmp) keeps what is inside it.
	sticky := mk(root, 0o777|fs.ModeSticky)
	openshell.SetSSHShimBase(t, sticky)
	s, err := openshell.NewSSHShim(bin)
	if err != nil || s == nil {
		t.Fatalf("NewSSHShim in a sticky directory = %v, %v", s, err)
	}
	defer s.Remove()

	// A symbolic link is resolved first: the shim's directory is below the
	// realSSH one, whatever the link points at later.
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(root, link); err != nil {
		t.Fatal(err)
	}
	openshell.SetSSHShimBase(t, link)
	linked, err := openshell.NewSSHShim(bin)
	if err != nil || filepath.Dir(linked.Dir) != root {
		t.Fatalf("NewSSHShim through a link = %+v, %v; want a directory in %s", linked, err, root)
	}
	defer linked.Remove()

	// Changed content, mode or directory after the write.
	writeFile(t, s.Path, "#!/bin/sh\nexec /usr/bin/ssh \"$@\"\n", 0o700)
	if err := s.Verify(); err == nil || !strings.Contains(err.Error(), "is not the shim DefenseClaw wrote") {
		t.Fatalf("Verify of a rewritten shim = %v", err)
	}
	if err := os.Chmod(linked.Path, 0o722); err != nil {
		t.Fatal(err)
	}
	if err := linked.Verify(); err == nil || !strings.Contains(err.Error(), "is not a private file of yours") {
		t.Fatalf("Verify of a writable shim = %v", err)
	}
	if err := os.Chmod(linked.Dir, 0o770); err != nil {
		t.Fatal(err)
	}
	if err := linked.Verify(); err == nil || !strings.Contains(err.Error(), "is writable by other users") {
		t.Fatalf("Verify in a group-writable directory = %v", err)
	}
}

// A shim that a PATH search would pass over is never used, since the
// OpenShell CLI would then run the user's own ssh, with its connection
// sharing: on a filesystem mounted noexec (as /tmp on hardened Linux
// hosts) the shim goes under DefenseClaw's data directory instead, and
// when no directory can hold one that runs, NewSSHShim refuses.
func TestSSHShimMustRun(t *testing.T) {
	skipOnWindows(t)
	bin := filepath.Join(t.TempDir(), "bin")
	realSSH := recordingSSH(t, bin)
	base := realTempDir(t)
	fallback := filepath.Join(realTempDir(t), "data", "openshell-ssh")
	openshell.SetSSHShimBase(t, base)
	openshell.SetSSHShimFallback(t, fallback)
	empty := func(dir string) {
		t.Helper()
		if entries, _ := os.ReadDir(dir); len(entries) != 0 {
			t.Fatalf("a refused shim left %v in %s", entries, dir)
		}
	}

	// The temporary directory is on a noexec mount: the shim is made under
	// the data directory, and runs from there.
	openshell.SetSSHShimNoexec(t, func(dir string) (bool, error) { return dir == base, nil })
	s, err := openshell.NewSSHShim(bin)
	if err != nil || s == nil {
		t.Fatalf("NewSSHShim with a noexec temporary directory = %v, %v", s, err)
	}
	defer s.Remove()
	if filepath.Dir(s.Dir) != fallback || s.Fallback != base+" is on a filesystem mounted noexec" {
		t.Fatalf("shim = %+v; want one under %s saying why", s, fallback)
	}
	expectMode(t, fallback, 0o700)
	empty(base)
	out, err := exec.Command(s.Path, "sandbox").Output()
	if want := "[-o][ControlMaster=no][-o][ControlPath=none][-o][ControlPersist=no][sandbox]"; err != nil || string(out) != want {
		t.Fatalf("the fallback shim ran ssh with %q, %v; want %q", out, err, want)
	}
	if err := s.Remove(); err != nil {
		t.Fatal(err)
	}

	// Neither directory can run it: refused, naming both.
	openshell.SetSSHShimNoexec(t, func(string) (bool, error) { return true, nil })
	if s, err := openshell.NewSSHShim(bin); err == nil || s != nil ||
		!strings.Contains(err.Error(), base+" is on a filesystem mounted noexec") ||
		!strings.Contains(err.Error(), fallback+" is on a filesystem mounted noexec") ||
		!strings.HasSuffix(err.Error(), "; set TMPDIR to a directory only you can write, on a filesystem not mounted noexec") {
		t.Fatalf("NewSSHShim with no directory that runs programs = %+v, %v", s, err)
	}

	// A shim the system will not run (the EACCES a noexec mount gives, or
	// an execution policy) is refused however its mount looks.
	openshell.SetSSHShimNoexec(t, func(string) (bool, error) { return false, nil })
	openshell.SetSSHShimMode(t, 0o600)
	s, err = openshell.NewSSHShim(bin)
	if err == nil || s != nil || !strings.Contains(err.Error(), "(a PATH search passes over the shim in "+base+"/defenseclaw-ssh-") ||
		!strings.Contains(err.Error(), "; a PATH search passes over the shim in "+fallback+"/defenseclaw-ssh-") ||
		strings.Count(err.Error(), ", which it cannot execute, and finds "+realSSH) != 2 {
		t.Fatalf("NewSSHShim of a shim that cannot run = %+v, %v", s, err)
	}
	empty(base)
	empty(fallback)
}

// The fallback directory is the openshell-ssh folder of the data directory
// DefenseClaw runs with, else of $DEFENSECLAW_HOME.
func TestSSHShimFallbackIsUnderTheDataDirectory(t *testing.T) {
	skipOnWindows(t)
	t.Cleanup(func() { openshell.SetSSHShimDataDir("") })
	t.Setenv("DEFENSECLAW_HOME", "/srv/dc-home")
	if got := openshell.SSHShimFallbackDir(); got != "/srv/dc-home/openshell-ssh" {
		t.Fatalf("fallback = %q", got)
	}
	openshell.SetSSHShimDataDir("/data/dc")
	if got := openshell.SSHShimFallbackDir(); got != "/data/dc/openshell-ssh" {
		t.Fatalf("fallback = %q", got)
	}
	openshell.SetSSHShimDataDir("relative")
	if got := openshell.SSHShimFallbackDir(); got != "" {
		t.Fatalf("fallback for a relative data directory = %q", got)
	}
}

// mountedNoexec reads the mount's flags: the filesystem this test binary
// runs from allows running programs, and a known noexec mount does not.
func TestMountedNoexecReadsTheMountFlags(t *testing.T) {
	skipOnWindows(t)
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if noexec, err := openshell.MountedNoexec(filepath.Dir(exe)); err != nil || noexec {
		t.Fatalf("MountedNoexec(%s) = %v, %v; the test binary runs from it", filepath.Dir(exe), noexec, err)
	}
	mount := knownNoexecMount()
	if mount == "" {
		t.Skip("no noexec mount to compare with")
	}
	if noexec, err := openshell.MountedNoexec(mount); err != nil || !noexec {
		t.Fatalf("MountedNoexec(%s) = %v, %v; it is mounted noexec", mount, noexec, err)
	}
}

// knownNoexecMount is a mount point this host lists as noexec, if any.
func knownNoexecMount() string {
	switch runtime.GOOS {
	case "linux":
		data, err := os.ReadFile("/proc/self/mounts")
		if err != nil {
			return ""
		}
		for _, line := range strings.Split(string(data), "\n") {
			f := strings.Fields(line)
			if len(f) >= 4 && (f[1] == "/proc" || f[1] == "/sys" || f[1] == "/dev/shm") && slices.Contains(strings.Split(f[3], ","), "noexec") {
				return f[1]
			}
		}
	case "darwin":
		// macOS mounts its VM swap volume noexec.
		out, err := exec.Command("/sbin/mount").Output()
		if err != nil {
			return ""
		}
		for _, line := range strings.Split(string(out), "\n") {
			if strings.Contains(line, " on /System/Volumes/VM (") && strings.Contains(line, "noexec") {
				return "/System/Volumes/VM"
			}
		}
	}
	return ""
}

// Directories that are not the user's are refused: the shim's own, and
// any above it that is neither the user's nor root's.
func TestSSHShimRefusesDirectoriesOfOtherUsers(t *testing.T) {
	skipOnWindows(t)
	bin := filepath.Join(t.TempDir(), "bin")
	recordingSSH(t, bin)
	base := realTempDir(t)
	openshell.SetSSHShimBase(t, base)
	yes := func(fs.FileInfo) bool { return true }
	notBase := func(info fs.FileInfo) bool { return info.Name() != filepath.Base(base) }

	openshell.SetSSHShimOwners(t, yes, notBase)
	if s, err := openshell.NewSSHShim(bin); err == nil || !strings.Contains(err.Error(), base+" belongs to another user") {
		t.Fatalf("NewSSHShim below another user's directory = %+v, %v", s, err)
	}
	openshell.SetSSHShimOwners(t, func(fs.FileInfo) bool { return false }, yes)
	if s, err := openshell.NewSSHShim(bin); err == nil || !strings.Contains(err.Error(), "is not owned by you") {
		t.Fatalf("NewSSHShim in a directory of another user's = %+v, %v", s, err)
	}
	if entries, _ := os.ReadDir(base); len(entries) != 0 {
		t.Fatalf("a refused shim left %v in %s", entries, base)
	}
}

// Every openshell invocation DefenseClaw builds runs with the shim first
// on its PATH (sandbox connect, the exec terminal, upload, download,
// forward start and stop, version), and the shim is gone once the
// command is done.
func TestInvocationsRunTheSSHShim(t *testing.T) {
	rec := openshelltest.NewSSHRecorder(t)
	cli := openshell.CLI{Binary: rec.OpenShell, Gateway: "openshell"}
	local := t.TempDir()
	build := []func() (openshell.Invocation, error){
		func() (openshell.Invocation, error) { return cli.Connect("box") },
		func() (openshell.Invocation, error) {
			return cli.Exec("box", []string{"claude"}, openshell.CLIExecOptions{TTY: true})
		},
		func() (openshell.Invocation, error) {
			return cli.Exec("box", []string{"true"}, openshell.CLIExecOptions{Timeout: time.Minute})
		},
		func() (openshell.Invocation, error) { return cli.Upload("box", local, "/sandbox", false) },
		func() (openshell.Invocation, error) { return cli.Download("box", "/sandbox/x", local) },
		func() (openshell.Invocation, error) { return cli.ForwardStart("box", 18789, "") },
		func() (openshell.Invocation, error) { return cli.ForwardStop("box", 18789) },
		func() (openshell.Invocation, error) { return cli.Version(), nil },
	}
	for i, b := range build {
		inv, err := b()
		if err != nil {
			t.Fatal(err)
		}
		if inv.Interactive {
			cmd, cancel, err := inv.Command(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			var out bytes.Buffer
			cmd.Stdin, cmd.Stdout, cmd.Stderr = nil, &out, &out
			if err := cmd.Run(); err != nil {
				t.Fatalf("%s: %v: %s", inv.Argv, err, out.String())
			}
			cancel()
		} else if out, err := inv.Output(context.Background()); err != nil {
			t.Fatalf("%s: %v: %s", inv.Argv, err, out)
		}
		calls := rec.ExpectShimmed(t, i+1)
		if got := calls[i].Args[len(openshell.SSHNoSharingOptions()):]; !slices.Equal(got, inv.Argv[1:]) {
			t.Fatalf("ssh got %q after the options, want the CLI's %q", got, inv.Argv[1:])
		}
	}
}

// A shim that cannot be made safely stops the invocation before the CLI
// runs.
func TestInvocationRefusesAnUnsafeShimDirectory(t *testing.T) {
	skipAsRoot(t)
	rec := openshelltest.NewSSHRecorder(t)
	base := realTempDir(t)
	if err := os.Chmod(base, 0o777); err != nil {
		t.Fatal(err)
	}
	openshell.SetSSHShimBase(t, base)
	inv, err := openshell.CLI{Binary: rec.OpenShell, Gateway: "openshell"}.Connect("box")
	if err != nil {
		t.Fatal(err)
	}
	if cmd, _, err := inv.Command(context.Background()); err == nil || cmd != nil || !strings.Contains(err.Error(), "set TMPDIR") {
		t.Fatalf("Command = %v, %v; want the unsafe directory refused", cmd, err)
	}
	if _, err := (openshell.Invocation{Argv: []string{rec.OpenShell}}).Output(context.Background()); err == nil {
		t.Fatal("Output ran with an unsafe shim directory")
	}
	if calls := rec.Calls(t); len(calls) != 0 {
		t.Fatalf("the CLI ran: %+v", calls)
	}

	// So does a shim that would not run: the CLI would run the user's ssh.
	if err := os.Chmod(base, 0o700); err != nil {
		t.Fatal(err)
	}
	openshell.SetSSHShimMode(t, 0o600)
	if cmd, _, err := inv.Command(context.Background()); err == nil || cmd != nil || !strings.Contains(err.Error(), "which it cannot execute") {
		t.Fatalf("Command = %v, %v; want a shim that does not run refused", cmd, err)
	}
	if calls := rec.Calls(t); len(calls) != 0 {
		t.Fatalf("the CLI ran: %+v", calls)
	}
}

// spawnSites are the files under internal/openshell that start processes
// themselves, and why each needs no ssh shim. Everything that runs the
// OpenShell CLI for a sandbox session goes through Invocation.Command
// (cli.go), which gives it the shim; a new process spawn elsewhere must
// either do the same or be added here with its reason.
var spawnSites = map[string]string{
	"cli.go":                      "Invocation.Command: every openshell sandbox invocation, with the ssh shim",
	"sshshim.go":                  "runs the ssh shim once, answering a probe without ssh, to prove a PATH search runs it",
	"runner.go":                   "ExecRunner: docker, brew, systemctl, the installer and openshell commands that open no ssh session",
	"image/docker.go":             "docker image builds",
	"sandboxcli/gitidentity.go":   "git config",
	"sandboxcli/ui.go":            "the pager",
	"sandboxcli/terminal_unix.go": "execs a harness in place for a nested run inside a sandbox",
}

func TestOnlyKnownFilesStartProcesses(t *testing.T) {
	found := map[string]bool{}
	err := filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return err
		}
		f, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			return err
		}
		ast.Inspect(f, func(n ast.Node) bool {
			var sel *ast.SelectorExpr
			switch n := n.(type) {
			case *ast.CallExpr:
				sel, _ = n.Fun.(*ast.SelectorExpr)
			case *ast.CompositeLit:
				sel, _ = n.Type.(*ast.SelectorExpr)
			}
			if sel == nil {
				return true
			}
			if pkg, ok := sel.X.(*ast.Ident); ok {
				switch pkg.Name + "." + sel.Sel.Name {
				case "exec.Command", "exec.CommandContext", "processutil.CommandContext", "os.StartProcess", "syscall.Exec", "syscall.ForkExec", "exec.Cmd":
					found[filepath.ToSlash(path)] = true
				}
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for path := range found {
		if _, ok := spawnSites[path]; !ok {
			t.Errorf("%s starts a process outside Invocation.Command: run the OpenShell CLI through an openshell.Invocation so it gets the ssh shim, or list the file in spawnSites with why it needs none", path)
		}
	}
	for path, why := range spawnSites {
		if why != "" && !found[path] {
			t.Errorf("%s no longer starts processes: remove it from spawnSites", path)
		}
	}
}
