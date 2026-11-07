package hookpaths

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
)

// A path below an explicit-id process link is resolved in the mount tree of
// the process the link names. The hook reads it only when it shares that
// process mount namespace; a namespace it does not share leaves the path
// unproved, whatever the link text and root identity say.
func TestGAP0641FixedPIDLinkNeedsTheSameMountTree(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux proc path")
	}
	root := t.TempDir()
	home := filepath.Join(root, "home")
	runner := filepath.Join(root, "runner", "child")
	for _, dir := range []string{filepath.Join(home, ".defenseclaw", "cache"), runner} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "runner", "status"), []byte("ordinary"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(runner)
	pidPath := fmt.Sprintf("/proc/%d/cwd", os.Getpid())
	path := pidPath + "/../status"
	if got := ProtectedReach(path, home, NewTargetMemo()); got != GradeNone {
		t.Fatalf("shared mount namespace: ordinary path %q grade=%s, want None", path, got)
	}

	views, restore := foreignMountViews(t)
	for name, set := range views {
		set()
		if fixedPIDLinkProved(pidPath) {
			t.Errorf("%s: link %q proved", name, pidPath)
		}
		if got := ProtectedReach(path, home, NewTargetMemo()); got == GradeNone {
			t.Errorf("%s: path %q grade=None, want uncertain", name, path)
		}
		if got := LateCallGrade("cat "+path, runner, home); got == GradeNone {
			t.Errorf("%s: command on %q grade=None, want uncertain", name, path)
		}
		restore()
	}
}

// The links of the hook own process share its mount tree, root link included.
func TestGAP0641OwnFixedPIDLinksShareTheMountTree(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux proc path")
	}
	pid := os.Getpid()
	for _, link := range []string{
		fmt.Sprintf("/proc/%d/root", pid),
		fmt.Sprintf("/proc/%d/cwd", pid),
		fmt.Sprintf("/proc/%d/task/%d/root", pid, pid),
		fmt.Sprintf("/proc/%d/task/%d/cwd", pid, pid),
	} {
		if !fixedPIDLinkProved(link) {
			t.Errorf("own link %q not proved", link)
		}
	}
}

const mntNSChildEnv = "DC_HOOKPATHS_MNTNS_CHILD_DIR"

// TestGAP0641MntNSChild is the helper process of the private-mount test. It
// runs only when the parent sets the environment variable.
func TestGAP0641MntNSChild(t *testing.T) {
	dir := os.Getenv(mntNSChildEnv)
	if dir == "" {
		t.Skip("helper process")
	}
	if err := syscall.Mount("tmpfs", dir, "tmpfs", 0, ""); err != nil {
		fmt.Printf("ns-skip: mount: %v\n", err)
		return
	}
	if err := os.Symlink(os.Getenv(mntNSChildEnv+"_TARGET"), filepath.Join(dir, "alias")); err != nil {
		fmt.Printf("ns-skip: symlink: %v\n", err)
		return
	}
	fmt.Println("ns-ready")
	_, _ = bufio.NewReader(os.Stdin).ReadByte()
}

// A relative alias that exists only in a private mount of another process is
// reached through the root link of that process. The root directory identity
// matches the hook, the mount tree does not.
func TestGAP0641FixedPIDRootLinkPrivateMountAlias(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux proc path")
	}
	root := t.TempDir()
	home := filepath.Join(root, "home")
	protected := filepath.Join(home, ".defenseclaw", "cache", "entry")
	aliasDir := filepath.Join(root, "aliasdir")
	for _, dir := range []string{filepath.Dir(protected), aliasDir} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(protected, []byte("protected"), 0600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestGAP0641MntNSChild$")
	cmd.Env = append(os.Environ(), mntNSChildEnv+"="+aliasDir, mntNSChildEnv+"_TARGET="+protected)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags:  syscall.CLONE_NEWUSER | syscall.CLONE_NEWNS,
		UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}},
		GidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}},
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Skipf("no private mount namespace here: %v", err)
	}
	t.Cleanup(func() {
		_ = stdin.Close()
		_ = cmd.Wait()
	})
	lines := make(chan string, 8)
	go func() {
		sc := bufio.NewScanner(stdout)
		for sc.Scan() {
			lines <- sc.Text()
		}
		close(lines)
	}()
	ready := false
	for !ready {
		select {
		case line, ok := <-lines:
			if !ok {
				t.Skip("helper process ended before the private mount was ready")
			}
			if strings.HasPrefix(line, "ns-skip:") {
				t.Skip(line)
			}
			ready = line == "ns-ready"
		case <-time.After(20 * time.Second):
			_ = cmd.Process.Kill()
			t.Skip("helper process did not report the private mount")
		}
	}
	rootLink := fmt.Sprintf("/proc/%d/root", cmd.Process.Pid)
	if _, err := PathStat(rootLink); err != nil {
		t.Skipf("root link of the helper is not readable here: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(aliasDir, "alias")); err == nil {
		t.Fatal("alias is visible in the hook mount namespace; fixture is not private")
	}
	path := rootLink + filepath.Join(aliasDir, "alias")
	if got := ProtectedReach(path, home, NewTargetMemo()); got == GradeNone {
		t.Errorf("protected alias %q through a private mount grade=None", path)
	}
	if got := LateCallGrade("cat "+path, root, home); got == GradeNone {
		t.Errorf("protected alias command on %q grade=None", path)
	}
}
