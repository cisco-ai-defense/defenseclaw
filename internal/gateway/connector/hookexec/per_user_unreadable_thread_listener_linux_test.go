// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package hookexec

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// init turns the test binary into the helper process of
// TestListenerHeldByAThreadOfAnotherGroupStaysUnverified. The helper is a copy
// of the test binary with the set-group-ID bit, so it starts with an effective
// group that differs from its real group. It inherits a listening socket as
// descriptor 3 and ends as a process the account can read in part: a worker
// thread keeps the group IDs the program started with (the kernel refuses the
// account its descriptor folder) and a private copy of the descriptor table
// that holds the socket, while the leader thread closes its own descriptor 3
// and takes the real group for every ID (its folder is readable and lists no
// socket). The process is dumpable, as the ordinary processes of an account
// are.
func init() {
	if os.Getenv("DC_TEST_MIXED_CREDENTIALS") != "1" {
		return
	}
	ready := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		if _, _, errno := syscall.RawSyscall(syscall.SYS_UNSHARE, syscall.CLONE_FILES, 0, 0); errno != 0 {
			ready <- errno
			return
		}
		ready <- nil
		select {}
	}()
	if err := <-ready; err != nil {
		fmt.Printf("MIXED_ERR=unshare: %v\n", err)
		os.Exit(0)
	}
	if err := syscall.Close(3); err != nil {
		fmt.Printf("MIXED_ERR=close: %v\n", err)
		os.Exit(0)
	}
	gid := uintptr(syscall.Getgid())
	if _, _, errno := syscall.RawSyscall(syscall.SYS_SETRESGID, gid, gid, gid); errno != 0 {
		fmt.Printf("MIXED_ERR=setresgid: %v\n", errno)
		os.Exit(0)
	}
	// Changing the effective group made the process non-dumpable; the
	// ordinary processes of an account are dumpable.
	const prSetDumpable = 4
	if _, _, errno := syscall.RawSyscall(syscall.SYS_PRCTL, prSetDumpable, 1, 0); errno != 0 {
		fmt.Printf("MIXED_ERR=dumpable: %v\n", errno)
		os.Exit(0)
	}
	fmt.Println("MIXED_READY")
	_, _ = io.Copy(io.Discard, os.Stdin)
	os.Exit(0)
}

// A listener that a live thread of another process of the account keeps open,
// where the kernel refuses this account that thread's descriptor folder while
// the process leader folder is readable and lists no socket, is not held by
// the recorded gateway alone: the proof of the owner is partial, so the call
// stays refused as unverified in every fail mode and never as an outage.
func TestListenerHeldByAThreadOfAnotherGroupStaysUnverified(t *testing.T) {
	shortConnectedWait(t, 150*time.Millisecond)
	groups, err := os.Getgroups()
	if err != nil {
		t.Skipf("no groups: %v", err)
	}
	other := -1
	for _, g := range groups {
		if g != os.Getgid() {
			other = g
			break
		}
	}
	if other < 0 {
		t.Skip("the account has no second group to run a set-group-ID helper in")
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	file, err := listener.(*net.TCPListener).File()
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	helper := filepath.Join(t.TempDir(), "mixed-credentials-helper")
	if err := copyTestBinary(helper); err != nil {
		t.Skipf("no helper binary: %v", err)
	}
	if err := os.Chown(helper, -1, other); err != nil {
		t.Skipf("no helper group: %v", err)
	}
	if err := os.Chmod(helper, 0o755|os.ModeSetgid); err != nil {
		t.Skipf("no set-group-ID helper: %v", err)
	}
	cmd := exec.Command(helper, "-test.run=^$")
	cmd.Env = append(os.Environ(), "DC_TEST_MIXED_CREDENTIALS=1")
	cmd.ExtraFiles = []*os.File{file}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Skipf("no second process: %v", err)
	}
	t.Cleanup(func() {
		_ = stdin.Close()
		_ = cmd.Wait()
	})
	reader := bufio.NewScanner(stdout)
	if !reader.Scan() || strings.TrimSpace(reader.Text()) != "MIXED_READY" {
		t.Skipf("the helper could not take mixed credentials: %q", reader.Text())
	}
	pid := cmd.Process.Pid
	if _, err := os.ReadDir(fmt.Sprintf("/proc/%d/fd", pid)); err != nil {
		t.Skipf("the leader folder of the helper is not readable: %v", err)
	}
	workers, err := os.ReadDir(fmt.Sprintf("/proc/%d/task", pid))
	if err != nil {
		t.Fatal(err)
	}
	refused := false
	for _, worker := range workers {
		if worker.Name() == strconv.Itoa(pid) {
			continue
		}
		if _, err := socketsOfThread(fmt.Sprintf("/proc/%d/task/%s", pid, worker.Name())); errors.Is(err, os.ErrPermission) {
			refused = true
		}
	}
	if !refused {
		t.Skip("the kernel lets this account read every thread of the helper")
	}
	if _, err := socketInodesOf("/proc", pid); !errors.Is(err, errUnreadableLiveThread) {
		t.Fatalf("a live thread folder this account may not read was not reported: %v", err)
	}
	ctx := WithPerUserGatewayDataDir(t.Context(), recordGateway(t, os.Getpid(), nil))
	_, err = PostPerUserHook(ctx, listener.Addr().String(), "/api/v1/claude-code/hook", nil, []byte("{}"))
	if err == nil {
		t.Fatal("a listener that accepts nothing answered")
	}
	if PerUserPostListenerUnanswered(err) || !PerUserPostPeerUnverified(err) {
		t.Fatalf("a listener held by a thread of another group was not refused as unverified: %v", err)
	}
}

// copyTestBinary copies the running test binary to path.
func copyTestBinary(path string) error {
	source, err := os.Executable()
	if err != nil {
		return err
	}
	in, err := os.Open(source)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0o755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}

// fakeThread describes one thread of a fake process table.
type fakeThread struct {
	tid      int
	state    string // state letter of the stat file
	readable bool   // whether this account may read the descriptor folder
	ids      string // user and group IDs: "own", "other group", or "" for no status file ("<ids>, exiting": the thread is exiting, PF_EXITING)
	inodes   []int
}

// writeFakeProcess writes process pid with the given threads under procRoot.
func writeFakeProcess(t *testing.T, procRoot string, pid int, threads ...fakeThread) {
	t.Helper()
	for _, th := range threads {
		dir := filepath.Join(procRoot, strconv.Itoa(pid), "task", strconv.Itoa(th.tid))
		fds := filepath.Join(dir, "fd")
		if err := os.MkdirAll(fds, 0o755); err != nil {
			t.Fatal(err)
		}
		for i, inode := range th.inodes {
			if err := os.Symlink(fmt.Sprintf("socket:[%d]", inode), filepath.Join(fds, strconv.Itoa(i+3))); err != nil {
				t.Fatal(err)
			}
		}
		ids, exiting := strings.CutSuffix(th.ids, ", exiting")
		flags := 0
		if exiting {
			flags = pfExiting
		}
		stat := fmt.Sprintf("%d (odd ) name) %s 1 1 1 0 -1 %d 0 0 0 0\n", th.tid, th.state, flags)
		if err := os.WriteFile(filepath.Join(dir, "stat"), []byte(stat), 0o644); err != nil {
			t.Fatal(err)
		}
		uid, gid := os.Geteuid(), os.Getegid()
		switch ids {
		case "own":
		case "other group":
			gid++
		default:
			uid = -1
		}
		if uid >= 0 {
			status := fmt.Sprintf("Name:\tx\nUid:\t%d\t%d\t%d\t%d\nGid:\t%d\t%d\t%d\t%d\n",
				uid, uid, uid, uid, os.Getgid(), gid, gid, gid)
			if err := os.WriteFile(filepath.Join(dir, "status"), []byte(status), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		if !th.readable {
			if err := os.Chmod(fds, 0); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.Chmod(fds, 0o755) })
		}
	}
}

// What a descriptor folder the kernel refuses means depends on the thread: a
// thread that has exited holds nothing, a process none of whose threads can be
// read with this account's own IDs is a non-dumpable process (an sshd session
// child), and any other live thread this account cannot read, beside readable
// ones or with other group IDs, may hold the socket.
func TestSocketInodesOfUnreadableThreads(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads every descriptor list")
	}
	for _, tc := range []struct {
		name    string
		threads []fakeThread
		want    error // nil: read; os.ErrPermission or errUnreadableLiveThread
		inodes  []int
	}{
		{"exited leader, readable worker", []fakeThread{
			{100, "Z", false, "own", nil}, {101, "S", true, "own", []int{11}}}, nil, []int{11}},
		{"every thread readable", []fakeThread{
			{100, "S", true, "own", nil}, {101, "S", true, "own", []int{11}}}, nil, []int{11}},
		{"exiting worker beside a readable leader", []fakeThread{
			{100, "S", true, "own", []int{11}}, {101, "R", false, "own, exiting", nil}}, nil, []int{11}},
		{"every thread of an exiting process", []fakeThread{
			{100, "R", false, "own, exiting", nil}, {101, "R", false, "other group, exiting", nil}}, nil, nil},
		{"live unreadable worker beside a readable leader", []fakeThread{
			{100, "S", true, "own", nil}, {101, "S", false, "other group", []int{11}}}, errUnreadableLiveThread, nil},
		{"live unreadable worker with own IDs beside a readable leader", []fakeThread{
			{100, "S", true, "own", nil}, {101, "S", false, "own", []int{11}}}, errUnreadableLiveThread, nil},
		{"live unreadable worker beside an exited leader, other group", []fakeThread{
			{100, "Z", false, "own", nil}, {101, "S", false, "other group", []int{11}}}, errUnreadableLiveThread, nil},
		{"process none of whose threads can be read, own IDs", []fakeThread{
			{100, "S", false, "own", nil}, {101, "S", false, "own", nil}}, os.ErrPermission, nil},
		{"process none of whose threads can be read, other group", []fakeThread{
			{100, "S", false, "other group", nil}}, errUnreadableLiveThread, nil},
		{"unreadable thread with no readable IDs", []fakeThread{
			{100, "S", false, "", nil}}, errUnreadableLiveThread, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			procRoot := t.TempDir()
			writeFakeProcess(t, procRoot, 100, tc.threads...)
			held, err := socketInodesOf(procRoot, 100)
			if !errors.Is(err, tc.want) || (tc.want == nil && err != nil) {
				t.Fatalf("socketInodesOf error = %v, want %v", err, tc.want)
			}
			for _, inode := range tc.inodes {
				if !held[strconv.Itoa(inode)] {
					t.Fatalf("inode %d not listed in %v", inode, held)
				}
			}
		})
	}
}

// The recorded gateway holds the listener alone only when no other process of
// the account can hold it: a live thread of a readable process that this
// account cannot read, with a listener it might hold, keeps the proof from
// being complete; an exited leader beside a readable worker, or a non-dumpable
// process of the account's own IDs, does not.
func TestListenerSoleHolderProofRefusesAnUnreadableLiveThread(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads every descriptor list")
	}
	const gateway = 4242
	server := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 18970}
	rows := []string{"0: 0100007F:4A1A 00000000:0000 0A 0 0 0 1000 0 11"}
	for _, tc := range []struct {
		name    string
		threads []fakeThread
		want    bool
	}{
		{"live unreadable worker beside a readable leader", []fakeThread{
			{5000, "S", true, "own", nil}, {5001, "S", false, "other group", []int{11}}}, false},
		{"exited leader and a readable worker without the listener", []fakeThread{
			{5000, "Z", false, "own", nil}, {5001, "S", true, "own", []int{77}}}, true},
		{"non-dumpable process of the account's own IDs", []fakeThread{
			{5000, "S", false, "own", nil}}, true},
		{"unreadable process of another group", []fakeThread{
			{5000, "S", false, "other group", nil}}, false},
		{"exiting process beside a readable thread", []fakeThread{
			{5000, "S", true, "own", nil}, {5001, "R", false, "own, exiting", nil}}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			procRoot := t.TempDir()
			writeThreadSockets(t, procRoot, gateway, gateway, []int{11})
			writeFakeProcess(t, procRoot, 5000, tc.threads...)
			if got := listenersHeldOnlyBy(procTables(t, rows, nil), procRoot, gateway, server); got != tc.want {
				t.Fatalf("listenersHeldOnlyBy = %v, want %v", got, tc.want)
			}
		})
	}
}
