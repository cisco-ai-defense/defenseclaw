// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package processutil

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/managed"
	"golang.org/x/sys/unix"
)

func waitForReachFile(t *testing.T, path string) {
	t.Helper()
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		if _, err := os.Stat(path); err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", path)
		}
	}
}

// r104 W25 review: while any scan ran, the gateway made itself non-dumpable,
// so a same-user status, stop, restart or upgrade could not read its /proc
// entries. Containment must leave the gateway's own state alone, through
// overlapping scans, a canceled scan and the end of the last one.
func TestRunTrackedLeavesTheGatewayDumpable(t *testing.T) {
	before, err := unix.PrctlRetInt(unix.PR_GET_DUMPABLE, 0, 0, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	check := func(when string) {
		t.Helper()
		if got, err := unix.PrctlRetInt(unix.PR_GET_DUMPABLE, 0, 0, 0, 0); err != nil || got != before {
			t.Errorf("gateway dumpable %s = %d, %v; want %d", when, got, err, before)
		}
		// Another process of this user, as daemon status runs it.
		self := "/proc/" + strconv.Itoa(os.Getpid())
		probe := exec.Command("/bin/sh", "-c", `readlink "$1/exe" >/dev/null && cat "$1/environ" >/dev/null`, "sh", self)
		if out, err := probe.CombinedOutput(); err != nil {
			t.Errorf("same-user process cannot read the gateway's /proc entries %s: %v: %s", when, err, out)
		}
	}
	dir := t.TempDir()
	start := func(ctx context.Context, name string) chan error {
		cmd := CommandContext(ctx, "/bin/sh", "-c",
			`: > "$1"; while [ ! -e "$2" ]; do sleep 0.02; done`,
			"sh", filepath.Join(dir, name+".active"), filepath.Join(dir, name+".release"))
		done := make(chan error, 1)
		go func() { done <- RunTracked(cmd) }()
		return done
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	first := start(context.Background(), "first")
	second := start(ctx, "second")
	waitForReachFile(t, filepath.Join(dir, "first.active"))
	waitForReachFile(t, filepath.Join(dir, "second.active"))
	check("while two scans run")
	if err := os.WriteFile(filepath.Join(dir, "first.release"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := <-first; err != nil {
		t.Fatalf("first scan = %v", err)
	}
	check("while the second scan runs")
	cancel()
	if err := <-second; err == nil {
		t.Fatal("canceled scan reported success")
	}
	check("after a canceled scan")
}

const (
	reachHelperEnv = "DC_PROCESSUTIL_REACH_HELPER"
	reachDirEnv    = "DC_PROCESSUTIL_REACH_DIR"
)

// TestRunTrackedCannotReachProcessesOutsideItsTreeHelper runs as the scanner.
// The host procfs still lists the gateway, the launcher and every other
// process; none of their ptrace-protected entries may open.
func TestRunTrackedCannotReachProcessesOutsideItsTreeHelper(t *testing.T) {
	spec := os.Getenv(reachHelperEnv)
	if spec == "" {
		t.Skip("helper process of TestRunTrackedCannotReachProcessesOutsideItsTree")
	}
	targets := map[string]string{}
	for _, item := range strings.Split(spec, ",") {
		name, pid, _ := strings.Cut(item, "=")
		targets[name] = pid
	}
	raw, err := os.ReadFile("/proc/self/stat")
	if err != nil {
		t.Fatal(err)
	}
	targets["launcher"] = strings.Fields(string(raw[strings.LastIndexByte(string(raw), ')')+1:]))[1]
	for name, pid := range targets {
		base := "/proc/" + pid
		if _, err := os.Stat(base); err != nil {
			t.Fatalf("%s is not in the host procfs: %v", name, err)
		}
		for _, entry := range []string{"mem", "environ", "maps", "auxv"} {
			if data, err := os.ReadFile(base + "/" + entry); err == nil {
				t.Errorf("scanner read %s %s (%d bytes)", name, entry, len(data))
			} else if !errors.Is(err, os.ErrPermission) {
				t.Errorf("read %s %s = %v, want permission denied", name, entry, err)
			}
		}
		for _, link := range []string{"exe", "cwd", "root", "fd/0", "fd/1", "fd/2"} {
			if target, err := os.Readlink(base + "/" + link); err == nil {
				t.Errorf("scanner resolved %s %s = %q", name, link, target)
			} else if !errors.Is(err, os.ErrPermission) {
				t.Errorf("readlink %s %s = %v, want permission denied", name, link, err)
			}
		}
		if file, err := os.Open(base + "/fd/1"); err == nil {
			_ = file.Close()
			t.Errorf("scanner opened %s stdout through /proc", name)
		}
	}
	// Landlock reports a handled access it refuses as EACCES before the
	// capability check that makes an unprivileged mknod fail with EPERM, so
	// this shows the scanner's own domain is active (AppArmor confinement,
	// as on Ubuntu, can refuse the reads above without it).
	probe := filepath.Join(os.Getenv(reachDirEnv), "block")
	if err := unix.Mknod(probe, unix.S_IFBLK|0o600, 0); !errors.Is(err, unix.EACCES) {
		t.Errorf("mknod of a block device in the scanner = %v, want EACCES from its Landlock domain", err)
	}
	// The scanner's own tree stays inspectable, as scanner runtimes need.
	if _, err := os.Readlink("/proc/self/exe"); err != nil {
		t.Errorf("scanner cannot read its own executable: %v", err)
	}
}

func TestRunTrackedCannotReachProcessesOutsideItsTree(t *testing.T) {
	peer := exec.Command("sleep", "60")
	if err := peer.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = peer.Process.Kill()
		_ = peer.Wait()
	}()
	cmd := CommandContext(context.Background(), os.Args[0], "-test.run=^TestRunTrackedCannotReachProcessesOutsideItsTreeHelper$")
	cmd.Env = append(os.Environ(), reachDirEnv+"="+t.TempDir(),
		reachHelperEnv+"=gateway="+strconv.Itoa(os.Getpid())+",peer="+strconv.Itoa(peer.Process.Pid))
	var out strings.Builder
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := RunTracked(cmd); err != nil {
		t.Fatalf("scanner reached a process outside its tree: %v: %s", err, out.String())
	}
}

// hostStatImpostor is a socket that is not the launcher's channel, and a
// probe that reports whether anything was written to it.
type hostStatImpostor struct {
	name     string
	fd       int
	received func() bool
}

func hostStatImpostors(t *testing.T) []hostStatImpostor {
	t.Helper()
	pending := func(fd int) func() bool {
		return func() bool {
			events := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
			n, _ := unix.Poll(events, 200)
			return n > 0
		}
	}
	loopback := &unix.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}}
	var impostors []hostStatImpostor
	listener, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.Bind(listener, loopback); err != nil {
		t.Fatal(err)
	}
	if err := unix.Listen(listener, 1); err != nil {
		t.Fatal(err)
	}
	address, err := unix.Getsockname(listener)
	if err != nil {
		t.Fatal(err)
	}
	client, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.Connect(client, address); err != nil {
		t.Fatal(err)
	}
	server, _, err := unix.Accept(listener)
	if err != nil {
		t.Fatal(err)
	}
	impostors = append(impostors, hostStatImpostor{"tcp", client, pending(server)})
	udpServer, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.Bind(udpServer, loopback); err != nil {
		t.Fatal(err)
	}
	udpAddress, err := unix.Getsockname(udpServer)
	if err != nil {
		t.Fatal(err)
	}
	udpClient, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.Connect(udpClient, udpAddress); err != nil {
		t.Fatal(err)
	}
	impostors = append(impostors, hostStatImpostor{"udp", udpClient, pending(udpServer)})
	for name, kind := range map[string]int{"unix stream": unix.SOCK_STREAM, "own seqpacket pair": unix.SOCK_SEQPACKET, "unix datagram": unix.SOCK_DGRAM} {
		pair, err := unix.Socketpair(unix.AF_UNIX, kind|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			t.Fatal(err)
		}
		impostors = append(impostors, hostStatImpostor{name, pair[0], pending(pair[1])})
	}
	return impostors
}

const hostStatHelperEnv = "DC_PROCESSUTIL_HOST_STAT_HELPER"

// TestRunTrackedHostStatTrustsOnlyTheLauncherHelper runs below the scanner's
// PID 1, where the launcher's channel is fd 5. Every other socket put on fd 5
// must be refused before a request is written to it.
func TestRunTrackedHostStatTrustsOnlyTheLauncherHelper(t *testing.T) {
	if os.Getenv(hostStatHelperEnv) != "1" {
		t.Skip("helper process of TestRunTrackedHostStatTrustsOnlyTheLauncher")
	}
	validate := func() error { return managed.ValidateTrustedFilePath("/etc/passwd", "root-owned file") }
	if err := validate(); err != nil {
		t.Fatalf("the launcher's channel was refused: %v", err)
	}
	launcher, err := unix.Dup(5)
	if err != nil {
		t.Fatal(err)
	}
	for _, impostor := range hostStatImpostors(t) {
		if err := unix.Dup3(impostor.fd, 5, 0); err != nil {
			t.Fatal(err)
		}
		if err := validate(); err == nil {
			t.Errorf("%s on fd 5 vouched for a root-owned file", impostor.name)
		}
		if impostor.received() {
			t.Errorf("a request was written to the %s on fd 5", impostor.name)
		}
	}
	if err := unix.Dup3(launcher, 5, 0); err != nil {
		t.Fatal(err)
	}
	if err := validate(); err != nil {
		t.Fatalf("the launcher's channel was refused after the impostors: %v", err)
	}
}

func TestRunTrackedHostStatTrustsOnlyTheLauncher(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root-owned files keep their owner in a root scanner; no host-stat request is made")
	}
	t.Run("go", func(t *testing.T) {
		// A shell PID 1 keeps the helper a child of the scanner's init.
		cmd := CommandContext(context.Background(), "/bin/sh", "-c", `"$@"; exit $?`, "sh",
			os.Args[0], "-test.run=^TestRunTrackedHostStatTrustsOnlyTheLauncherHelper$")
		cmd.Env = append(os.Environ(), hostStatHelperEnv+"=1")
		var out strings.Builder
		cmd.Stdout, cmd.Stderr = &out, &out
		if err := RunTracked(cmd); err != nil {
			t.Fatalf("Go host-stat reader: %v: %s", err, out.String())
		}
	})
	t.Run("python", func(t *testing.T) {
		python, err := exec.LookPath("python3")
		if err != nil {
			t.Skip("python3 is not installed")
		}
		cli, err := filepath.Abs("../../cli")
		if err != nil {
			t.Fatal(err)
		}
		code := `import os, select, socket
from defenseclaw.file_permissions import tracked_host_owner_uid
info = os.stat('/etc/passwd')
assert tracked_host_owner_uid('/etc/passwd', info) == 0, 'launcher channel refused'
launcher = os.dup(5)
listener = socket.create_server(('127.0.0.1', 0))
tcp = socket.create_connection(listener.getsockname())
server, _ = listener.accept()
udp_server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udp_server.bind(('127.0.0.1', 0))
udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udp.connect(udp_server.getsockname())
impostors = {'tcp': (tcp, server), 'udp': (udp, udp_server)}
for name, kind in (('unix stream', socket.SOCK_STREAM), ('own seqpacket pair', socket.SOCK_SEQPACKET), ('unix datagram', socket.SOCK_DGRAM)):
    impostors[name] = socket.socketpair(socket.AF_UNIX, kind)
for name, (mine, other) in impostors.items():
    os.dup2(mine.fileno(), 5)
    assert tracked_host_owner_uid('/etc/passwd', info) == -1, name + ' vouched for a root-owned file'
    assert not select.select([other], [], [], 0.2)[0], 'a request was written to the ' + name
os.dup2(launcher, 5)
assert tracked_host_owner_uid('/etc/passwd', info) == 0, 'launcher channel refused after the impostors'
print('ok')`
		cmd := CommandContext(context.Background(), python, "-c", code)
		cmd.Env = append(os.Environ(), "PYTHONPATH="+cli)
		var out strings.Builder
		cmd.Stdout, cmd.Stderr = &out, &out
		if err := RunTracked(cmd); err != nil || strings.TrimSpace(out.String()) != "ok" {
			t.Fatalf("Python host-stat reader: %v: %s", err, out.String())
		}
	})
}
