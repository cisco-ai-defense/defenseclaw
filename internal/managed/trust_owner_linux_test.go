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

package managed

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestHostOwnerUIDFailsClosedWithoutTrackedBroker(t *testing.T) {
	t.Setenv("DEFENSECLAW_TRACKED_HOST_STAT_FD", "")
	info, err := os.Stat("/etc/passwd")
	if err != nil {
		t.Fatal(err)
	}
	if got := hostOwnerUID("/etc/passwd", info, 65534); got != ^uint32(0) {
		t.Fatalf("overflow owner without broker = %d; want refused owner", got)
	}
}

// A host daemon can have PID 1 as its parent and an unrelated socket on fd 5:
// one of its own socketpairs, or a TCP connection, whose peer the kernel
// reports as PID 0. Neither is the launcher's channel, and no custody request
// may be written to it outside a tracked scanner's namespace.
func TestHostOwnerUIDRejectsHostSocketWithParentPID1(t *testing.T) {
	const stageEnv = "DC_MANAGED_BROKER_TEST_STAGE"
	const markerEnv = "DC_MANAGED_BROKER_TEST_MARKER"
	const middleEnv = "DC_MANAGED_BROKER_TEST_MIDDLE_PID"
	if stage := os.Getenv(stageEnv); stage != "" {
		if stage == "middle" {
			null, err := os.Open(os.DevNull)
			if err != nil {
				os.Exit(2)
			}
			leaf := exec.Command(os.Args[0], "-test.run=^TestHostOwnerUIDRejectsHostSocketWithParentPID1$")
			leaf.Env = append(os.Environ(), stageEnv+"=leaf", middleEnv+"="+strconv.Itoa(os.Getpid()))
			leaf.ExtraFiles = []*os.File{null, null, os.NewFile(5, "host-socket")}
			if leaf.Start() != nil {
				os.Exit(2)
			}
			os.Exit(0)
		}
		marker := os.Getenv(markerEnv)
		// The middle names itself: it can exit before this process first
		// reads its parent, and a parent read then would wait on PID 1.
		middle, err := strconv.Atoi(os.Getenv(middleEnv))
		if err != nil {
			os.Exit(5)
		}
		for deadline := time.Now().Add(5 * time.Second); os.Getppid() == middle; time.Sleep(10 * time.Millisecond) {
			if time.Now().After(deadline) {
				os.Exit(3)
			}
		}
		if adopter := os.Getppid(); adopter != 1 {
			// A child subreaper (systemd --user, a container init) adopted
			// this process, so the parent-PID-1 case cannot be built here.
			_ = os.WriteFile(marker, []byte("subreaper "+strconv.Itoa(adopter)), 0o600)
			os.Exit(0)
		}
		info, err := os.Stat("/etc/passwd")
		if err != nil {
			os.Exit(4)
		}
		owner := hostOwnerUID("/etc/passwd", info, 65534)
		_ = os.WriteFile(marker, []byte(strconv.FormatUint(uint64(owner), 10)), 0o600)
		os.Exit(0)
	}

	for name, open := range map[string]func(t *testing.T) (child, peer int){
		"own socketpair": func(t *testing.T) (int, int) {
			fd, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
			if err != nil {
				t.Fatal(err)
			}
			return fd[1], fd[0]
		},
		"tcp connection": func(t *testing.T) (int, int) {
			listener, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer unix.Close(listener)
			if err := unix.Bind(listener, &unix.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}}); err != nil {
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
			return client, server
		},
	} {
		t.Run(name, func(t *testing.T) {
			childFD, peerFD := open(t)
			child := os.NewFile(uintptr(childFD), "host-socket-child")
			peer := os.NewFile(uintptr(peerFD), "host-socket-peer")
			defer child.Close()
			defer peer.Close()
			null, err := os.Open(os.DevNull)
			if err != nil {
				t.Fatal(err)
			}
			defer null.Close()
			marker := filepath.Join(t.TempDir(), "broker-result")
			middle := exec.Command(os.Args[0], "-test.run=^TestHostOwnerUIDRejectsHostSocketWithParentPID1$")
			middle.Env = append(os.Environ(), stageEnv+"=middle", markerEnv+"="+marker,
				"DEFENSECLAW_TRACKED_HOST_STAT_FD=5")
			middle.ExtraFiles = []*os.File{null, null, child}
			if output, err := middle.CombinedOutput(); err != nil {
				t.Fatalf("start reparented host helper: %v: %s", err, output)
			}
			deadline := time.Now().Add(5 * time.Second)
			for ; ; time.Sleep(20 * time.Millisecond) {
				if raw, err := os.ReadFile(marker); err == nil {
					got := strings.TrimSpace(string(raw))
					if adopter, ok := strings.CutPrefix(got, "subreaper "); ok {
						t.Skipf("a child subreaper (PID %s) adopted the helper instead of PID 1; this host cannot build the parent-PID-1 case", adopter)
					}
					if got != strconv.FormatUint(uint64(^uint32(0)), 10) {
						t.Fatalf("host owner from unrelated socket = %s, want refused owner", got)
					}
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("reparented host helper did not finish")
				}
			}
			events := []unix.PollFd{{Fd: int32(peer.Fd()), Events: unix.POLLIN}}
			if n, err := pollHostSocketPeer(events, deadline, unix.Poll); err != nil || n != 0 {
				t.Fatalf("host process sent a request to an unrelated socket: poll=%d err=%v", n, err)
			}
		})
	}
}

func pollHostSocketPeer(events []unix.PollFd, deadline time.Time, poll func([]unix.PollFd, int) (int, error)) (int, error) {
	for {
		n, err := poll(events, 0)
		if !errors.Is(err, unix.EINTR) || !time.Now().Before(deadline) {
			return n, err
		}
	}
}

func TestHostSocketPollRetriesInterruptedCall(t *testing.T) {
	calls := 0
	n, err := pollHostSocketPeer(nil, time.Now().Add(time.Second), func([]unix.PollFd, int) (int, error) {
		calls++
		if calls == 1 {
			return -1, unix.EINTR
		}
		return 0, nil
	})
	if n != 0 || err != nil || calls != 2 {
		t.Fatalf("poll after interruption = (%d, %v), calls=%d; want (0, nil), calls=2", n, err, calls)
	}
}

func TestHostSocketPollKeepsReadyPeerAndDeadline(t *testing.T) {
	for _, tc := range []struct {
		name     string
		deadline time.Time
		result   int
		err      error
	}{
		{name: "quiet peer", deadline: time.Now().Add(time.Second)},
		{name: "ready peer", deadline: time.Now().Add(time.Second), result: 1},
		{name: "interrupted at deadline", deadline: time.Now().Add(-time.Second), result: -1, err: unix.EINTR},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			n, err := pollHostSocketPeer(nil, tc.deadline, func([]unix.PollFd, int) (int, error) {
				calls++
				return tc.result, tc.err
			})
			if n != tc.result || !errors.Is(err, tc.err) || calls != 1 {
				t.Fatalf("poll = (%d, %v), calls=%d; want (%d, %v), calls=1", n, err, calls, tc.result, tc.err)
			}
		})
	}
}
