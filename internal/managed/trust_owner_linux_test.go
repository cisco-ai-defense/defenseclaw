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

// A host daemon can have PID 1 as its parent and an unrelated socket on fd 5.
// It must not send a custody request outside a tracked scanner namespace.
func TestHostOwnerUIDRejectsHostSocketWithParentPID1(t *testing.T) {
	const stageEnv = "DC_MANAGED_BROKER_TEST_STAGE"
	const markerEnv = "DC_MANAGED_BROKER_TEST_MARKER"
	if stage := os.Getenv(stageEnv); stage != "" {
		if stage == "middle" {
			null, err := os.Open(os.DevNull)
			if err != nil {
				os.Exit(2)
			}
			leaf := exec.Command(os.Args[0], "-test.run=^TestHostOwnerUIDRejectsHostSocketWithParentPID1$")
			leaf.Env = append(os.Environ(), stageEnv+"=leaf")
			leaf.ExtraFiles = []*os.File{null, null, os.NewFile(5, "host-socket")}
			if leaf.Start() != nil {
				os.Exit(2)
			}
			os.Exit(0)
		}
		for deadline := time.Now().Add(5 * time.Second); os.Getppid() != 1; time.Sleep(10 * time.Millisecond) {
			if time.Now().After(deadline) {
				os.Exit(3)
			}
		}
		info, err := os.Stat("/etc/passwd")
		if err != nil {
			os.Exit(4)
		}
		owner := hostOwnerUID("/etc/passwd", info, 65534)
		_ = os.WriteFile(os.Getenv(markerEnv), []byte(strconv.FormatUint(uint64(owner), 10)), 0o600)
		os.Exit(0)
	}

	fd, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	peer := os.NewFile(uintptr(fd[0]), "host-socket-peer")
	child := os.NewFile(uintptr(fd[1]), "host-socket-child")
	defer peer.Close()
	defer child.Close()
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
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(20 * time.Millisecond) {
		if raw, err := os.ReadFile(marker); err == nil {
			if got := strings.TrimSpace(string(raw)); got != strconv.FormatUint(uint64(^uint32(0)), 10) {
				t.Fatalf("host owner from unrelated broker = %s, want refused owner", got)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("reparented host helper did not finish")
		}
	}
	events := []unix.PollFd{{Fd: int32(peer.Fd()), Events: unix.POLLIN}}
	if n, err := unix.Poll(events, 0); err != nil || n != 0 {
		t.Fatalf("host gateway sent a request to an unrelated socket: poll=%d err=%v", n, err)
	}
}
